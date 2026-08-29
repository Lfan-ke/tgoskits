//! Format-agnostic executable dispatch for ArceOS/StarryOS.
//!
//! StarryOS is today a single Linux personality: its loader only understands ELF
//! and its trap handler dispatches a hard-coded Linux syscall table. ArceOS's
//! design goal is to host Linux, Windows and macOS personalities over the shared
//! `ax_*` primitives. This crate is the dispatch layer that makes that possible,
//! mirroring the Linux kernel's `binfmt` subsystem: a set of [`Personality`]
//! handlers is tried in order and the first to recognize an image owns it
//! (see [`dispatch`], the analogue of `fs/exec.c::search_binary_handler`).
//!
//! The crate is `no_std` and holds no kernel types. Personalities reach the
//! kernel through the small [`LoadEnv`] and [`TrapEnv`] capability boundaries,
//! and the caller owns the personality set, so nothing here allocates or keeps
//! global mutable state.

#![cfg_attr(not(test), no_std)]
#![feature(used_with_arg)]

pub mod macho;
pub mod pe;

use ax_crate_interface::def_interface;
use bitflags::bitflags;

/// The OS personality a user binary targets.
///
/// Named after the Rust/LLVM target-triple OS field (`*-linux-*`,
/// `*-pc-windows-*`, `*-apple-darwin`) so the mapping to a real toolchain target
/// is unambiguous - not the product names (macOS) nor the userland (GNU).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Abi {
    /// ELF images executing the Linux syscall ABI (glibc or musl).
    Linux,
    /// PE/COFF images executing the Windows NT native ABI.
    Windows,
    /// Mach-O images executing the Darwin (BSD + Mach) ABI.
    Darwin,
    /// A bare interrupt-vector table: the degenerate dispatch domain for
    /// embedded targets, with no OS object model and no magic-routed image
    /// format. Installed explicitly by an integrator, not selected by [`detect`].
    Embedded,
}

/// Errors surfaced while recognizing, loading or running a foreign binary.
///
/// Kept small and `Copy` so integration glue can translate each variant to the
/// personality's own errno space (`ENOEXEC`, `ENOMEM`, ...).
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum AbiError {
    /// No registered personality recognized the image (`ENOEXEC`).
    #[error("unrecognized executable format")]
    UnknownFormat,
    /// A header was malformed or truncated (`ENOEXEC`).
    #[error("malformed or truncated image header")]
    MalformedImage,
    /// A recognized but unsupported image variant, e.g. a 32-bit PE.
    #[error("unsupported image variant")]
    Unsupported,
    /// Mapping the image into the target address space failed (`ENOMEM`).
    #[error("mapping user memory failed")]
    MapFailed,
}

/// Result type for personality operations.
pub type AbiResult<T> = Result<T, AbiError>;

bitflags! {
    /// Protection for a user mapping, neutral across personalities. Maps onto
    /// `PROT_*`, PE section characteristics and Mach-O `vm_prot` at the edges.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct Prot: u32 {
        /// Readable pages.
        const READ = 1 << 0;
        /// Writable pages.
        const WRITE = 1 << 1;
        /// Executable pages.
        const EXEC = 1 << 2;
    }
}

/// A request to load an executable image, borrowed to keep the core allocation-free.
pub struct LoadRequest<'a> {
    /// The raw executable bytes.
    pub image: &'a [u8],
    /// Program arguments (`argv`), personality-neutral.
    pub args: &'a [&'a str],
    /// Environment strings (`envp`), personality-neutral.
    pub envs: &'a [&'a str],
}

/// The outcome of loading an image: where to begin user execution.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Loaded {
    /// First user instruction pointer (virtual address).
    pub entry: u64,
    /// Initial user stack pointer, or `0` when the personality defers stack
    /// setup to the kernel (e.g. an ELF aux vector built during exec).
    pub stack: u64,
}

/// Load-time capabilities the kernel exposes to a personality.
///
/// A deliberately small capability boundary: a loader fundamentally needs to
/// place bytes into the target address space with a protection. The trait grows
/// per phase as real loaders demand more (e.g. querying the mmap base), rather
/// than starting as a wide god-interface.
pub trait LoadEnv {
    /// Map `[va, va + len)` with `prot`, initializing the head from `init`
    /// (the remainder is zero-filled, as `.bss` and PE uninitialized data need).
    fn map_region(&mut self, va: u64, len: u64, prot: Prot, init: Option<&[u8]>) -> AbiResult<()>;
}

/// Runtime trap capabilities for one syscall.
///
/// The personality reads this ABI-neutral view of the trapped register file and
/// writes the result back, then dispatches internally to its own number space
/// (Linux `Sysno`, NT SSDT index, or Darwin class+number).
pub trait TrapEnv {
    /// The syscall number as seen in the trap frame.
    fn nr(&self) -> usize;
    /// Positional syscall argument `i` (0-based).
    fn arg(&self, i: usize) -> usize;
    /// Write the syscall's return value into the trap frame.
    fn set_result(&mut self, value: usize);

    /// Report failure through whatever channel the ABI uses beyond the return
    /// register: Darwin sets the carry flag and returns a positive errno, where
    /// Linux folds both into a negative value. A host without such a channel
    /// ignores this, and an ABI that encodes failure in the value alone never
    /// calls it.
    fn set_error(&mut self, _failed: bool) {}
}

/// Whether a trapped index was serviced.
///
/// A syscall, a VM exit, an interrupt vector and a custom instruction are the
/// same shape - an index carried by a trap - so dispatch reports only whether
/// something claimed it. `Passthrough` lets the caller try the next handler
/// (a [`CustomHandler`]) or apply the domain's default (e.g. `ENOSYS`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Dispatch {
    /// The index was handled; the result is already written to the trap frame.
    Handled,
    /// The index is not one this handler owns; try the next handler.
    Passthrough,
}

/// A loadable, runnable OS personality: one entry in the dispatch table, the
/// analogue of a `struct linux_binfmt`.
///
/// `Sync` because a single set of personalities is shared read-only across CPUs.
pub trait Personality: Sync {
    /// Which ABI this personality implements.
    fn abi(&self) -> Abi;

    /// Does this handler claim `image`? Mirrors the head-magic check a
    /// `linux_binfmt::load_binary` performs before committing. Must be cheap and
    /// side-effect free: [`dispatch`] may call it on several handlers.
    fn recognizes(&self, image: &[u8]) -> bool;

    /// Service one trapped index (a syscall) for a task of this personality,
    /// reporting whether it was this personality's. `Passthrough` defers to the
    /// registered [`CustomHandler`]s.
    fn handle_syscall(&self, env: &mut dyn TrapEnv) -> Dispatch;

    /// Service a trapped index without touching the frame, reporting the
    /// outcome instead. A host that still carries its own table uses this, so
    /// its own epilogue runs for serviced and unclaimed calls alike. `None`
    /// means the call is not this personality's, or that it only offers the
    /// frame-writing form above.
    fn route(&self, _env: &dyn TrapEnv) -> TrapOutcome {
        None
    }

    /// How this personality loads its images, when it is the one that loads
    /// them. `None` says the hosting OS still owns that, which is the honest
    /// answer while a loader has not moved out of a kernel yet.
    fn loader(&self) -> Option<&dyn Loader> {
        None
    }
}

/// Placing an executable image into a target address space - the analogue of
/// `linux_binfmt::load_binary`, kept apart from [`Personality`] because loading
/// and servicing traps are separate capabilities that move out of a kernel at
/// different times.
pub trait Loader: Sync {
    /// Map `req.image` into `env` and return where to begin execution.
    fn load(&self, req: &LoadRequest<'_>, env: &mut dyn LoadEnv) -> AbiResult<Loaded>;
}

/// One personality's entry in the registry.
///
/// The entries live in their own linker section, so a personality appears by
/// being linked in and disappears by being dropped from the dependency list -
/// nobody keeps a list. This is how drivers register in this workspace too.
#[repr(C)]
pub struct Registration {
    get: fn() -> &'static dyn Personality,
}

impl Registration {
    /// Wrap the accessor a registration hands out.
    pub const fn new(get: fn() -> &'static dyn Personality) -> Self {
        Self { get }
    }

    /// The personality this entry registers.
    pub fn personality(&self) -> &'static dyn Personality {
        (self.get)()
    }
}

/// Register a personality with the platform.
///
/// Takes a path to a `fn() -> &'static dyn Personality`.
#[macro_export]
macro_rules! register_sysabi {
    ($get:path) => {
        const _: () = {
            #[used(linker)]
            #[unsafe(link_section = "abi_register")]
            static REGISTRATION: $crate::Registration = $crate::Registration::new($get);
        };
    };
}

/// A personality that claims nothing, registered so the section always exists
/// and its bounds are always defined, however few personalities are linked in.
struct NoPersonality;

impl Personality for NoPersonality {
    fn abi(&self) -> Abi {
        Abi::Embedded
    }
    fn recognizes(&self, _image: &[u8]) -> bool {
        false
    }
    fn handle_syscall(&self, _env: &mut dyn TrapEnv) -> Dispatch {
        Dispatch::Passthrough
    }
}

fn no_personality() -> &'static dyn Personality {
    static IT: NoPersonality = NoPersonality;
    &IT
}

register_sysabi!(no_personality);

/// Every personality this build linked in.
pub fn registered() -> &'static [Registration] {
    // Declared as opaque symbols: only their addresses matter, and a function
    // item keeps the declaration free of a type the linker never sees.
    unsafe extern "C" {
        fn __start_abi_register();
        fn __stop_abi_register();
    }
    let start = __start_abi_register as *const () as *const Registration;
    let stop = __stop_abi_register as *const () as *const Registration;
    // SAFETY: the two symbols bound one array of `Registration`, which the
    // linker fills from the `abi_register` section of every linked crate.
    unsafe {
        let len = (stop as usize - start as usize) / size_of::<Registration>();
        core::slice::from_raw_parts(start, len)
    }
}

/// Ask each registered personality to service a trapped index, stopping at the
/// first that claims it.
/// Offer a trapped index to each linked personality until one claims it.
pub fn dispatch_registered_trap(env: &mut dyn TrapEnv) -> Dispatch {
    for entry in registered() {
        if entry.personality().handle_syscall(env) == Dispatch::Handled {
            return Dispatch::Handled;
        }
    }
    Dispatch::Passthrough
}

pub fn route_registered(env: &dyn TrapEnv) -> TrapOutcome {
    registered()
        .iter()
        .find_map(|entry| entry.personality().route(env))
}

/// Route `image` to the first registered personality that claims it.
///
/// # Errors
///
/// [`AbiError::UnknownFormat`] when none does.
pub fn dispatch_registered(image: &[u8]) -> AbiResult<&'static dyn Personality> {
    registered()
        .iter()
        .map(Registration::personality)
        .find(|p| p.recognizes(image))
        .ok_or(AbiError::UnknownFormat)
}

/// A user-registered handler for a trapped index - the extension point for
/// adding syscalls/hypercalls/instructions without forking a personality,
/// analogous to RISC-V's reserved custom opcode space or a Chipyard RoCC
/// accelerator. Run in registration order, before or after the personality
/// depending on which entry point the caller uses ([`dispatch_trap`] for
/// coequal extension, [`dispatch_trap_intercept`] for override).
pub trait CustomHandler: Sync {
    /// Service the trapped index if it is one this extension owns.
    fn handle(&self, env: &mut dyn TrapEnv) -> Dispatch;
}

/// What servicing a trapped index produced: `None` when no personality claimed
/// it, otherwise the outcome - a return value, or a positive error number the
/// caller encodes its own way.
pub type TrapOutcome = Option<Result<isize, i32>>;

/// The dispatch entry a hosting kernel calls, without naming a personality.
///
/// The ABI layer supplies the single implementation: it knows which domains are
/// compiled in and which one owns the running task. So swapping the ABI a system
/// speaks is a dependency change there - the kernel keeps calling this.
#[def_interface]
pub trait TrapDispatch {
    /// Service a trapped index for the calling task's personality, which writes
    /// the result itself: how a result is encoded into the frame is part of an
    /// ABI, not of the kernel hosting it.
    fn dispatch(env: &mut dyn TrapEnv) -> Dispatch;
}

/// Run each custom handler in registration order, stopping at the first that
/// claims the index.
fn run_custom(custom: &[&dyn CustomHandler], env: &mut dyn TrapEnv) -> Dispatch {
    for &h in custom {
        if h.handle(env) == Dispatch::Handled {
            return Dispatch::Handled;
        }
    }
    Dispatch::Passthrough
}

/// Route a trapped index to the personality first, then to the custom handlers,
/// stopping at the first that claims it, or [`Dispatch::Passthrough`] when none
/// does (the caller then applies the personality's default, `ENOSYS`).
///
/// Personality-first: custom handlers only see indices the base ABI passed
/// through, so they extend its reserved space and cannot shadow it. This is the
/// safe default, in which a custom ABI is a peer of the Linux/Windows/Darwin
/// personalities rather than an override of one.
pub fn dispatch_trap(
    personality: &dyn Personality,
    custom: &[&dyn CustomHandler],
    env: &mut dyn TrapEnv,
) -> Dispatch {
    if personality.handle_syscall(env) == Dispatch::Handled {
        return Dispatch::Handled;
    }
    run_custom(custom, env)
}

/// Route a trapped index to the custom handlers first, then to the personality.
///
/// Custom-first: a custom handler may claim an index the personality also owns,
/// redirecting that syscall to the user's own implementation. The deliberate
/// opt-in counterpart to [`dispatch_trap`] - it trades the safety of a
/// non-shadowable base ABI for the power to intercept it.
pub fn dispatch_trap_intercept(
    personality: &dyn Personality,
    custom: &[&dyn CustomHandler],
    env: &mut dyn TrapEnv,
) -> Dispatch {
    if run_custom(custom, env) == Dispatch::Handled {
        return Dispatch::Handled;
    }
    if personality.handle_syscall(env) == Dispatch::Handled {
        return Dispatch::Handled;
    }
    Dispatch::Passthrough
}

/// Route `image` to the first registered personality that recognizes it, the
/// analogue of `fs/exec.c::search_binary_handler`.
///
/// The caller owns the handler set (typically a `&'static [&'static dyn
/// Personality]` assembled by the umbrella crate or kernel), so registration
/// order - hence match priority - is explicit and there is no global state.
pub fn dispatch<'a>(
    handlers: &'a [&'a dyn Personality],
    image: &[u8],
) -> AbiResult<&'a dyn Personality> {
    handlers
        .iter()
        .copied()
        .find(|p| p.recognizes(image))
        .ok_or(AbiError::UnknownFormat)
}

/// Recognize an image's format by its leading magic bytes, independent of any
/// registered handler. A fast, pure classifier a handler's [`Personality::recognizes`]
/// can build on, and the routing StarryOS's loader needs before a personality
/// set exists. Returns `None` for an unrecognized image (the caller reports
/// `ENOEXEC`).
pub fn detect(image: &[u8]) -> Option<Abi> {
    // ELF: "\x7fELF".
    if image.starts_with(b"\x7fELF") {
        return Some(Abi::Linux);
    }
    // Mach-O: thin 32/64-bit little/big-endian, or a fat/universal archive.
    if matches!(
        image.first_chunk::<4>(),
        Some(
            [0xFE, 0xED, 0xFA, 0xCE]
                | [0xFE, 0xED, 0xFA, 0xCF]
                | [0xCE, 0xFA, 0xED, 0xFE]
                | [0xCF, 0xFA, 0xED, 0xFE]
                | [0xCA, 0xFE, 0xBA, 0xBE]
        )
    ) {
        return Some(Abi::Darwin);
    }
    // PE: "MZ" DOS header whose `e_lfanew` (@0x3C) points at a "PE\0\0" signature.
    if image.starts_with(b"MZ") {
        let pe_off = image.get(0x3C..0x40)?;
        let pe_off = u32::from_le_bytes(pe_off.try_into().ok()?) as usize;
        if image.get(pe_off..pe_off + 4) == Some(b"PE\0\0") {
            return Some(Abi::Windows);
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detect_routes_each_format_by_magic() {
        assert_eq!(detect(b"\x7fELF\x02\x01\x01"), Some(Abi::Linux));
        assert_eq!(detect(&[0xFE, 0xED, 0xFA, 0xCF, 0, 0]), Some(Abi::Darwin));
        assert_eq!(detect(&[0xCA, 0xFE, 0xBA, 0xBE]), Some(Abi::Darwin));
        assert_eq!(detect(b"not an exe"), None);
        assert_eq!(detect(b""), None);
        // "MZ" without a valid PE pointer is not routed to Windows.
        assert_eq!(detect(b"MZ\x00\x00"), None);
    }

    // A PE stub whose PE signature sits at `pe_off`, modeling the gap (Rich
    // header, larger DOS stub) different linkers leave before it.
    fn pe_stub(pe_off: usize) -> Vec<u8> {
        let mut b = vec![0u8; pe_off + 4];
        b[0..2].copy_from_slice(b"MZ");
        b[0x3C..0x40].copy_from_slice(&(pe_off as u32).to_le_bytes());
        b[pe_off..pe_off + 4].copy_from_slice(b"PE\0\0");
        b
    }

    #[test]
    fn detect_is_libc_and_toolchain_agnostic() {
        // Every libc/target ELF shares the magic, so all route to Linux: glibc
        // dynamic, musl static, newlib 32-bit, and a big-endian image differ
        // only past the first four bytes.
        for ident in [
            b"\x7fELF\x02\x01\x01\x00", // 64-bit LE (glibc/musl)
            b"\x7fELF\x01\x01\x01\x00", // 32-bit LE (newlib)
            b"\x7fELF\x02\x02\x01\x00", // 64-bit BE
        ] {
            assert_eq!(detect(ident), Some(Abi::Linux));
        }

        // MinGW (GNU) and MSVC both emit PE/COFF; MSVC usually leaves a Rich
        // header before the PE signature. Both must route to Windows.
        assert_eq!(detect(&pe_stub(0x80)), Some(Abi::Windows)); // compact (MinGW)
        assert_eq!(detect(&pe_stub(0x120)), Some(Abi::Windows)); // Rich-header gap (MSVC)

        // clang Mach-O: thin 64/32-bit and a fat/universal archive.
        for magic in [
            [0xFE, 0xED, 0xFA, 0xCF],
            [0xFE, 0xED, 0xFA, 0xCE],
            [0xCA, 0xFE, 0xBA, 0xBE],
        ] {
            assert_eq!(detect(&magic), Some(Abi::Darwin));
        }
    }

    // A handler that claims any image whose magic maps to its ABI, so the
    // dispatch tests exercise real routing rather than a constant.
    struct MagicHandler(Abi);

    impl Personality for MagicHandler {
        fn abi(&self) -> Abi {
            self.0
        }
        fn recognizes(&self, image: &[u8]) -> bool {
            detect(image) == Some(self.0)
        }
        fn handle_syscall(&self, _env: &mut dyn TrapEnv) -> Dispatch {
            // This mock owns no syscalls, so every index passes through - which is
            // exactly what lets the extension tests reach the custom handlers.
            Dispatch::Passthrough
        }
    }

    // A trap frame exposing a fixed index, enough to drive dispatch routing.
    struct Trap {
        nr: usize,
        result: Option<usize>,
    }
    impl TrapEnv for Trap {
        fn nr(&self) -> usize {
            self.nr
        }
        fn arg(&self, _i: usize) -> usize {
            0
        }
        fn set_result(&mut self, value: usize) {
            self.result = Some(value);
        }
    }

    // A custom extension that claims one reserved index (RoCC-style), writing a
    // sentinel result so the test can see it ran.
    struct CustomOne(usize);
    impl CustomHandler for CustomOne {
        fn handle(&self, env: &mut dyn TrapEnv) -> Dispatch {
            if env.nr() == self.0 {
                env.set_result(0xC0DE);
                Dispatch::Handled
            } else {
                Dispatch::Passthrough
            }
        }
    }

    #[test]
    fn custom_handler_extends_a_passthrough_personality() {
        let linux = MagicHandler(Abi::Linux);
        let custom = CustomOne(0x900);
        let handlers: [&dyn CustomHandler; 1] = [&custom];

        // The reserved index reaches the custom handler and is serviced.
        let mut owned = Trap {
            nr: 0x900,
            result: None,
        };
        assert_eq!(
            dispatch_trap(&linux, &handlers, &mut owned),
            Dispatch::Handled
        );
        assert_eq!(owned.result, Some(0xC0DE));

        // An index nobody claims passes through for the caller's default.
        let mut unowned = Trap {
            nr: 0x901,
            result: None,
        };
        assert_eq!(
            dispatch_trap(&linux, &handlers, &mut unowned),
            Dispatch::Passthrough
        );
        assert_eq!(unowned.result, None);
    }

    #[test]
    fn intercept_lets_custom_override_the_personality() {
        // A personality that owns index 0x42, writing 0xBA5E.
        struct OwnsOne;
        impl Personality for OwnsOne {
            fn abi(&self) -> Abi {
                Abi::Linux
            }
            fn recognizes(&self, _image: &[u8]) -> bool {
                false
            }
            fn handle_syscall(&self, env: &mut dyn TrapEnv) -> Dispatch {
                if env.nr() == 0x42 {
                    env.set_result(0xBA5E);
                    Dispatch::Handled
                } else {
                    Dispatch::Passthrough
                }
            }
        }
        let base = OwnsOne;
        let custom = CustomOne(0x42); // also claims 0x42, writing 0xC0DE
        let handlers: [&dyn CustomHandler; 1] = [&custom];

        // Personality-first: the base ABI owns 0x42, so it wins and custom never runs.
        let mut a = Trap {
            nr: 0x42,
            result: None,
        };
        assert_eq!(dispatch_trap(&base, &handlers, &mut a), Dispatch::Handled);
        assert_eq!(a.result, Some(0xBA5E));

        // Custom-first: the interceptor overrides the base ABI's 0x42.
        let mut b = Trap {
            nr: 0x42,
            result: None,
        };
        assert_eq!(
            dispatch_trap_intercept(&base, &handlers, &mut b),
            Dispatch::Handled
        );
        assert_eq!(b.result, Some(0xC0DE));
    }

    #[test]
    fn dispatch_selects_matching_handler() {
        let linux = MagicHandler(Abi::Linux);
        let windows = MagicHandler(Abi::Windows);
        let handlers: [&dyn Personality; 2] = [&linux, &windows];

        assert_eq!(
            dispatch(&handlers, b"\x7fELF\x02").unwrap().abi(),
            Abi::Linux
        );

        let mut pe = vec![0u8; 0x84];
        pe[0..2].copy_from_slice(b"MZ");
        pe[0x3C..0x40].copy_from_slice(&0x80u32.to_le_bytes());
        pe[0x80..0x84].copy_from_slice(b"PE\0\0");
        assert_eq!(dispatch(&handlers, &pe).unwrap().abi(), Abi::Windows);
    }

    #[test]
    fn dispatch_first_registered_wins() {
        // Two handlers that both claim ELF; registration order decides priority,
        // exactly as search_binary_handler walks the list in order.
        let first = MagicHandler(Abi::Linux);
        let second = MagicHandler(Abi::Linux);
        let handlers: [&dyn Personality; 2] = [&first, &second];
        let chosen = dispatch(&handlers, b"\x7fELF").unwrap();
        assert!(core::ptr::eq(chosen, &first as &dyn Personality));
    }

    #[test]
    fn dispatch_unknown_format_errors() {
        let linux = MagicHandler(Abi::Linux);
        let handlers: [&dyn Personality; 1] = [&linux];
        // `&dyn Personality` is neither Debug nor PartialEq, so match the Result
        // rather than compare it whole.
        assert!(matches!(
            dispatch(&handlers, b"garbage"),
            Err(AbiError::UnknownFormat)
        ));
    }
}
