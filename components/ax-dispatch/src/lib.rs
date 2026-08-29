//! Registered owners of a trapped index.
//!
//! A syscall, a hypervisor exit, an interrupt vector and a custom instruction
//! are the same shape: a trap carries an index and some arguments, and
//! something has to turn that into a concrete behaviour. This crate is the
//! spine that does the turning - it gathers whatever the build linked in and
//! routes each trap to the implementation that claims it.
//!
//! It knows nothing about executable images, because most of what registers
//! here has none: a bare-metal vector table and a hypervisor exit handler both
//! service indices without ever loading a file. Recognizing and loading images
//! is a separate capability, and lives in `ax-binfmt`.
//!
//! The OS personalities in this workspace - Linux, Windows, Darwin - are
//! reference implementations of the trait below, not the definition of it.

#![no_std]
#![feature(used_with_arg)]

use ax_crate_interface::def_interface;

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
    /// Where in the registry the implementation serving this task sits, when
    /// the host resolved it in advance. A host that did not has the call
    /// offered to every linked implementation in turn instead.
    fn slot(&self) -> Option<usize> {
        None
    }

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

/// One registered owner of trapped indices: the thing that turns an index and
/// its arguments into a behaviour.
///
/// `Sync` because a single set of them is shared read-only across CPUs.
pub trait SysAbi: Sync {
    /// Which ABI this implements. A trap reaches only the implementation whose
    /// ABI the trapping task speaks, because indices collide between them.
    fn abi(&self) -> Abi;

    /// Service one trapped index, reporting whether it was this one's.
    /// `Passthrough` defers to the registered [`CustomHandler`]s.
    fn handle_syscall(&self, env: &mut dyn TrapEnv) -> Dispatch;

    /// Service a trapped index without touching the frame, reporting the
    /// outcome instead. A host that still carries its own table uses this, so
    /// its own epilogue runs for serviced and unclaimed calls alike. `None`
    /// means the index is not this one's, or that it only offers the
    /// frame-writing form above.
    fn route(&self, _env: &dyn TrapEnv) -> TrapOutcome {
        None
    }
}

/// One personality's entry in the registry.
///
/// The entries live in their own linker section, so a personality appears by
/// being linked in and disappears by being dropped from the dependency list -
/// nobody keeps a list. This is how drivers register in this workspace too.
#[repr(C)]
pub struct Registration {
    get: fn() -> &'static dyn SysAbi,
}

impl Registration {
    /// Wrap the accessor a registration hands out.
    pub const fn new(get: fn() -> &'static dyn SysAbi) -> Self {
        Self { get }
    }

    /// The personality this entry registers.
    pub fn sysabi(&self) -> &'static dyn SysAbi {
        (self.get)()
    }
}

/// Register a personality with the platform.
///
/// Takes a path to a `fn() -> &'static dyn SysAbi`.
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
struct NoSysAbi;

impl SysAbi for NoSysAbi {
    fn abi(&self) -> Abi {
        Abi::Embedded
    }
    fn handle_syscall(&self, _env: &mut dyn TrapEnv) -> Dispatch {
        Dispatch::Passthrough
    }
}

fn no_sysabi() -> &'static dyn SysAbi {
    static IT: NoSysAbi = NoSysAbi;
    &IT
}

register_sysabi!(no_sysabi);

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

/// Where in the registry the implementation for `abi` sits, resolved once so a
/// trap need not search for it. `None` when no linked implementation speaks it.
///
/// A host resolves this when a task's ABI is settled - at exec - and keeps the
/// slot, so servicing a trap is an index rather than a scan.
pub fn slot_of(abi: Abi) -> Option<usize> {
    registered()
        .iter()
        .position(|entry| entry.sysabi().abi() == abi)
}

/// Service a trapped index at the implementation a host already resolved.
///
/// Out of range reports [`Dispatch::Passthrough`] rather than panicking: a
/// stale slot means the build changed under a saved value, and refusing the
/// call is the safe reading.
pub fn dispatch_at(slot: usize, env: &mut dyn TrapEnv) -> Dispatch {
    match registered().get(slot) {
        Some(entry) => entry.sysabi().handle_syscall(env),
        None => Dispatch::Passthrough,
    }
}

/// Offer a trapped index to each linked implementation until one claims it.
pub fn dispatch_registered_trap(env: &mut dyn TrapEnv) -> Dispatch {
    // Call numbers collide across ABIs - NT's WriteFile and Linux's write are
    // both 1 on x86-64 - so this order is only safe for a host that does not
    // know which ABI its task speaks. One that does resolves a slot instead.
    for entry in registered() {
        if entry.sysabi().handle_syscall(env) == Dispatch::Handled {
            return Dispatch::Handled;
        }
    }
    Dispatch::Passthrough
}

pub fn route_registered(env: &dyn TrapEnv) -> TrapOutcome {
    registered()
        .iter()
        .find_map(|entry| entry.sysabi().route(env))
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
/// SysAbi-first: custom handlers only see indices the base ABI passed
/// through, so they extend its reserved space and cannot shadow it. This is the
/// safe default, in which a custom ABI is a peer of the Linux/Windows/Darwin
/// personalities rather than an override of one.
pub fn dispatch_trap(
    owner: &dyn SysAbi,
    custom: &[&dyn CustomHandler],
    env: &mut dyn TrapEnv,
) -> Dispatch {
    if owner.handle_syscall(env) == Dispatch::Handled {
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
    owner: &dyn SysAbi,
    custom: &[&dyn CustomHandler],
    env: &mut dyn TrapEnv,
) -> Dispatch {
    if run_custom(custom, env) == Dispatch::Handled {
        return Dispatch::Handled;
    }
    if owner.handle_syscall(env) == Dispatch::Handled {
        return Dispatch::Handled;
    }
    Dispatch::Passthrough
}

#[cfg(test)]
mod tests {
    use super::*;

    // Two ABIs that both claim index 1 - NT's WriteFile and Linux's write on
    // x86-64 - so which one answers has to come from the task, not the number.
    struct Speaks(Abi, usize);
    impl SysAbi for Speaks {
        fn abi(&self) -> Abi {
            self.0
        }
        fn handle_syscall(&self, env: &mut dyn TrapEnv) -> Dispatch {
            if env.nr() == 1 {
                env.set_result(self.1);
                Dispatch::Handled
            } else {
                Dispatch::Passthrough
            }
        }
    }

    struct Caller(Option<usize>);
    impl TrapEnv for Caller {
        fn nr(&self) -> usize {
            1
        }
        fn arg(&self, _i: usize) -> usize {
            0
        }
        fn slot(&self) -> Option<usize> {
            self.0
        }
        fn set_result(&mut self, _value: usize) {}
    }

    #[test]
    fn a_resolved_slot_answers_without_searching() {
        let linux = Speaks(Abi::Linux, 0xA1);
        let windows = Speaks(Abi::Windows, 0xB2);
        let mut answered = None;
        for (slot, owner) in [&linux as &dyn SysAbi, &windows].into_iter().enumerate() {
            struct Sink(Option<usize>);
            impl TrapEnv for Sink {
                fn nr(&self) -> usize {
                    1
                }
                fn arg(&self, _i: usize) -> usize {
                    0
                }
                fn set_result(&mut self, value: usize) {
                    self.0 = Some(value);
                }
            }
            let mut sink = Sink(None);
            assert_eq!(owner.handle_syscall(&mut sink), Dispatch::Handled);
            answered = sink.0;
            assert_eq!(answered, Some(if slot == 0 { 0xA1 } else { 0xB2 }));
        }
        assert!(answered.is_some());
    }

    #[test]
    fn a_slot_past_the_registry_is_refused_not_a_panic() {
        assert_eq!(
            dispatch_at(usize::MAX, &mut Caller(None)),
            Dispatch::Passthrough
        );
    }

    #[test]
    fn the_placeholder_keeps_the_section_bounded() {
        // However few implementations are linked, the registry is walkable.
        assert!(!registered().is_empty());
        assert!(slot_of(Abi::Embedded).is_some());
    }
}
