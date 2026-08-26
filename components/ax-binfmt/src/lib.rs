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

pub mod macho;
pub mod pe;

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

    /// Map `req.image` into `env` and return where to start. The analogue of
    /// `linux_binfmt::load_binary`.
    fn load(&self, req: &LoadRequest<'_>, env: &mut dyn LoadEnv) -> AbiResult<Loaded>;

    /// Dispatch one trapped syscall for a task of this personality.
    fn handle_syscall(&self, env: &mut dyn TrapEnv);
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
        fn load(&self, _req: &LoadRequest<'_>, _env: &mut dyn LoadEnv) -> AbiResult<Loaded> {
            Ok(Loaded { entry: 0, stack: 0 })
        }
        fn handle_syscall(&self, _env: &mut dyn TrapEnv) {}
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
