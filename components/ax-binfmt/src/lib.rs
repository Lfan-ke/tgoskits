//! Executable formats: recognizing an image and placing it in memory.
//!
//! The counterpart to `ax-dispatch`. That crate routes a trapped index to the
//! implementation that owns it; this one answers the earlier question of which
//! implementation a given file belongs to, and hands the file to whatever
//! knows how to map it.
//!
//! The two are separate because they are separate capabilities that leave a
//! kernel at different times, and because plenty of what registers for
//! dispatch - a bare-metal vector table, a hypervisor exit handler - has no
//! image at all. A format registers here; an ABI registers there; a package
//! that does both, like the Windows one, registers twice.

#![no_std]
#![feature(used_with_arg)]

#[cfg(test)]
extern crate alloc;

pub use ax_dispatch::Abi;
use bitflags::bitflags;
pub use linkme;

pub mod macho;
pub mod pe;

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
    /// The image reaches the system through a library this system does not
    /// provide, so mapping it would only defer the failure to its first call
    /// into an unresolved address (`ENOEXEC`).
    #[error("image imports a library this system does not provide")]
    MissingLibrary,
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
    /// The raw executable bytes, as much of them as the host read to recognize
    /// the format. A loader that maps from the file uses [`file`](Self::file).
    pub image: &'a [u8],
    /// Where the host wants the image placed, for a format whose addresses are
    /// relative. A format with fixed addresses ignores it.
    pub load_base: u64,
    /// The pathname the host resolved the program by. A format that looks
    /// for other files beside the program needs it: Windows searches a
    /// program's own directory for its libraries before the system's.
    pub path: &'a str,
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
    /// Where the thread's own control block is, for an ABI that fixes it at
    /// load - Windows places the TEB and points `gs` at it - or `0` for one
    /// that sets its thread pointer itself once running, as ELF does.
    pub thread_pointer: u64,
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

    /// Map `[va, va + len)` from the image being loaded, at `offset` in the
    /// file, copy-on-write, with the file's contribution ending at `file_end`
    /// and the rest zero-filled.
    ///
    /// The difference from [`map_region`](Self::map_region) is where the bytes
    /// come from and when: this leaves them in the host's page cache and lets
    /// them arrive as they are touched, which is what `binfmt_elf` gets from
    /// `vm_mmap` for a `PT_LOAD` and what makes a large image cheap to start.
    fn map_image(
        &mut self,
        va: u64,
        len: u64,
        prot: Prot,
        offset: u64,
        file_end: u64,
    ) -> AbiResult<()>;

    /// Read from the image being loaded without mapping it, so a loader can
    /// read its own headers. Returns how many bytes arrived.
    fn read_image(&mut self, at: u64, out: &mut [u8]) -> AbiResult<usize>;

    /// Continue with `path` as the image being loaded, for a format whose
    /// image names the interpreter that should run it. Both stay mapped: an
    /// ELF maps its own `PT_LOAD`s and then the interpreter's, which is what
    /// this sequencing is for. The host owns the files throughout; a loader
    /// never holds one.
    fn interpret(&mut self, _path: &str) -> AbiResult<()> {
        Err(AbiError::Unsupported)
    }

    /// Record key/value metadata the format wants kept, for a host that
    /// republishes it. Linux exposes the auxiliary vector this way, under
    /// procfs; a host with nowhere to put it ignores the call.
    fn record_metadata(&mut self, _pairs: &[(usize, usize)]) {}

    /// Discard what is mapped and put back whatever the host always maps -
    /// its own fixed mappings, the stack, the heap - before a format lays out
    /// a new image, as an exec does.
    fn reset(&mut self) -> AbiResult<()> {
        Err(AbiError::Unsupported)
    }

    /// Write `bytes` at `va`, which must already be mapped writable. A format
    /// that relocates an image, or that lays out the initial stack itself,
    /// needs this after mapping rather than at map time.
    fn write(&mut self, _va: u64, _bytes: &[u8]) -> AbiResult<()> {
        Err(AbiError::Unsupported)
    }

    /// How long the image being loaded is, for a format that has to bound a
    /// file offset its own headers gave it.
    fn image_len(&self) -> u64 {
        0
    }

    /// The highest address anything is mapped at so far, so a format placing a
    /// second image - an interpreter - can pick a base clear of the first.
    fn mapped_end(&self) -> u64 {
        0
    }

    /// The top of the stack the host prepared. A format lays out whatever its
    /// ABI puts there and reports the resulting pointer in [`Loaded::stack`].
    fn stack_top(&self) -> u64 {
        0
    }

    /// What the processor can do, as the host reports it. Formats that hand a
    /// program a capability word (`AT_HWCAP`) pass this through.
    fn cpu_capabilities(&self) -> u64 {
        0
    }
}

/// Every executable format this build linked in.
///
/// As with the ABI registry, the linker gathers the entries: a format appears
/// by being linked in and disappears by being dropped from the dependency
/// list, and nobody keeps a list.
#[linkme::distributed_slice]
pub static BINFMTS: [fn() -> &'static dyn ImageFormat];

/// Register an executable format with the platform.
///
/// Takes a path to a `fn() -> &'static dyn ImageFormat`.
#[macro_export]
macro_rules! register_binfmt {
    ($get:path) => {
        const _: () = {
            #[$crate::linkme::distributed_slice($crate::BINFMTS)]
            #[linkme(crate = $crate::linkme)]
            static REGISTRATION: fn() -> &'static dyn $crate::ImageFormat = $get;
        };
    };
}

/// Hand `image` to the first registered format that claims it, the analogue of
/// `fs/exec.c::search_binary_handler`.
///
/// # Errors
///
/// [`AbiError::UnknownFormat`] when none does.
pub fn dispatch_image(image: &[u8]) -> AbiResult<&'static dyn ImageFormat> {
    BINFMTS
        .iter()
        .map(|get| get())
        .find(|f| f.recognizes(image))
        .ok_or(AbiError::UnknownFormat)
}

/// An executable format: recognizing an image and placing it in memory.
///
/// The analogue of `struct linux_binfmt`. Kept apart from `ax_dispatch::SysAbi`
/// because loading an image and servicing its traps are separate capabilities
/// that leave a kernel at different times: a package may implement either or
/// both.
pub trait ImageFormat: Sync {
    /// Which ABI an image of this format speaks, so the loader can say what the
    /// process becomes.
    fn abi(&self) -> Abi;

    /// Does this format claim `image`? Mirrors the head-magic check a
    /// `linux_binfmt::load_binary` performs before committing. Must be cheap
    /// and side-effect free: [`dispatch_image`] may call it on several.
    fn recognizes(&self, image: &[u8]) -> bool;

    /// Map `req.image` into `env` and return where to begin execution.
    fn load(&self, req: &LoadRequest<'_>, env: &mut dyn LoadEnv) -> AbiResult<Loaded>;
}

/// Recognize an image's format by its leading magic bytes, independent of any
/// registered format. A fast, pure classifier an [`ImageFormat::recognizes`]
/// can build on, and the routing a loader needs before any format is linked.
/// Returns `None` for an unrecognized image (the caller reports `ENOEXEC`).
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
