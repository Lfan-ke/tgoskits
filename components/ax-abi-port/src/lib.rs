//! Capability ports for ArceOS ABI personalities.
//!
//! A personality (`ax-abi-linux` and its siblings) implements a foreign syscall
//! ABI without depending on `axtask`/`axfs`/`axmm`: it reaches the machine and
//! the OS only through the traits here. A hosting OS implements them once, over
//! whatever it already has, and every personality runs on that one contract -
//! rather than each domain inventing its own host interface for the same files,
//! memory and tasks.
//!
//! Two layers, mirroring gVisor's split of a swappable `Platform` from the
//! Sentry's service subsystems:
//!
//! - [`Platform`] - the minimal arch/memory primitives (copy user memory).
//! - [`Tasks`]/[`Files`]/[`Mem`]/[`Signals`]/[`Clock`]/[`Random`]/[`System`]/
//!   [`Creds`] - the OS services a syscall implementation drives.
//!
//! The ports carry primitives, not syscalls: a domain implements each syscall's
//! semantics, flags and errno itself (the zero-passthrough rule), copies user
//! memory through [`Platform`], and never forwards a call to the host. That
//! keeps every domain unit-testable against mock ports.
//!
//! [`Host`] bundles the ports, and [`CurrentHost`] is the global binding the
//! kernel provides so a trap path can reach them without threading a parameter.

#![no_std]

use ax_crate_interface::def_interface;
#[cfg(feature = "mm")]
use bitflags::bitflags;

/// A syscall outcome: `Ok(return value)` or `Err(positive errno)`. A domain
/// encodes it into the trap frame its ABI's way (`-errno` for Linux).
pub type SysResult = Result<isize, i32>;

pub use ax_io::SeekFrom;

/// `ENOSYS` - no handler for this call (yet).
pub const ENOSYS: i32 = 38;
/// `EFAULT` - a user pointer was not accessible.
pub const EFAULT: i32 = 14;
/// `EINVAL` - an argument was invalid.
pub const EINVAL: i32 = 22;
/// `EBADF` - not an open descriptor.
pub const EBADF: i32 = 9;
/// `ESRCH` - no such process.
pub const ESRCH: i32 = 3;
/// `ESPIPE` - the descriptor does not admit positional io.
pub const ESPIPE: i32 = 29;
/// `EOPNOTSUPP` - the operation is not one this build carries out.
pub const EOPNOTSUPP: i32 = 95;
/// `EINTR` - a signal cut the call short.
pub const EINTR: i32 = 4;

/// The minimal arch/memory platform, à la gVisor's `Platform`: move bytes across
/// the user/kernel boundary. Everything a personality needs from the CPU/MMU
/// that is not a higher-level service goes here.
pub trait Platform: Sync {
    fn read_user(&self, uaddr: usize, out: &mut [u8]) -> SysResult;
    fn write_user(&self, uaddr: usize, data: &[u8]) -> SysResult;
}

#[cfg(feature = "task")]
pub trait Tasks: Sync {
    /// The caller's process id. A host whose namespace cannot see the caller
    /// says so, so the port reports a result rather than a bare number.
    fn getpid(&self) -> SysResult;
    /// The parent's process id, or the host's error when there is no parent
    /// it can name.
    fn getppid(&self) -> SysResult;
    /// The caller's thread id, which always exists.
    fn gettid(&self) -> u32;
    fn set_tid_address(&self, tidptr: usize) -> SysResult;
    fn sched_yield(&self) -> SysResult;
    /// Terminate the calling thread. A host whose exit path returns - marking
    /// the thread and letting the trap return handle it - reports that outcome
    /// here rather than diverging.
    fn exit(&self, code: i32) -> SysResult;
    /// Terminate every thread in the process.
    fn exit_group(&self, code: i32) -> SysResult;
}

/// What a program says it will do with a range, so the host can act on it.
///
/// The numbers each ABI uses for these disagree - Darwin's `MADV_FREE` is 5
/// where Linux's is 8 - so the advice crosses the port as what it means rather
/// than as the number one of them writes it with.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Advice {
    /// No expectation; undo any earlier advice.
    Normal,
    /// Access will be random, so reading ahead is wasted.
    Random,
    /// Access will be sequential, so reading ahead pays.
    Sequential,
    /// The range will be needed soon.
    WillNeed,
    /// The range is not needed; a later read may see zeroes or the file again.
    DontNeed,
    /// The range's contents may be discarded, and the pages reclaimed.
    Free,
    /// Punch the range out of whatever backs it, so a later read sees zeroes.
    /// Only a shared file-backed range can be removed this way.
    Remove,
    /// Advice the host has no action for, which is not an error to give.
    Ignored,
}

/// One run of user memory. An ABI decodes its own vector layout and names the
/// runs it found this way, so the host never learns what an `iovec` looks like.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Segment {
    /// Where the run starts in user memory.
    pub uaddr: usize,
    /// How many bytes it covers.
    pub len: usize,
}

/// File-descriptor service.
///
/// Bulk transfers name a user range rather than a kernel buffer, and each does
/// exactly one underlying read or write. That is what a pipe, socket or tty
/// needs: a second underlying read would block where the call should have
/// returned, and a bounce buffer would cap the result into a short transfer the
/// kernel would not have produced. The domain still owns the call: it decodes
/// and validates the arguments and maps the errno; the host owns moving the
/// bytes, since only it can touch user memory and the file layer together.
#[cfg(feature = "fs")]
pub trait Files: Sync {
    /// Read from `fd` into the user range at `uaddr`, returning the count read.
    fn read(&self, fd: i32, uaddr: usize, len: usize) -> SysResult;
    /// Write the user range at `uaddr` to `fd`, returning the count written.
    fn write(&self, fd: i32, uaddr: usize, len: usize) -> SysResult;
    fn close(&self, fd: i32) -> SysResult;
    fn dup(&self, fd: i32) -> SysResult;
    fn seek(&self, fd: i32, to: SeekFrom) -> SysResult;
    /// Report whether `fd` is open, without touching it.
    fn validate(&self, fd: i32) -> SysResult;
    /// Read from `fd` into `segs` in order, in one underlying transfer.
    fn readv(&self, fd: i32, segs: &[Segment]) -> SysResult;
    /// Write `segs` in order to `fd`, in one underlying transfer.
    fn writev(&self, fd: i32, segs: &[Segment]) -> SysResult;
    /// Read from `fd` at absolute `offset` into `segs`, in one transfer.
    fn preadv(&self, fd: i32, segs: &[Segment], offset: u64) -> SysResult;
    /// Write `segs` to `fd` at absolute `offset`, in one transfer.
    fn pwritev(&self, fd: i32, segs: &[Segment], offset: u64) -> SysResult;
    /// Whether `fd` can be read or written at an absolute offset. Which
    /// descriptors can is the host's property, and so is the error it reports
    /// for the ones that cannot; an ABI asks before it validates an offset,
    /// because that is the order the check falls in.
    fn seekable(&self, fd: i32) -> SysResult;
    /// Read from `fd` at absolute `offset` into the user range at `uaddr`,
    /// leaving the file position unchanged.
    fn pread(&self, fd: i32, uaddr: usize, len: usize, offset: u64) -> SysResult;
    /// Write the user range at `uaddr` to `fd` at absolute `offset`, leaving the
    /// file position unchanged.
    fn pwrite(&self, fd: i32, uaddr: usize, len: usize, offset: u64) -> SysResult;
    /// Duplicate `oldfd` onto `newfd`, closing what `newfd` held, and return
    /// `newfd`. The two are never equal here: what that means is the ABI's call,
    /// so a domain settles it before asking.
    fn dup_onto(&self, oldfd: i32, newfd: i32, cloexec: bool) -> SysResult;
    /// Flush `fd` to backing storage. `datasync` may skip metadata not needed
    /// for data integrity.
    fn fsync(&self, fd: i32, datasync: bool) -> SysResult;
    /// Set the size of `fd` to `len`, zero-extending on growth.
    fn ftruncate(&self, fd: i32, len: u64) -> SysResult;
}

#[cfg(feature = "mm")]
bitflags! {
    /// How a mapping may be used. The three access bits are common to every ABI;
    /// the growth hints say a region is a stack that extends one way, which some
    /// hosts track and others ignore.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct Prot: u32 {
        /// Readable.
        const READ = 1 << 0;
        /// Writable.
        const WRITE = 1 << 1;
        /// Executable.
        const EXEC = 1 << 2;
        /// Grows toward lower addresses.
        const GROWS_DOWN = 1 << 3;
        /// Grows toward higher addresses.
        const GROWS_UP = 1 << 4;
    }
}

/// Where a new mapping's contents come from.
#[cfg(feature = "mm")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MapSource {
    /// Zero-filled pages.
    Anonymous,
    /// A file, from `offset`.
    File {
        /// The descriptor to map.
        fd: i32,
        /// Where in the file the mapping starts.
        offset: usize,
    },
}

/// A request to place a new mapping.
#[cfg(feature = "mm")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MapRequest {
    /// Where to place it; zero asks the host to choose.
    pub addr: usize,
    /// How much to map.
    pub len: usize,
    /// What the mapping allows.
    pub prot: Prot,
    /// Place it exactly at `addr`, replacing whatever is there.
    pub fixed: bool,
    /// Writes are visible to others mapping the same object.
    pub shared: bool,
    /// What backs it.
    pub source: MapSource,
}

#[cfg(feature = "mm")]
pub trait Mem: Sync {
    /// Where the program break sits now.
    fn brk(&self) -> usize;
    /// Move the program break to `addr`, mapping or unmapping to match. Fails
    /// when the host will not place it there; what a caller reports for that is
    /// the ABI's business.
    fn set_brk(&self, addr: usize) -> SysResult;
    /// Place a mapping, returning the address it went to.
    fn map(&self, req: &MapRequest) -> SysResult;
    /// Unmap `[addr, addr+len)`. The length is rounded up to whole pages here,
    /// since the page size is the host's to know.
    fn unmap(&self, addr: usize, len: usize) -> SysResult;
    /// Change what `[addr, addr+len)` allows.
    fn protect(&self, addr: usize, len: usize, prot: Prot) -> SysResult;
    /// Advise usage of `[addr, addr+len)`. The host validates `advice`, since
    /// which hints it honours is its own property, as is page alignment.
    /// Apply `advice` to `[addr, addr+len)`. The caller has already checked the
    /// advice is one its ABI defines; whether this host acts on it is its own
    /// business.
    fn advise(&self, addr: usize, len: usize, advice: Advice) -> SysResult;
    /// Write back the file-backed parts of `[addr, addr+len)`.
    fn writeback(&self, addr: usize, len: usize) -> SysResult;
}

/// A source of randomness. Fills a kernel buffer; a domain copies it to user
/// memory. Every modern libc draws from it at startup.
#[cfg(feature = "random")]
pub trait Random: Sync {
    /// Fill `len` bytes of user memory at `uaddr` with entropy, returning how
    /// many arrived. `blocking` asks for the source that waits for entropy
    /// over the one that never does.
    fn fill(&self, uaddr: usize, len: usize, blocking: bool) -> SysResult;
}

/// Signal delivery and the blocked-signal mask. A domain moves the user
/// `sigset_t` itself; this port carries the mask as a `u64`.
/// Who a signal is aimed at, once an ABI has read its own encoding of that.
#[cfg(feature = "signal")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignalTarget {
    /// One process.
    Process(u32),
    /// Every process in the caller's group.
    CallerGroup,
    /// Every process the caller may signal.
    All,
    /// Every process in one group.
    Group(u32),
}

#[cfg(feature = "signal")]
pub trait Signals: Sync {
    /// Send `signo` to `target`. A zero `signo` only checks that the target
    /// exists and may be signalled.
    fn kill(&self, target: SignalTarget, signo: u32) -> SysResult;
    /// Send `signo` to thread `tid` of thread-group `tgid`.
    fn tgkill(&self, tgid: u32, tid: u32, signo: u32) -> SysResult;
    /// Send `signo` to the thread `tid`, named without its group.
    fn tkill(&self, tid: u32, signo: u32) -> SysResult;
    /// Apply `new` to the blocked-signal mask per `how` (`SIG_BLOCK`/`UNBLOCK`/
    /// `SETMASK`, already validated), returning the previous mask. `None` queries.
    fn sigprocmask(&self, how: i32, new: Option<u64>) -> Result<u64, i32>;
}

/// How a sleep ended. A sleep cut short says how far it got, because an ABI
/// that hands the caller the time remaining has to work that out itself.
#[cfg(feature = "time")]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Slept {
    /// The whole requested span elapsed.
    Full,
    /// Something interrupted it after `elapsed_ns`.
    Short { errno: i32, elapsed_ns: u64 },
}

/// Clocks and sleeping, in nanoseconds. A domain packs the `timespec`/`timeval`
/// structs itself; this port only supplies the raw counters.
#[cfg(feature = "time")]
pub trait Clock: Sync {
    fn monotonic_ns(&self) -> u64;
    fn wall_ns(&self) -> u64;
    /// Sleep for `ns`, reporting whether it ran out or was cut short.
    fn sleep_ns(&self, ns: u64) -> Slept;
}

/// One field of the system identity a `uname`-style call reports.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg(feature = "system")]
pub enum UtsField {
    SysName,
    NodeName,
    Release,
    Version,
    Machine,
    DomainName,
}

#[cfg(feature = "system")]
pub trait System: Sync {
    /// Report the system identity, calling `put` once per [`UtsField`].
    ///
    /// Push rather than return, because a hosting OS keeps these fields behind a
    /// lock and can then report a consistent snapshot without allocating or
    /// lending out a borrow. A domain lays the values into its own ABI struct,
    /// so the wire format stays out of this port.
    fn uname(&self, put: &mut dyn FnMut(UtsField, &str));
}

/// Process credentials. Each getter returns the `(real, effective, saved)`
/// triple; a domain projects the single ids it needs from it.
#[cfg(feature = "creds")]
pub trait Creds: Sync {
    fn uids(&self) -> (u32, u32, u32);
    fn gids(&self) -> (u32, u32, u32);
}

/// The capabilities a hosting OS registers for the personalities it runs.
///
/// Only [`platform`](Host::platform) is required - moving bytes across the user
/// boundary is what every ABI needs before anything else. The rest are optional
/// and default to absent, so a host registers the capabilities it actually has:
/// plug in a filesystem and the file-related syscalls of whichever personality
/// is loaded light up; leave it out and a domain simply does not offer them, and
/// the trap falls back to whatever the host does with an unclaimed call.
///
/// That is the same composition the rest of the system uses - a capability is a
/// part you fit, not a slot you must fill.
pub trait Host: Sync {
    fn platform(&self) -> &dyn Platform;
    #[cfg(feature = "task")]
    fn tasks(&self) -> Option<&dyn Tasks> {
        None
    }
    #[cfg(feature = "fs")]
    fn files(&self) -> Option<&dyn Files> {
        None
    }
    #[cfg(feature = "mm")]
    fn mem(&self) -> Option<&dyn Mem> {
        None
    }
    #[cfg(feature = "signal")]
    fn signals(&self) -> Option<&dyn Signals> {
        None
    }
    #[cfg(feature = "time")]
    fn clock(&self) -> Option<&dyn Clock> {
        None
    }
    #[cfg(feature = "random")]
    fn random(&self) -> Option<&dyn Random> {
        None
    }
    #[cfg(feature = "system")]
    fn system(&self) -> Option<&dyn System> {
        None
    }
    #[cfg(feature = "creds")]
    fn creds(&self) -> Option<&dyn Creds> {
        None
    }
}

/// The global binding a hosting OS provides so a trap path can reach the
/// registered [`Host`] without a parameter - ArceOS's own way to invert the
/// dependency (the kernel `#[impl_interface]`s this, a domain `call_interface!`s
/// it), which keeps this layer free of a hand-rolled registry.
#[def_interface]
pub trait CurrentHost {
    fn current() -> &'static dyn Host;
}
