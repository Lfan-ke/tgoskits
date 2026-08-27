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

/// A syscall outcome: `Ok(return value)` or `Err(positive errno)`. A domain
/// encodes it into the trap frame its ABI's way (`-errno` for Linux).
pub type SysResult = Result<isize, i32>;

/// `ENOSYS` - no handler for this call (yet).
pub const ENOSYS: i32 = 38;
/// `EFAULT` - a user pointer was not accessible.
pub const EFAULT: i32 = 14;
/// `EINVAL` - an argument was invalid.
pub const EINVAL: i32 = 22;
/// `EBADF` - not an open descriptor.
pub const EBADF: i32 = 9;

/// The minimal arch/memory platform, à la gVisor's `Platform`: move bytes across
/// the user/kernel boundary. Everything a personality needs from the CPU/MMU
/// that is not a higher-level service goes here.
pub trait Platform: Sync {
    fn read_user(&self, uaddr: usize, out: &mut [u8]) -> SysResult;
    fn write_user(&self, uaddr: usize, data: &[u8]) -> SysResult;
}

#[cfg(feature = "task")]
pub trait Tasks: Sync {
    fn getpid(&self) -> u32;
    fn getppid(&self) -> u32;
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

/// Where a seek measures from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg(feature = "fs")]
pub enum SeekFrom {
    /// The start of the file.
    Start,
    /// The current position.
    Current,
    /// The end of the file.
    End,
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
    fn seek(&self, fd: i32, offset: isize, from: SeekFrom) -> SysResult;
    /// Report whether `fd` is open, without touching it.
    fn validate(&self, fd: i32) -> SysResult;
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
pub trait Mem: Sync {
    fn brk(&self, addr: usize) -> SysResult;
    fn mmap(
        &self,
        addr: usize,
        len: usize,
        prot: i32,
        flags: i32,
        fd: i32,
        offset: usize,
    ) -> SysResult;
    fn munmap(&self, addr: usize, len: usize) -> SysResult;
    fn mprotect(&self, addr: usize, len: usize, prot: i32) -> SysResult;
    /// Advise usage of `[addr, addr+len)`. The host validates `advice`, since
    /// which hints it honours is its own property, as is page alignment.
    fn madvise(&self, addr: usize, len: usize, advice: i32) -> SysResult;
    /// Flush `[addr, addr+len)` of a file mapping. A domain validates `flags`.
    fn msync(&self, addr: usize, len: usize, flags: i32) -> SysResult;
}

/// A source of randomness. Fills a kernel buffer; a domain copies it to user
/// memory. Every modern libc draws from it at startup.
#[cfg(feature = "random")]
pub trait Random: Sync {
    fn fill(&self, buf: &mut [u8]) -> SysResult;
}

/// Signal delivery and the blocked-signal mask. A domain moves the user
/// `sigset_t` itself; this port carries the mask as a `u64`.
#[cfg(feature = "signal")]
pub trait Signals: Sync {
    fn kill(&self, pid: i32, sig: i32) -> SysResult;
    fn tgkill(&self, tgid: i32, tid: i32, sig: i32) -> SysResult;
    /// Apply `new` to the blocked-signal mask per `how` (`SIG_BLOCK`/`UNBLOCK`/
    /// `SETMASK`, already validated), returning the previous mask. `None` queries.
    fn sigprocmask(&self, how: i32, new: Option<u64>) -> Result<u64, i32>;
}

/// Clocks and sleeping, in nanoseconds. A domain packs the `timespec`/`timeval`
/// structs itself; this port only supplies the raw counters.
#[cfg(feature = "time")]
pub trait Clock: Sync {
    fn monotonic_ns(&self) -> u64;
    fn wall_ns(&self) -> u64;
    fn sleep_ns(&self, ns: u64) -> SysResult;
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
