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

/// The minimal arch/memory platform, à la gVisor's `Platform`: move bytes across
/// the user/kernel boundary. Everything a personality needs from the CPU/MMU
/// that is not a higher-level service goes here.
pub trait Platform: Sync {
    /// Copy `out.len()` bytes from user virtual address `uaddr` into `out`,
    /// faulting with `EFAULT` if the range is not readable.
    fn read_user(&self, uaddr: usize, out: &mut [u8]) -> SysResult;
    /// Copy `data` to user virtual address `uaddr`, faulting with `EFAULT` if
    /// the range is not writable.
    fn write_user(&self, uaddr: usize, data: &[u8]) -> SysResult;
}

/// Process and thread service.
pub trait Tasks: Sync {
    /// Thread-group id of the caller.
    fn getpid(&self) -> u32;
    /// Thread-group id of the caller's parent.
    fn getppid(&self) -> u32;
    /// Id of the calling thread.
    fn gettid(&self) -> u32;
    /// Record the clear-child-tid pointer, returning the caller's tid.
    fn set_tid_address(&self, tidptr: usize) -> SysResult;
    /// Relinquish the CPU.
    fn sched_yield(&self) -> SysResult;
    /// Terminate the calling thread.
    fn exit(&self, code: i32) -> !;
    /// Terminate every thread in the process.
    fn exit_group(&self, code: i32) -> !;
}

/// File-descriptor service. Buffers are kernel-side; a domain does the user copy
/// through [`Platform`], keeping this port free of user-memory concerns.
pub trait Files: Sync {
    /// Read up to `buf.len()` bytes from `fd`, returning the count read.
    fn read(&self, fd: i32, buf: &mut [u8]) -> SysResult;
    /// Write `buf` to `fd`, returning the count written.
    fn write(&self, fd: i32, buf: &[u8]) -> SysResult;
    /// Close a descriptor.
    fn close(&self, fd: i32) -> SysResult;
    /// Duplicate a descriptor to the lowest free number.
    fn dup(&self, fd: i32) -> SysResult;
    /// Reposition `fd`'s offset (`whence` is `SEEK_*`).
    fn lseek(&self, fd: i32, offset: isize, whence: i32) -> SysResult;
    /// Read from `fd` at absolute `offset`, leaving the file position unchanged.
    fn pread(&self, fd: i32, buf: &mut [u8], offset: u64) -> SysResult;
    /// Write to `fd` at absolute `offset`, leaving the file position unchanged.
    fn pwrite(&self, fd: i32, buf: &[u8], offset: u64) -> SysResult;
    /// Duplicate `oldfd` onto the specific `newfd`, closing `newfd` first if
    /// open, and return `newfd`. `cloexec` sets close-on-exec on the copy.
    fn dup2(&self, oldfd: i32, newfd: i32, cloexec: bool) -> SysResult;
    /// Flush `fd` to backing storage. `datasync` may skip metadata not needed
    /// for data integrity.
    fn fsync(&self, fd: i32, datasync: bool) -> SysResult;
    /// Set the size of `fd` to `len`, zero-extending on growth.
    fn ftruncate(&self, fd: i32, len: u64) -> SysResult;
}

/// Address-space service.
pub trait Mem: Sync {
    /// Move the program break to `addr` (0 queries), returning the break.
    fn brk(&self, addr: usize) -> SysResult;
    /// Map memory, returning the mapped address.
    fn mmap(
        &self,
        addr: usize,
        len: usize,
        prot: i32,
        flags: i32,
        fd: i32,
        offset: usize,
    ) -> SysResult;
    /// Unmap `[addr, addr+len)`.
    fn munmap(&self, addr: usize, len: usize) -> SysResult;
    /// Change protection of `[addr, addr+len)`.
    fn mprotect(&self, addr: usize, len: usize, prot: i32) -> SysResult;
    /// Advise usage of `[addr, addr+len)`. A domain validates `advice`; page
    /// alignment is this port's concern, since it knows the page size.
    fn madvise(&self, addr: usize, len: usize, advice: i32) -> SysResult;
    /// Flush `[addr, addr+len)` of a file mapping. A domain validates `flags`.
    fn msync(&self, addr: usize, len: usize, flags: i32) -> SysResult;
}

/// A source of randomness. Fills a kernel buffer; a domain copies it to user
/// memory. Every modern libc draws from it at startup.
pub trait Random: Sync {
    /// Fill `buf` with random bytes, returning the count produced.
    fn fill(&self, buf: &mut [u8]) -> SysResult;
}

/// Signal delivery and the blocked-signal mask. A domain moves the user
/// `sigset_t` itself; this port carries the mask as a `u64`.
pub trait Signals: Sync {
    /// Send `sig` to process `pid`.
    fn kill(&self, pid: i32, sig: i32) -> SysResult;
    /// Send `sig` to thread `tid` in thread-group `tgid`.
    fn tgkill(&self, tgid: i32, tid: i32, sig: i32) -> SysResult;
    /// Apply `new` to the blocked-signal mask per `how` (`SIG_BLOCK`/`UNBLOCK`/
    /// `SETMASK`, already validated), returning the previous mask. `None` queries.
    fn sigprocmask(&self, how: i32, new: Option<u64>) -> Result<u64, i32>;
}

/// Clocks and sleeping, in nanoseconds. A domain packs the `timespec`/`timeval`
/// structs itself; this port only supplies the raw counters.
pub trait Clock: Sync {
    /// Monotonic time since boot.
    fn monotonic_ns(&self) -> u64;
    /// Wall-clock time since the Unix epoch.
    fn wall_ns(&self) -> u64;
    /// Sleep for `ns` nanoseconds.
    fn sleep_ns(&self, ns: u64) -> SysResult;
}

/// One field of the system identity a `uname`-style call reports.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UtsField {
    /// OS name, e.g. `"Linux"`.
    SysName,
    /// Host name on the network.
    NodeName,
    /// OS release.
    Release,
    /// OS version.
    Version,
    /// Hardware identifier, e.g. `"x86_64"`.
    Machine,
    /// NIS/YP domain name.
    DomainName,
}

/// System identity.
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
pub trait Creds: Sync {
    /// Real, effective and saved user IDs.
    fn uids(&self) -> (u32, u32, u32);
    /// Real, effective and saved group IDs.
    fn gids(&self) -> (u32, u32, u32);
}

/// The bundle of ports a hosting OS implements for the personalities it runs.
pub trait Host: Sync {
    /// Arch/memory platform.
    fn platform(&self) -> &dyn Platform;
    /// Process/thread service.
    fn tasks(&self) -> &dyn Tasks;
    /// File-descriptor service.
    fn files(&self) -> &dyn Files;
    /// Address-space service.
    fn mem(&self) -> &dyn Mem;
    /// Signal delivery and masking.
    fn signals(&self) -> &dyn Signals;
    /// Clocks and sleeping.
    fn clock(&self) -> &dyn Clock;
    /// Randomness.
    fn random(&self) -> &dyn Random;
    /// System identity.
    fn system(&self) -> &dyn System;
    /// Process credentials.
    fn creds(&self) -> &dyn Creds;
}

/// The global binding a hosting OS provides so a trap path can reach the
/// registered [`Host`] without a parameter - ArceOS's own way to invert the
/// dependency (the kernel `#[impl_interface]`s this, a domain `call_interface!`s
/// it), which keeps this layer free of a hand-rolled registry.
#[def_interface]
pub trait CurrentHost {
    /// The `Host` the kernel registered for the current context.
    fn current() -> &'static dyn Host;
}
