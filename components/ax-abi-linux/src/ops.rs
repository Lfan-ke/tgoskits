//! The ports the Linux personality is written against - dependency inversion so
//! the domain never touches `axtask`/`axfs`/`axmm` directly.
//!
//! Two layers, mirroring gVisor's split of a swappable `Platform` from the
//! Sentry's service subsystems:
//!
//! - [`Platform`] - the minimal arch/memory primitives (copy user memory). A
//!   hosting OS backs it with `axhal`/`axmm`.
//! - [`Tasks`]/[`Files`]/[`Mem`] - domain services the syscall logic calls,
//!   backed by `axtask`/`axfs-ng`/`axmm`.
//!
//! The domain implements every syscall itself (zero passthrough): it reads and
//! validates arguments, copies user memory through [`Platform`], and drives the
//! services - it never forwards a syscall to the host. A hosting OS registers
//! one [`LinuxHost`] bundle, exactly as a program plugs an allocator into
//! `GlobalAlloc`, and everything here unit-tests with mock ports.

/// A syscall outcome: `Ok(return value)` or `Err(positive errno)`. The dispatch
/// layer encodes it into the trap frame the Linux way (`-errno` on failure).
pub type SysResult = Result<isize, i32>;

/// `ENOSYS` - no handler for this syscall (yet).
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
    /// `getpid` - thread-group id.
    fn getpid(&self) -> u32;
    /// `getppid` - parent's thread-group id.
    fn getppid(&self) -> u32;
    /// `gettid` - this thread's id.
    fn gettid(&self) -> u32;
    /// `set_tid_address` - record the clear-child-tid pointer, return the tid.
    fn set_tid_address(&self, tidptr: usize) -> SysResult;
    /// `sched_yield` - relinquish the CPU.
    fn sched_yield(&self) -> SysResult;
    /// `exit` - terminate the calling thread.
    fn exit(&self, code: i32) -> !;
    /// `exit_group` - terminate every thread in the process.
    fn exit_group(&self, code: i32) -> !;
}

/// File-descriptor service. Buffers are kernel-side; the domain does the user
/// copy through [`Platform`], keeping this port free of user-memory concerns.
pub trait Files: Sync {
    /// Read up to `buf.len()` bytes from `fd` into the kernel buffer `buf`,
    /// returning the count read.
    fn read(&self, fd: i32, buf: &mut [u8]) -> SysResult;
    /// Write the kernel buffer `buf` to `fd`, returning the count written.
    fn write(&self, fd: i32, buf: &[u8]) -> SysResult;
    /// `close` a descriptor.
    fn close(&self, fd: i32) -> SysResult;
    /// `dup` a descriptor to the lowest free number.
    fn dup(&self, fd: i32) -> SysResult;
    /// `lseek` - reposition `fd`'s offset (`whence` is `SEEK_*`).
    fn lseek(&self, fd: i32, offset: isize, whence: i32) -> SysResult;
}

/// Address-space service.
pub trait Mem: Sync {
    /// `brk` - move the program break to `addr` (0 queries), returning the break.
    fn brk(&self, addr: usize) -> SysResult;
    /// `mmap` - map memory, returning the mapped address.
    fn mmap(
        &self,
        addr: usize,
        len: usize,
        prot: i32,
        flags: i32,
        fd: i32,
        offset: usize,
    ) -> SysResult;
    /// `munmap` - unmap `[addr, addr+len)`.
    fn munmap(&self, addr: usize, len: usize) -> SysResult;
    /// `mprotect` - change protection of `[addr, addr+len)`.
    fn mprotect(&self, addr: usize, len: usize, prot: i32) -> SysResult;
}

/// A source of randomness (`getrandom`, `/dev/urandom`). Fills a kernel buffer;
/// the domain copies it to user memory. Every modern libc calls this at startup.
pub trait Random: Sync {
    /// Fill `buf` with random bytes, returning the count produced.
    fn fill(&self, buf: &mut [u8]) -> SysResult;
}

/// Signal delivery and the blocked-signal mask. The domain reads/writes the
/// user `sigset_t` itself; this port takes and returns the mask as a `u64`.
pub trait Signals: Sync {
    /// `kill` - send `sig` to process `pid`.
    fn kill(&self, pid: i32, sig: i32) -> SysResult;
    /// `tgkill` - send `sig` to thread `tid` in thread-group `tgid`.
    fn tgkill(&self, tgid: i32, tid: i32, sig: i32) -> SysResult;
    /// Apply `new` to the blocked-signal mask per `how` (`SIG_BLOCK`/`UNBLOCK`/
    /// `SETMASK`, already validated), returning the previous mask. `None` queries.
    fn sigprocmask(&self, how: i32, new: Option<u64>) -> Result<u64, i32>;
}

/// Clocks and sleeping, in nanoseconds. The domain packs the `timespec`/
/// `timeval` structs itself; this port only supplies the raw counters.
pub trait Clock: Sync {
    /// Monotonic time since boot, in nanoseconds (`CLOCK_MONOTONIC`).
    fn monotonic_ns(&self) -> u64;
    /// Wall-clock time since the Unix epoch, in nanoseconds (`CLOCK_REALTIME`).
    fn wall_ns(&self) -> u64;
    /// Sleep for `ns` nanoseconds.
    fn sleep_ns(&self, ns: u64) -> SysResult;
}

/// The bundle of ports a hosting OS registers for the Linux personality.
pub trait LinuxHost: Sync {
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
}
