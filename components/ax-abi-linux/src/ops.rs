//! OS-service provider traits - the "ports" a hosting OS registers.
//!
//! The Linux personality is expressed against these capability boundaries, not
//! against `axtask`/`axfs`/`axmm` directly. A hosting OS (StarryOS) implements
//! them over its concrete managers and registers one [`LinuxServices`] bundle,
//! exactly as a program plugs a concrete allocator into `GlobalAlloc`. This
//! keeps `ax-abi-linux` free of kernel-runtime dependencies and unit-testable
//! with mock providers, and lets any ArceOS-derived OS reuse the personality by
//! registering its own managers.
//!
//! Pointer arguments are raw user virtual addresses; the provider reads or
//! writes user memory through the address space it owns.

/// A syscall outcome: `Ok(return value)` or `Err(positive errno)`. The dispatch
/// layer encodes it into the trap frame the Linux way (`-errno` on failure).
pub type SysResult = Result<isize, i32>;

/// `ENOSYS` - returned for a syscall no provider handles yet.
pub const ENOSYS: i32 = 38;

/// Process and thread control.
pub trait TaskOps: Sync {
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
    /// `exit_group` - terminate all threads in the process.
    fn exit_group(&self, code: i32) -> !;
}

/// File-descriptor I/O.
pub trait FileOps: Sync {
    /// `read` up to `len` bytes from `fd` into user buffer `buf`.
    fn read(&self, fd: i32, buf: usize, len: usize) -> SysResult;
    /// `write` up to `len` bytes from user buffer `buf` to `fd`.
    fn write(&self, fd: i32, buf: usize, len: usize) -> SysResult;
    /// `close` a descriptor.
    fn close(&self, fd: i32) -> SysResult;
    /// `dup` a descriptor, returning the new lowest-available number.
    fn dup(&self, fd: i32) -> SysResult;
    /// `lseek` - reposition `fd`'s offset (`whence` is `SEEK_*`).
    fn lseek(&self, fd: i32, offset: isize, whence: i32) -> SysResult;
}

/// User address-space management.
pub trait MemOps: Sync {
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

/// The bundle of OS services the Linux personality needs. A hosting OS
/// implements this over its concrete managers and registers it once via
/// [`crate::register`].
pub trait LinuxServices: Sync {
    /// Process/thread control.
    fn task(&self) -> &dyn TaskOps;
    /// File-descriptor I/O.
    fn file(&self) -> &dyn FileOps;
    /// Address-space management.
    fn mem(&self) -> &dyn MemOps;
}
