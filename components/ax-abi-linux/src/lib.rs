//! Linux personality for ArceOS/StarryOS.
//!
//! StarryOS is natively a Linux ABI, but its syscall table is woven directly
//! into the kernel. This crate re-expresses that ABI through dependency
//! inversion: the Linux syscall logic here depends only on the OS-service
//! *ports* in [`ops`] plus [`ax_binfmt`], never on `axtask`/`axfs`/`axmm`. A
//! hosting OS implements those ports over its concrete managers and registers
//! one [`ops::LinuxServices`] bundle via [`register`] - the same inversion a
//! program uses to plug a concrete allocator into `GlobalAlloc`. That keeps this
//! crate free of kernel-runtime dependencies and unit-testable with mock
//! providers, and lets any ArceOS-derived OS reuse the Linux personality.
//!
//! Migration is incremental: syscalls move behind these ports one family at a
//! time, the host implements each port over its existing code, and Linux
//! behavior stays byte-for-byte identical.

#![cfg_attr(not(test), no_std)]

pub mod ops;

use ax_binfmt::{Abi, TrapEnv};
use ax_lazyinit::LazyInit;
use ops::{ENOSYS, LinuxServices, SysResult};
use syscalls::Sysno;

// The hosting OS registers its service bundle once at boot; every syscall reads
// it. Set-once (`LazyInit`) mirrors the global-allocator contract: exactly one
// provider, installed before the first user program runs.
static SERVICES: LazyInit<&'static dyn LinuxServices> = LazyInit::new();

/// Install the hosting OS's service implementation. Call once during boot,
/// before the first user thread traps.
pub fn register(services: &'static dyn LinuxServices) {
    SERVICES.init_once(services);
}

fn services() -> &'static dyn LinuxServices {
    *SERVICES
}

/// The Linux personality: recognizes ELF images and dispatches Linux syscalls.
#[derive(Debug, Clone, Copy, Default)]
pub struct LinuxAbi;

impl LinuxAbi {
    /// The ABI this personality implements.
    pub const fn abi() -> Abi {
        Abi::Linux
    }

    /// Whether `image` is an ELF this personality claims.
    pub fn recognizes(image: &[u8]) -> bool {
        ax_binfmt::detect(image) == Some(Abi::Linux)
    }

    /// Dispatch one trapped Linux syscall, writing the result into `uctx`.
    pub fn handle_syscall(uctx: &mut dyn TrapEnv) {
        let result = dispatch(services(), uctx);
        uctx.set_result(encode(result));
    }
}

/// Route one syscall to the registered services. Separated from the trap-frame
/// write so it can be unit-tested with mock services and a mock [`TrapEnv`].
fn dispatch(svc: &dyn LinuxServices, uctx: &dyn TrapEnv) -> SysResult {
    let Some(sysno) = Sysno::new(uctx.nr()) else {
        return Err(ENOSYS);
    };
    let arg = |i| uctx.arg(i);
    let (task, file, mem) = (svc.task(), svc.file(), svc.mem());
    match sysno {
        // File-descriptor I/O.
        Sysno::read => file.read(arg(0) as i32, arg(1), arg(2)),
        Sysno::write => file.write(arg(0) as i32, arg(1), arg(2)),
        Sysno::close => file.close(arg(0) as i32),
        Sysno::dup => file.dup(arg(0) as i32),
        Sysno::lseek => file.lseek(arg(0) as i32, arg(1) as isize, arg(2) as i32),

        // Process and thread control.
        Sysno::getpid => Ok(task.getpid() as isize),
        Sysno::getppid => Ok(task.getppid() as isize),
        Sysno::gettid => Ok(task.gettid() as isize),
        Sysno::set_tid_address => task.set_tid_address(arg(0)),
        Sysno::sched_yield => task.sched_yield(),
        Sysno::exit => task.exit(arg(0) as i32),
        Sysno::exit_group => task.exit_group(arg(0) as i32),

        // Address-space management.
        Sysno::brk => mem.brk(arg(0)),
        Sysno::mmap => mem.mmap(
            arg(0),
            arg(1),
            arg(2) as i32,
            arg(3) as i32,
            arg(4) as i32,
            arg(5),
        ),
        Sysno::munmap => mem.munmap(arg(0), arg(1)),
        Sysno::mprotect => mem.mprotect(arg(0), arg(1), arg(2) as i32),

        _ => Err(ENOSYS),
    }
}

/// Encode a [`SysResult`] the Linux way: the value on success, `-errno` on
/// failure (both as the raw register-width bits).
fn encode(result: SysResult) -> usize {
    match result {
        Ok(value) => value as usize,
        Err(errno) => (-(errno as isize)) as usize,
    }
}

#[cfg(test)]
mod tests {
    use core::cell::RefCell;

    use super::{
        ops::{FileOps, MemOps, TaskOps},
        *,
    };

    // A trap frame with a preset syscall number and arguments.
    struct Trap {
        nr: usize,
        args: [usize; 6],
        result: Option<usize>,
    }
    impl Trap {
        fn new(nr: Sysno, args: [usize; 6]) -> Self {
            Self {
                nr: nr as usize,
                args,
                result: None,
            }
        }
    }
    impl TrapEnv for Trap {
        fn nr(&self) -> usize {
            self.nr
        }
        fn arg(&self, i: usize) -> usize {
            self.args[i]
        }
        fn set_result(&mut self, value: usize) {
            self.result = Some(value);
        }
    }

    // Mock services recording the last routed call, so dispatch is observable.
    #[derive(Default)]
    struct Mock {
        last: RefCell<Option<(&'static str, [usize; 6])>>,
    }
    impl Mock {
        fn note(&self, name: &'static str, a: [usize; 6]) {
            *self.last.borrow_mut() = Some((name, a));
        }
    }
    // RefCell is not Sync; the trait needs Sync only for the real 'static
    // provider, so wrap it for the single-threaded test.
    unsafe impl Sync for Mock {}

    impl TaskOps for Mock {
        fn getpid(&self) -> u32 {
            42
        }
        fn getppid(&self) -> u32 {
            1
        }
        fn gettid(&self) -> u32 {
            7
        }
        fn set_tid_address(&self, tidptr: usize) -> SysResult {
            self.note("set_tid_address", [tidptr, 0, 0, 0, 0, 0]);
            Ok(7)
        }
        fn sched_yield(&self) -> SysResult {
            self.note("sched_yield", [0; 6]);
            Ok(0)
        }
        fn exit(&self, code: i32) -> ! {
            panic!("exit {code}")
        }
        fn exit_group(&self, code: i32) -> ! {
            panic!("exit_group {code}")
        }
    }
    impl FileOps for Mock {
        fn read(&self, fd: i32, buf: usize, len: usize) -> SysResult {
            self.note("read", [fd as usize, buf, len, 0, 0, 0]);
            Ok(len as isize)
        }
        fn write(&self, fd: i32, buf: usize, len: usize) -> SysResult {
            self.note("write", [fd as usize, buf, len, 0, 0, 0]);
            Ok(len as isize)
        }
        fn close(&self, fd: i32) -> SysResult {
            self.note("close", [fd as usize, 0, 0, 0, 0, 0]);
            Ok(0)
        }
        fn dup(&self, fd: i32) -> SysResult {
            self.note("dup", [fd as usize, 0, 0, 0, 0, 0]);
            Ok(9)
        }
        fn lseek(&self, fd: i32, offset: isize, whence: i32) -> SysResult {
            self.note(
                "lseek",
                [fd as usize, offset as usize, whence as usize, 0, 0, 0],
            );
            Ok(offset)
        }
    }
    impl MemOps for Mock {
        fn brk(&self, addr: usize) -> SysResult {
            self.note("brk", [addr, 0, 0, 0, 0, 0]);
            Ok(addr as isize)
        }
        fn mmap(
            &self,
            addr: usize,
            len: usize,
            prot: i32,
            flags: i32,
            fd: i32,
            offset: usize,
        ) -> SysResult {
            self.note(
                "mmap",
                [
                    addr,
                    len,
                    prot as usize,
                    flags as usize,
                    fd as usize,
                    offset,
                ],
            );
            Ok(0x1000)
        }
        fn munmap(&self, addr: usize, len: usize) -> SysResult {
            self.note("munmap", [addr, len, 0, 0, 0, 0]);
            Ok(0)
        }
        fn mprotect(&self, addr: usize, len: usize, prot: i32) -> SysResult {
            self.note("mprotect", [addr, len, prot as usize, 0, 0, 0]);
            Ok(0)
        }
    }
    impl LinuxServices for Mock {
        fn task(&self) -> &dyn TaskOps {
            self
        }
        fn file(&self) -> &dyn FileOps {
            self
        }
        fn mem(&self) -> &dyn MemOps {
            self
        }
    }

    #[test]
    fn routes_file_syscalls_with_correct_args() {
        let m = Mock::default();
        assert_eq!(
            dispatch(&m, &Trap::new(Sysno::write, [1, 0xdead, 16, 0, 0, 0])),
            Ok(16)
        );
        assert_eq!(*m.last.borrow(), Some(("write", [1, 0xdead, 16, 0, 0, 0])));
        assert_eq!(
            dispatch(&m, &Trap::new(Sysno::read, [3, 0xbeef, 8, 0, 0, 0])),
            Ok(8)
        );
        assert_eq!(m.last.borrow().unwrap().0, "read");
    }

    #[test]
    fn routes_task_and_mem_syscalls() {
        let m = Mock::default();
        assert_eq!(dispatch(&m, &Trap::new(Sysno::getpid, [0; 6])), Ok(42));
        assert_eq!(
            dispatch(&m, &Trap::new(Sysno::brk, [0x8000, 0, 0, 0, 0, 0])),
            Ok(0x8000)
        );
        assert_eq!(m.last.borrow().unwrap(), ("brk", [0x8000, 0, 0, 0, 0, 0]));
    }

    #[test]
    fn unknown_syscall_is_enosys() {
        let m = Mock::default();
        // Sysno::gettimeofday is not in the first migrated slice.
        assert_eq!(
            dispatch(&m, &Trap::new(Sysno::gettimeofday, [0; 6])),
            Err(ENOSYS)
        );
    }

    #[test]
    fn encode_follows_linux_convention() {
        assert_eq!(encode(Ok(16)), 16);
        assert_eq!(encode(Err(ENOSYS)), (-(ENOSYS as isize)) as usize);
    }

    #[test]
    #[should_panic(expected = "exit_group 0")]
    fn exit_group_is_routed() {
        let m = Mock::default();
        let _ = dispatch(&m, &Trap::new(Sysno::exit_group, [0; 6]));
    }
}
