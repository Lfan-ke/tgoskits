//! Darwin's BSD system calls, serviced over the shared capability ports.
//!
//! A Darwin trap carries a class in the top byte of the call number: the BSD
//! calls this module owns are class 2, and everything else - Mach traps, which
//! arrive as negative numbers - belongs to another layer. The numbers below are
//! transcribed from XNU's `bsd/kern/syscalls.master`.
//!
//! Failure is reported Darwin's way: a positive errno in the return register
//! with the carry flag set, which is why the trap frame carries
//! [`TrapEnv::set_error`] alongside the value.

use ax_abi_port::{Host, MapRequest, MapSource, Prot, SeekFrom, SysResult};
use ax_binfmt::{Dispatch, TrapEnv};

/// Where the call class sits in a Darwin system-call number.
const CLASS_SHIFT: usize = 24;
/// The class BSD calls carry.
const CLASS_UNIX: usize = 2;
/// The call number, once the class is stripped.
const NUMBER_MASK: usize = (1 << CLASS_SHIFT) - 1;
/// The page size Darwin's alignment rules are written against.
const PAGE_SIZE: usize = 4096;

/// `EINVAL`.
const EINVAL: i32 = 22;
/// `EBADF`.
const EBADF: i32 = 9;

/// The BSD calls this personality services, from `syscalls.master`.
mod nr {
    pub const EXIT: usize = 1;
    pub const READ: usize = 3;
    pub const WRITE: usize = 4;
    pub const CLOSE: usize = 6;
    pub const GETPID: usize = 20;
    pub const GETUID: usize = 24;
    pub const GETEUID: usize = 25;
    pub const GETPPID: usize = 39;
    pub const DUP: usize = 41;
    pub const GETEGID: usize = 43;
    pub const GETGID: usize = 47;
    pub const MSYNC: usize = 65;
    pub const MUNMAP: usize = 73;
    pub const MPROTECT: usize = 74;
    pub const MADVISE: usize = 75;
    pub const DUP2: usize = 90;
    pub const FSYNC: usize = 95;
    pub const PREAD: usize = 153;
    pub const PWRITE: usize = 154;
    pub const MMAP: usize = 197;
    pub const LSEEK: usize = 199;
    pub const FTRUNCATE: usize = 201;
}

/// Darwin's `PROT_*`, which match the BSD numbering Linux also uses.
fn prot_from_abi(prot: u32) -> Result<Prot, i32> {
    const READ: u32 = 0x1;
    const WRITE: u32 = 0x2;
    const EXEC: u32 = 0x4;
    if prot & !(READ | WRITE | EXEC) != 0 {
        return Err(EINVAL);
    }
    let mut bits = Prot::empty();
    bits.set(Prot::READ, prot & READ != 0);
    bits.set(Prot::WRITE, prot & WRITE != 0);
    bits.set(Prot::EXEC, prot & EXEC != 0);
    Ok(bits)
}

/// `mmap`: Darwin shares the shape but numbers its flags its own way.
fn map(host: &dyn Host, a: &[usize; 6]) -> Option<SysResult> {
    const SHARED: u32 = 0x0001;
    const PRIVATE: u32 = 0x0002;
    const FIXED: u32 = 0x0010;
    const ANON: u32 = 0x1000;
    let flags = a[3] as u32;
    if flags & !(SHARED | PRIVATE | FIXED | ANON) != 0 {
        // The rest are Darwin's own; this personality does not claim them yet.
        return None;
    }
    let mem = host.mem()?;
    Some((|| {
        if a[1] == 0 {
            return Err(EINVAL);
        }
        let prot = prot_from_abi(a[2] as u32)?;
        let shared = match (flags & SHARED != 0, flags & PRIVATE != 0) {
            (true, false) => true,
            (false, true) => false,
            _ => return Err(EINVAL),
        };
        let offset = a[5];
        if !offset.is_multiple_of(PAGE_SIZE) {
            return Err(EINVAL);
        }
        let fd = a[4] as i32;
        let source = if flags & ANON != 0 {
            MapSource::Anonymous
        } else if fd < 0 {
            return Err(EBADF);
        } else {
            MapSource::File { fd, offset }
        };
        mem.map(&MapRequest {
            addr: a[0],
            len: a[1],
            prot,
            fixed: flags & FIXED != 0,
            shared,
            source,
        })
    })())
}

/// Service one trapped BSD call, or report that it is not this personality's.
pub fn dispatch(env: &mut dyn TrapEnv, host: &dyn Host) -> Dispatch {
    let nr = env.nr();
    if nr >> CLASS_SHIFT != CLASS_UNIX {
        return Dispatch::Passthrough;
    }
    let a = [
        env.arg(0),
        env.arg(1),
        env.arg(2),
        env.arg(3),
        env.arg(4),
        env.arg(5),
    ];
    let Some(outcome) = route(host, nr & NUMBER_MASK, &a) else {
        return Dispatch::Passthrough;
    };
    match outcome {
        Ok(value) => {
            env.set_error(false);
            env.set_result(value as usize);
        }
        Err(errno) => {
            // Darwin returns the errno itself and raises the carry flag.
            env.set_error(true);
            env.set_result(errno as usize);
        }
    }
    Dispatch::Handled
}

fn route(host: &dyn Host, call: usize, a: &[usize; 6]) -> Option<SysResult> {
    let fd = a[0] as i32;
    Some(match call {
        nr::EXIT => host.tasks()?.exit_group((a[0] as i32) << 8),
        nr::READ => host.files()?.read(fd, a[1], a[2]),
        nr::WRITE => host.files()?.write(fd, a[1], a[2]),
        nr::CLOSE => host.files()?.close(fd),
        nr::DUP => host.files()?.dup(fd),
        nr::DUP2 => host.files()?.dup_onto(fd, a[1] as i32, false),
        nr::FSYNC => host.files()?.fsync(fd, false),
        nr::FTRUNCATE => {
            let len = a[1] as i64;
            if len < 0 {
                Err(EINVAL)
            } else {
                host.files()?.ftruncate(fd, len as u64)
            }
        }
        nr::LSEEK => {
            let from = match a[2] {
                0 => SeekFrom::Start,
                1 => SeekFrom::Current,
                2 => SeekFrom::End,
                _ => return Some(Err(EINVAL)),
            };
            host.files()?.seek(fd, a[1] as isize, from)
        }
        nr::PREAD => {
            let offset = a[3] as i64;
            if offset < 0 {
                Err(EINVAL)
            } else {
                host.files()?.pread(fd, a[1], a[2], offset as u64)
            }
        }
        nr::PWRITE => {
            let offset = a[3] as i64;
            if offset < 0 {
                Err(EINVAL)
            } else {
                host.files()?.pwrite(fd, a[1], a[2], offset as u64)
            }
        }
        nr::GETPID => Ok(host.tasks()?.getpid() as isize),
        nr::GETPPID => Ok(host.tasks()?.getppid() as isize),
        nr::GETUID => Ok(host.creds()?.uids().0 as isize),
        nr::GETEUID => Ok(host.creds()?.uids().1 as isize),
        nr::GETGID => Ok(host.creds()?.gids().0 as isize),
        nr::GETEGID => Ok(host.creds()?.gids().1 as isize),
        nr::MMAP => return map(host, a),
        nr::MUNMAP => {
            if a[1] == 0 {
                Err(EINVAL)
            } else {
                host.mem()?.unmap(a[0], a[1])
            }
        }
        nr::MPROTECT => {
            let prot = match prot_from_abi(a[2] as u32) {
                Ok(prot) => prot,
                Err(errno) => return Some(Err(errno)),
            };
            if !a[0].is_multiple_of(PAGE_SIZE) {
                Err(EINVAL)
            } else if a[1] == 0 {
                Ok(0)
            } else {
                host.mem()?.protect(a[0], a[1], prot)
            }
        }
        nr::MADVISE => host.mem()?.advise(a[0], a[1], a[2] as i32),
        nr::MSYNC => {
            if !a[0].is_multiple_of(PAGE_SIZE) {
                Err(EINVAL)
            } else if a[1] == 0 {
                Ok(0)
            } else {
                host.mem()?.writeback(a[0], a[1])
            }
        }
        _ => return None,
    })
}

#[cfg(test)]
mod tests {
    use core::cell::RefCell;

    use ax_abi_port::{Creds, Files, Mem, Platform, Tasks};

    use super::*;

    /// A BSD call as it arrives: the class in the top byte, the number below.
    fn unix_call(nr: usize) -> usize {
        (CLASS_UNIX << CLASS_SHIFT) | nr
    }

    #[derive(Default)]
    struct Trap {
        nr: usize,
        args: [usize; 6],
        result: Option<usize>,
        failed: Option<bool>,
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
        fn set_error(&mut self, failed: bool) {
            self.failed = Some(failed);
        }
    }

    #[derive(Default)]
    struct MockHost {
        wrote: RefCell<Option<(i32, usize, usize)>>,
        mapped: RefCell<Option<MapRequest>>,
    }
    // Single-threaded tests; the ports ask for Sync on a real host.
    unsafe impl Sync for MockHost {}

    impl Platform for MockHost {
        fn read_user(&self, _u: usize, _o: &mut [u8]) -> SysResult {
            Ok(0)
        }
        fn write_user(&self, _u: usize, _d: &[u8]) -> SysResult {
            Ok(0)
        }
    }
    impl Files for MockHost {
        fn read(&self, _fd: i32, _u: usize, len: usize) -> SysResult {
            Ok(len as isize)
        }
        fn write(&self, fd: i32, uaddr: usize, len: usize) -> SysResult {
            if fd < 0 {
                return Err(EBADF);
            }
            *self.wrote.borrow_mut() = Some((fd, uaddr, len));
            Ok(len as isize)
        }
        fn close(&self, _fd: i32) -> SysResult {
            Ok(0)
        }
        fn dup(&self, _fd: i32) -> SysResult {
            Ok(5)
        }
        fn seek(&self, _fd: i32, offset: isize, _from: SeekFrom) -> SysResult {
            Ok(offset)
        }
        fn validate(&self, _fd: i32) -> SysResult {
            Ok(0)
        }
        fn pread(&self, _fd: i32, _u: usize, len: usize, _o: u64) -> SysResult {
            Ok(len as isize)
        }
        fn pwrite(&self, _fd: i32, _u: usize, len: usize, _o: u64) -> SysResult {
            Ok(len as isize)
        }
        fn dup_onto(&self, _old: i32, new: i32, _cloexec: bool) -> SysResult {
            Ok(new as isize)
        }
        fn fsync(&self, _fd: i32, _datasync: bool) -> SysResult {
            Ok(0)
        }
        fn ftruncate(&self, _fd: i32, _len: u64) -> SysResult {
            Ok(0)
        }
    }
    impl Mem for MockHost {
        fn brk(&self) -> usize {
            0
        }
        fn set_brk(&self, _addr: usize) -> SysResult {
            Ok(0)
        }
        fn map(&self, req: &MapRequest) -> SysResult {
            *self.mapped.borrow_mut() = Some(*req);
            Ok(0x9000)
        }
        fn unmap(&self, _a: usize, _l: usize) -> SysResult {
            Ok(0)
        }
        fn protect(&self, _a: usize, _l: usize, _p: Prot) -> SysResult {
            Ok(0)
        }
        fn advise(&self, _a: usize, _l: usize, _adv: i32) -> SysResult {
            Ok(0)
        }
        fn writeback(&self, _a: usize, _l: usize) -> SysResult {
            Ok(0)
        }
    }
    impl Tasks for MockHost {
        fn getpid(&self) -> u32 {
            77
        }
        fn getppid(&self) -> u32 {
            1
        }
        fn gettid(&self) -> u32 {
            77
        }
        fn set_tid_address(&self, _t: usize) -> SysResult {
            Ok(77)
        }
        fn sched_yield(&self) -> SysResult {
            Ok(0)
        }
        fn exit(&self, _status: i32) -> SysResult {
            Ok(0)
        }
        fn exit_group(&self, _status: i32) -> SysResult {
            Ok(0)
        }
    }
    impl Creds for MockHost {
        fn uids(&self) -> (u32, u32, u32) {
            (501, 501, 0)
        }
        fn gids(&self) -> (u32, u32, u32) {
            (20, 20, 0)
        }
    }
    impl Host for MockHost {
        fn platform(&self) -> &dyn Platform {
            self
        }
        fn files(&self) -> Option<&dyn Files> {
            Some(self)
        }
        fn mem(&self) -> Option<&dyn Mem> {
            Some(self)
        }
        fn tasks(&self) -> Option<&dyn Tasks> {
            Some(self)
        }
        fn creds(&self) -> Option<&dyn Creds> {
            Some(self)
        }
    }

    // The personality resolves its host through the platform binding, so the
    // test binary provides one; these tests pass their own host directly.
    struct StaticHost;
    impl Platform for StaticHost {
        fn read_user(&self, _u: usize, _o: &mut [u8]) -> SysResult {
            Ok(0)
        }
        fn write_user(&self, _u: usize, _d: &[u8]) -> SysResult {
            Ok(0)
        }
    }
    impl Host for StaticHost {
        fn platform(&self) -> &dyn Platform {
            self
        }
    }
    struct Binding;
    #[ax_crate_interface::impl_interface]
    impl ax_abi_port::CurrentHost for Binding {
        fn current() -> &'static dyn Host {
            static HOST: StaticHost = StaticHost;
            &HOST
        }
    }

    #[test]
    fn services_the_unix_class_and_leaves_the_rest() {
        let host = MockHost::default();
        let mut write = Trap {
            nr: unix_call(nr::WRITE),
            args: [1, 0x200, 12, 0, 0, 0],
            ..Trap::default()
        };
        assert_eq!(dispatch(&mut write, &host), Dispatch::Handled);
        assert_eq!(write.result, Some(12));
        assert_eq!(write.failed, Some(false));
        assert_eq!(*host.wrote.borrow(), Some((1, 0x200, 12)));

        // A Mach trap is another class and stays with the caller.
        let mut mach = Trap {
            nr: 0x100_0000 | 26,
            ..Trap::default()
        };
        assert_eq!(dispatch(&mut mach, &host), Dispatch::Passthrough);
        assert_eq!(mach.result, None);
    }

    #[test]
    fn failure_returns_the_errno_and_raises_the_carry_flag() {
        let host = MockHost::default();
        let mut env = Trap {
            nr: unix_call(nr::WRITE),
            args: [-1i32 as usize, 0x200, 4, 0, 0, 0],
            ..Trap::default()
        };
        assert_eq!(dispatch(&mut env, &host), Dispatch::Handled);
        // Darwin reports the errno itself, not its negation.
        assert_eq!(env.result, Some(EBADF as usize));
        assert_eq!(env.failed, Some(true));
    }

    #[test]
    fn identity_calls_read_the_credentials() {
        let host = MockHost::default();
        for (call, want) in [
            (nr::GETPID, 77),
            (nr::GETPPID, 1),
            (nr::GETUID, 501),
            (nr::GETGID, 20),
        ] {
            let mut env = Trap {
                nr: unix_call(call),
                ..Trap::default()
            };
            assert_eq!(dispatch(&mut env, &host), Dispatch::Handled);
            assert_eq!(env.result, Some(want));
        }
    }

    #[test]
    fn mmap_translates_darwins_own_flag_numbering() {
        let host = MockHost::default();
        // MAP_PRIVATE | MAP_ANON with read and write protection.
        let mut env = Trap {
            nr: unix_call(nr::MMAP),
            args: [0, 0x3000, 0x1 | 0x2, 0x0002 | 0x1000, -1i32 as usize, 0],
            ..Trap::default()
        };
        assert_eq!(dispatch(&mut env, &host), Dispatch::Handled);
        assert_eq!(env.result, Some(0x9000));
        let request = host.mapped.borrow().unwrap();
        assert_eq!(request.prot, Prot::READ | Prot::WRITE);
        assert_eq!(request.source, MapSource::Anonymous);
        assert!(!request.shared);

        // A flag this personality does not claim goes back to the caller.
        let mut exotic = Trap {
            nr: unix_call(nr::MMAP),
            args: [0, 0x1000, 0x1, 0x0002 | 0x1000 | 0x0800, -1i32 as usize, 0],
            ..Trap::default()
        };
        assert_eq!(dispatch(&mut exotic, &host), Dispatch::Passthrough);
    }
}
