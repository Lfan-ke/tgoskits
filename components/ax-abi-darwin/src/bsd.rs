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

use ax_abi_port::{
    Advice, At, Attributes, Create, Host, MapRequest, MapSource, NodeKind, OpenHow, Prot, SeekFrom,
    SysResult,
};
use ax_dispatch::{Dispatch, TrapEnv};

/// Where the call class sits in a Darwin system-call number.
const CLASS_SHIFT: usize = 24;
/// The class BSD calls carry.
const CLASS_UNIX: usize = 2;
/// The class Mach traps carry. They are a separate call space from the BSD
/// one, reached through the same instruction, and a Darwin program uses both -
/// `sched_yield` in libc is the Mach trap `swtch_pri`, not a BSD call.
const CLASS_MACH: usize = 1;
/// The call number, once the class is stripped.
const NUMBER_MASK: usize = (1 << CLASS_SHIFT) - 1;
/// The page size Darwin's alignment rules are written against.
const PAGE_SIZE: usize = 4096;

/// `EINVAL`.
const EINVAL: i32 = 22;
/// `EBADF`.
const EBADF: i32 = 9;

/// The BSD calls this personality services, from `syscalls.master`.
/// The `O_*` bits XNU's `<sys/fcntl.h>` defines. The low bits agree with other
/// systems and the rest do not, so this ABI names its own rather than assume.
mod oflag {
    pub const ACCMODE: usize = 0x0003;
    pub const RDONLY: usize = 0x0000;
    pub const WRONLY: usize = 0x0001;
    pub const RDWR: usize = 0x0002;
    pub const CREAT: usize = 0x0200;
    pub const EXCL: usize = 0x0800;
    pub const TRUNC: usize = 0x0400;
    pub const APPEND: usize = 0x0008;
    pub const NOFOLLOW: usize = 0x0100;
    pub const DIRECTORY: usize = 0x0010_0000;
    pub const CLOEXEC: usize = 0x0100_0000;
}

/// `AT_FDCWD` is -2 on Darwin, where other systems use -100.
const AT_FDCWD: i32 = -2;

/// The longest path this ABI resolves, matching XNU's `PATH_MAX`.
const PATH_MAX: usize = 1024;

mod nr {
    pub const EXIT: usize = 1;
    pub const READ: usize = 3;
    pub const WRITE: usize = 4;
    pub const OPEN: usize = 5;
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
    pub const OPENAT: usize = 463;
    // The 64-bit inode variants, which is what everything has used since
    // 10.6; the older numbers describe a `struct stat` with a 32-bit inode
    // that no current binary asks for.
    pub const STAT64: usize = 338;
    pub const FSTAT64: usize = 339;
    pub const LSTAT64: usize = 340;
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
    let class = nr >> CLASS_SHIFT;
    if class == CLASS_MACH {
        return mach(env, host);
    }
    if class != CLASS_UNIX {
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

/// Service a Mach trap.
///
/// Lay attributes out as Darwin's `struct stat64`, which orders its fields its
/// own way and carries each timestamp as a `timespec` pair.
fn write_stat(host: &dyn Host, at: usize, attr: &Attributes) -> SysResult {
    const STAT64_LEN: usize = 144;
    let mut buf = [0u8; STAT64_LEN];
    let mode = attr.mode
        | match attr.kind {
            NodeKind::File => 0o100000,
            NodeKind::Directory => 0o040000,
            NodeKind::Symlink => 0o120000,
            NodeKind::CharDevice => 0o020000,
            NodeKind::BlockDevice => 0o060000,
            NodeKind::Fifo => 0o010000,
            NodeKind::Socket => 0o140000,
        };
    let put32 =
        |buf: &mut [u8], at: usize, v: u32| buf[at..at + 4].copy_from_slice(&v.to_le_bytes());
    let put64 =
        |buf: &mut [u8], at: usize, v: u64| buf[at..at + 8].copy_from_slice(&v.to_le_bytes());
    let put_time = |buf: &mut [u8], at: usize, ns: u64| {
        buf[at..at + 8].copy_from_slice(&(ns / 1_000_000_000).to_le_bytes());
        buf[at + 8..at + 16].copy_from_slice(&(ns % 1_000_000_000).to_le_bytes());
    };
    put32(&mut buf, 0, attr.device as u32); // st_dev
    put32(&mut buf, 4, mode & 0xFFFF); // st_mode is 16 bits here
    put32(&mut buf, 6, attr.links as u32); // st_nlink, packed after st_mode
    put64(&mut buf, 8, attr.inode); // st_ino
    put32(&mut buf, 16, attr.uid);
    put32(&mut buf, 20, attr.gid);
    put32(&mut buf, 24, attr.rdev as u32);
    put_time(&mut buf, 32, attr.accessed_ns);
    put_time(&mut buf, 48, attr.modified_ns);
    put_time(&mut buf, 64, attr.changed_ns);
    // st_birthtimespec has no counterpart in what the host reports, so it
    // carries the status-change time rather than a made-up value.
    put_time(&mut buf, 80, attr.changed_ns);
    put64(&mut buf, 96, attr.size);
    put64(&mut buf, 104, attr.blocks);
    put32(&mut buf, 112, attr.block_size as u32);
    host.platform().write_user(at, &buf)?;
    Ok(0)
}

/// Turn a Darwin `open` flag word into the neutral request the host resolves.
fn open_request(flags: usize, mode: u32) -> Result<OpenHow, i32> {
    let (read, write) = match flags & oflag::ACCMODE {
        oflag::RDONLY => (true, false),
        oflag::WRONLY => (false, true),
        oflag::RDWR => (true, true),
        _ => return Err(EINVAL),
    };
    Ok(OpenHow {
        read,
        write,
        append: flags & oflag::APPEND != 0,
        truncate: flags & oflag::TRUNC != 0,
        create: match (flags & oflag::CREAT != 0, flags & oflag::EXCL != 0) {
            (true, true) => Create::Exclusive,
            (true, false) => Create::IfAbsent,
            // O_EXCL without O_CREAT is undefined on Darwin as elsewhere, and
            // is treated as the plain open it reads as.
            (false, _) => Create::Never,
        },
        directory: flags & oflag::DIRECTORY != 0,
        follow: flags & oflag::NOFOLLOW == 0,
        close_on_exec: flags & oflag::CLOEXEC != 0,
        mode: mode & 0o7777,
    })
}

/// Read a path argument, which Darwin writes as a NUL-terminated byte string.
fn read_path<'a>(host: &dyn Host, at: usize, out: &'a mut [u8; PATH_MAX]) -> Result<&'a str, i32> {
    let len = host.platform().read_user_cstr(at, out)? as usize;
    core::str::from_utf8(&out[..len]).map_err(|_| EINVAL)
}

/// Mach's calls are the other half of the Darwin ABI, and a program reaches
/// both through the same instruction with the class in the top byte. Only the
/// two that give up the processor are here; the rest of Mach - ports, messages,
/// virtual memory - is its own object model and is not this package's yet.
fn mach(env: &mut dyn TrapEnv, host: &dyn Host) -> Dispatch {
    /// `swtch_pri`, which libc's `sched_yield` issues.
    const SWTCH_PRI: usize = 59;
    /// `swtch`, its older sibling.
    const SWTCH: usize = 60;

    let Some(tasks) = host.tasks() else {
        return Dispatch::Passthrough;
    };
    match env.nr() & NUMBER_MASK {
        SWTCH_PRI | SWTCH => {
            let _ = tasks.sched_yield();
            // Both report whether anything else was waiting; saying nothing
            // was is honest here and is what a caller treats as "keep going".
            env.set_error(false);
            env.set_result(0);
            Dispatch::Handled
        }
        _ => Dispatch::Passthrough,
    }
}

fn route(host: &dyn Host, call: usize, a: &[usize; 6]) -> Option<SysResult> {
    let fd = a[0] as i32;
    Some(match call {
        // XNU's `exit` encodes the status the same way, through W_EXITCODE.
        // open(path, flags, mode) and openat(fd, path, flags, mode). The flag
        // word and the encoding of the name are this ABI's; resolving the name
        // is the host's.
        nr::OPEN | nr::OPENAT => {
            let paths = host.paths()?;
            let at_dir = if call == nr::OPENAT {
                match a[0] as i32 {
                    AT_FDCWD => At::Cwd,
                    fd => At::Dir(fd),
                }
            } else {
                At::Cwd
            };
            let base = usize::from(call == nr::OPENAT);
            let mut buf = [0u8; PATH_MAX];
            let path = match read_path(host, a[base], &mut buf) {
                Ok(path) => path,
                Err(errno) => return Some(Err(errno)),
            };
            match open_request(a[base + 1], a[base + 2] as u32) {
                Ok(how) => paths.open(at_dir, path, &how),
                Err(errno) => return Some(Err(errno)),
            }
        }
        // stat(path, buf), lstat(path, buf) and fstat(fd, buf). The layout is
        // this ABI's; what is in it is the host's.
        nr::STAT64 | nr::LSTAT64 => {
            let paths = host.paths()?;
            let mut buf = [0u8; PATH_MAX];
            let path = match read_path(host, a[0], &mut buf) {
                Ok(path) => path,
                Err(errno) => return Some(Err(errno)),
            };
            match paths.attributes(At::Cwd, path, call == nr::STAT64) {
                Ok(attr) => write_stat(host, a[1], &attr),
                Err(errno) => Err(errno),
            }
        }
        nr::FSTAT64 => match host.paths()?.attributes_of(fd) {
            Ok(attr) => write_stat(host, a[1], &attr),
            Err(errno) => Err(errno),
        },
        nr::EXIT => host.tasks()?.exit_group((a[0] as i32) << 8),
        nr::READ => host.files()?.read(fd, a[1], a[2]),
        nr::WRITE => host.files()?.write(fd, a[1], a[2]),
        nr::CLOSE => host.files()?.close(fd),
        nr::DUP => host.files()?.dup(fd),
        nr::DUP2 => {
            // XNU's dup2 checks the descriptor and then returns the target
            // unchanged when the two are the same, rather than closing and
            // reopening it.
            let to = a[1] as i32;
            if fd == to {
                host.files()?.validate(fd).map(|_| to as isize)
            } else {
                host.files()?.dup_onto(fd, to, false)
            }
        }
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
            let offset = a[1] as isize;
            let to = match a[2] {
                0 if offset < 0 => return Some(Err(EINVAL)),
                0 => SeekFrom::Start(offset as u64),
                1 => SeekFrom::Current(offset as i64),
                2 => SeekFrom::End(offset as i64),
                _ => return Some(Err(EINVAL)),
            };
            host.files()?.seek(fd, to)
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
        nr::GETPID => host.tasks()?.getpid(),
        nr::GETPPID => host.tasks()?.getppid(),
        nr::GETUID => Ok(host.creds()?.uids().0 as isize),
        nr::GETEUID => Ok(host.creds()?.uids().1 as isize),
        nr::GETGID => Ok(host.creds()?.gids().0 as isize),
        nr::GETEGID => Ok(host.creds()?.gids().1 as isize),
        nr::MMAP => return map(host, a),
        nr::MUNMAP => {
            // XNU refuses an unaligned address as well as a zero length.
            if a[1] == 0 || !a[0].is_multiple_of(PAGE_SIZE) {
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
        nr::MADVISE => {
            // XNU's `sys/mman.h`. These part company with Linux's from five
            // onward - MADV_FREE is 5 here and 8 there - so the number is
            // translated rather than passed on.
            let meaning = match a[2] {
                0 => Advice::Normal,
                1 => Advice::Random,
                2 => Advice::Sequential,
                3 => Advice::WillNeed,
                4 => Advice::DontNeed,
                5 => Advice::Free,
                // MADV_ZERO_WIRED_PAGES, the FREE_REUSABLE/REUSE pair,
                // CAN_REUSE and PAGEOUT: asking is valid, and there is
                // nothing here that acts on them.
                6..=10 => Advice::Ignored,
                _ => return Some(Err(EINVAL)),
            };
            if !a[0].is_multiple_of(PAGE_SIZE) {
                Err(EINVAL)
            } else if a[1] == 0 {
                Ok(0)
            } else {
                host.mem()?.advise(a[0], a[1], meaning)
            }
        }
        nr::MSYNC => {
            // XNU's flags, whose values are its own: MS_ASYNC is 1 and
            // MS_INVALIDATE 2 as elsewhere, but MS_SYNC is 0x10 rather than
            // Linux's 4. Asking for both kinds of sync at once is a
            // contradiction.
            const MS_ASYNC: usize = 0x1;
            const MS_INVALIDATE: usize = 0x2;
            const MS_SYNC: usize = 0x10;
            let flags_bad = a[2] & !(MS_ASYNC | MS_INVALIDATE | MS_SYNC) != 0
                || a[2] & (MS_ASYNC | MS_SYNC) == MS_ASYNC | MS_SYNC;
            if flags_bad || !a[0].is_multiple_of(PAGE_SIZE) {
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
    #[test]
    fn madvise_translates_darwins_numbering_not_linuxs() {
        let host = MockHost::default();
        // MADV_FREE is 5 on Darwin and 8 on Linux; passing the number through
        // would mean something else entirely on the host.
        let mut env = Trap::at(nr::MADVISE, [0x1000, 0x1000, 5, 0, 0, 0]);
        assert_eq!(dispatch(&mut env, &host), Dispatch::Handled);
        assert_eq!(*host.advised.borrow(), Some(Advice::Free));

        // The values above the shared range are Darwin's own and have no
        // action here, which is not a failure.
        let mut reuse = Trap::at(nr::MADVISE, [0x1000, 0x1000, 7, 0, 0, 0]);
        assert_eq!(dispatch(&mut reuse, &host), Dispatch::Handled);
        assert_eq!(*host.advised.borrow(), Some(Advice::Ignored));

        // Anything past what Darwin defines is refused.
        let mut bad = Trap::at(nr::MADVISE, [0x1000, 0x1000, 99, 0, 0, 0]);
        assert_eq!(dispatch(&mut bad, &host), Dispatch::Handled);
        assert_eq!(bad.failed, Some(true));
    }

    #[test]
    fn msync_takes_darwins_flag_values() {
        let host = MockHost::default();
        // MS_SYNC is 0x10 here, where Linux writes 4.
        let mut ok = Trap::at(nr::MSYNC, [0x1000, 0x1000, 0x10, 0, 0, 0]);
        assert_eq!(dispatch(&mut ok, &host), Dispatch::Handled);
        assert_eq!(ok.failed, Some(false));

        // Both kinds of sync at once is a contradiction, and an undefined bit
        // is refused rather than ignored.
        for flags in [0x1 | 0x10, 0x40] {
            let mut bad = Trap::at(nr::MSYNC, [0x1000, 0x1000, flags, 0, 0, 0]);
            assert_eq!(dispatch(&mut bad, &host), Dispatch::Handled);
            assert_eq!(bad.failed, Some(true), "flags {flags:#x}");
        }
    }

    #[test]
    fn munmap_wants_a_page_aligned_address() {
        let host = MockHost::default();
        let mut bad = Trap::at(nr::MUNMAP, [0x1001, 0x1000, 0, 0, 0, 0]);
        assert_eq!(dispatch(&mut bad, &host), Dispatch::Handled);
        assert_eq!(bad.failed, Some(true));
    }

    use alloc::{
        string::{String, ToString},
        vec,
        vec::Vec,
    };
    use core::cell::RefCell;

    use ax_abi_port::{Creds, EFAULT, Files, Mem, Paths, Platform, Tasks};

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
    impl Trap {
        /// A BSD call, with the class the number carries.
        fn at(call: usize, args: [usize; 6]) -> Self {
            Self {
                nr: unix_call(call),
                args,
                result: None,
                failed: None,
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
        fn set_error(&mut self, failed: bool) {
            self.failed = Some(failed);
        }
    }

    #[derive(Default)]
    struct MockHost {
        wrote: RefCell<Option<(i32, usize, usize)>>,
        mapped: RefCell<Option<MapRequest>>,
        advised: RefCell<Option<Advice>>,
        /// User memory, as one flat buffer starting at address zero.
        mem: RefCell<Vec<u8>>,
        opened: RefCell<Option<(At, String, OpenHow)>>,
        asked: RefCell<Option<(String, bool)>>,
        describes: Option<Attributes>,
    }
    // Single-threaded tests; the ports ask for Sync on a real host.
    unsafe impl Sync for MockHost {}

    impl Platform for MockHost {
        fn read_user(&self, uaddr: usize, out: &mut [u8]) -> SysResult {
            let mem = self.mem.borrow();
            let end = uaddr + out.len();
            if end > mem.len() {
                return Err(EFAULT);
            }
            out.copy_from_slice(&mem[uaddr..end]);
            Ok(0)
        }
        fn write_user(&self, uaddr: usize, data: &[u8]) -> SysResult {
            let mut mem = self.mem.borrow_mut();
            let end = uaddr + data.len();
            if end > mem.len() {
                return Err(EFAULT);
            }
            mem[uaddr..end].copy_from_slice(data);
            Ok(0)
        }
        fn read_user_cstr(&self, uaddr: usize, out: &mut [u8]) -> SysResult {
            // Reads one byte at a time so it stops at the terminator, which
            // is what a host with real mappings has to do anyway.
            for (i, slot) in out.iter_mut().enumerate() {
                let mut byte = [0u8; 1];
                self.read_user(uaddr + i, &mut byte)?;
                if byte[0] == 0 {
                    return Ok(i as isize);
                }
                *slot = byte[0];
            }
            Ok(out.len() as isize)
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
        fn seek(&self, _fd: i32, to: ax_abi_port::SeekFrom) -> SysResult {
            Ok(match to {
                ax_abi_port::SeekFrom::Start(at) => at as isize,
                ax_abi_port::SeekFrom::Current(by) | ax_abi_port::SeekFrom::End(by) => by as isize,
            })
        }
        fn validate(&self, _fd: i32) -> SysResult {
            Ok(0)
        }
        fn seekable(&self, _fd: i32) -> SysResult {
            Ok(0)
        }
        fn readv(&self, _fd: i32, _segs: &[ax_abi_port::Segment]) -> SysResult {
            Ok(0)
        }
        fn preadv(&self, _fd: i32, _segs: &[ax_abi_port::Segment], _offset: u64) -> SysResult {
            Ok(0)
        }
        fn writev(&self, _fd: i32, _segs: &[ax_abi_port::Segment]) -> SysResult {
            Ok(0)
        }
        fn pwritev(&self, _fd: i32, _segs: &[ax_abi_port::Segment], _offset: u64) -> SysResult {
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
        fn advise(&self, _a: usize, _l: usize, adv: Advice) -> SysResult {
            *self.advised.borrow_mut() = Some(adv);
            Ok(0)
        }
        fn writeback(&self, _a: usize, _l: usize) -> SysResult {
            Ok(0)
        }
    }
    impl Tasks for MockHost {
        fn getpid(&self) -> SysResult {
            Ok(77)
        }
        fn getppid(&self) -> SysResult {
            Ok(1)
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
    type SysResultAttr = Result<Attributes, i32>;

    impl Paths for MockHost {
        fn open(&self, at: At, path: &str, how: &OpenHow) -> SysResult {
            *self.opened.borrow_mut() = Some((at, path.to_string(), *how));
            Ok(5)
        }
        fn attributes(&self, _at: At, path: &str, follow: bool) -> SysResultAttr {
            *self.asked.borrow_mut() = Some((path.to_string(), follow));
            self.describes.clone().ok_or(ax_abi_port::ENOENT)
        }
        fn attributes_of(&self, _fd: i32) -> SysResultAttr {
            self.describes.clone().ok_or(ax_abi_port::EBADF)
        }
    }

    impl Host for MockHost {
        fn platform(&self) -> &dyn Platform {
            self
        }
        fn paths(&self) -> Option<&dyn Paths> {
            Some(self)
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
        fn read_user_cstr(&self, uaddr: usize, out: &mut [u8]) -> SysResult {
            // Reads one byte at a time so it stops at the terminator, which
            // is what a host with real mappings has to do anyway.
            for (i, slot) in out.iter_mut().enumerate() {
                let mut byte = [0u8; 1];
                self.read_user(uaddr + i, &mut byte)?;
                if byte[0] == 0 {
                    return Ok(i as isize);
                }
                *slot = byte[0];
            }
            Ok(out.len() as isize)
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

    /// A host whose user memory holds `path` as a NUL-terminated string at 0x40.
    fn host_with_path(path: &str) -> (MockHost, usize) {
        const AT: usize = 0x40;
        let mut mem = vec![0u8; 0x200];
        mem[AT..AT + path.len()].copy_from_slice(path.as_bytes());
        (
            MockHost {
                mem: RefCell::new(mem),
                ..MockHost::default()
            },
            AT,
        )
    }

    #[test]
    fn open_resolves_a_name_through_the_paths_port() {
        let (host, at) = host_with_path("/lib/python3.14/os.py");
        // open(path, O_RDONLY | O_CLOEXEC, 0)
        let mut env = Trap::at(nr::OPEN, [at, oflag::RDONLY | oflag::CLOEXEC, 0, 0, 0, 0]);
        assert_eq!(dispatch(&mut env, &host), Dispatch::Handled);
        assert_eq!(env.result, Some(5));
        assert_eq!(env.failed, Some(false));

        let opened = host.opened.borrow();
        let (dir, name, how) = opened.as_ref().unwrap();
        assert_eq!(*dir, At::Cwd);
        assert_eq!(name, "/lib/python3.14/os.py");
        assert!(how.read && !how.write && how.close_on_exec);
        assert_eq!(how.create, Create::Never);
    }

    #[test]
    fn openat_names_the_directory_it_is_relative_to() {
        let (host, at) = host_with_path("os.py");
        // openat(9, path, O_RDWR, 0)
        let mut env = Trap::at(nr::OPENAT, [9, at, oflag::RDWR, 0, 0, 0]);
        assert_eq!(dispatch(&mut env, &host), Dispatch::Handled);
        let opened = host.opened.borrow();
        let (dir, name, how) = opened.as_ref().unwrap();
        assert_eq!(*dir, At::Dir(9));
        assert_eq!(name, "os.py");
        assert!(how.read && how.write);

        // AT_FDCWD is -2 here, not the -100 other systems use, and names the
        // working directory rather than a descriptor.
        let (host, at) = host_with_path("os.py");
        let mut env = Trap::at(nr::OPENAT, [AT_FDCWD as usize, at, oflag::RDONLY, 0, 0, 0]);
        dispatch(&mut env, &host);
        assert_eq!(host.opened.borrow().as_ref().unwrap().0, At::Cwd);
    }

    #[test]
    fn creation_flags_carry_their_darwin_values() {
        // O_CREAT is 0x200 and O_EXCL 0x800 here, where Linux uses 0x40 and
        // 0x80: reading them with the wrong table would create the wrong file.
        let (host, at) = host_with_path("/tmp/new");
        let flags = oflag::WRONLY | oflag::CREAT | oflag::EXCL | oflag::TRUNC;
        let mut env = Trap::at(nr::OPEN, [at, flags, 0o644, 0, 0, 0]);
        assert_eq!(dispatch(&mut env, &host), Dispatch::Handled);
        let opened = host.opened.borrow();
        let how = &opened.as_ref().unwrap().2;
        assert_eq!(how.create, Create::Exclusive);
        assert!(how.truncate && how.write && !how.read);
        assert_eq!(how.mode, 0o644);
    }

    #[test]
    fn refuses_an_access_mode_that_names_nothing() {
        let (host, at) = host_with_path("/tmp/f");
        let mut env = Trap::at(nr::OPEN, [at, oflag::ACCMODE, 0, 0, 0, 0]);
        assert_eq!(dispatch(&mut env, &host), Dispatch::Handled);
        assert_eq!(env.failed, Some(true));
        assert_eq!(env.result, Some(EINVAL as usize));
        assert!(host.opened.borrow().is_none());
    }

    fn sample_attributes() -> Attributes {
        Attributes {
            kind: NodeKind::File,
            mode: 0o644,
            size: 1234,
            block_size: 4096,
            blocks: 8,
            device: 1,
            rdev: 0,
            inode: 42,
            links: 3,
            uid: 501,
            gid: 20,
            accessed_ns: 1_000_000_000_500_000_000,
            modified_ns: 1_000_000_001_250_000_000,
            changed_ns: 1_000_000_002_750_000_000,
        }
    }

    #[test]
    fn stat_lays_the_answer_out_the_way_darwin_reads_it() {
        let (mut host, at) = host_with_path("/lib/python3.14/os.py");
        host.describes = Some(sample_attributes());
        let mut env = Trap::at(nr::STAT64, [at, 0x80, 0, 0, 0, 0]);
        assert_eq!(dispatch(&mut env, &host), Dispatch::Handled);
        assert_eq!(env.failed, Some(false));

        let asked = host.asked.borrow();
        let (name, follow) = asked.as_ref().unwrap();
        assert_eq!(name, "/lib/python3.14/os.py");
        assert!(
            *follow,
            "stat follows a link; lstat is the one that does not"
        );

        let mem = host.mem.borrow();
        let at32 = |o: usize| u32::from_le_bytes(mem[0x80 + o..0x84 + o].try_into().unwrap());
        let at64 = |o: usize| u64::from_le_bytes(mem[0x80 + o..0x88 + o].try_into().unwrap());
        // st_mode carries the node type in its top bits and is 16 bits wide
        // here, with st_nlink packed directly after it.
        assert_eq!(at32(4) & 0xFFFF, 0o100644);
        assert_eq!(at64(8), 42, "st_ino");
        assert_eq!(at32(16), 501, "st_uid");
        assert_eq!(at32(20), 20, "st_gid");
        assert_eq!(at64(96), 1234, "st_size");
        assert_eq!(at64(104), 8, "st_blocks");
        assert_eq!(at32(112), 4096, "st_blksize");
        // Each timestamp is a seconds/nanoseconds pair, not one number.
        assert_eq!(at64(48), 1_000_000_001, "st_mtimespec.tv_sec");
        assert_eq!(at64(56), 250_000_000, "st_mtimespec.tv_nsec");
    }

    #[test]
    fn lstat_asks_about_the_link_itself() {
        let (mut host, at) = host_with_path("/tmp/link");
        host.describes = Some(sample_attributes());
        let mut env = Trap::at(nr::LSTAT64, [at, 0x80, 0, 0, 0, 0]);
        assert_eq!(dispatch(&mut env, &host), Dispatch::Handled);
        assert!(!host.asked.borrow().as_ref().unwrap().1);
    }

    #[test]
    fn a_name_that_is_not_there_is_reported_as_such() {
        let (host, at) = host_with_path("/nope");
        let mut env = Trap::at(nr::STAT64, [at, 0x80, 0, 0, 0, 0]);
        assert_eq!(dispatch(&mut env, &host), Dispatch::Handled);
        assert_eq!(env.failed, Some(true));
        assert_eq!(env.result, Some(ax_abi_port::ENOENT as usize));
    }

    #[test]
    fn a_directory_keeps_its_kind_in_the_mode() {
        let (mut host, at) = host_with_path("/lib");
        let mut dir = sample_attributes();
        dir.kind = NodeKind::Directory;
        dir.mode = 0o755;
        host.describes = Some(dir);
        let mut env = Trap::at(nr::STAT64, [at, 0x80, 0, 0, 0, 0]);
        dispatch(&mut env, &host);
        let mem = host.mem.borrow();
        let mode = u32::from_le_bytes(mem[0x84..0x88].try_into().unwrap()) & 0xFFFF;
        assert_eq!(mode, 0o040755);
    }
}
