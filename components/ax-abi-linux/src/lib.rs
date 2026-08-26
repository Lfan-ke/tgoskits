//! Linux personality for ArceOS/StarryOS.
//!
//! StarryOS is natively a Linux ABI, but its syscall table is woven into the
//! kernel. This crate re-expresses that ABI through dependency inversion: the
//! syscall logic here depends only on the [`ops`] ports plus [`ax_binfmt`],
//! never on `axtask`/`axfs`/`axmm`. It implements every syscall itself - reading
//! and validating arguments, copying user memory through the [`ops::Platform`]
//! port, and driving the [`ops::Files`]/[`ops::Tasks`]/[`ops::Mem`] services -
//! and never forwards a syscall to the host (the zero-passthrough rule gVisor's
//! Sentry follows). A hosting OS registers one [`ops::LinuxHost`] over its
//! concrete managers, so the crate stays kernel-runtime-free and unit-testable
//! with mock ports, and any ArceOS-derived OS can reuse the Linux personality.
//!
//! `dispatch` takes the host by reference so its logic is testable; the kernel
//! binds the registered host to a parameter-less entry at integration time.

#![cfg_attr(not(test), no_std)]

pub mod ops;

use ax_binfmt::{Abi, TrapEnv};
use ops::{EINVAL, ENOSYS, LinuxHost, SysResult};
use syscalls::Sysno;

/// Bounce-buffer size for user-memory copies; larger transfers loop.
const CHUNK: usize = 256;
/// Nanoseconds per second, for packing `timespec`/`timeval`.
const NS_PER_SEC: u64 = 1_000_000_000;
/// `CLOCK_REALTIME` - wall-clock time since the Unix epoch.
const CLOCK_REALTIME: i32 = 0;
/// `CLOCK_MONOTONIC` - time since an arbitrary fixed point.
const CLOCK_MONOTONIC: i32 = 1;

/// The Linux personality: recognizes ELF images and services Linux syscalls
/// against a host's ports.
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

    /// Service one trapped syscall against `host`, writing the result into `uctx`.
    pub fn handle_syscall(host: &dyn LinuxHost, uctx: &mut dyn TrapEnv) {
        let result = dispatch(host, uctx);
        uctx.set_result(encode(result));
    }
}

/// Route one syscall to its handler. Kept free of the trap-frame write so it can
/// be unit-tested with mock ports and a mock [`TrapEnv`].
fn dispatch(host: &dyn LinuxHost, uctx: &dyn TrapEnv) -> SysResult {
    let Some(sysno) = Sysno::new(uctx.nr()) else {
        return Err(ENOSYS);
    };
    let arg = |i| uctx.arg(i);
    match sysno {
        // fd I/O - the domain copies user memory itself, then drives Files.
        Sysno::read => sys_read(host, arg(0) as i32, arg(1), arg(2)),
        Sysno::write => sys_write(host, arg(0) as i32, arg(1), arg(2)),
        Sysno::close => host.files().close(arg(0) as i32),
        Sysno::dup => host.files().dup(arg(0) as i32),
        Sysno::lseek => host
            .files()
            .lseek(arg(0) as i32, arg(1) as isize, arg(2) as i32),

        // Process and thread control.
        Sysno::getpid => Ok(host.tasks().getpid() as isize),
        Sysno::getppid => Ok(host.tasks().getppid() as isize),
        Sysno::gettid => Ok(host.tasks().gettid() as isize),
        Sysno::set_tid_address => host.tasks().set_tid_address(arg(0)),
        Sysno::sched_yield => host.tasks().sched_yield(),
        Sysno::exit => host.tasks().exit(arg(0) as i32),
        Sysno::exit_group => host.tasks().exit_group(arg(0) as i32),

        // Address space.
        Sysno::brk => host.mem().brk(arg(0)),
        Sysno::mmap => host.mem().mmap(
            arg(0),
            arg(1),
            arg(2) as i32,
            arg(3) as i32,
            arg(4) as i32,
            arg(5),
        ),
        Sysno::munmap => host.mem().munmap(arg(0), arg(1)),
        Sysno::mprotect => host.mem().mprotect(arg(0), arg(1), arg(2) as i32),

        // Clocks - the domain packs the timespec/timeval itself.
        Sysno::clock_gettime => sys_clock_gettime(host, arg(0) as i32, arg(1)),
        Sysno::gettimeofday => sys_gettimeofday(host, arg(0)),
        Sysno::nanosleep => sys_nanosleep(host, arg(0), arg(1)),

        _ => Err(ENOSYS),
    }
}

/// `write(fd, ubuf, len)`: copy from user in bounded chunks and write each to
/// `fd`, honoring short writes - the domain owns the transfer, not the host.
fn sys_write(host: &dyn LinuxHost, fd: i32, ubuf: usize, len: usize) -> SysResult {
    let (platform, files) = (host.platform(), host.files());
    let mut buf = [0u8; CHUNK];
    let mut done = 0;
    while done < len {
        let n = (len - done).min(CHUNK);
        platform.read_user(ubuf + done, &mut buf[..n])?;
        let written = files.write(fd, &buf[..n])? as usize;
        done += written;
        if written < n {
            break;
        }
    }
    Ok(done as isize)
}

/// `read(fd, ubuf, len)`: read from `fd` in bounded chunks and copy each to
/// user, stopping at EOF or a short read.
fn sys_read(host: &dyn LinuxHost, fd: i32, ubuf: usize, len: usize) -> SysResult {
    let (platform, files) = (host.platform(), host.files());
    let mut buf = [0u8; CHUNK];
    let mut done = 0;
    while done < len {
        let n = (len - done).min(CHUNK);
        let got = files.read(fd, &mut buf[..n])? as usize;
        if got == 0 {
            break;
        }
        platform.write_user(ubuf + done, &buf[..got])?;
        done += got;
        if got < n {
            break;
        }
    }
    Ok(done as isize)
}

/// `clock_gettime(clockid, ts)`: read the requested clock and pack a `timespec`
/// (two 64-bit words) into user memory.
fn sys_clock_gettime(host: &dyn LinuxHost, clockid: i32, ts: usize) -> SysResult {
    let ns = match clockid {
        CLOCK_REALTIME => host.clock().wall_ns(),
        CLOCK_MONOTONIC => host.clock().monotonic_ns(),
        _ => return Err(EINVAL),
    };
    let packed = pack_time_pair((ns / NS_PER_SEC) as i64, (ns % NS_PER_SEC) as i64);
    host.platform().write_user(ts, &packed)?;
    Ok(0)
}

/// `gettimeofday(tv)`: pack the wall clock as a `timeval` (seconds + microseconds).
fn sys_gettimeofday(host: &dyn LinuxHost, tv: usize) -> SysResult {
    if tv == 0 {
        return Ok(0);
    }
    let ns = host.clock().wall_ns();
    let packed = pack_time_pair((ns / NS_PER_SEC) as i64, (ns % NS_PER_SEC / 1_000) as i64);
    host.platform().write_user(tv, &packed)?;
    Ok(0)
}

/// `nanosleep(req, rem)`: read the requested `timespec`, sleep, and clear `rem`
/// (this personality does not interrupt sleeps yet, so no time ever remains).
fn sys_nanosleep(host: &dyn LinuxHost, req: usize, rem: usize) -> SysResult {
    let mut buf = [0u8; 16];
    host.platform().read_user(req, &mut buf)?;
    let sec = i64::from_le_bytes(buf[..8].try_into().unwrap());
    let nsec = i64::from_le_bytes(buf[8..].try_into().unwrap());
    if sec < 0 || !(0..NS_PER_SEC as i64).contains(&nsec) {
        return Err(EINVAL);
    }
    host.clock()
        .sleep_ns(sec as u64 * NS_PER_SEC + nsec as u64)?;
    if rem != 0 {
        host.platform().write_user(rem, &[0u8; 16])?;
    }
    Ok(0)
}

/// Pack two 64-bit little-endian words - the shared layout of `timespec` and
/// `timeval` on 64-bit Linux.
fn pack_time_pair(hi: i64, lo: i64) -> [u8; 16] {
    let mut b = [0u8; 16];
    b[..8].copy_from_slice(&hi.to_le_bytes());
    b[8..].copy_from_slice(&lo.to_le_bytes());
    b
}

/// Encode a [`SysResult`] the Linux way: the value on success, `-errno` on
/// failure (both as raw register-width bits).
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
        ops::{Clock, EFAULT, Files, Mem, Platform, Tasks},
        *,
    };

    // A trap frame with a preset syscall number and arguments.
    struct Trap {
        nr: usize,
        args: [usize; 6],
    }
    impl Trap {
        fn new(nr: Sysno, args: [usize; 6]) -> Self {
            Self {
                nr: nr as usize,
                args,
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
        fn set_result(&mut self, _value: usize) {}
    }

    // A host whose "user memory" is a byte vector at base 0, whose Files echoes
    // writes into a log and serves reads from a queue - enough to exercise the
    // real copy orchestration.
    #[derive(Default)]
    struct Host {
        umem: RefCell<Vec<u8>>,
        written: RefCell<Vec<u8>>,
        to_read: RefCell<Vec<u8>>,
        slept: RefCell<u64>,
    }
    // Single-threaded test only; the ports need Sync for the real 'static host.
    unsafe impl Sync for Host {}

    impl Platform for Host {
        fn read_user(&self, uaddr: usize, out: &mut [u8]) -> SysResult {
            let mem = self.umem.borrow();
            let end = uaddr.checked_add(out.len()).ok_or(EFAULT)?;
            let src = mem.get(uaddr..end).ok_or(EFAULT)?;
            out.copy_from_slice(src);
            Ok(0)
        }
        fn write_user(&self, uaddr: usize, data: &[u8]) -> SysResult {
            let mut mem = self.umem.borrow_mut();
            let end = uaddr.checked_add(data.len()).ok_or(EFAULT)?;
            let dst = mem.get_mut(uaddr..end).ok_or(EFAULT)?;
            dst.copy_from_slice(data);
            Ok(0)
        }
    }
    impl Files for Host {
        fn read(&self, _fd: i32, buf: &mut [u8]) -> SysResult {
            let mut src = self.to_read.borrow_mut();
            let n = buf.len().min(src.len());
            buf[..n].copy_from_slice(&src[..n]);
            src.drain(..n);
            Ok(n as isize)
        }
        fn write(&self, _fd: i32, buf: &[u8]) -> SysResult {
            self.written.borrow_mut().extend_from_slice(buf);
            Ok(buf.len() as isize)
        }
        fn close(&self, _fd: i32) -> SysResult {
            Ok(0)
        }
        fn dup(&self, _fd: i32) -> SysResult {
            Ok(9)
        }
        fn lseek(&self, _fd: i32, offset: isize, _whence: i32) -> SysResult {
            Ok(offset)
        }
    }
    impl Tasks for Host {
        fn getpid(&self) -> u32 {
            42
        }
        fn getppid(&self) -> u32 {
            1
        }
        fn gettid(&self) -> u32 {
            7
        }
        fn set_tid_address(&self, _tidptr: usize) -> SysResult {
            Ok(7)
        }
        fn sched_yield(&self) -> SysResult {
            Ok(0)
        }
        fn exit(&self, code: i32) -> ! {
            panic!("exit {code}")
        }
        fn exit_group(&self, code: i32) -> ! {
            panic!("exit_group {code}")
        }
    }
    impl Mem for Host {
        fn brk(&self, addr: usize) -> SysResult {
            Ok(addr as isize)
        }
        fn mmap(&self, _a: usize, _l: usize, _p: i32, _f: i32, _fd: i32, _o: usize) -> SysResult {
            Ok(0x1000)
        }
        fn munmap(&self, _a: usize, _l: usize) -> SysResult {
            Ok(0)
        }
        fn mprotect(&self, _a: usize, _l: usize, _p: i32) -> SysResult {
            Ok(0)
        }
    }
    impl Clock for Host {
        fn monotonic_ns(&self) -> u64 {
            5 * NS_PER_SEC + 250
        }
        fn wall_ns(&self) -> u64 {
            1_700_000_000 * NS_PER_SEC + 500_000
        }
        fn sleep_ns(&self, ns: u64) -> SysResult {
            *self.slept.borrow_mut() = ns;
            Ok(0)
        }
    }
    impl LinuxHost for Host {
        fn platform(&self) -> &dyn Platform {
            self
        }
        fn tasks(&self) -> &dyn Tasks {
            self
        }
        fn clock(&self) -> &dyn Clock {
            self
        }
        fn files(&self) -> &dyn Files {
            self
        }
        fn mem(&self) -> &dyn Mem {
            self
        }
    }

    #[test]
    fn write_copies_from_user_then_drives_files() {
        let host = Host::default();
        *host.umem.borrow_mut() = vec![b'h', b'i', b'!', 0, 0];
        // write(fd=1, ubuf=0, len=3): the domain copies "hi!" out of user memory
        // and hands it to Files - no passthrough.
        let r = dispatch(&host, &Trap::new(Sysno::write, [1, 0, 3, 0, 0, 0]));
        assert_eq!(r, Ok(3));
        assert_eq!(&*host.written.borrow(), b"hi!");
    }

    #[test]
    fn read_reads_files_then_copies_to_user() {
        let host = Host::default();
        *host.umem.borrow_mut() = vec![0u8; 4];
        *host.to_read.borrow_mut() = vec![9, 8, 7];
        let r = dispatch(&host, &Trap::new(Sysno::read, [0, 0, 4, 0, 0, 0]));
        assert_eq!(r, Ok(3)); // short read at EOF
        assert_eq!(&host.umem.borrow()[..3], &[9, 8, 7]);
    }

    #[test]
    fn write_past_user_memory_faults() {
        let host = Host::default();
        *host.umem.borrow_mut() = vec![1, 2];
        let r = dispatch(&host, &Trap::new(Sysno::write, [1, 0, 8, 0, 0, 0]));
        assert_eq!(r, Err(EFAULT));
    }

    #[test]
    fn routes_primitive_syscalls() {
        let host = Host::default();
        assert_eq!(dispatch(&host, &Trap::new(Sysno::getpid, [0; 6])), Ok(42));
        assert_eq!(
            dispatch(&host, &Trap::new(Sysno::brk, [0x8000, 0, 0, 0, 0, 0])),
            Ok(0x8000)
        );
        assert_eq!(
            dispatch(&host, &Trap::new(Sysno::dup, [3, 0, 0, 0, 0, 0])),
            Ok(9)
        );
    }

    #[test]
    fn unknown_syscall_is_enosys() {
        let host = Host::default();
        assert_eq!(
            dispatch(&host, &Trap::new(Sysno::reboot, [0; 6])),
            Err(ENOSYS)
        );
    }

    #[test]
    fn clock_gettime_packs_monotonic_into_user() {
        let host = Host::default();
        *host.umem.borrow_mut() = vec![0u8; 16];
        let r = dispatch(
            &host,
            &Trap::new(
                Sysno::clock_gettime,
                [CLOCK_MONOTONIC as usize, 0, 0, 0, 0, 0],
            ),
        );
        assert_eq!(r, Ok(0));
        let mem = host.umem.borrow();
        let sec = i64::from_le_bytes(mem[..8].try_into().unwrap());
        let nsec = i64::from_le_bytes(mem[8..16].try_into().unwrap());
        assert_eq!((sec, nsec), (5, 250));
    }

    #[test]
    fn clock_gettime_rejects_unknown_clock() {
        let host = Host::default();
        *host.umem.borrow_mut() = vec![0u8; 16];
        assert_eq!(
            dispatch(&host, &Trap::new(Sysno::clock_gettime, [99, 0, 0, 0, 0, 0])),
            Err(EINVAL)
        );
    }

    #[test]
    fn nanosleep_reads_request_and_sleeps() {
        let host = Host::default();
        // A timespec of { 2s, 3ns } at user address 0.
        *host.umem.borrow_mut() = pack_time_pair(2, 3).to_vec();
        let r = dispatch(&host, &Trap::new(Sysno::nanosleep, [0, 0, 0, 0, 0, 0]));
        assert_eq!(r, Ok(0));
        assert_eq!(*host.slept.borrow(), 2 * NS_PER_SEC + 3);
    }

    #[test]
    fn encode_follows_linux_convention() {
        assert_eq!(encode(Ok(16)), 16);
        assert_eq!(encode(Err(ENOSYS)), (-(ENOSYS as isize)) as usize);
    }
}
