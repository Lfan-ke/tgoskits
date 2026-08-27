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
use ax_crate_interface::{call_interface, def_interface};
use ops::{EINVAL, ENOSYS, LinuxHost, SysResult};
use syscalls::Sysno;

/// The global binding a hosting OS provides so the trap path can reach its
/// registered [`LinuxHost`] without a parameter - ArceOS's native way to invert
/// the dependency (the kernel `#[impl_interface]`s this, we `call_interface!` it),
/// keeping this crate free of a hand-rolled registry.
#[def_interface]
pub trait CurrentHost {
    /// The `LinuxHost` the kernel registered for the current context.
    fn current() -> &'static dyn LinuxHost;
}

/// Bounce-buffer size for user-memory copies; larger transfers loop.
const CHUNK: usize = 256;
/// Maximum `iovcnt` for scatter/gather I/O (`UIO_MAXIOV`).
const IOV_MAX: usize = 1024;
/// Size of one 64-bit `struct iovec` (an 8-byte base pointer and 8-byte length).
const IOVEC_SIZE: usize = 16;
/// `O_CLOEXEC` (generic ABI, all four targets) - the only flag `dup3` accepts.
const O_CLOEXEC: i32 = 0o2000000;
/// One `new_utsname` field width (arch-independent), and the packed struct length.
const UTS_FIELD: usize = 65;
const UTS_LEN: usize = 6 * UTS_FIELD;
/// Nanoseconds per second, for packing `timespec`/`timeval`.
const NS_PER_SEC: u64 = 1_000_000_000;
/// `CLOCK_REALTIME` - wall-clock time since the Unix epoch.
const CLOCK_REALTIME: i32 = 0;
/// `CLOCK_MONOTONIC` - time since an arbitrary fixed point.
const CLOCK_MONOTONIC: i32 = 1;
/// The kernel `sigset_t` the syscall ABI expects is exactly 8 bytes.
const SIGSET_SIZE: usize = 8;

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

    /// The parameter-less entry the kernel trap path calls: it resolves the
    /// registered host through [`CurrentHost`], then services the syscall. The
    /// kernel binds the host with `#[impl_interface]`.
    pub fn handle_trapped_syscall(uctx: &mut dyn TrapEnv) {
        Self::handle_syscall(call_interface!(CurrentHost::current), uctx);
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
        Sysno::dup2 => host.files().dup2(arg(0) as i32, arg(1) as i32, false),
        Sysno::dup3 => sys_dup3(host, arg(0) as i32, arg(1) as i32, arg(2) as i32),
        Sysno::lseek => host
            .files()
            .lseek(arg(0) as i32, arg(1) as isize, arg(2) as i32),
        Sysno::writev => sys_writev(host, arg(0) as i32, arg(1), arg(2) as i32),
        Sysno::readv => sys_readv(host, arg(0) as i32, arg(1), arg(2) as i32),
        Sysno::pread64 => sys_pread64(host, arg(0) as i32, arg(1), arg(2), arg(3) as i64),
        Sysno::pwrite64 => sys_pwrite64(host, arg(0) as i32, arg(1), arg(2), arg(3) as i64),
        Sysno::fsync => host.files().fsync(arg(0) as i32, false),
        Sysno::fdatasync => host.files().fsync(arg(0) as i32, true),
        Sysno::ftruncate => sys_ftruncate(host, arg(0) as i32, arg(1) as i64),

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
        Sysno::clock_getres => sys_clock_getres(host, arg(0) as i32, arg(1)),
        Sysno::gettimeofday => sys_gettimeofday(host, arg(0)),
        Sysno::nanosleep => sys_nanosleep(host, arg(0), arg(1)),

        // Signals - the domain moves the sigset; the port carries a u64 mask.
        Sysno::kill => host.signals().kill(arg(0) as i32, arg(1) as i32),
        Sysno::tgkill => host
            .signals()
            .tgkill(arg(0) as i32, arg(1) as i32, arg(2) as i32),
        Sysno::rt_sigprocmask => sys_rt_sigprocmask(host, arg(0) as i32, arg(1), arg(2), arg(3)),

        // Randomness - the domain fills user memory from the Random port.
        Sysno::getrandom => sys_getrandom(host, arg(0), arg(1)),

        // System identity - the domain packs the utsname struct itself.
        Sysno::uname => sys_uname(host, arg(0)),

        // Credentials - identity getters project from the (real, eff, saved) triple.
        Sysno::getuid => Ok(host.creds().uids().0 as isize),
        Sysno::geteuid => Ok(host.creds().uids().1 as isize),
        Sysno::getgid => Ok(host.creds().gids().0 as isize),
        Sysno::getegid => Ok(host.creds().gids().1 as isize),
        Sysno::getresuid => sys_getres(host, host.creds().uids(), arg(0), arg(1), arg(2)),
        Sysno::getresgid => sys_getres(host, host.creds().gids(), arg(0), arg(1), arg(2)),

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

/// `writev(fd, iov, iovcnt)`: gather-write. The domain reads the `iovec` array
/// from user memory itself, then writes each segment through Files by reusing
/// [`sys_write`], honoring a short write. The array is validated up front (count
/// and the summed-length overflow Linux checks), so a bad `iov` faults before
/// any data is written.
fn sys_writev(host: &dyn LinuxHost, fd: i32, iov: usize, iovcnt: i32) -> SysResult {
    let count = check_iovcnt(iovcnt)?;
    total_iov_len(host, iov, count)?;
    let mut done = 0;
    for i in 0..count {
        let (base, len) = read_iovec(host, iov, i)?;
        let written = sys_write(host, fd, base, len)? as usize;
        done += written;
        if written < len {
            break;
        }
    }
    Ok(done as isize)
}

/// `readv(fd, iov, iovcnt)`: scatter-read. Reads into each user segment through
/// [`sys_read`], stopping at EOF or a short read, after validating the array.
fn sys_readv(host: &dyn LinuxHost, fd: i32, iov: usize, iovcnt: i32) -> SysResult {
    let count = check_iovcnt(iovcnt)?;
    total_iov_len(host, iov, count)?;
    let mut done = 0;
    for i in 0..count {
        let (base, len) = read_iovec(host, iov, i)?;
        let got = sys_read(host, fd, base, len)? as usize;
        done += got;
        if got < len {
            break;
        }
    }
    Ok(done as isize)
}

/// Validate an `iovcnt`: Linux rejects a negative count or one past `IOV_MAX`.
fn check_iovcnt(iovcnt: i32) -> Result<usize, i32> {
    if iovcnt < 0 || iovcnt as usize > IOV_MAX {
        return Err(EINVAL);
    }
    Ok(iovcnt as usize)
}

/// Read `iovec[i]` from the user array at `iov`, returning `(base, len)`.
fn read_iovec(host: &dyn LinuxHost, iov: usize, i: usize) -> Result<(usize, usize), i32> {
    let mut entry = [0u8; IOVEC_SIZE];
    host.platform()
        .read_user(iov + i * IOVEC_SIZE, &mut entry)?;
    let base = usize::from_le_bytes(entry[..8].try_into().unwrap());
    let len = usize::from_le_bytes(entry[8..].try_into().unwrap());
    Ok((base, len))
}

/// Sum the segment lengths, faulting if the array is unreadable and returning
/// `EINVAL` if the total would overflow `ssize_t` - the up-front import Linux
/// does before transferring any bytes.
fn total_iov_len(host: &dyn LinuxHost, iov: usize, count: usize) -> SysResult {
    let mut total: usize = 0;
    for i in 0..count {
        let (_, len) = read_iovec(host, iov, i)?;
        total = total
            .checked_add(len)
            .filter(|&t| t <= isize::MAX as usize)
            .ok_or(EINVAL)?;
    }
    Ok(total as isize)
}

/// `pread64(fd, ubuf, len, offset)`: positioned read - like [`sys_read`] but at
/// an absolute `offset` that advances per chunk, leaving the file position
/// untouched. A negative offset is `EINVAL`.
fn sys_pread64(host: &dyn LinuxHost, fd: i32, ubuf: usize, len: usize, offset: i64) -> SysResult {
    if offset < 0 {
        return Err(EINVAL);
    }
    let (platform, files) = (host.platform(), host.files());
    let mut buf = [0u8; CHUNK];
    let mut done = 0;
    while done < len {
        let n = (len - done).min(CHUNK);
        let got = files.pread(fd, &mut buf[..n], offset as u64 + done as u64)? as usize;
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

/// `pwrite64(fd, ubuf, len, offset)`: positioned write - like [`sys_write`] but
/// at an absolute `offset` that advances per chunk. A negative offset is `EINVAL`.
fn sys_pwrite64(host: &dyn LinuxHost, fd: i32, ubuf: usize, len: usize, offset: i64) -> SysResult {
    if offset < 0 {
        return Err(EINVAL);
    }
    let (platform, files) = (host.platform(), host.files());
    let mut buf = [0u8; CHUNK];
    let mut done = 0;
    while done < len {
        let n = (len - done).min(CHUNK);
        platform.read_user(ubuf + done, &mut buf[..n])?;
        let written = files.pwrite(fd, &buf[..n], offset as u64 + done as u64)? as usize;
        done += written;
        if written < n {
            break;
        }
    }
    Ok(done as isize)
}

/// `ftruncate(fd, len)`: resize `fd`. A negative length is `EINVAL`; the port
/// zero-extends the file on growth.
fn sys_ftruncate(host: &dyn LinuxHost, fd: i32, len: i64) -> SysResult {
    if len < 0 {
        return Err(EINVAL);
    }
    host.files().ftruncate(fd, len as u64)
}

/// `dup3(oldfd, newfd, flags)`: duplicate onto a specific fd like `dup2`, but
/// equal fds are `EINVAL` (not the `dup2` no-op) and the only accepted flag is
/// `O_CLOEXEC`. The port performs the fd-table replacement.
fn sys_dup3(host: &dyn LinuxHost, oldfd: i32, newfd: i32, flags: i32) -> SysResult {
    if oldfd == newfd || (flags & !O_CLOEXEC) != 0 {
        return Err(EINVAL);
    }
    host.files().dup2(oldfd, newfd, flags & O_CLOEXEC != 0)
}

/// `getrandom(ubuf, len)`: fill user memory from the Random port in bounded
/// chunks. Flags (GRND_NONBLOCK/RANDOM) do not change behavior for this backend.
fn sys_getrandom(host: &dyn LinuxHost, ubuf: usize, len: usize) -> SysResult {
    let (platform, random) = (host.platform(), host.random());
    let mut buf = [0u8; CHUNK];
    let mut done = 0;
    while done < len {
        let n = (len - done).min(CHUNK);
        let got = random.fill(&mut buf[..n])? as usize;
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

/// `uname(buf)`: report system identity. The domain packs the six `utsname`
/// fields, each NUL-padded to 65 bytes, and writes the 390-byte struct to user.
fn sys_uname(host: &dyn LinuxHost, buf: usize) -> SysResult {
    let u = host.system().uname();
    let fields = [
        u.sysname,
        u.nodename,
        u.release,
        u.version,
        u.machine,
        u.domainname,
    ];
    let mut out = [0u8; UTS_LEN];
    for (slot, field) in out.chunks_mut(UTS_FIELD).zip(fields) {
        let src = field.as_bytes();
        let n = src.len().min(UTS_FIELD - 1); // keep the trailing NUL
        slot[..n].copy_from_slice(&src[..n]);
    }
    host.platform().write_user(buf, &out)?;
    Ok(0)
}

/// `getresuid`/`getresgid`: write a `(real, effective, saved)` id triple to three
/// user pointers, each a 32-bit id.
fn sys_getres(
    host: &dyn LinuxHost,
    ids: (u32, u32, u32),
    real: usize,
    eff: usize,
    saved: usize,
) -> SysResult {
    let platform = host.platform();
    platform.write_user(real, &ids.0.to_le_bytes())?;
    platform.write_user(eff, &ids.1.to_le_bytes())?;
    platform.write_user(saved, &ids.2.to_le_bytes())?;
    Ok(0)
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

/// `clock_getres(clockid, res)`: report a clock's resolution. Both supported
/// clocks are nanosecond-resolution; a null `res` is a valid clock-liveness query.
fn sys_clock_getres(host: &dyn LinuxHost, clockid: i32, res: usize) -> SysResult {
    if !matches!(clockid, CLOCK_REALTIME | CLOCK_MONOTONIC) {
        return Err(EINVAL);
    }
    if res != 0 {
        host.platform().write_user(res, &pack_time_pair(0, 1))?;
    }
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

/// `rt_sigprocmask(how, set, old, sigsetsize)`: move the user `sigset_t` itself
/// (carried through the port as a `u64`), validating the ABI's fixed size and
/// the `how` selector.
fn sys_rt_sigprocmask(
    host: &dyn LinuxHost,
    how: i32,
    set: usize,
    old: usize,
    sigsetsize: usize,
) -> SysResult {
    if sigsetsize != SIGSET_SIZE {
        return Err(EINVAL);
    }
    let new = if set != 0 {
        if !(0..=2).contains(&how) {
            return Err(EINVAL);
        }
        let mut buf = [0u8; SIGSET_SIZE];
        host.platform().read_user(set, &mut buf)?;
        Some(u64::from_le_bytes(buf))
    } else {
        None
    };
    let previous = host.signals().sigprocmask(how, new)?;
    if old != 0 {
        host.platform().write_user(old, &previous.to_le_bytes())?;
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
        ops::{
            Clock, Creds, EFAULT, Files, Mem, Platform, Random, Signals, System, Tasks, UtsName,
        },
        *,
    };

    // A trap frame with a preset syscall number and arguments, recording the
    // result so the parameter-less entry can be observed end to end.
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

    // A trivial `'static` host for exercising the crate_interface global binding.
    struct FixedHost;
    impl Platform for FixedHost {
        fn read_user(&self, _u: usize, _o: &mut [u8]) -> SysResult {
            Ok(0)
        }
        fn write_user(&self, _u: usize, _d: &[u8]) -> SysResult {
            Ok(0)
        }
    }
    impl Tasks for FixedHost {
        fn getpid(&self) -> u32 {
            1
        }
        fn getppid(&self) -> u32 {
            0
        }
        fn gettid(&self) -> u32 {
            1
        }
        fn set_tid_address(&self, _t: usize) -> SysResult {
            Ok(1)
        }
        fn sched_yield(&self) -> SysResult {
            Ok(0)
        }
        fn exit(&self, _c: i32) -> ! {
            panic!("exit")
        }
        fn exit_group(&self, _c: i32) -> ! {
            panic!("exit_group")
        }
    }
    impl Files for FixedHost {
        fn read(&self, _fd: i32, _b: &mut [u8]) -> SysResult {
            Ok(0)
        }
        fn write(&self, _fd: i32, b: &[u8]) -> SysResult {
            Ok(b.len() as isize)
        }
        fn close(&self, _fd: i32) -> SysResult {
            Ok(0)
        }
        fn dup(&self, _fd: i32) -> SysResult {
            Ok(0)
        }
        fn lseek(&self, _fd: i32, o: isize, _w: i32) -> SysResult {
            Ok(o)
        }
        fn pread(&self, _fd: i32, _b: &mut [u8], _o: u64) -> SysResult {
            Ok(0)
        }
        fn pwrite(&self, _fd: i32, b: &[u8], _o: u64) -> SysResult {
            Ok(b.len() as isize)
        }
        fn dup2(&self, _oldfd: i32, newfd: i32, _cloexec: bool) -> SysResult {
            Ok(newfd as isize)
        }
        fn fsync(&self, _fd: i32, _datasync: bool) -> SysResult {
            Ok(0)
        }
        fn ftruncate(&self, _fd: i32, _len: u64) -> SysResult {
            Ok(0)
        }
    }
    impl Mem for FixedHost {
        fn brk(&self, a: usize) -> SysResult {
            Ok(a as isize)
        }
        fn mmap(&self, _a: usize, _l: usize, _p: i32, _f: i32, _fd: i32, _o: usize) -> SysResult {
            Ok(0)
        }
        fn munmap(&self, _a: usize, _l: usize) -> SysResult {
            Ok(0)
        }
        fn mprotect(&self, _a: usize, _l: usize, _p: i32) -> SysResult {
            Ok(0)
        }
    }
    impl Signals for FixedHost {
        fn kill(&self, _p: i32, _s: i32) -> SysResult {
            Ok(0)
        }
        fn tgkill(&self, _t: i32, _i: i32, _s: i32) -> SysResult {
            Ok(0)
        }
        fn sigprocmask(&self, _h: i32, _n: Option<u64>) -> Result<u64, i32> {
            Ok(0)
        }
    }
    impl Clock for FixedHost {
        fn monotonic_ns(&self) -> u64 {
            0
        }
        fn wall_ns(&self) -> u64 {
            0
        }
        fn sleep_ns(&self, _n: u64) -> SysResult {
            Ok(0)
        }
    }
    impl Random for FixedHost {
        fn fill(&self, b: &mut [u8]) -> SysResult {
            Ok(b.len() as isize)
        }
    }
    impl System for FixedHost {
        fn uname(&self) -> UtsName<'_> {
            UtsName {
                sysname: "Linux",
                nodename: "starry",
                release: "6.0.0",
                version: "#1",
                machine: "x86_64",
                domainname: "(none)",
            }
        }
    }
    impl Creds for FixedHost {
        fn uids(&self) -> (u32, u32, u32) {
            (0, 0, 0)
        }
        fn gids(&self) -> (u32, u32, u32) {
            (0, 0, 0)
        }
    }
    impl LinuxHost for FixedHost {
        fn platform(&self) -> &dyn Platform {
            self
        }
        fn tasks(&self) -> &dyn Tasks {
            self
        }
        fn files(&self) -> &dyn Files {
            self
        }
        fn mem(&self) -> &dyn Mem {
            self
        }
        fn signals(&self) -> &dyn Signals {
            self
        }
        fn clock(&self) -> &dyn Clock {
            self
        }
        fn random(&self) -> &dyn Random {
            self
        }
        fn system(&self) -> &dyn System {
            self
        }
        fn creds(&self) -> &dyn Creds {
            self
        }
    }

    // Bind the global CurrentHost port to the fixed host, as the kernel would.
    struct Binding;
    #[ax_crate_interface::impl_interface]
    impl CurrentHost for Binding {
        fn current() -> &'static dyn LinuxHost {
            static HOST: FixedHost = FixedHost;
            &HOST
        }
    }

    #[test]
    fn parameter_less_entry_resolves_the_bound_host() {
        // handle_trapped_syscall resolves the registered host via crate_interface
        // and services the syscall; getpid comes from FixedHost (1).
        let mut trap = Trap::new(Sysno::getpid, [0; 6]);
        LinuxAbi::handle_trapped_syscall(&mut trap);
        assert_eq!(trap.result, Some(1));
    }

    // A host whose "user memory" is a byte vector at base 0, whose Files echoes
    // writes into a log and serves reads from a queue - enough to exercise the
    // real copy orchestration.
    #[derive(Default)]
    struct Host {
        umem: RefCell<Vec<u8>>,
        written: RefCell<Vec<u8>>,
        to_read: RefCell<Vec<u8>>,
        file: RefCell<Vec<u8>>,
        slept: RefCell<u64>,
        mask: RefCell<u64>,
        killed: RefCell<Option<(i32, i32)>>,
        duped: RefCell<Option<(i32, i32, bool)>>,
        synced: RefCell<Option<bool>>,
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
        fn pread(&self, _fd: i32, buf: &mut [u8], offset: u64) -> SysResult {
            let file = self.file.borrow();
            let start = (offset as usize).min(file.len());
            let n = buf.len().min(file.len() - start);
            buf[..n].copy_from_slice(&file[start..start + n]);
            Ok(n as isize)
        }
        fn pwrite(&self, _fd: i32, buf: &[u8], offset: u64) -> SysResult {
            let mut file = self.file.borrow_mut();
            let end = offset as usize + buf.len();
            if file.len() < end {
                file.resize(end, 0);
            }
            file[offset as usize..end].copy_from_slice(buf);
            Ok(buf.len() as isize)
        }
        fn dup2(&self, oldfd: i32, newfd: i32, cloexec: bool) -> SysResult {
            *self.duped.borrow_mut() = Some((oldfd, newfd, cloexec));
            Ok(newfd as isize)
        }
        fn fsync(&self, _fd: i32, datasync: bool) -> SysResult {
            *self.synced.borrow_mut() = Some(datasync);
            Ok(0)
        }
        fn ftruncate(&self, _fd: i32, len: u64) -> SysResult {
            self.file.borrow_mut().resize(len as usize, 0);
            Ok(0)
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
    impl Signals for Host {
        fn kill(&self, pid: i32, sig: i32) -> SysResult {
            *self.killed.borrow_mut() = Some((pid, sig));
            Ok(0)
        }
        fn tgkill(&self, _tgid: i32, tid: i32, sig: i32) -> SysResult {
            *self.killed.borrow_mut() = Some((tid, sig));
            Ok(0)
        }
        fn sigprocmask(&self, how: i32, new: Option<u64>) -> Result<u64, i32> {
            let old = *self.mask.borrow();
            if let Some(m) = new {
                let mut mask = self.mask.borrow_mut();
                *mask = match how {
                    0 => *mask | m,  // SIG_BLOCK
                    1 => *mask & !m, // SIG_UNBLOCK
                    _ => m,          // SIG_SETMASK
                };
            }
            Ok(old)
        }
    }
    impl Random for Host {
        fn fill(&self, buf: &mut [u8]) -> SysResult {
            buf.fill(0xAB); // deterministic for the test
            Ok(buf.len() as isize)
        }
    }
    impl System for Host {
        fn uname(&self) -> UtsName<'_> {
            UtsName {
                sysname: "Linux",
                nodename: "node",
                release: "rel",
                version: "ver",
                machine: "riscv64",
                domainname: "(none)",
            }
        }
    }
    impl Creds for Host {
        fn uids(&self) -> (u32, u32, u32) {
            (1000, 1000, 0) // real, effective, saved
        }
        fn gids(&self) -> (u32, u32, u32) {
            (1000, 1000, 0)
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
        fn signals(&self) -> &dyn Signals {
            self
        }
        fn clock(&self) -> &dyn Clock {
            self
        }
        fn random(&self) -> &dyn Random {
            self
        }
        fn files(&self) -> &dyn Files {
            self
        }
        fn mem(&self) -> &dyn Mem {
            self
        }
        fn system(&self) -> &dyn System {
            self
        }
        fn creds(&self) -> &dyn Creds {
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

    // Lay a 64-bit iovec { base, len } at `entry` (index) in `mem`.
    fn put_iovec(mem: &mut [u8], index: usize, base: usize, len: usize) {
        let off = index * 16;
        mem[off..off + 8].copy_from_slice(&base.to_le_bytes());
        mem[off + 8..off + 16].copy_from_slice(&len.to_le_bytes());
    }

    #[test]
    fn writev_gathers_segments() {
        let host = Host::default();
        let mut mem = vec![0u8; 0x100];
        put_iovec(&mut mem, 0, 0x40, 3);
        put_iovec(&mut mem, 1, 0x80, 2);
        mem[0x40..0x43].copy_from_slice(b"abc");
        mem[0x80..0x82].copy_from_slice(b"de");
        *host.umem.borrow_mut() = mem;
        // writev(fd=1, iov=0, iovcnt=2): the domain reads the iovec array itself
        // and gathers both segments into Files in order - no passthrough.
        let r = dispatch(&host, &Trap::new(Sysno::writev, [1, 0, 2, 0, 0, 0]));
        assert_eq!(r, Ok(5));
        assert_eq!(&*host.written.borrow(), b"abcde");
    }

    #[test]
    fn readv_scatters_into_segments() {
        let host = Host::default();
        let mut mem = vec![0u8; 0x100];
        put_iovec(&mut mem, 0, 0x40, 2);
        put_iovec(&mut mem, 1, 0x80, 3);
        *host.umem.borrow_mut() = mem;
        *host.to_read.borrow_mut() = vec![1, 2, 3, 4, 5];
        let r = dispatch(&host, &Trap::new(Sysno::readv, [0, 0, 2, 0, 0, 0]));
        assert_eq!(r, Ok(5));
        assert_eq!(&host.umem.borrow()[0x40..0x42], &[1, 2]);
        assert_eq!(&host.umem.borrow()[0x80..0x83], &[3, 4, 5]);
    }

    #[test]
    fn writev_rejects_bad_iovcnt() {
        let host = Host::default();
        // IOV_MAX + 1 segments is refused before any transfer.
        let r = dispatch(&host, &Trap::new(Sysno::writev, [1, 0, 1025, 0, 0, 0]));
        assert_eq!(r, Err(EINVAL));
        assert!(host.written.borrow().is_empty());
    }

    #[test]
    fn writev_faults_on_bad_iov_before_writing() {
        let host = Host::default();
        // The iovec array itself is past the end of user memory: writev must
        // fault during the up-front import, before any segment is written.
        *host.umem.borrow_mut() = vec![0u8; 8];
        let r = dispatch(&host, &Trap::new(Sysno::writev, [1, 0, 2, 0, 0, 0]));
        assert_eq!(r, Err(EFAULT));
        assert!(host.written.borrow().is_empty());
    }

    #[test]
    fn pread_reads_at_offset() {
        let host = Host::default();
        *host.file.borrow_mut() = vec![10, 11, 12, 13, 14, 15];
        *host.umem.borrow_mut() = vec![0u8; 4];
        // pread(fd=3, ubuf=0, len=3, offset=2) reads [12,13,14] at the offset.
        let r = dispatch(&host, &Trap::new(Sysno::pread64, [3, 0, 3, 2, 0, 0]));
        assert_eq!(r, Ok(3));
        assert_eq!(&host.umem.borrow()[..3], &[12, 13, 14]);
    }

    #[test]
    fn pwrite_writes_at_offset() {
        let host = Host::default();
        *host.file.borrow_mut() = vec![0u8; 4];
        *host.umem.borrow_mut() = vec![b'X', b'Y'];
        // pwrite(fd=3, ubuf=0, len=2, offset=3) grows the file and writes at 3.
        let r = dispatch(&host, &Trap::new(Sysno::pwrite64, [3, 0, 2, 3, 0, 0]));
        assert_eq!(r, Ok(2));
        assert_eq!(&*host.file.borrow(), &[0, 0, 0, b'X', b'Y']);
    }

    #[test]
    fn pread_rejects_negative_offset() {
        let host = Host::default();
        // A negative loff_t (here -1) is EINVAL, before any access.
        let r = dispatch(
            &host,
            &Trap::new(Sysno::pread64, [3, 0, 3, (-1i64) as usize, 0, 0]),
        );
        assert_eq!(r, Err(EINVAL));
    }

    #[test]
    fn dup2_duplicates_onto_target() {
        let host = Host::default();
        let r = dispatch(&host, &Trap::new(Sysno::dup2, [3, 7, 0, 0, 0, 0]));
        assert_eq!(r, Ok(7));
        assert_eq!(*host.duped.borrow(), Some((3, 7, false)));
    }

    #[test]
    fn dup3_sets_cloexec() {
        let host = Host::default();
        let r = dispatch(
            &host,
            &Trap::new(Sysno::dup3, [3, 7, O_CLOEXEC as usize, 0, 0, 0]),
        );
        assert_eq!(r, Ok(7));
        assert_eq!(*host.duped.borrow(), Some((3, 7, true)));
    }

    #[test]
    fn dup3_rejects_equal_fds() {
        let host = Host::default();
        // dup3 with oldfd == newfd is EINVAL, unlike the dup2 no-op.
        let r = dispatch(&host, &Trap::new(Sysno::dup3, [5, 5, 0, 0, 0, 0]));
        assert_eq!(r, Err(EINVAL));
        assert!(host.duped.borrow().is_none());
    }

    #[test]
    fn dup3_rejects_unknown_flags() {
        let host = Host::default();
        let r = dispatch(&host, &Trap::new(Sysno::dup3, [3, 7, 0x1, 0, 0, 0]));
        assert_eq!(r, Err(EINVAL));
        assert!(host.duped.borrow().is_none());
    }

    #[test]
    fn uname_packs_utsname_fields() {
        let host = Host::default();
        // Pre-fill with 0xFF to prove the domain writes NUL padding, not garbage.
        *host.umem.borrow_mut() = vec![0xFFu8; 6 * 65];
        let r = dispatch(&host, &Trap::new(Sysno::uname, [0, 0, 0, 0, 0, 0]));
        assert_eq!(r, Ok(0));
        let mem = host.umem.borrow();
        // Field 0 (sysname) is "Linux", NUL-padded within its 65-byte slot.
        assert_eq!(&mem[0..5], b"Linux");
        assert_eq!(mem[5], 0);
        // Field 4 (machine) sits at offset 4*65 and reads "riscv64".
        assert_eq!(&mem[4 * 65..4 * 65 + 7], b"riscv64");
        assert_eq!(mem[4 * 65 + 7], 0);
    }

    #[test]
    fn fsync_and_fdatasync_distinguish_datasync() {
        let host = Host::default();
        assert_eq!(
            dispatch(&host, &Trap::new(Sysno::fsync, [3, 0, 0, 0, 0, 0])),
            Ok(0)
        );
        assert_eq!(*host.synced.borrow(), Some(false));
        assert_eq!(
            dispatch(&host, &Trap::new(Sysno::fdatasync, [3, 0, 0, 0, 0, 0])),
            Ok(0)
        );
        assert_eq!(*host.synced.borrow(), Some(true));
    }

    #[test]
    fn ftruncate_grows_and_shrinks() {
        let host = Host::default();
        *host.file.borrow_mut() = vec![1, 2, 3, 4];
        // Grow to 6: the new tail is zero-filled.
        assert_eq!(
            dispatch(&host, &Trap::new(Sysno::ftruncate, [3, 6, 0, 0, 0, 0])),
            Ok(0)
        );
        assert_eq!(&*host.file.borrow(), &[1, 2, 3, 4, 0, 0]);
        // Shrink to 2.
        assert_eq!(
            dispatch(&host, &Trap::new(Sysno::ftruncate, [3, 2, 0, 0, 0, 0])),
            Ok(0)
        );
        assert_eq!(&*host.file.borrow(), &[1, 2]);
    }

    #[test]
    fn ftruncate_rejects_negative_length() {
        let host = Host::default();
        let r = dispatch(
            &host,
            &Trap::new(Sysno::ftruncate, [3, (-1i64) as usize, 0, 0, 0, 0]),
        );
        assert_eq!(r, Err(EINVAL));
    }

    #[test]
    fn identity_getters_project_from_the_triple() {
        let host = Host::default();
        assert_eq!(dispatch(&host, &Trap::new(Sysno::getuid, [0; 6])), Ok(1000));
        assert_eq!(
            dispatch(&host, &Trap::new(Sysno::geteuid, [0; 6])),
            Ok(1000)
        );
        assert_eq!(dispatch(&host, &Trap::new(Sysno::getgid, [0; 6])), Ok(1000));
        assert_eq!(
            dispatch(&host, &Trap::new(Sysno::getegid, [0; 6])),
            Ok(1000)
        );
    }

    #[test]
    fn getresuid_writes_the_triple() {
        let host = Host::default();
        *host.umem.borrow_mut() = vec![0u8; 32];
        // ruid at 0, euid at 8, suid at 16, each a 4-byte id.
        let r = dispatch(&host, &Trap::new(Sysno::getresuid, [0, 8, 16, 0, 0, 0]));
        assert_eq!(r, Ok(0));
        let mem = host.umem.borrow();
        assert_eq!(u32::from_le_bytes(mem[0..4].try_into().unwrap()), 1000);
        assert_eq!(u32::from_le_bytes(mem[8..12].try_into().unwrap()), 1000);
        assert_eq!(u32::from_le_bytes(mem[16..20].try_into().unwrap()), 0);
    }

    #[test]
    fn getresuid_faults_on_bad_pointer() {
        let host = Host::default();
        *host.umem.borrow_mut() = vec![0u8; 8];
        // The saved-uid pointer is past the end of user memory.
        let r = dispatch(&host, &Trap::new(Sysno::getresuid, [0, 4, 999, 0, 0, 0]));
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
    fn clock_getres_reports_nanosecond_resolution() {
        let host = Host::default();
        *host.umem.borrow_mut() = vec![0u8; 32];
        // res at a non-null user address (address 0 is NULL per the ABI).
        let r = dispatch(
            &host,
            &Trap::new(
                Sysno::clock_getres,
                [CLOCK_MONOTONIC as usize, 8, 0, 0, 0, 0],
            ),
        );
        assert_eq!(r, Ok(0));
        let mem = host.umem.borrow();
        assert_eq!(i64::from_le_bytes(mem[8..16].try_into().unwrap()), 0);
        assert_eq!(i64::from_le_bytes(mem[16..24].try_into().unwrap()), 1);
    }

    #[test]
    fn clock_getres_allows_null_res() {
        let host = Host::default();
        // A null res pointer still validates the clock id and returns 0.
        let r = dispatch(
            &host,
            &Trap::new(
                Sysno::clock_getres,
                [CLOCK_REALTIME as usize, 0, 0, 0, 0, 0],
            ),
        );
        assert_eq!(r, Ok(0));
    }

    #[test]
    fn clock_getres_rejects_unknown_clock() {
        let host = Host::default();
        assert_eq!(
            dispatch(&host, &Trap::new(Sysno::clock_getres, [99, 0, 0, 0, 0, 0])),
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
    fn rt_sigprocmask_moves_the_mask() {
        let host = Host::default();
        *host.mask.borrow_mut() = 0b0100;
        // Non-zero user addresses: address 0 is NULL, meaning "no set/old".
        *host.umem.borrow_mut() = vec![0u8; 24];
        host.umem.borrow_mut()[8..16].copy_from_slice(&0b1010u64.to_le_bytes());
        // SIG_SETMASK=2, new at uaddr 8, old written to uaddr 16.
        let r = dispatch(
            &host,
            &Trap::new(Sysno::rt_sigprocmask, [2, 8, 16, SIGSET_SIZE, 0, 0]),
        );
        assert_eq!(r, Ok(0));
        let old = u64::from_le_bytes(host.umem.borrow()[16..24].try_into().unwrap());
        assert_eq!(old, 0b0100);
        assert_eq!(*host.mask.borrow(), 0b1010);
    }

    #[test]
    fn rt_sigprocmask_rejects_bad_sigsetsize() {
        let host = Host::default();
        assert_eq!(
            dispatch(&host, &Trap::new(Sysno::rt_sigprocmask, [2, 0, 0, 4, 0, 0])),
            Err(EINVAL)
        );
    }

    #[test]
    fn getrandom_fills_user_memory() {
        let host = Host::default();
        *host.umem.borrow_mut() = vec![0u8; 5];
        let r = dispatch(&host, &Trap::new(Sysno::getrandom, [0, 5, 0, 0, 0, 0]));
        assert_eq!(r, Ok(5));
        assert_eq!(&*host.umem.borrow(), &[0xAB; 5]);
    }

    #[test]
    fn kill_routes_to_signals() {
        let host = Host::default();
        assert_eq!(
            dispatch(&host, &Trap::new(Sysno::kill, [1234, 9, 0, 0, 0, 0])),
            Ok(0)
        );
        assert_eq!(*host.killed.borrow(), Some((1234, 9)));
    }

    #[test]
    fn encode_follows_linux_convention() {
        assert_eq!(encode(Ok(16)), 16);
        assert_eq!(encode(Err(ENOSYS)), (-(ENOSYS as isize)) as usize);
    }
}
