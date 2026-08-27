//! Linux personality for ArceOS/StarryOS.
//!
//! StarryOS is natively a Linux ABI, but its syscall table is woven into the
//! kernel. This crate re-expresses that ABI through dependency inversion: the
//! syscall logic here depends only on the [`ops`] ports plus [`ax_binfmt`],
//! never on `axtask`/`axfs`/`axmm`. It implements every syscall itself - reading
//! and validating arguments, copying user memory through the [`ops::Platform`]
//! port, and driving the [`ops::Files`]/[`ops::Tasks`]/[`ops::Mem`] services -
//! and never forwards a syscall to the host (the zero-passthrough rule gVisor's
//! Sentry follows). A hosting OS registers one [`ops::Host`] over its
//! concrete managers, so the crate stays kernel-runtime-free and unit-testable
//! with mock ports, and any ArceOS-derived OS can reuse the Linux personality.
//!
//! `dispatch` takes the host by reference so its logic is testable; the kernel
//! binds the registered host to a parameter-less entry at integration time.

#![cfg_attr(not(test), no_std)]

#[cfg(not(any(
    feature = "fs",
    feature = "mm",
    feature = "task",
    feature = "signal",
    feature = "time",
    feature = "system",
    feature = "creds"
)))]
compile_error!("ax-abi-linux needs at least one syscall family enabled");

pub use ax_abi_port as ops;
use ax_binfmt::{Abi, Dispatch, TrapEnv};
use ax_crate_interface::call_interface;
use ops::{ENOSYS, Host, SysResult};
use syscalls::Sysno;

/// `O_CLOEXEC` (generic ABI, all four targets) - the only flag `dup3` accepts.
#[cfg(feature = "fs")]
const O_CLOEXEC: i32 = 0o2000000;
/// One `new_utsname` field width (arch-independent), and the packed struct length.
#[cfg(feature = "system")]
const UTS_FIELD: usize = 65;
#[cfg(feature = "system")]
const UTS_LEN: usize = 6 * UTS_FIELD;
/// Nanoseconds per second, for packing `timespec`/`timeval`.
#[cfg(feature = "time")]
const NS_PER_SEC: u64 = 1_000_000_000;
/// `CLOCK_REALTIME` - wall-clock time since the Unix epoch.
#[cfg(feature = "time")]
const CLOCK_REALTIME: i32 = 0;
/// `CLOCK_MONOTONIC` - time since an arbitrary fixed point.
#[cfg(feature = "time")]
const CLOCK_MONOTONIC: i32 = 1;
/// The kernel `sigset_t` the syscall ABI expects is exactly 8 bytes.
#[cfg(feature = "signal")]
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
    pub fn handle_syscall(host: &dyn Host, uctx: &mut dyn TrapEnv) {
        let result = dispatch(host, uctx);
        uctx.set_result(encode(result));
    }

    /// The parameter-less entry the kernel trap path calls: it resolves the
    /// registered host through [`CurrentHost`], then services the syscall. The
    /// kernel binds the host with `#[impl_interface]`.
    pub fn handle_trapped_syscall(uctx: &mut dyn TrapEnv) {
        Self::handle_syscall(call_interface!(ax_abi_port::CurrentHost::current), uctx);
    }

    /// Service a trapped syscall domain-first: write the result and report
    /// [`Dispatch::Handled`] when it is one this domain owns, else
    /// [`Dispatch::Passthrough`] with `uctx` untouched. This is the seam a
    /// monolithic kernel uses during incremental migration - it tries the domain,
    /// then falls back to its own remaining table for syscalls not yet moved.
    pub fn try_handle_syscall(host: &dyn Host, uctx: &mut dyn TrapEnv) -> Dispatch {
        match route(host, uctx) {
            Some(result) => {
                uctx.set_result(encode(result));
                Dispatch::Handled
            }
            None => Dispatch::Passthrough,
        }
    }

    /// The parameter-less domain-first entry: resolves the registered host, then
    /// [`try_handle_syscall`](Self::try_handle_syscall).
    pub fn try_handle_trapped_syscall(uctx: &mut dyn TrapEnv) -> Dispatch {
        Self::try_handle_syscall(call_interface!(ax_abi_port::CurrentHost::current), uctx)
    }

    /// Route a trapped syscall against `host` without touching the trap frame:
    /// `Some(outcome)` when this domain owns the call, `None` to leave it to the
    /// caller. A kernel that still carries its own table uses this, so that its
    /// own epilogue - signal-redirect check, tracing, retval encoding - keeps
    /// running for migrated and unmigrated calls alike.
    pub fn route_syscall(host: &dyn Host, uctx: &dyn TrapEnv) -> Option<SysResult> {
        route(host, uctx)
    }

    /// The parameter-less form of [`route_syscall`](Self::route_syscall).
    pub fn route_trapped_syscall(uctx: &dyn TrapEnv) -> Option<SysResult> {
        route(call_interface!(ax_abi_port::CurrentHost::current), uctx)
    }
}

/// Route one syscall to its handler, or `None` when the trapped number is not one
/// this domain owns, so a hosting kernel can fall back to its own table during
/// migration. Free of the trap-frame write, so it unit-tests with mock ports.
fn route(host: &dyn Host, uctx: &dyn TrapEnv) -> Option<SysResult> {
    let sysno = Sysno::new(uctx.nr())?;
    let arg = |i| uctx.arg(i);
    Some(match sysno {
        // fd I/O - the domain copies user memory itself, then drives Files.
        #[cfg(feature = "fs")]
        Sysno::read => host.files()?.read(arg(0) as i32, arg(1), arg(2)),
        #[cfg(feature = "fs")]
        Sysno::write => host.files()?.write(arg(0) as i32, arg(1), arg(2)),
        #[cfg(feature = "fs")]
        Sysno::close => host.files()?.close(arg(0) as i32),
        #[cfg(feature = "fs")]
        Sysno::dup => host.files()?.dup(arg(0) as i32),
        // Only the x86_64 table carries dup2; the generic ABI has dup3 alone.
        #[cfg(all(feature = "fs", target_arch = "x86_64"))]
        Sysno::dup2 => sys_dup2(host.files()?, arg(0) as i32, arg(1) as i32),
        #[cfg(feature = "fs")]
        Sysno::dup3 => sys_dup3(host.files()?, arg(0) as i32, arg(1) as i32, arg(2) as i32),
        #[cfg(feature = "fs")]
        Sysno::lseek => sys_lseek(host.files()?, arg(0) as i32, arg(1) as isize, arg(2) as i32),
        #[cfg(feature = "fs")]
        Sysno::pread64 => sys_pread64(host.files()?, arg(0) as i32, arg(1), arg(2), arg(3) as i64),
        #[cfg(feature = "fs")]
        Sysno::pwrite64 => {
            sys_pwrite64(host.files()?, arg(0) as i32, arg(1), arg(2), arg(3) as i64)
        }
        #[cfg(feature = "fs")]
        Sysno::fsync => host.files()?.fsync(arg(0) as i32, false),
        #[cfg(feature = "fs")]
        Sysno::fdatasync => host.files()?.fsync(arg(0) as i32, true),
        #[cfg(feature = "fs")]
        Sysno::ftruncate => sys_ftruncate(host.files()?, arg(0) as i32, arg(1) as i64),

        // Process and thread control.
        #[cfg(feature = "task")]
        Sysno::getpid => Ok(host.tasks()?.getpid() as isize),
        #[cfg(feature = "task")]
        Sysno::getppid => Ok(host.tasks()?.getppid() as isize),
        #[cfg(feature = "task")]
        Sysno::gettid => Ok(host.tasks()?.gettid() as isize),
        #[cfg(feature = "task")]
        Sysno::set_tid_address => host.tasks()?.set_tid_address(arg(0)),
        #[cfg(feature = "task")]
        Sysno::sched_yield => host.tasks()?.sched_yield(),
        // The wait-status encoding is the ABI's, so the domain applies it.
        #[cfg(feature = "task")]
        Sysno::exit => host.tasks()?.exit((arg(0) as i32) << 8),
        #[cfg(feature = "task")]
        Sysno::exit_group => host.tasks()?.exit_group((arg(0) as i32) << 8),

        // Address space.
        #[cfg(feature = "mm")]
        Sysno::brk => sys_brk(host.mem()?, arg(0)),
        #[cfg(feature = "mm")]
        Sysno::mmap => host.mem()?.mmap(
            arg(0),
            arg(1),
            arg(2) as i32,
            arg(3) as i32,
            arg(4) as i32,
            arg(5),
        ),
        #[cfg(feature = "mm")]
        Sysno::munmap => sys_munmap(host.mem()?, arg(0), arg(1)),
        #[cfg(feature = "mm")]
        Sysno::mprotect => host.mem()?.mprotect(arg(0), arg(1), arg(2) as i32),
        #[cfg(feature = "mm")]
        Sysno::madvise => host.mem()?.madvise(arg(0), arg(1), arg(2) as i32),
        #[cfg(feature = "mm")]
        Sysno::msync => sys_msync(host.mem()?, arg(0), arg(1), arg(2) as i32),

        // Clocks - the domain packs the timespec/timeval itself.
        #[cfg(feature = "time")]
        Sysno::clock_gettime => {
            sys_clock_gettime(host.platform(), host.clock()?, arg(0) as i32, arg(1))?
        }
        #[cfg(feature = "time")]
        Sysno::clock_getres => sys_clock_getres(host.platform(), arg(0) as i32, arg(1))?,
        #[cfg(feature = "time")]
        Sysno::gettimeofday => sys_gettimeofday(host.platform(), host.clock()?, arg(0), arg(1))?,

        // Signals - the domain moves the sigset; the port carries a u64 mask.
        #[cfg(feature = "signal")]
        Sysno::kill => host.signals()?.kill(arg(0) as i32, arg(1) as i32),
        #[cfg(feature = "signal")]
        Sysno::tgkill => host
            .signals()?
            .tgkill(arg(0) as i32, arg(1) as i32, arg(2) as i32),
        #[cfg(feature = "signal")]
        Sysno::rt_sigprocmask => sys_rt_sigprocmask(
            host.platform(),
            host.signals()?,
            arg(0) as i32,
            arg(1),
            arg(2),
            arg(3),
        ),

        // System identity - the domain packs the utsname struct itself.
        #[cfg(feature = "system")]
        Sysno::uname => sys_uname(host.platform(), host.system()?, arg(0)),

        // Credentials - identity getters project from the (real, eff, saved) triple.
        #[cfg(feature = "creds")]
        Sysno::getuid => Ok(host.creds()?.uids().0 as isize),
        #[cfg(feature = "creds")]
        Sysno::geteuid => Ok(host.creds()?.uids().1 as isize),
        #[cfg(feature = "creds")]
        Sysno::getgid => Ok(host.creds()?.gids().0 as isize),
        #[cfg(feature = "creds")]
        Sysno::getegid => Ok(host.creds()?.gids().1 as isize),
        #[cfg(feature = "creds")]
        Sysno::getresuid => sys_getres(
            host.platform(),
            host.creds()?.uids(),
            arg(0),
            arg(1),
            arg(2),
        ),
        #[cfg(feature = "creds")]
        Sysno::getresgid => sys_getres(
            host.platform(),
            host.creds()?.gids(),
            arg(0),
            arg(1),
            arg(2),
        ),

        _ => return None,
    })
}

/// Collapse an unowned syscall to `ENOSYS` - for a domain that is the sole
/// handler, and for the unit tests.
fn dispatch(host: &dyn Host, uctx: &dyn TrapEnv) -> SysResult {
    route(host, uctx).unwrap_or(Err(ENOSYS))
}

/// `pread64(fd, ubuf, len, offset)`: positioned read of the user range. A
/// negative offset is `EINVAL`.
#[cfg(feature = "fs")]
fn sys_pread64(files: &dyn ops::Files, fd: i32, ubuf: usize, len: usize, offset: i64) -> SysResult {
    if offset < 0 {
        return Err(ops::EINVAL);
    }
    files.pread(fd, ubuf, len, offset as u64)
}

/// `pwrite64(fd, ubuf, len, offset)`: positioned write of the user range.
#[cfg(feature = "fs")]
fn sys_pwrite64(
    files: &dyn ops::Files,
    fd: i32,
    ubuf: usize,
    len: usize,
    offset: i64,
) -> SysResult {
    if offset < 0 {
        return Err(ops::EINVAL);
    }
    files.pwrite(fd, ubuf, len, offset as u64)
}

/// `munmap(addr, len)`: a zero length is `EINVAL`, which is the ABI's rule
/// rather than the host's.
#[cfg(feature = "mm")]
fn sys_munmap(mem: &dyn ops::Mem, addr: usize, len: usize) -> SysResult {
    if len == 0 {
        return Err(ops::EINVAL);
    }
    mem.unmap(addr, len)
}

/// `brk(addr)`: query with zero, otherwise move the break. Linux answers a
/// refused move with the break that still stands, not with an error.
#[cfg(feature = "mm")]
fn sys_brk(mem: &dyn ops::Mem, addr: usize) -> SysResult {
    let current = mem.brk() as isize;
    if addr == 0 {
        return Ok(current);
    }
    Ok(mem.set_brk(addr).map_or(current, |_| addr as isize))
}

/// `ftruncate(fd, len)`: resize `fd`. A negative length is `EINVAL`; the port
/// zero-extends the file on growth.
#[cfg(feature = "fs")]
fn sys_ftruncate(files: &dyn ops::Files, fd: i32, len: i64) -> SysResult {
    if len < 0 {
        return Err(ops::EINVAL);
    }
    files.ftruncate(fd, len as u64)
}

/// `lseek(fd, offset, whence)`: translate the ABI's `whence` and refuse a
/// negative absolute offset, then seek through the port.
#[cfg(feature = "fs")]
fn sys_lseek(files: &dyn ops::Files, fd: i32, offset: isize, whence: i32) -> SysResult {
    let from = match whence {
        0 if offset < 0 => return Err(ops::EINVAL),
        0 => ops::SeekFrom::Start,
        1 => ops::SeekFrom::Current,
        2 => ops::SeekFrom::End,
        _ => return Err(ops::EINVAL),
    };
    files.seek(fd, offset, from)
}

/// `dup2(oldfd, newfd)`: duplicating an fd onto itself is a no-op that still
/// checks the fd, which is where it parts from `dup3`.
#[cfg(feature = "fs")]
fn sys_dup2(files: &dyn ops::Files, oldfd: i32, newfd: i32) -> SysResult {
    if oldfd == newfd {
        files.validate(oldfd)?;
        return Ok(newfd as isize);
    }
    files.dup_onto(oldfd, newfd, false)
}

/// `dup3(oldfd, newfd, flags)`: duplicate onto a specific fd like `dup2`, but
/// equal fds are `EINVAL` (not the `dup2` no-op) and the only accepted flag is
/// `O_CLOEXEC`. The port performs the fd-table replacement.
#[cfg(feature = "fs")]
fn sys_dup3(files: &dyn ops::Files, oldfd: i32, newfd: i32, flags: i32) -> SysResult {
    if oldfd == newfd || (flags & !O_CLOEXEC) != 0 {
        return Err(ops::EINVAL);
    }
    files.dup_onto(oldfd, newfd, flags & O_CLOEXEC != 0)
}

/// `msync(addr, len, flags)`: reject unknown flag bits and the mutually exclusive
/// `MS_SYNC`+`MS_ASYNC` pair, then flush through the Mem port.
#[cfg(feature = "mm")]
fn sys_msync(mem: &dyn ops::Mem, addr: usize, len: usize, flags: i32) -> SysResult {
    const MS_ASYNC: i32 = 1;
    const MS_INVALIDATE: i32 = 2;
    const MS_SYNC: i32 = 4;
    let known = MS_ASYNC | MS_INVALIDATE | MS_SYNC;
    if flags & !known != 0 || flags & (MS_ASYNC | MS_SYNC) == (MS_ASYNC | MS_SYNC) {
        return Err(ops::EINVAL);
    }
    mem.msync(addr, len, flags)
}

/// `uname(buf)`: report system identity. The domain packs the six `utsname`
/// fields, each NUL-padded to 65 bytes, and writes the 390-byte struct to user.
#[cfg(feature = "system")]
fn sys_uname(platform: &dyn ops::Platform, system: &dyn ops::System, buf: usize) -> SysResult {
    let mut out = [0u8; UTS_LEN];
    system.uname(&mut |field, value| {
        let slot = match field {
            ops::UtsField::SysName => 0,
            ops::UtsField::NodeName => 1,
            ops::UtsField::Release => 2,
            ops::UtsField::Version => 3,
            ops::UtsField::Machine => 4,
            ops::UtsField::DomainName => 5,
        } * UTS_FIELD;
        let src = value.as_bytes();
        let n = src.len().min(UTS_FIELD - 1); // keep the trailing NUL
        out[slot..slot + n].copy_from_slice(&src[..n]);
    });
    platform.write_user(buf, &out)?;
    Ok(0)
}

/// `getresuid`/`getresgid`: write a `(real, effective, saved)` id triple to three
/// user pointers, each a 32-bit id.
#[cfg(feature = "creds")]
fn sys_getres(
    platform: &dyn ops::Platform,
    ids: (u32, u32, u32),
    real: usize,
    eff: usize,
    saved: usize,
) -> SysResult {
    platform.write_user(real, &ids.0.to_le_bytes())?;
    platform.write_user(eff, &ids.1.to_le_bytes())?;
    platform.write_user(saved, &ids.2.to_le_bytes())?;
    Ok(0)
}

/// `clock_gettime(clockid, ts)`: pack a `timespec` for the clocks this domain
/// reads through the port; any other clock goes back to the caller's table.
#[cfg(feature = "time")]
fn sys_clock_gettime(
    platform: &dyn ops::Platform,
    clock: &dyn ops::Clock,
    clockid: i32,
    ts: usize,
) -> Option<SysResult> {
    let ns = match clockid {
        CLOCK_REALTIME => clock.wall_ns(),
        CLOCK_MONOTONIC => clock.monotonic_ns(),
        _ => return None,
    };
    let packed = pack_time_pair((ns / NS_PER_SEC) as i64, (ns % NS_PER_SEC) as i64);
    Some(platform.write_user(ts, &packed).map(|_| 0))
}

/// `clock_getres(clockid, res)`: both clocks this domain serves are
/// nanosecond-resolution; a null `res` is a valid clock-liveness query.
#[cfg(feature = "time")]
fn sys_clock_getres(platform: &dyn ops::Platform, clockid: i32, res: usize) -> Option<SysResult> {
    if !matches!(clockid, CLOCK_REALTIME | CLOCK_MONOTONIC) {
        return None;
    }
    if res == 0 {
        return Some(Ok(0));
    }
    Some(platform.write_user(res, &pack_time_pair(0, 1)).map(|_| 0))
}

/// `gettimeofday(tv, tz)`: pack the wall clock as a `timeval`. The obsolete
/// timezone argument is not this domain's to fill, so a caller that passes one
/// goes back to the table that still implements it.
#[cfg(feature = "time")]
fn sys_gettimeofday(
    platform: &dyn ops::Platform,
    clock: &dyn ops::Clock,
    tv: usize,
    tz: usize,
) -> Option<SysResult> {
    if tz != 0 {
        return None;
    }
    if tv == 0 {
        return Some(Ok(0));
    }
    let ns = clock.wall_ns();
    let packed = pack_time_pair((ns / NS_PER_SEC) as i64, (ns % NS_PER_SEC / 1_000) as i64);
    Some(platform.write_user(tv, &packed).map(|_| 0))
}

/// `rt_sigprocmask(how, set, old, sigsetsize)`: move the user `sigset_t`, which
/// the ABI fixes at eight bytes.
///
/// The previous mask is reported before the new one is read, which is the order
/// a caller passing both pointers observes today.
#[cfg(feature = "signal")]
fn sys_rt_sigprocmask(
    platform: &dyn ops::Platform,
    signals: &dyn ops::Signals,
    how: i32,
    set: usize,
    old: usize,
    sigsetsize: usize,
) -> SysResult {
    if sigsetsize != SIGSET_SIZE {
        return Err(ops::EINVAL);
    }
    let previous = signals.sigprocmask(how, None)?;
    if old != 0 {
        platform.write_user(old, &previous.to_le_bytes())?;
    }
    if set != 0 {
        if !(0..=2).contains(&how) {
            return Err(ops::EINVAL);
        }
        let mut buf = [0u8; SIGSET_SIZE];
        platform.read_user(set, &mut buf)?;
        signals.sigprocmask(how, Some(u64::from_le_bytes(buf)))?;
    }
    Ok(0)
}

/// Pack two 64-bit little-endian words - the shared layout of `timespec` and
/// `timeval` on 64-bit Linux.
#[cfg(feature = "time")]
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
        ops::{Clock, Creds, CurrentHost, EFAULT, Files, Mem, Platform, Signals, System, Tasks},
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
        fn exit(&self, _c: i32) -> SysResult {
            Ok(0)
        }
        fn exit_group(&self, _c: i32) -> SysResult {
            Ok(0)
        }
    }
    impl Files for FixedHost {
        fn read(&self, _fd: i32, _u: usize, _len: usize) -> SysResult {
            Ok(0)
        }
        fn write(&self, _fd: i32, _u: usize, len: usize) -> SysResult {
            Ok(len as isize)
        }
        fn close(&self, _fd: i32) -> SysResult {
            Ok(0)
        }
        fn dup(&self, _fd: i32) -> SysResult {
            Ok(0)
        }
        fn seek(&self, _fd: i32, o: isize, _from: ops::SeekFrom) -> SysResult {
            Ok(o)
        }
        fn validate(&self, _fd: i32) -> SysResult {
            Ok(0)
        }
        fn pread(&self, _fd: i32, _u: usize, _len: usize, _o: u64) -> SysResult {
            Ok(0)
        }
        fn pwrite(&self, _fd: i32, _u: usize, len: usize, _o: u64) -> SysResult {
            Ok(len as isize)
        }
        fn dup_onto(&self, _oldfd: i32, newfd: i32, _cloexec: bool) -> SysResult {
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
        fn brk(&self) -> usize {
            0
        }
        fn set_brk(&self, _addr: usize) -> SysResult {
            Ok(0)
        }
        fn mmap(&self, _a: usize, _l: usize, _p: i32, _f: i32, _fd: i32, _o: usize) -> SysResult {
            Ok(0)
        }
        fn unmap(&self, _a: usize, _l: usize) -> SysResult {
            Ok(0)
        }
        fn mprotect(&self, _a: usize, _l: usize, _p: i32) -> SysResult {
            Ok(0)
        }
        fn madvise(&self, _a: usize, _l: usize, _adv: i32) -> SysResult {
            Ok(0)
        }
        fn msync(&self, _a: usize, _l: usize, _f: i32) -> SysResult {
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
    impl System for FixedHost {
        fn uname(&self, put: &mut dyn FnMut(ops::UtsField, &str)) {
            put(ops::UtsField::SysName, "Linux");
            put(ops::UtsField::NodeName, "starry");
            put(ops::UtsField::Release, "6.0.0");
            put(ops::UtsField::Version, "#1");
            put(ops::UtsField::Machine, "x86_64");
            put(ops::UtsField::DomainName, "(none)");
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
    impl Host for FixedHost {
        fn platform(&self) -> &dyn Platform {
            self
        }
        fn tasks(&self) -> Option<&dyn Tasks> {
            Some(self)
        }
        fn files(&self) -> Option<&dyn Files> {
            Some(self)
        }
        fn mem(&self) -> Option<&dyn Mem> {
            Some(self)
        }
        fn signals(&self) -> Option<&dyn Signals> {
            Some(self)
        }
        fn clock(&self) -> Option<&dyn Clock> {
            Some(self)
        }
        fn system(&self) -> Option<&dyn System> {
            Some(self)
        }
        fn creds(&self) -> Option<&dyn Creds> {
            Some(self)
        }
    }

    // Bind the global CurrentHost port to the fixed host, as the kernel would.
    struct Binding;
    #[ax_crate_interface::impl_interface]
    impl CurrentHost for Binding {
        fn current() -> &'static dyn Host {
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
    struct Mock {
        umem: RefCell<Vec<u8>>,
        written: RefCell<Vec<u8>>,
        to_read: RefCell<Vec<u8>>,
        file: RefCell<Vec<u8>>,
        slept: RefCell<u64>,
        mask: RefCell<u64>,
        killed: RefCell<Option<(i32, i32)>>,
        duped: RefCell<Option<(i32, i32, bool)>>,
        exited: RefCell<Option<(i32, bool)>>,
        synced: RefCell<Option<bool>>,
        heap: RefCell<usize>,
    }
    // Single-threaded test only; the ports need Sync for the real 'static host.
    unsafe impl Sync for Mock {}

    impl Platform for Mock {
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
    impl Files for Mock {
        fn read(&self, _fd: i32, uaddr: usize, len: usize) -> SysResult {
            let bytes: Vec<u8> = {
                let mut src = self.to_read.borrow_mut();
                let n = len.min(src.len());
                src.drain(..n).collect()
            };
            self.write_user(uaddr, &bytes)?;
            Ok(bytes.len() as isize)
        }
        fn write(&self, _fd: i32, uaddr: usize, len: usize) -> SysResult {
            let mut buf = vec![0u8; len];
            self.read_user(uaddr, &mut buf)?;
            self.written.borrow_mut().extend_from_slice(&buf);
            Ok(len as isize)
        }
        fn close(&self, _fd: i32) -> SysResult {
            Ok(0)
        }
        fn dup(&self, _fd: i32) -> SysResult {
            Ok(9)
        }
        fn seek(&self, _fd: i32, offset: isize, _from: ops::SeekFrom) -> SysResult {
            Ok(offset)
        }
        fn validate(&self, fd: i32) -> SysResult {
            if fd < 0 { Err(ops::EBADF) } else { Ok(0) }
        }
        fn pread(&self, _fd: i32, uaddr: usize, len: usize, offset: u64) -> SysResult {
            let bytes: Vec<u8> = {
                let file = self.file.borrow();
                let start = (offset as usize).min(file.len());
                file[start..(start + len).min(file.len())].to_vec()
            };
            self.write_user(uaddr, &bytes)?;
            Ok(bytes.len() as isize)
        }
        fn pwrite(&self, _fd: i32, uaddr: usize, len: usize, offset: u64) -> SysResult {
            let mut buf = vec![0u8; len];
            self.read_user(uaddr, &mut buf)?;
            let mut file = self.file.borrow_mut();
            let end = offset as usize + len;
            if file.len() < end {
                file.resize(end, 0);
            }
            file[offset as usize..end].copy_from_slice(&buf);
            Ok(len as isize)
        }
        fn dup_onto(&self, oldfd: i32, newfd: i32, cloexec: bool) -> SysResult {
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
    impl Tasks for Mock {
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
        fn exit(&self, code: i32) -> SysResult {
            *self.exited.borrow_mut() = Some((code, false));
            Ok(0)
        }
        fn exit_group(&self, code: i32) -> SysResult {
            *self.exited.borrow_mut() = Some((code, true));
            Ok(0)
        }
    }
    impl Mem for Mock {
        fn brk(&self) -> usize {
            *self.heap.borrow()
        }
        fn set_brk(&self, addr: usize) -> SysResult {
            // The mock stands in for a host that refuses to go below its base.
            if addr < 0x1000 {
                return Err(ops::EINVAL);
            }
            *self.heap.borrow_mut() = addr;
            Ok(0)
        }
        fn mmap(&self, _a: usize, _l: usize, _p: i32, _f: i32, _fd: i32, _o: usize) -> SysResult {
            Ok(0x1000)
        }
        fn unmap(&self, _a: usize, _l: usize) -> SysResult {
            Ok(0)
        }
        fn mprotect(&self, _a: usize, _l: usize, _p: i32) -> SysResult {
            Ok(0)
        }
        fn madvise(&self, _a: usize, _l: usize, advice: i32) -> SysResult {
            Ok(advice as isize) // echo so the test sees the delegated advice
        }
        fn msync(&self, _a: usize, _l: usize, flags: i32) -> SysResult {
            Ok(flags as isize)
        }
    }
    impl Signals for Mock {
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
    impl System for Mock {
        fn uname(&self, put: &mut dyn FnMut(ops::UtsField, &str)) {
            put(ops::UtsField::SysName, "Linux");
            put(ops::UtsField::NodeName, "node");
            put(ops::UtsField::Release, "rel");
            put(ops::UtsField::Version, "ver");
            put(ops::UtsField::Machine, "riscv64");
            put(ops::UtsField::DomainName, "(none)");
        }
    }
    impl Creds for Mock {
        fn uids(&self) -> (u32, u32, u32) {
            (1000, 1000, 0) // real, effective, saved
        }
        fn gids(&self) -> (u32, u32, u32) {
            (1000, 1000, 0)
        }
    }
    impl Clock for Mock {
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
    impl Host for Mock {
        fn platform(&self) -> &dyn Platform {
            self
        }
        fn tasks(&self) -> Option<&dyn Tasks> {
            Some(self)
        }
        fn files(&self) -> Option<&dyn Files> {
            Some(self)
        }
        fn mem(&self) -> Option<&dyn Mem> {
            Some(self)
        }
        fn signals(&self) -> Option<&dyn Signals> {
            Some(self)
        }
        fn clock(&self) -> Option<&dyn Clock> {
            Some(self)
        }
        fn system(&self) -> Option<&dyn System> {
            Some(self)
        }
        fn creds(&self) -> Option<&dyn Creds> {
            Some(self)
        }
    }

    #[test]
    fn write_copies_from_user_then_drives_files() {
        let host = Mock::default();
        *host.umem.borrow_mut() = vec![b'h', b'i', b'!', 0, 0];
        // write(fd=1, ubuf=0, len=3): the domain copies "hi!" out of user memory
        // and hands it to Files - no passthrough.
        let r = dispatch(&host, &Trap::new(Sysno::write, [1, 0, 3, 0, 0, 0]));
        assert_eq!(r, Ok(3));
        assert_eq!(&*host.written.borrow(), b"hi!");
    }

    #[test]
    fn read_reads_files_then_copies_to_user() {
        let host = Mock::default();
        *host.umem.borrow_mut() = vec![0u8; 4];
        *host.to_read.borrow_mut() = vec![9, 8, 7];
        let r = dispatch(&host, &Trap::new(Sysno::read, [0, 0, 4, 0, 0, 0]));
        assert_eq!(r, Ok(3)); // short read at EOF
        assert_eq!(&host.umem.borrow()[..3], &[9, 8, 7]);
    }

    #[test]
    fn write_past_user_memory_faults() {
        let host = Mock::default();
        *host.umem.borrow_mut() = vec![1, 2];
        let r = dispatch(&host, &Trap::new(Sysno::write, [1, 0, 8, 0, 0, 0]));
        assert_eq!(r, Err(EFAULT));
    }

    #[test]
    fn pread_reads_at_offset() {
        let host = Mock::default();
        *host.file.borrow_mut() = vec![10, 11, 12, 13, 14, 15];
        *host.umem.borrow_mut() = vec![0u8; 4];
        // pread(fd=3, ubuf=0, len=3, offset=2) reads [12,13,14] at the offset.
        let r = dispatch(&host, &Trap::new(Sysno::pread64, [3, 0, 3, 2, 0, 0]));
        assert_eq!(r, Ok(3));
        assert_eq!(&host.umem.borrow()[..3], &[12, 13, 14]);
    }

    #[test]
    fn pwrite_writes_at_offset() {
        let host = Mock::default();
        *host.file.borrow_mut() = vec![0u8; 4];
        *host.umem.borrow_mut() = vec![b'X', b'Y'];
        // pwrite(fd=3, ubuf=0, len=2, offset=3) grows the file and writes at 3.
        let r = dispatch(&host, &Trap::new(Sysno::pwrite64, [3, 0, 2, 3, 0, 0]));
        assert_eq!(r, Ok(2));
        assert_eq!(&*host.file.borrow(), &[0, 0, 0, b'X', b'Y']);
    }

    #[test]
    fn pread_rejects_negative_offset() {
        let host = Mock::default();
        // A negative loff_t (here -1) is EINVAL, before any access.
        let r = dispatch(
            &host,
            &Trap::new(Sysno::pread64, [3, 0, 3, (-1i64) as usize, 0, 0]),
        );
        assert_eq!(r, Err(ops::EINVAL));
    }

    #[test]
    fn dup2_duplicates_onto_target() {
        let host = Mock::default();
        let r = dispatch(&host, &Trap::new(Sysno::dup2, [3, 7, 0, 0, 0, 0]));
        assert_eq!(r, Ok(7));
        assert_eq!(*host.duped.borrow(), Some((3, 7, false)));
    }

    #[test]
    fn dup2_onto_itself_is_a_checked_no_op() {
        let host = Mock::default();
        // Same fd: dup2 keeps it and reports it, where dup3 refuses.
        assert_eq!(
            dispatch(&host, &Trap::new(Sysno::dup2, [5, 5, 0, 0, 0, 0])),
            Ok(5)
        );
        assert!(host.duped.borrow().is_none());
        // A closed fd still fails the check.
        assert_eq!(
            dispatch(
                &host,
                &Trap::new(Sysno::dup2, [-1i32 as usize, -1i32 as usize, 0, 0, 0, 0])
            ),
            Err(ops::EBADF)
        );
    }

    #[test]
    fn dup3_sets_cloexec() {
        let host = Mock::default();
        let r = dispatch(
            &host,
            &Trap::new(Sysno::dup3, [3, 7, O_CLOEXEC as usize, 0, 0, 0]),
        );
        assert_eq!(r, Ok(7));
        assert_eq!(*host.duped.borrow(), Some((3, 7, true)));
    }

    #[test]
    fn dup3_rejects_equal_fds() {
        let host = Mock::default();
        // dup3 with oldfd == newfd is EINVAL, unlike the dup2 no-op.
        let r = dispatch(&host, &Trap::new(Sysno::dup3, [5, 5, 0, 0, 0, 0]));
        assert_eq!(r, Err(ops::EINVAL));
        assert!(host.duped.borrow().is_none());
    }

    #[test]
    fn dup3_rejects_unknown_flags() {
        let host = Mock::default();
        let r = dispatch(&host, &Trap::new(Sysno::dup3, [3, 7, 0x1, 0, 0, 0]));
        assert_eq!(r, Err(ops::EINVAL));
        assert!(host.duped.borrow().is_none());
    }

    #[test]
    fn uname_packs_utsname_fields() {
        let host = Mock::default();
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
        let host = Mock::default();
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
        let host = Mock::default();
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
        let host = Mock::default();
        let r = dispatch(
            &host,
            &Trap::new(Sysno::ftruncate, [3, (-1i64) as usize, 0, 0, 0, 0]),
        );
        assert_eq!(r, Err(ops::EINVAL));
    }

    #[test]
    fn identity_getters_project_from_the_triple() {
        let host = Mock::default();
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
        let host = Mock::default();
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
        let host = Mock::default();
        *host.umem.borrow_mut() = vec![0u8; 8];
        // The saved-uid pointer is past the end of user memory.
        let r = dispatch(&host, &Trap::new(Sysno::getresuid, [0, 4, 999, 0, 0, 0]));
        assert_eq!(r, Err(EFAULT));
    }

    #[test]
    fn madvise_delegates_known_advice() {
        let host = Mock::default();
        // MADV_DONTNEED (4) is known, so it reaches the Mem port (which echoes it).
        let r = dispatch(
            &host,
            &Trap::new(Sysno::madvise, [0x1000, 0x2000, 4, 0, 0, 0]),
        );
        assert_eq!(r, Ok(4));
    }

    #[test]
    fn msync_rejects_sync_and_async_together() {
        let host = Mock::default();
        // MS_ASYNC(1) | MS_SYNC(4) is a mutually exclusive combination.
        let r = dispatch(
            &host,
            &Trap::new(Sysno::msync, [0x1000, 0x1000, 5, 0, 0, 0]),
        );
        assert_eq!(r, Err(ops::EINVAL));
    }

    #[test]
    fn msync_delegates_valid_flags() {
        let host = Mock::default();
        // MS_SYNC(4) alone is valid and reaches the Mem port.
        let r = dispatch(
            &host,
            &Trap::new(Sysno::msync, [0x1000, 0x1000, 4, 0, 0, 0]),
        );
        assert_eq!(r, Ok(4));
    }

    #[test]
    fn routes_primitive_syscalls() {
        let host = Mock::default();
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

    // A host with nothing but the platform port: the parts a domain needs are
    // fitted, not assumed.
    struct BarePlatform;
    impl Platform for BarePlatform {
        fn read_user(&self, _u: usize, _o: &mut [u8]) -> SysResult {
            Ok(0)
        }
        fn write_user(&self, _u: usize, _d: &[u8]) -> SysResult {
            Ok(0)
        }
    }
    impl Host for BarePlatform {
        fn platform(&self) -> &dyn Platform {
            self
        }
    }

    #[test]
    fn a_syscall_needs_its_capability_fitted() {
        let bare = BarePlatform;
        // No file capability, so the domain does not claim the file syscalls and
        // the caller keeps whatever it does with an unclaimed call.
        assert!(route(&bare, &Trap::new(Sysno::read, [0, 0, 8, 0, 0, 0])).is_none());
        assert!(route(&bare, &Trap::new(Sysno::close, [3, 0, 0, 0, 0, 0])).is_none());
        // Nor the task, memory or credential ones.
        assert!(route(&bare, &Trap::new(Sysno::getpid, [0; 6])).is_none());
        assert!(route(&bare, &Trap::new(Sysno::brk, [0, 0, 0, 0, 0, 0])).is_none());
        assert!(route(&bare, &Trap::new(Sysno::getuid, [0; 6])).is_none());

        // The same domain, given a host that fits those parts, serves them.
        let full = Mock::default();
        assert_eq!(
            route(&full, &Trap::new(Sysno::getpid, [0; 6])),
            Some(Ok(42))
        );
    }

    #[test]
    fn brk_reports_the_standing_break_when_refused() {
        let host = Mock::default();
        *host.heap.borrow_mut() = 0x4000;
        // A query leaves it alone.
        assert_eq!(
            dispatch(&host, &Trap::new(Sysno::brk, [0, 0, 0, 0, 0, 0])),
            Ok(0x4000)
        );
        // A move the host takes reports the new break.
        assert_eq!(
            dispatch(&host, &Trap::new(Sysno::brk, [0x8000, 0, 0, 0, 0, 0])),
            Ok(0x8000)
        );
        // A move it refuses reports the break that still stands, not an error.
        assert_eq!(
            dispatch(&host, &Trap::new(Sysno::brk, [0x10, 0, 0, 0, 0, 0])),
            Ok(0x8000)
        );
    }

    #[test]
    fn unknown_syscall_is_enosys() {
        let host = Mock::default();
        assert_eq!(
            dispatch(&host, &Trap::new(Sysno::reboot, [0; 6])),
            Err(ENOSYS)
        );
    }

    #[test]
    fn try_handle_reports_handled_or_passthrough() {
        let host = Mock::default();
        *host.umem.borrow_mut() = vec![b'h', b'i', 0];
        // A syscall the domain owns is handled and its result written to uctx.
        let mut owned = Trap::new(Sysno::write, [1, 0, 2, 0, 0, 0]);
        assert_eq!(
            LinuxAbi::try_handle_syscall(&host, &mut owned),
            Dispatch::Handled
        );
        assert_eq!(owned.result, Some(2));
        // One the domain does not own passes through untouched, so a kernel can
        // fall back to its own table.
        let mut unowned = Trap::new(Sysno::reboot, [0; 6]);
        assert_eq!(
            LinuxAbi::try_handle_syscall(&host, &mut unowned),
            Dispatch::Passthrough
        );
        assert_eq!(unowned.result, None);
    }

    #[test]
    fn clock_gettime_packs_monotonic_into_user() {
        let host = Mock::default();
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
    fn clock_gettime_hands_back_an_unknown_clock() {
        let host = Mock::default();
        // The domain serves two clocks; the rest stay with the caller's table.
        assert!(route(&host, &Trap::new(Sysno::clock_gettime, [99, 0, 0, 0, 0, 0])).is_none());
    }

    #[test]
    fn clock_getres_reports_nanosecond_resolution() {
        let host = Mock::default();
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
        let host = Mock::default();
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
    fn clock_getres_hands_back_an_unknown_clock() {
        let host = Mock::default();
        assert!(route(&host, &Trap::new(Sysno::clock_getres, [99, 0, 0, 0, 0, 0])).is_none());
    }

    #[test]
    fn rt_sigprocmask_moves_the_mask() {
        let host = Mock::default();
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
        let host = Mock::default();
        assert_eq!(
            dispatch(&host, &Trap::new(Sysno::rt_sigprocmask, [2, 0, 0, 4, 0, 0])),
            Err(ops::EINVAL)
        );
    }

    #[test]
    fn exit_routes_to_tasks() {
        let host = Mock::default();
        assert_eq!(
            dispatch(&host, &Trap::new(Sysno::exit, [3, 0, 0, 0, 0, 0])),
            Ok(0)
        );
        // The wait status carries the exit code in its upper byte.
        assert_eq!(*host.exited.borrow(), Some((3 << 8, false)));
        assert_eq!(
            dispatch(&host, &Trap::new(Sysno::exit_group, [4, 0, 0, 0, 0, 0])),
            Ok(0)
        );
        assert_eq!(*host.exited.borrow(), Some((4 << 8, true)));
    }

    #[test]
    fn kill_routes_to_signals() {
        let host = Mock::default();
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
