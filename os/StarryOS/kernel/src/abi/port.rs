//! StarryOS's implementation of the personality capability ports.
//!
//! Each method is either a direct reach for the kernel object that owns the
//! primitive, or a call into the existing `sys_*` implementation of it. The
//! latter is what keeps a migrated syscall behaving exactly as before: the
//! domain takes over decoding and validating the call, while the primitive
//! underneath stays the one the kernel already ships.

use alloc::vec::Vec;
use core::{ffi::c_char, mem::MaybeUninit, time::Duration};

use ax_abi_port::{
    At, Attributes, NodeKind, OpenHow, Paths,
    Clock, Creds, Files, MapRequest, MapSource, Mem, Platform, Prot, Random, SeekFrom,
    Advice, Segment, SignalTarget, Signals, Slept, SysResult, System, Tasks, UtsField,
};
use ax_runtime::hal;
use ax_task::current;
use linux_raw_sys::general::{SIG_BLOCK, SIG_SETMASK, SIG_UNBLOCK};
use starry_signal::SignalSet;
use starry_vm::{vm_load_until_nul, vm_read_slice, vm_write_slice};

use linux_raw_sys::general::{AT_EMPTY_PATH, AT_FDCWD, AT_SYMLINK_NOFOLLOW};

use super::{KernelHost, errno, port_result};
use crate::{
    StarryError, StarryResult,
    file::{ResolveAtResult, add_file_like, close_file_like, get_file_like, resolve_at},
    mm::VmBytesMut,
    syscall,
    syscall::{KillTarget, MmapFlags, MmapProt, open_path},
    task::{AsThread, PgidNumber, TgidNumber, current_pid_view, do_exit},
};

impl Platform for KernelHost {
    fn read_user(&self, uaddr: usize, out: &mut [u8]) -> SysResult {
        // SAFETY: `MaybeUninit<u8>` has the same layout as `u8`, and the read
        // only ever stores initialized bytes into the buffer.
        let buf =
            unsafe { core::slice::from_raw_parts_mut(out.as_mut_ptr().cast::<MaybeUninit<u8>>(), out.len()) };
        vm_read_slice(uaddr as *const u8, buf).map_err(|e| errno(StarryError::from(e)))?;
        Ok(0)
    }

    fn read_user_cstr(&self, uaddr: usize, out: &mut [u8]) -> SysResult {
        let bytes = vm_load_until_nul(uaddr as *const u8)
            .map_err(|e| errno(StarryError::from(e)))?;
        if bytes.len() > out.len() {
            return Err(errno(StarryError::NameTooLong));
        }
        out[..bytes.len()].copy_from_slice(&bytes);
        Ok(bytes.len() as isize)
    }

    fn write_user(&self, uaddr: usize, data: &[u8]) -> SysResult {
        vm_write_slice(uaddr as *mut u8, data).map_err(|e| errno(StarryError::from(e)))?;
        Ok(0)
    }
}

impl Tasks for KernelHost {
    fn getpid(&self) -> SysResult {
        let curr = current();
        current_pid_view()
            .visible_process_number(&curr.as_thread().proc_data.identity())
            .map(|pid| pid.get() as isize)
            .ok_or(errno(StarryError::NoSuchProcess))
    }

    fn getppid(&self) -> SysResult {
        let curr = current();
        let parent = curr
            .as_thread()
            .proc_data
            .proc
            .parent()
            .ok_or(errno(StarryError::NoSuchProcess))?;
        Ok(current_pid_view()
            .visible_process_number(&parent.identity())
            .map_or(0, |pid| pid.get() as isize))
    }

    fn gettid(&self) -> u32 {
        current().as_thread().user_tid().get()
    }

    fn set_tid_address(&self, tidptr: usize) -> SysResult {
        let curr = current();
        let thread = curr.as_thread();
        thread.set_clear_child_tid(tidptr);
        Ok(thread.user_tid().get() as isize)
    }

    fn sched_yield(&self) -> SysResult {
        ax_task::yield_now();
        Ok(0)
    }

    fn exit(&self, status: i32) -> SysResult {
        do_exit(status, false);
        Ok(0)
    }

    fn exit_group(&self, status: i32) -> SysResult {
        do_exit(status, true);
        Ok(0)
    }
}

/// The kernel names a run by a plain pair.
fn runs(segs: &[Segment]) -> Vec<(usize, usize)> {
    segs.iter().map(|s| (s.uaddr, s.len)).collect()
}

impl Paths for KernelHost {
    fn open(&self, at: At, path: &str, how: &OpenHow) -> SysResult {
        // Every ABI words a request differently - `O_*` bits, a Windows
        // `CreateDisposition`, a Darwin flag set - and each decodes its own
        // before it gets here. What the host does with what is left is resolve
        // the name and install the result.
        let dirfd = match at {
            At::Cwd => AT_FDCWD,
            At::Dir(fd) => fd,
        };
        port_result(open_path(dirfd, path, how))
    }

    fn attributes(&self, at: At, path: &str, follow: bool) -> Result<Attributes, i32> {
        let dirfd = match at {
            At::Cwd => AT_FDCWD,
            At::Dir(fd) => fd,
        };
        let flags = if follow { 0 } else { AT_SYMLINK_NOFOLLOW };
        describe(resolve_at(dirfd, Some(path), flags))
    }

    fn attributes_of(&self, fd: i32) -> Result<Attributes, i32> {
        describe(resolve_at(fd, None, AT_EMPTY_PATH))
    }
}

/// Restate what the filesystem said in the neutral shape the port speaks.
fn describe(resolved: StarryResult<ResolveAtResult>) -> Result<Attributes, i32> {
    let stat = resolved.and_then(|r| r.stat()).map_err(errno)?;
    // The mode carries the node type in its top bits, which is where every
    // caller of this reads it from; naming it separately saves each ABI from
    // decoding the same octal.
    const IFMT: u32 = 0o170000;
    let kind = match stat.mode & IFMT {
        0o040000 => NodeKind::Directory,
        0o120000 => NodeKind::Symlink,
        0o020000 => NodeKind::CharDevice,
        0o060000 => NodeKind::BlockDevice,
        0o010000 => NodeKind::Fifo,
        0o140000 => NodeKind::Socket,
        _ => NodeKind::File,
    };
    Ok(Attributes {
        kind,
        mode: stat.mode & !IFMT,
        size: stat.size,
        block_size: u64::from(stat.blksize),
        blocks: stat.blocks,
        device: stat.dev,
        rdev: u64::from(stat.rdev.major()) << 32 | u64::from(stat.rdev.minor()),
        inode: stat.ino,
        links: u64::from(stat.nlink),
        uid: stat.uid,
        gid: stat.gid,
        accessed_ns: stat.atime.as_nanos() as u64,
        modified_ns: stat.mtime.as_nanos() as u64,
        changed_ns: stat.ctime.as_nanos() as u64,
    })
}

impl Files for KernelHost {
    fn read(&self, fd: i32, uaddr: usize, len: usize) -> SysResult {
        let file = get_file_like(fd).map_err(errno)?;
        let read = file
            .read(&mut VmBytesMut::new(uaddr as *mut u8, len))
            .map_err(errno)?;
        Ok(read as isize)
    }

    fn close(&self, fd: i32) -> SysResult {
        close_file_like(fd).map_err(errno)?;
        Ok(0)
    }

    fn dup(&self, fd: i32) -> SysResult {
        let file = get_file_like(fd).map_err(errno)?;
        let new_fd = add_file_like(file, false).map_err(errno)?;
        Ok(new_fd as isize)
    }

    fn pread(&self, fd: i32, uaddr: usize, len: usize, offset: u64) -> SysResult {
        port_result(syscall::read_at_fd(fd, uaddr as *mut u8, len, offset))
    }

    fn pwrite(&self, fd: i32, uaddr: usize, len: usize, offset: u64) -> SysResult {
        port_result(syscall::write_at_fd(fd, uaddr as *const u8, len, offset))
    }

    fn write(&self, fd: i32, uaddr: usize, len: usize) -> SysResult {
        port_result(syscall::write_file(fd, uaddr as *const u8, len))
    }

    fn seek(&self, fd: i32, to: SeekFrom) -> SysResult {
        port_result(syscall::seek_file(fd, to))
    }

    fn validate(&self, fd: i32) -> SysResult {
        get_file_like(fd).map_err(errno)?;
        Ok(0)
    }

    fn readv(&self, fd: i32, segs: &[Segment]) -> SysResult {
        port_result(syscall::read_segments(fd, &runs(segs)))
    }

    fn writev(&self, fd: i32, segs: &[Segment]) -> SysResult {
        port_result(syscall::write_segments(fd, &runs(segs)))
    }

    fn preadv(&self, fd: i32, segs: &[Segment], offset: u64) -> SysResult {
        port_result(syscall::read_at_segments(fd, &runs(segs), offset))
    }

    fn pwritev(&self, fd: i32, segs: &[Segment], offset: u64) -> SysResult {
        port_result(syscall::write_at_segments(fd, &runs(segs), offset))
    }

    fn seekable(&self, fd: i32) -> SysResult {
        syscall::seekable_fd(fd).map_err(errno)?;
        Ok(0)
    }

    fn dup_onto(&self, oldfd: i32, newfd: i32, cloexec: bool) -> SysResult {
        port_result(syscall::dup_onto(oldfd, newfd, cloexec))
    }

    fn fsync(&self, fd: i32, datasync: bool) -> SysResult {
        port_result(syscall::sync_file(fd, datasync))
    }

    fn ftruncate(&self, fd: i32, len: u64) -> SysResult {
        port_result(syscall::truncate_file(fd, len))
    }
}

impl Mem for KernelHost {
    fn brk(&self) -> usize {
        syscall::heap_top()
    }

    fn set_brk(&self, addr: usize) -> SysResult {
        syscall::set_heap_top(addr).map_err(errno)?;
        Ok(0)
    }

    fn map(&self, req: &MapRequest) -> SysResult {
        let mut prot = MmapProt::empty();
        for (port, host) in [
            (Prot::READ, MmapProt::READ),
            (Prot::WRITE, MmapProt::WRITE),
            (Prot::EXEC, MmapProt::EXEC),
            (Prot::GROWS_DOWN, MmapProt::GROWDOWN),
            (Prot::GROWS_UP, MmapProt::GROWSUP),
        ] {
            prot.set(host, req.prot.contains(port));
        }
        let map_type = if req.shared {
            MmapFlags::SHARED
        } else {
            MmapFlags::PRIVATE
        };
        let mut flags = map_type;
        if req.fixed {
            flags |= MmapFlags::FIXED;
        }
        let (anonymous, fd, offset) = match req.source {
            MapSource::Anonymous => {
                flags |= MmapFlags::ANONYMOUS;
                (true, -1, 0)
            }
            MapSource::File { fd, offset } => (false, fd, offset),
        };
        port_result(syscall::map_range(
            req.addr, req.len, prot, flags, map_type, anonymous, fd, offset,
        ))
    }

    fn unmap(&self, addr: usize, len: usize) -> SysResult {
        port_result(syscall::unmap_range(addr, len))
    }

    fn protect(&self, addr: usize, len: usize, prot: Prot) -> SysResult {
        let mut flags = MmapProt::empty();
        for (port, host) in [
            (Prot::READ, MmapProt::READ),
            (Prot::WRITE, MmapProt::WRITE),
            (Prot::EXEC, MmapProt::EXEC),
            (Prot::GROWS_DOWN, MmapProt::GROWDOWN),
            (Prot::GROWS_UP, MmapProt::GROWSUP),
        ] {
            flags.set(host, prot.contains(port));
        }
        port_result(syscall::protect_range(addr, len, flags))
    }

    fn advise(&self, addr: usize, len: usize, advice: Advice) -> SysResult {
        // The kernel's own range advice speaks Linux's numbering, which is one
        // ABI's spelling of these; translate at the boundary rather than
        // letting a domain write that spelling.
        use linux_raw_sys::general::{
            MADV_DONTNEED, MADV_FREE, MADV_NORMAL, MADV_RANDOM, MADV_REMOVE, MADV_SEQUENTIAL,
            MADV_WILLNEED,
        };
        let advice = match advice {
            Advice::Normal => MADV_NORMAL,
            Advice::Random => MADV_RANDOM,
            Advice::Sequential => MADV_SEQUENTIAL,
            Advice::WillNeed => MADV_WILLNEED,
            Advice::DontNeed => MADV_DONTNEED,
            Advice::Free => MADV_FREE,
            Advice::Remove => MADV_REMOVE,
            // Nothing to do, and saying so is not a failure.
            Advice::Ignored => return Ok(0),
        };
        port_result(syscall::advise_range(addr, len, advice as i32))
    }

    fn writeback(&self, addr: usize, len: usize) -> SysResult {
        port_result(syscall::writeback_range(addr, len))
    }
}

impl Random for KernelHost {
    fn fill(&self, uaddr: usize, len: usize, blocking: bool) -> SysResult {
        port_result(syscall::fill_random(uaddr, len, blocking))
    }
}

impl Signals for KernelHost {
    fn kill(&self, target: SignalTarget, signo: u32) -> SysResult {
        let target = match target {
            SignalTarget::Process(tgid) => KillTarget::Process(
                TgidNumber::try_from(tgid).map_err(errno)?,
            ),
            SignalTarget::CallerGroup => KillTarget::CurrentProcessGroup,
            SignalTarget::All => KillTarget::AllPermittedProcesses,
            SignalTarget::Group(pgid) => KillTarget::ProcessGroup(
                PgidNumber::try_from(pgid).map_err(errno)?,
            ),
        };
        port_result(syscall::signal_target(target, signo))
    }

    fn tgkill(&self, tgid: u32, tid: u32, signo: u32) -> SysResult {
        port_result(syscall::signal_thread(tgid, tid, signo))
    }

    fn tkill(&self, tid: u32, signo: u32) -> SysResult {
        port_result(syscall::signal_one_thread(tid, signo))
    }

    fn sigprocmask(&self, how: i32, new: Option<u64>) -> Result<u64, i32> {
        let curr = current();
        let signal = &curr.as_thread().signal;
        let old = signal.blocked();
        if let Some(mask) = new {
            let set = set_from_bits(mask);
            signal.set_blocked(match how as u32 {
                SIG_BLOCK => old | set,
                SIG_UNBLOCK => old & !set,
                SIG_SETMASK => set,
                _ => return Err(errno(StarryError::InvalidInput)),
            });
        }
        Ok(set_to_bits(old))
    }
}

impl Clock for KernelHost {
    fn monotonic_ns(&self) -> u64 {
        hal::time::monotonic_time_nanos()
    }

    fn wall_ns(&self) -> u64 {
        hal::time::monotonic_time_nanos() + hal::time::epochoffset_nanos()
    }

    fn sleep_ns(&self, ns: u64) -> Slept {
        match syscall::sleep_monotonic(Duration::from_nanos(ns)) {
            (Ok(()), _) => Slept::Full,
            (Err(e), actual) => Slept::Short {
                errno: errno(e),
                elapsed_ns: actual.as_nanos().min(u64::MAX as u128) as u64,
            },
        }
    }
}

impl System for KernelHost {
    fn uname(&self, put: &mut dyn FnMut(UtsField, &str)) {
        let curr = current();
        // Snapshot under the namespace locks, then report: the domain must not
        // run while this kernel holds them.
        let uts = {
            let nsproxy = curr.as_thread().proc_data.nsproxy.lock();
            let ns = nsproxy.uts_ns.lock();
            crate::namespace::build_utsname(&ns)
        };
        put(UtsField::SysName, nul_terminated(&uts.sysname));
        put(UtsField::NodeName, nul_terminated(&uts.nodename));
        put(UtsField::Release, nul_terminated(&uts.release));
        put(UtsField::Version, nul_terminated(&uts.version));
        put(UtsField::Machine, nul_terminated(&uts.machine));
        put(UtsField::DomainName, nul_terminated(&uts.domainname));
    }
}

impl Creds for KernelHost {
    fn uids(&self) -> (u32, u32, u32) {
        // A user namespace that cannot map the caller's ids reports the
        // overflow id for all three, exactly as the kernel's own getters do.
        let overflow = syscall::user_ns_overflow_uid();
        if overflow != 0 {
            return (overflow, overflow, overflow);
        }
        let curr = current();
        let cred = curr.as_thread().cred();
        (cred.uid, cred.euid, cred.suid)
    }

    fn gids(&self) -> (u32, u32, u32) {
        let overflow = syscall::user_ns_overflow_gid();
        if overflow != 0 {
            return (overflow, overflow, overflow);
        }
        let curr = current();
        let cred = curr.as_thread().cred();
        (cred.gid, cred.egid, cred.sgid)
    }
}

/// The text before the first NUL of a fixed-width ABI string field.
fn nul_terminated(raw: &[c_char]) -> &str {
    // SAFETY: `c_char` is a one-byte integer on every supported target, and the
    // bytes are only read.
    let bytes = unsafe { core::slice::from_raw_parts(raw.as_ptr().cast::<u8>(), raw.len()) };
    let end = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
    core::str::from_utf8(&bytes[..end]).unwrap_or_default()
}

/// `sigset_t` crosses the port as the `u64` the Linux ABI defines it to be.
fn set_from_bits(bits: u64) -> SignalSet {
    // SAFETY: `kernel_sigset_t` has the same layout as `[c_ulong; 1]`, which is
    // how `starry-signal` itself converts between the two.
    SignalSet::from(unsafe { core::mem::transmute::<u64, linux_raw_sys::general::kernel_sigset_t>(bits) })
}

fn set_to_bits(set: SignalSet) -> u64 {
    let raw: linux_raw_sys::general::kernel_sigset_t = set.into();
    // SAFETY: as above, the two types share a layout.
    unsafe { core::mem::transmute::<linux_raw_sys::general::kernel_sigset_t, u64>(raw) }
}
