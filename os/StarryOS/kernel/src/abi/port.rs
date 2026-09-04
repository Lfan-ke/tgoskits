//! StarryOS's implementation of the personality capability ports.
//!
//! Each method is either a direct reach for the kernel object that owns the
//! primitive, or a call into the existing `sys_*` implementation of it. The
//! latter is what keeps a migrated syscall behaving exactly as before: the
//! domain takes over decoding and validating the call, while the primitive
//! underneath stays the one the kernel already ships.

use alloc::vec::Vec;
use core::{ffi::c_char, mem::align_of, mem::MaybeUninit, time::Duration};

use ax_abi_port::{
    Access, At, Attributes, NodeKind, OpenHow, Paths,
    Clock, Creds, Files, MapRequest, MapSource, Mem, Platform, Prot, Random, SeekFrom,
    Address, Advice, Domain, Ready, Segment, Shutdown as PortShutdown, SignalTarget, Signals,
    Slept,
    SocketKind, SocketOption, Sockets, SysResult, System, Tasks, UtsField, Wait,
};
use ax_net::{SocketAddrEx, SocketOps};
use linux_raw_sys::net::{AF_INET, AF_INET6, AF_UNIX};
use ax_runtime::hal;
use ax_runtime::hal::cpu::UserAtomicU32Op;
use ax_task::current;
use axfs_ng_vfs::NodePermission;
use linux_raw_sys::general::{SIG_BLOCK, SIG_SETMASK, SIG_UNBLOCK};
use starry_signal::SignalSet;
use starry_vm::{vm_load_until_nul, vm_read_slice, vm_write_slice};

use linux_raw_sys::general::{AT_EMPTY_PATH, AT_FDCWD, AT_SYMLINK_NOFOLLOW, R_OK, W_OK, X_OK};

use super::{KernelHost, errno, port_result};
use crate::{
    StarryError, StarryResult,
    file::{
        Directory, FileLike, ResolveAtResult, add_file_like, close_file_like, get_file_like,
        resolve_at, with_fs, Pipe,
    },
    mm::{
        VmBytes, VmBytesMut, atomic_update_user_u32_nofault, fault_in_user_u32_read,
        fault_in_user_u32_write, read_user_u32_nofault,
    },
    syscall::access_permitted,
    syscall,
    syscall::{KillTarget, MmapFlags, MmapProt, open_path},
    task::{
        AsThread, FutexAccessError, FutexKey, FutexKeyMode, PgidNumber, TgidNumber,
        current_pid_view, do_exit, futex_table_for, retry_futex_nofault,
    },
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

    fn trace(&self, message: &str) {
        warn!("abi: {message}");
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

    fn exit(&self, code: i32) -> SysResult {
        do_exit(code << 8, false);
        Ok(0)
    }

    fn wait(&self, pid: u32, status_out: usize, nohang: bool) -> Result<u32, i32> {
        const WNOHANG: u32 = 1;
        let options = if nohang { WNOHANG } else { 0 };
        crate::syscall::sys_waitpid(pid as i32, status_out as *mut i32, options)
            .map(|reaped| reaped as u32)
            .map_err(errno)
    }

    fn exit_group(&self, code: i32) -> SysResult {
        do_exit(code << 8, true);
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

    fn unlink(&self, at: At, path: &str) -> Result<(), i32> {
        let dirfd = match at {
            At::Cwd => AT_FDCWD,
            At::Dir(fd) => fd,
        };
        with_fs(dirfd, |fs| {
            fs.remove_file(path)?;
            Ok(())
        })
        .map_err(errno)
    }

    fn mkdir(&self, at: At, path: &str, mode: u32) -> Result<(), i32> {
        let dirfd = match at {
            At::Cwd => AT_FDCWD,
            At::Dir(fd) => fd,
        };
        let curr = current();
        let thread = curr.as_thread();
        let mode = NodePermission::from_bits_truncate((mode & !thread.proc_data.umask()) as u16);
        let cred = thread.cred();
        with_fs(dirfd, |fs| {
            fs.create_dir(path, mode, cred.fsuid, cred.fsgid)?;
            Ok(())
        })
        .map_err(errno)
    }

    fn rename(&self, at: At, old: &str, new: &str) -> Result<(), i32> {
        use axfs_ng_vfs::path::Path;
        let dirfd = match at {
            At::Cwd => AT_FDCWD,
            At::Dir(fd) => fd,
        };
        let (old_dir, old_name) =
            with_fs(dirfd, |fs| Ok(fs.resolve_parent(Path::new(old))?)).map_err(errno)?;
        let (new_dir, new_name) =
            with_fs(dirfd, |fs| Ok(fs.resolve_parent(Path::new(new))?)).map_err(errno)?;
        old_dir
            .rename(&old_name, &new_dir, &new_name)
            .map_err(|err| errno(StarryError::from(err)))
    }

    fn rmdir(&self, at: At, path: &str) -> Result<(), i32> {
        let dirfd = match at {
            At::Cwd => AT_FDCWD,
            At::Dir(fd) => fd,
        };
        with_fs(dirfd, |fs| {
            fs.remove_dir(path)?;
            Ok(())
        })
        .map_err(errno)
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

    fn path_of(&self, fd: i32, put: &mut dyn FnMut(&str)) -> Result<(), i32> {
        let file = get_file_like(fd).map_err(errno)?;
        put(&file.path());
        Ok(())
    }

    fn read_dir(&self, fd: i32, sink: &mut dyn FnMut(&str, NodeKind) -> bool) -> Result<(), i32> {
        use axfs_ng_vfs::NodeType;
        let dir = Directory::from_fd(fd).map_err(errno)?;
        let mut stop = false;
        dir.inner()
            .read_dir(
                axfs_ng_vfs::DirectoryCursor::START,
                &mut |name: &[u8], _ino, node_type, _cursor| {
                // A name the filesystem holds as bytes may not be text; one
                // that is not is skipped rather than guessed at.
                let Ok(name) = core::str::from_utf8(name) else {
                    return true;
                };
                if name == "." || name == ".." {
                    return true;
                }
                let kind = match node_type {
                    NodeType::Directory => NodeKind::Directory,
                    NodeType::Symlink => NodeKind::Symlink,
                    NodeType::CharacterDevice => NodeKind::CharDevice,
                    NodeType::BlockDevice => NodeKind::BlockDevice,
                    NodeType::Fifo => NodeKind::Fifo,
                    NodeType::Socket => NodeKind::Socket,
                    _ => NodeKind::File,
                };
                if !sink(name, kind) {
                    stop = true;
                    return false;
                }
                true
                },
            )
            .map_err(|e| errno(e.into()))?;
        let _ = stop;
        Ok(())
    }

    fn umask(&self) -> u32 {
        current().as_thread().proc_data.umask() as u32
    }

    fn set_mode(&self, at: At, path: &str, mode: u32, follow: bool) -> Result<(), i32> {
        let flags = if follow { 0 } else { AT_SYMLINK_NOFOLLOW };
        let dirfd = match at {
            At::Cwd => AT_FDCWD,
            At::Dir(fd) => fd,
        };
        let Some(location) = resolve_at(dirfd, Some(path), flags)
            .map_err(errno)?
            .into_file()
        else {
            return Err(errno(StarryError::NotADirectory));
        };
        location
            .update_metadata(axfs_ng_vfs::MetadataUpdate {
                mode: Some(NodePermission::from_bits_truncate(mode as u16)),
                ..Default::default()
            })
            .map_err(|e| errno(e.into()))
    }

    fn set_mode_of(&self, fd: i32, mode: u32) -> Result<(), i32> {
        let Some(location) = resolve_at(fd, None, AT_EMPTY_PATH)
            .map_err(errno)?
            .into_file()
        else {
            return Err(errno(StarryError::NotADirectory));
        };
        location
            .update_metadata(axfs_ng_vfs::MetadataUpdate {
                mode: Some(NodePermission::from_bits_truncate(mode as u16)),
                ..Default::default()
            })
            .map_err(|e| errno(e.into()))
    }

    fn set_times(
        &self,
        at: At,
        path: &str,
        accessed: Option<u64>,
        modified: Option<u64>,
        follow: bool,
    ) -> Result<(), i32> {
        let flags = if follow { 0 } else { AT_SYMLINK_NOFOLLOW };
        let dirfd = match at {
            At::Cwd => AT_FDCWD,
            At::Dir(fd) => fd,
        };
        set_times(resolve_at(dirfd, Some(path), flags), accessed, modified)
    }

    fn set_times_of(
        &self,
        fd: i32,
        accessed: Option<u64>,
        modified: Option<u64>,
    ) -> Result<(), i32> {
        set_times(resolve_at(fd, None, AT_EMPTY_PATH), accessed, modified)
    }

    fn permitted(
        &self,
        at: At,
        path: &str,
        wants: Access,
        follow: bool,
        _real_ids: bool,
    ) -> Result<(), i32> {
        // The kernel decides from the filesystem credentials, which is the one
        // identity it tracks; the real-versus-effective distinction an ABI can
        // ask for is not one it can answer differently today, so the answer is
        // the same one `faccessat2` has always given.
        let dirfd = match at {
            At::Cwd => AT_FDCWD,
            At::Dir(fd) => fd,
        };
        let flags = if follow { 0 } else { AT_SYMLINK_NOFOLLOW };
        let file = resolve_at(dirfd, Some(path), flags).map_err(errno)?;
        access_permitted(&file, access_mode(wants)).map_err(errno)
    }

    fn permitted_of(&self, fd: i32, wants: Access, _real_ids: bool) -> Result<(), i32> {
        let file = resolve_at(fd, None, AT_EMPTY_PATH).map_err(errno)?;
        access_permitted(&file, access_mode(wants)).map_err(errno)
    }
}

/// Restate the neutral request as the `R_OK`/`W_OK`/`X_OK` mask the kernel's
/// own check reads.
fn access_mode(wants: Access) -> u32 {
    let mut mode = 0;
    if wants.read {
        mode |= R_OK;
    }
    if wants.write {
        mode |= W_OK;
    }
    if wants.execute {
        mode |= X_OK;
    }
    mode
}

/// Restate what the filesystem said in the neutral shape the port speaks.
/// Stamp a resolved name with the times given, leaving out what was not.
fn set_times(
    resolved: StarryResult<ResolveAtResult>,
    accessed: Option<u64>,
    modified: Option<u64>,
) -> Result<(), i32> {
    let Some(location) = resolved.map_err(errno)?.into_file() else {
        return Err(errno(StarryError::NotADirectory));
    };
    location
        .update_metadata(axfs_ng_vfs::MetadataUpdate {
            atime: accessed.map(Duration::from_nanos),
            mtime: modified.map(Duration::from_nanos),
            ..Default::default()
        })
        .map_err(|e| errno(e.into()))
}

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

    fn poll(&self, interest: &mut [(i32, Ready)], timeout_ns: Option<u64>) -> Result<usize, i32> {
        use core::task::{Context, Poll};

        use axpoll::{IoEvents, Pollable};
        use core::future::poll_fn;

        use ax_task::future::{block_on, interruptible, timeout};

        // The descriptors, with what each asked about. One that is not ours is
        // answered on its own entry, the way poll reports POLLNVAL, instead of
        // failing the whole call.
        struct Set(Vec<(alloc::sync::Arc<dyn FileLike>, IoEvents)>);
        impl Pollable for Set {
            fn poll(&self) -> IoEvents {
                IoEvents::empty()
            }
            fn register(&self, context: &mut Context<'_>, _events: IoEvents) {
                for (file, events) in &self.0 {
                    file.register(context, *events);
                }
            }
        }

        let mut files = Vec::with_capacity(interest.len());
        let mut invalid = 0;
        for (fd, ready) in interest.iter_mut() {
            // The entry carries what the caller asked about on the way in and
            // what it got on the way out, so what it asked for is taken before
            // the slot is cleared.
            let wanted = *ready;
            *ready = Ready::default();
            match get_file_like(*fd) {
                Ok(file) => {
                    let mut events = IoEvents::ALWAYS_POLL;
                    events.set(IoEvents::IN, wanted.read);
                    events.set(IoEvents::OUT, wanted.write);
                    files.push(Some((file, events)));
                }
                Err(_) => {
                    ready.error = true;
                    invalid += 1;
                    files.push(None);
                }
            }
        }
        if invalid > 0 {
            return Ok(invalid);
        }

        let set = Set(files.into_iter().flatten().collect());
        let ready_now = |interest: &mut [(i32, Ready)]| {
            let mut count = 0;
            for (slot, (file, wanted)) in interest.iter_mut().zip(set.0.iter()) {
                let events = file.poll();
                let ready = Ready {
                    read: events.contains(IoEvents::IN),
                    write: events.contains(IoEvents::OUT),
                    error: events.intersects(IoEvents::ERR | IoEvents::HUP | IoEvents::NVAL),
                };
                let asked = (ready.read && wanted.contains(IoEvents::IN))
                    || (ready.write && wanted.contains(IoEvents::OUT))
                    || ready.error;
                slot.1 = if asked { ready } else { Ready::default() };
                if asked {
                    count += 1;
                }
            }
            count
        };

        let interest = core::cell::RefCell::new(interest);
        let wait = poll_fn(|cx| {
            let mut count = ready_now(&mut interest.borrow_mut()[..]);
            if count > 0 {
                return Poll::Ready(count);
            }
            set.register(cx, IoEvents::empty());
            count = ready_now(&mut interest.borrow_mut()[..]);
            if count > 0 {
                return Poll::Ready(count);
            }
            Poll::Pending
        });
        let deadline = timeout_ns.map(Duration::from_nanos);
        match block_on(interruptible(timeout(deadline, wait))) {
            // The deadline passed with nothing ready, which is not a failure.
            Ok(Err(_)) => Ok(0),
            Ok(Ok(count)) => Ok(count),
            Err(error) => Err(errno(error.into())),
        }
    }

    fn close(&self, fd: i32) -> SysResult {
        close_file_like(fd).map_err(errno)?;
        Ok(0)
    }

    fn pipe(&self) -> Result<(i32, i32), i32> {
        let (read_end, write_end) = Pipe::new();
        let read_fd = read_end.add_to_fd_table(true).map_err(errno)?;
        let write_fd = write_end.add_to_fd_table(true).map_err(|err| {
            let _ = close_file_like(read_fd);
            errno(err)
        })?;
        Ok((read_fd, write_fd))
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

/// Threads block and wake on a word of their own memory, which is what the
/// kernel's futexes are. The port takes a plain timeout rather than a
/// `timespec` in user memory, so a personality can wait on a deadline it
/// computed itself.
impl Wait for KernelHost {
    fn wait(&self, addr: usize, expected: u32, timeout_ns: Option<u64>) -> Result<bool, i32> {
        let word = addr as *const u32;
        if !addr.is_multiple_of(align_of::<u32>()) {
            return Err(errno(StarryError::InvalidInput));
        }
        let key = FutexKey::new_current(addr, FutexKeyMode::Private);
        let table = futex_table_for(&key);
        // The word is read once before parking so a caller that is already
        // out of date is told to look again instead of sleeping on a value
        // nobody will wake it for.
        match read_user_u32_nofault(word) {
            Ok(value) if value != expected => return Err(errno(StarryError::WouldBlock)),
            Ok(_) => {}
            Err(_) => return Err(errno(StarryError::BadAddress)),
        }
        let timeout = timeout_ns.map(Duration::from_nanos);
        let futex = table.get_or_insert(&key);
        let cleanup = table.cleanup_for(&key);
        // The queue reports three outcomes and they are not the same: it
        // slept and was woken, it never slept because the word had already
        // changed, or the deadline passed - and the last of those arrives as
        // an error rather than a value.
        match retry_futex_nofault(
            || {
                futex.wq.wait_if_with_cleanup_nofault(
                    u32::MAX,
                    timeout,
                    Some(cleanup.clone()),
                    || match read_user_u32_nofault(word) {
                        Ok(value) => Ok(value == expected),
                        Err(_) => Err(FutexAccessError::Fault),
                    },
                )
            },
            || fault_in_user_u32_read(word),
        ) {
            Ok(true) => Ok(true),
            Ok(false) => Err(errno(StarryError::WouldBlock)),
            // The deadline arrives as an error, and as more than one variant
            // of it - the queue's own timeout and the task timer's each have
            // their own. What they share is the number they report, so that
            // is what this compares.
            Err(other) => {
                let code = errno(other);
                if code == errno(StarryError::TimedOut) {
                    Ok(false)
                } else {
                    Err(code)
                }
            }
        }
    }

    fn swap(&self, addr: usize, value: u32) -> Result<u32, i32> {
        atomic(addr, UserAtomicU32Op::Set, value)
    }

    fn fetch_add(&self, addr: usize, value: u32) -> Result<u32, i32> {
        atomic(addr, UserAtomicU32Op::Add, value)
    }

    fn wake(&self, addr: usize, count: u32) -> Result<u32, i32> {
        if !addr.is_multiple_of(align_of::<u32>()) {
            return Err(errno(StarryError::InvalidInput));
        }
        let key = FutexKey::new_current(addr, FutexKeyMode::Private);
        let woken = futex_table_for(&key)
            .get(&key)
            .map_or(0, |futex| futex.wq.wake(count as usize, u32::MAX));
        ax_task::yield_now();
        Ok(woken as u32)
    }
}

/// One atomic update of a user word, reported the way the ports report errors.
fn atomic(addr: usize, operation: UserAtomicU32Op, argument: u32) -> Result<u32, i32> {
    if !addr.is_multiple_of(align_of::<u32>()) {
        return Err(errno(StarryError::InvalidInput));
    }
    let word = addr as *mut u32;
    retry_futex_nofault(
        || {
            atomic_update_user_u32_nofault(word, operation, argument)
                .map_err(|_| FutexAccessError::Fault)
        },
        || fault_in_user_u32_write(word),
    )
    .map_err(errno)
}

/// Turning a port address into the one the network stack speaks, and back.
/// Only the shape differs: the bytes and the port are the same address.
fn endpoint(at: &Address) -> SocketAddrEx {
    let addr = match *at {
        Address::V4(bytes, port) => {
            core::net::SocketAddr::V4(core::net::SocketAddrV4::new(bytes.into(), port))
        }
        Address::V6(bytes, port, scope) => core::net::SocketAddr::V6(
            core::net::SocketAddrV6::new(bytes.into(), port, 0, scope),
        ),
        // A name on this machine is a unix socket in the abstract namespace:
        // no file is made for it, which is what a Windows pipe name is like
        // and what the personality asking for one wants.
        Address::Local(ref bytes, len) => {
            let name: alloc::sync::Arc<[u8]> = bytes[..len as usize].into();
            return SocketAddrEx::Unix(ax_net::unix::UnixSocketAddr::Abstract(name));
        }
    };
    SocketAddrEx::Ip(addr)
}

fn address(from: SocketAddrEx) -> Result<Address, i32> {
    match from {
        SocketAddrEx::Ip(core::net::SocketAddr::V4(v4)) => {
            Ok(Address::V4(v4.ip().octets(), v4.port()))
        }
        SocketAddrEx::Ip(core::net::SocketAddr::V6(v6)) => {
            Ok(Address::V6(v6.ip().octets(), v6.port(), v6.scope_id()))
        }
        SocketAddrEx::Unix(ax_net::unix::UnixSocketAddr::Abstract(name)) => {
            Address::local(&name).ok_or(errno(StarryError::InvalidInput))
        }
        // A socket with no name of its own, or one named by a file: neither
        // is an address a caller can be handed back here.
        _ => Err(errno(StarryError::OperationNotSupported)),
    }
}

/// The socket behind a descriptor.
fn socket_of(fd: i32) -> Result<alloc::sync::Arc<crate::file::Socket>, i32> {
    crate::file::Socket::from_fd(fd).map_err(errno)
}

impl Sockets for KernelHost {
    fn open(&self, domain: Domain, kind: SocketKind) -> Result<i32, i32> {
        use ax_net::{
            tcp::TcpSocket,
            udp::UdpSocket,
            unix::{DgramTransport, StreamTransport, UnixSocket},
        };
        let credentials = crate::file::Socket::current_unix_credentials();
        let inner: ax_net::Socket = match (domain, kind) {
            (Domain::Local, SocketKind::Stream) => {
                UnixSocket::new(StreamTransport::new(credentials)).into()
            }
            (Domain::Local, SocketKind::SeqPacket) => {
                UnixSocket::new(DgramTransport::new_seqpacket(credentials)).into()
            }
            (Domain::Local, SocketKind::Datagram) => {
                UnixSocket::new(DgramTransport::new(credentials)).into()
            }
            (_, SocketKind::Stream) => TcpSocket::new().into(),
            (_, SocketKind::Datagram) => UdpSocket::new().into(),
            // Only a local socket keeps message boundaries over a connection
            // here; a network one that asked would be told it cannot.
            (_, SocketKind::SeqPacket) => {
                return Err(errno(StarryError::OperationNotSupported));
            }
        };
        let family = match domain {
            Domain::Inet => AF_INET,
            Domain::Inet6 => AF_INET6,
            Domain::Local => AF_UNIX,
        };
        let socket = crate::file::Socket::new(inner, family);
        socket.add_to_fd_table(false).map_err(errno).map(|fd| fd as i32)
    }

    fn bind(&self, fd: i32, at: &Address) -> Result<(), i32> {
        socket_of(fd)?.bind(endpoint(at)).map_err(|e| errno(e.into()))
    }

    fn connect(&self, fd: i32, to: &Address) -> Result<(), i32> {
        socket_of(fd)?
            .connect(endpoint(to))
            .map_err(|e| errno(e.into()))
    }

    fn listen(&self, fd: i32, backlog: u32) -> Result<(), i32> {
        socket_of(fd)?
            .listen(backlog as usize)
            .map_err(|e| errno(e.into()))
    }

    fn accept(&self, fd: i32) -> Result<(i32, Option<Address>), i32> {
        let socket = socket_of(fd)?;
        let taken = socket.accept().map_err(|e| errno(e.into()))?;
        // A peer that never took a name has no address to report, which is
        // not a reason to refuse the connection it made.
        let peer = taken.peer_addr().ok().and_then(|peer| address(peer).ok());
        let file = crate::file::Socket::new(taken, socket.ip_domain());
        let fd = file.add_to_fd_table(false).map_err(errno)? as i32;
        Ok((fd, peer))
    }

    fn send(&self, fd: i32, uaddr: usize, len: usize, to: Option<&Address>) -> SysResult {
        let socket = socket_of(fd)?;
        let options = ax_net::SendOptions {
            to: to.map(endpoint),
            ..Default::default()
        };
        socket
            .send(&mut VmBytes::new(uaddr as *const u8, len), options)
            .map(|sent| sent as isize)
            .map_err(|e| errno(e.into()))
    }

    fn recv(
        &self,
        fd: i32,
        uaddr: usize,
        len: usize,
        peek: bool,
    ) -> Result<(usize, Option<Address>), i32> {
        let socket = socket_of(fd)?;
        let mut from = SocketAddrEx::Ip(core::net::SocketAddr::V4(
            core::net::SocketAddrV4::new(core::net::Ipv4Addr::UNSPECIFIED, 0),
        ));
        let mut flags = ax_net::RecvFlags::empty();
        flags.set(ax_net::RecvFlags::PEEK, peek);
        let options = ax_net::RecvOptions {
            from: Some(&mut from),
            flags,
            ..Default::default()
        };
        let read = socket
            .recv(&mut VmBytesMut::new(uaddr as *mut u8, len), options)
            .map_err(|e| errno(e.into()))?;
        Ok((read, address(from).ok()))
    }

    fn shutdown(&self, fd: i32, how: PortShutdown) -> Result<(), i32> {
        let how = match how {
            PortShutdown::Read => ax_net::Shutdown::Read,
            PortShutdown::Write => ax_net::Shutdown::Write,
            PortShutdown::Both => ax_net::Shutdown::Both,
        };
        socket_of(fd)?.shutdown(how).map_err(|e| errno(e.into()))
    }

    fn local(&self, fd: i32) -> Result<Address, i32> {
        address(socket_of(fd)?.local_addr().map_err(|e| errno(e.into()))?)
    }

    fn peer(&self, fd: i32) -> Result<Address, i32> {
        address(socket_of(fd)?.peer_addr().map_err(|e| errno(e.into()))?)
    }

    fn set_blocking(&self, fd: i32, blocking: bool) -> Result<(), i32> {
        socket_of(fd)?
            .set_nonblocking(!blocking)
            .map_err(|e| errno(e.into()))
    }

    fn pending(&self, fd: i32) -> Result<usize, i32> {
        socket_of(fd)?.recv_available().map_err(|e| errno(e.into()))
    }

    fn set_option(&self, fd: i32, option: SocketOption, value: u32) -> Result<(), i32> {
        use ax_net::options::{Configurable, SetSocketOption as Set};
        let socket = socket_of(fd)?;
        let on = value != 0;
        let size = value as usize;
        let done = match option {
            SocketOption::ReuseAddress => socket.set_option(Set::ReuseAddress(&on)),
            SocketOption::KeepAlive => socket.set_option(Set::KeepAlive(&on)),
            SocketOption::NoDelay => socket.set_option(Set::NoDelay(&on)),
            SocketOption::Broadcast => socket.set_option(Set::Broadcast(&on)),
            SocketOption::SendBuffer => socket.set_option(Set::SendBuffer(&size)),
            SocketOption::ReceiveBuffer => socket.set_option(Set::ReceiveBuffer(&size)),
            // What the socket is, and what went wrong, are reports rather
            // than settings.
            SocketOption::Error | SocketOption::Kind => {
                return Err(errno(StarryError::OperationNotSupported));
            }
        };
        done.map_err(|e| errno(e.into()))
    }

    fn option(&self, fd: i32, option: SocketOption) -> Result<u32, i32> {
        use ax_net::options::{Configurable, GetSocketOption as Get};
        let socket = socket_of(fd)?;
        let (mut flag, mut size, mut number) = (false, 0usize, 0i32);
        let done = match option {
            SocketOption::ReuseAddress => socket.get_option(Get::ReuseAddress(&mut flag)),
            SocketOption::KeepAlive => socket.get_option(Get::KeepAlive(&mut flag)),
            SocketOption::NoDelay => socket.get_option(Get::NoDelay(&mut flag)),
            SocketOption::Broadcast => socket.get_option(Get::Broadcast(&mut flag)),
            SocketOption::SendBuffer => socket.get_option(Get::SendBuffer(&mut size)),
            SocketOption::ReceiveBuffer => socket.get_option(Get::ReceiveBuffer(&mut size)),
            SocketOption::Error => socket.get_option(Get::Error(&mut number)),
            SocketOption::Kind => socket.get_option(Get::SocketType(&mut number)),
        };
        done.map_err(|e| errno(e.into()))?;
        Ok(match option {
            SocketOption::ReuseAddress
            | SocketOption::KeepAlive
            | SocketOption::NoDelay
            | SocketOption::Broadcast => u32::from(flag),
            SocketOption::SendBuffer | SocketOption::ReceiveBuffer => size as u32,
            SocketOption::Error | SocketOption::Kind => number as u32,
        })
    }
}
