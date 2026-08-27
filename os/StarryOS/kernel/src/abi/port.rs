//! StarryOS's implementation of the personality capability ports.
//!
//! Each method is either a direct reach for the kernel object that owns the
//! primitive, or a call into the existing `sys_*` implementation of it. The
//! latter is what keeps a migrated syscall behaving exactly as before: the
//! domain takes over decoding and validating the call, while the primitive
//! underneath stays the one the kernel already ships.

use core::{ffi::c_char, mem::MaybeUninit, time::Duration};

use ax_abi_port::{
    Clock, Creds, Files, Mem, Platform, Random, Signals, SysResult, System, Tasks, UtsField,
};
use ax_runtime::hal;
use ax_task::{
    current,
    future::{block_on, interruptible, sleep},
};
use linux_raw_sys::general::{SIG_BLOCK, SIG_UNBLOCK};
use starry_signal::SignalSet;
use starry_vm::{vm_read_slice, vm_write_slice};

use super::{KernelHost, errno, port_result};
use crate::{
    StarryError,
    file::{File, FileLike, add_file_like, close_file_like, get_file_like},
    mm::{VmBytes, VmBytesMut},
    syscall,
    task::{AsThread, current_pid_view, do_exit},
};

/// `O_CLOEXEC` as the generic ABI defines it, the only flag `dup3` accepts.
const O_CLOEXEC: i32 = 0o2000000;

impl Platform for KernelHost {
    fn read_user(&self, uaddr: usize, out: &mut [u8]) -> SysResult {
        // SAFETY: `MaybeUninit<u8>` has the same layout as `u8`, and the read
        // only ever stores initialized bytes into the buffer.
        let buf =
            unsafe { core::slice::from_raw_parts_mut(out.as_mut_ptr().cast::<MaybeUninit<u8>>(), out.len()) };
        vm_read_slice(uaddr as *const u8, buf).map_err(|e| errno(StarryError::from(e)))?;
        Ok(0)
    }

    fn write_user(&self, uaddr: usize, data: &[u8]) -> SysResult {
        vm_write_slice(uaddr as *mut u8, data).map_err(|e| errno(StarryError::from(e)))?;
        Ok(0)
    }
}

impl Tasks for KernelHost {
    fn getpid(&self) -> u32 {
        let curr = current();
        current_pid_view()
            .visible_process_number(&curr.as_thread().proc_data.identity())
            .map_or(0, |pid| pid.get())
    }

    fn getppid(&self) -> u32 {
        let curr = current();
        curr.as_thread()
            .proc_data
            .proc
            .parent()
            .and_then(|parent| current_pid_view().visible_process_number(&parent.identity()))
            .map_or(0, |pid| pid.get())
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
        let file = File::from_fd(fd).map_err(errno)?;
        let read = file
            .inner()
            .read_at(VmBytesMut::new(uaddr as *mut u8, len), offset)
            .map_err(|e| errno(StarryError::from(e)))?;
        Ok(read as isize)
    }

    fn pwrite(&self, fd: i32, uaddr: usize, len: usize, offset: u64) -> SysResult {
        let file = File::from_fd(fd).map_err(errno)?;
        let written = file
            .inner()
            .write_at(VmBytes::new(uaddr as *const u8, len), offset)
            .map_err(|e| errno(StarryError::from(e)))?;
        Ok(written as isize)
    }

    // The remaining transfers still need their primitive lifted out of the
    // kernel's own syscall entry (the write path carries the file-object write
    // hook and the memfd seal checks; lseek, fsync and ftruncate carry the
    // per-file-kind dispatch). Until then the domain does not claim them, so
    // nothing routes through a port that would only forward a syscall.
    fn write(&self, fd: i32, uaddr: usize, len: usize) -> SysResult {
        port_result(syscall::sys_write(fd, uaddr as *mut u8, len))
    }

    fn lseek(&self, fd: i32, offset: isize, whence: i32) -> SysResult {
        port_result(syscall::sys_lseek(fd, offset as _, whence))
    }

    fn dup2(&self, oldfd: i32, newfd: i32, cloexec: bool) -> SysResult {
        #[cfg(target_arch = "x86_64")]
        if !cloexec {
            return port_result(syscall::sys_dup2(oldfd, newfd));
        }
        let flags = if cloexec { O_CLOEXEC } else { 0 };
        port_result(syscall::sys_dup3(oldfd, newfd, flags))
    }

    fn fsync(&self, fd: i32, datasync: bool) -> SysResult {
        port_result(if datasync {
            syscall::sys_fdatasync(fd)
        } else {
            syscall::sys_fsync(fd)
        })
    }

    fn ftruncate(&self, fd: i32, len: u64) -> SysResult {
        port_result(syscall::sys_ftruncate(fd, len as _))
    }
}

impl Mem for KernelHost {
    fn brk(&self, addr: usize) -> SysResult {
        port_result(syscall::sys_brk(addr))
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
        port_result(syscall::sys_mmap(addr, len, prot as u32, flags as u32, fd, offset as _))
    }

    fn munmap(&self, addr: usize, len: usize) -> SysResult {
        port_result(syscall::sys_munmap(addr, len))
    }

    fn mprotect(&self, addr: usize, len: usize, prot: i32) -> SysResult {
        port_result(syscall::sys_mprotect(addr, len, prot as u32))
    }

    fn madvise(&self, addr: usize, len: usize, advice: i32) -> SysResult {
        port_result(syscall::sys_madvise(addr, len, advice))
    }

    fn msync(&self, addr: usize, len: usize, flags: i32) -> SysResult {
        port_result(syscall::sys_msync(addr, len, flags as u32))
    }
}

impl Random for KernelHost {
    fn fill(&self, buf: &mut [u8]) -> SysResult {
        let entry = ax_fs_ng::vfs::current_fs_context()
            .lock()
            .resolve("/dev/urandom")
            .map_err(|e| errno(StarryError::from(e)))?;
        let file = entry
            .entry()
            .as_file()
            .map_err(|e| errno(StarryError::from(e)))?;
        file.read_at(buf, 0)
            .map(|n| n as isize)
            .map_err(|e| errno(StarryError::from(e)))
    }
}

impl Signals for KernelHost {
    fn kill(&self, pid: i32, sig: i32) -> SysResult {
        port_result(syscall::sys_kill(pid, sig as u32))
    }

    fn tgkill(&self, tgid: i32, tid: i32, sig: i32) -> SysResult {
        port_result(syscall::sys_tgkill(tgid, tid, sig as u32))
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
                _ => set,
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

    fn sleep_ns(&self, ns: u64) -> SysResult {
        block_on(interruptible(sleep(Duration::from_nanos(ns))))
            .map_err(|e| errno(StarryError::from(e)))?;
        Ok(0)
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
