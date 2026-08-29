//! NT system-call dispatch for the Windows personality.
//!
//! A NATIVE PE issues NT syscalls through the ntdll stubs it links. Because this
//! personality ships its own ntdll, it also owns the system-service numbers:
//! [`NtSyscall`] is our stable index space, not a copy of a particular Windows
//! build's volatile SSDT. [`dispatch`] reads the trapped register file, routes
//! the call number to a method of the [`NtApi`] capability, and writes back the
//! NTSTATUS - mirroring how the Linux personality turns a `Sysno` into a `sys_*`
//! call. This module is the pure, testable routing layer.
//!
//! [`NtApi`] is where an NT call reaches the machine, and it is meant to become
//! a thin translation over the shared `ax-abi-port` capabilities rather than a
//! second host interface: a handle resolves to a descriptor here, in the domain,
//! and the transfer itself uses the same file and memory ports the Linux domain
//! drives. That keeps one set of adapters in the hosting kernel.
//!
//! Argument positions follow the NT syscall signatures (`ntdll` prototypes /
//! ReactOS `ntoskrnl/io`,`mm`), read via the ABI-neutral [`TrapEnv`].

use ax_abi_port::{Host, MapRequest, MapSource, Prot};
use ax_dispatch::{Dispatch, TrapEnv};

use crate::handle::Handle;

/// An NTSTATUS code. The high bit marks failure, so [`Ntstatus::is_success`]
/// treats any non-negative value as success.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(transparent)]
pub struct Ntstatus(pub u32);

impl Ntstatus {
    /// `STATUS_SUCCESS`.
    pub const SUCCESS: Ntstatus = Ntstatus(0x0000_0000);
    /// `STATUS_NOT_IMPLEMENTED`.
    pub const NOT_IMPLEMENTED: Ntstatus = Ntstatus(0xC000_0002);
    /// `STATUS_INVALID_HANDLE`.
    pub const INVALID_HANDLE: Ntstatus = Ntstatus(0xC000_0008);
    /// `STATUS_INVALID_PARAMETER`.
    pub const INVALID_PARAMETER: Ntstatus = Ntstatus(0xC000_000D);
    /// `STATUS_ACCESS_VIOLATION`.
    pub const ACCESS_VIOLATION: Ntstatus = Ntstatus(0xC000_0005);
    /// `STATUS_UNSUCCESSFUL`.
    pub const UNSUCCESSFUL: Ntstatus = Ntstatus(0xC000_0001);

    /// Whether the status denotes success (top bit clear).
    pub const fn is_success(self) -> bool {
        self.0 & 0x8000_0000 == 0
    }
}

/// The NT system calls this personality implements, in its own stable order.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NtSyscall {
    /// `NtClose(Handle)`.
    Close,
    /// `NtWriteFile(...)`.
    WriteFile,
    /// `NtReadFile(...)`.
    ReadFile,
    /// `NtCreateFile(...)`.
    CreateFile,
    /// `NtAllocateVirtualMemory(...)`.
    AllocateVirtualMemory,
    /// `NtProtectVirtualMemory(...)`.
    ProtectVirtualMemory,
    /// `NtFreeVirtualMemory(...)`.
    FreeVirtualMemory,
    /// `NtTerminateProcess(...)`.
    TerminateProcess,
    /// `NtQueryInformationProcess(...)`.
    QueryInformationProcess,
}

impl NtSyscall {
    /// Map a system-service number to its call, or `None` if unimplemented.
    pub const fn from_nr(nr: u32) -> Option<NtSyscall> {
        Some(match nr {
            0 => NtSyscall::Close,
            1 => NtSyscall::WriteFile,
            2 => NtSyscall::ReadFile,
            3 => NtSyscall::CreateFile,
            4 => NtSyscall::AllocateVirtualMemory,
            5 => NtSyscall::ProtectVirtualMemory,
            6 => NtSyscall::FreeVirtualMemory,
            7 => NtSyscall::TerminateProcess,
            8 => NtSyscall::QueryInformationProcess,
            _ => return None,
        })
    }

    /// The system-service number for this call.
    pub const fn nr(self) -> u32 {
        self as u32
    }
}

/// Translate a port error into the NTSTATUS a Windows program expects.
fn status_from_errno(errno: i32) -> Ntstatus {
    match errno {
        ax_abi_port::EBADF => Ntstatus::INVALID_HANDLE,
        ax_abi_port::EINVAL => Ntstatus::INVALID_PARAMETER,
        ax_abi_port::EFAULT => Ntstatus::ACCESS_VIOLATION,
        ax_abi_port::ENOSYS => Ntstatus::NOT_IMPLEMENTED,
        _ => Ntstatus::UNSUCCESSFUL,
    }
}

/// The 64-bit `IO_STATUS_BLOCK`: the status word, then the byte count.
fn write_io_status(host: &dyn Host, at: usize, status: Ntstatus, information: usize) -> Ntstatus {
    if at == 0 {
        return status;
    }
    let mut block = [0u8; 16];
    block[..8].copy_from_slice(&u64::from(status.0).to_le_bytes());
    block[8..].copy_from_slice(&(information as u64).to_le_bytes());
    match host.platform().write_user(at, &block) {
        Ok(_) => status,
        Err(errno) => status_from_errno(errno),
    }
}

/// Read a `PVOID*` out of user memory.
fn read_pointer(host: &dyn Host, at: usize) -> Result<usize, Ntstatus> {
    let mut buf = [0u8; 8];
    host.platform()
        .read_user(at, &mut buf)
        .map_err(status_from_errno)?;
    Ok(u64::from_le_bytes(buf) as usize)
}

/// Translate the `PAGE_*` protection constants a Windows caller passes.
fn prot_from_page(protect: usize) -> Prot {
    const PAGE_READONLY: usize = 0x02;
    const PAGE_READWRITE: usize = 0x04;
    const PAGE_EXECUTE: usize = 0x10;
    const PAGE_EXECUTE_READ: usize = 0x20;
    const PAGE_EXECUTE_READWRITE: usize = 0x40;
    match protect & 0xFF {
        PAGE_READONLY => Prot::READ,
        PAGE_READWRITE => Prot::READ | Prot::WRITE,
        PAGE_EXECUTE => Prot::EXEC,
        PAGE_EXECUTE_READ => Prot::READ | Prot::EXEC,
        PAGE_EXECUTE_READWRITE => Prot::READ | Prot::WRITE | Prot::EXEC,
        _ => Prot::empty(),
    }
}

/// The descriptor an NT handle names. Handles are indices in this personality,
/// so a handle is a descriptor with the NT numbering applied.
fn descriptor(handle: usize) -> Result<i32, Ntstatus> {
    u32::try_from(handle)
        .ok()
        .and_then(|raw| Handle(raw).slot())
        .and_then(|index| i32::try_from(index).ok())
        .ok_or(Ntstatus::INVALID_HANDLE)
}

/// Service one trapped NT system call against the host's capabilities.
///
/// Reports [`Dispatch::Passthrough`] for a number this personality does not
/// implement, so the caller can apply its own answer. Argument positions follow
/// each call's NT prototype.
pub fn dispatch(env: &mut dyn TrapEnv, host: &dyn Host) -> Dispatch {
    let Some(call) = NtSyscall::from_nr(env.nr() as u32) else {
        return Dispatch::Passthrough;
    };
    let a = |i| env.arg(i);
    let status = match call {
        NtSyscall::Close => match (descriptor(a(0)), host.files()) {
            (Ok(fd), Some(files)) => files
                .close(fd)
                .map_or_else(status_from_errno, |_| Ntstatus::SUCCESS),
            (Err(status), _) => status,
            (_, None) => Ntstatus::NOT_IMPLEMENTED,
        },
        NtSyscall::WriteFile | NtSyscall::ReadFile => {
            let (Some(files), Ok(fd)) = (host.files(), descriptor(a(0))) else {
                return finish(env, Ntstatus::INVALID_HANDLE);
            };
            let (buffer, length, io_status) = (a(1), a(2), a(3));
            let transferred = if matches!(call, NtSyscall::WriteFile) {
                files.write(fd, buffer, length)
            } else {
                files.read(fd, buffer, length)
            };
            match transferred {
                Ok(n) => write_io_status(host, io_status, Ntstatus::SUCCESS, n as usize),
                Err(errno) => write_io_status(host, io_status, status_from_errno(errno), 0),
            }
        }
        NtSyscall::AllocateVirtualMemory => {
            let Some(mem) = host.mem() else {
                return finish(env, Ntstatus::NOT_IMPLEMENTED);
            };
            let (base_ptr, size, protect) = (a(1), a(2), a(3));
            let base = match read_pointer(host, base_ptr) {
                Ok(base) => base,
                Err(status) => return finish(env, status),
            };
            let request = MapRequest {
                addr: base,
                len: size,
                prot: prot_from_page(protect),
                fixed: base != 0,
                shared: false,
                source: MapSource::Anonymous,
            };
            match mem.map(&request) {
                Ok(at) => {
                    let placed = (at as usize as u64).to_le_bytes();
                    match host.platform().write_user(base_ptr, &placed) {
                        Ok(_) => Ntstatus::SUCCESS,
                        Err(errno) => status_from_errno(errno),
                    }
                }
                Err(errno) => status_from_errno(errno),
            }
        }
        NtSyscall::ProtectVirtualMemory => {
            let Some(mem) = host.mem() else {
                return finish(env, Ntstatus::NOT_IMPLEMENTED);
            };
            let base = match read_pointer(host, a(1)) {
                Ok(base) => base,
                Err(status) => return finish(env, status),
            };
            mem.protect(base, a(2), prot_from_page(a(3)))
                .map_or_else(status_from_errno, |_| Ntstatus::SUCCESS)
        }
        NtSyscall::FreeVirtualMemory => {
            let Some(mem) = host.mem() else {
                return finish(env, Ntstatus::NOT_IMPLEMENTED);
            };
            let base = match read_pointer(host, a(1)) {
                Ok(base) => base,
                Err(status) => return finish(env, status),
            };
            mem.unmap(base, a(2))
                .map_or_else(status_from_errno, |_| Ntstatus::SUCCESS)
        }
        NtSyscall::TerminateProcess => match host.tasks() {
            Some(tasks) => tasks
                .exit_group(a(1) as i32)
                .map_or_else(status_from_errno, |_| Ntstatus::SUCCESS),
            None => Ntstatus::NOT_IMPLEMENTED,
        },
        // Opening by name needs a path capability, and the process-information
        // classes need process metadata; neither port exists yet, so these stay
        // with the caller rather than answering with something invented.
        NtSyscall::CreateFile | NtSyscall::QueryInformationProcess => {
            return Dispatch::Passthrough;
        }
    };
    finish(env, status)
}

/// Write an NTSTATUS back and report the call as serviced.
fn finish(env: &mut dyn TrapEnv, status: Ntstatus) -> Dispatch {
    env.set_result(status.0 as usize);
    Dispatch::Handled
}

#[cfg(test)]
mod tests {
    use alloc::{vec, vec::Vec};
    use core::cell::RefCell;

    use super::*;

    #[test]
    fn status_success_and_failure() {
        assert!(Ntstatus::SUCCESS.is_success());
        assert!(!Ntstatus::NOT_IMPLEMENTED.is_success());
        assert!(!Ntstatus::INVALID_HANDLE.is_success());
    }

    #[test]
    fn syscall_numbers_round_trip() {
        for nr in 0..9 {
            assert_eq!(NtSyscall::from_nr(nr).unwrap().nr(), nr);
        }
        assert_eq!(NtSyscall::from_nr(9), None);
    }

    // A trap frame with preset syscall number and arguments.
    struct FakeTrap {
        nr: usize,
        args: [usize; 9],
        result: Option<usize>,
    }
    impl TrapEnv for FakeTrap {
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

    // A host whose file port records what it was asked to move, and whose user
    // memory is one flat buffer at address zero.
    #[derive(Default)]
    struct MockHost {
        mem: RefCell<Vec<u8>>,
        wrote: RefCell<Option<(i32, usize, usize)>>,
        closed: RefCell<Option<i32>>,
        mapped: RefCell<Option<MapRequest>>,
    }
    // The tests are single-threaded; the ports ask for Sync on a real host.
    unsafe impl Sync for MockHost {}

    impl ax_abi_port::Platform for MockHost {
        fn read_user(&self, uaddr: usize, out: &mut [u8]) -> ax_abi_port::SysResult {
            let mem = self.mem.borrow();
            let end = uaddr + out.len();
            if end > mem.len() {
                return Err(ax_abi_port::EFAULT);
            }
            out.copy_from_slice(&mem[uaddr..end]);
            Ok(0)
        }
        fn write_user(&self, uaddr: usize, data: &[u8]) -> ax_abi_port::SysResult {
            let mut mem = self.mem.borrow_mut();
            let end = uaddr + data.len();
            if end > mem.len() {
                return Err(ax_abi_port::EFAULT);
            }
            mem[uaddr..end].copy_from_slice(data);
            Ok(0)
        }
    }

    impl ax_abi_port::Files for MockHost {
        fn read(&self, _fd: i32, _uaddr: usize, len: usize) -> ax_abi_port::SysResult {
            Ok(len as isize)
        }
        fn write(&self, fd: i32, uaddr: usize, len: usize) -> ax_abi_port::SysResult {
            *self.wrote.borrow_mut() = Some((fd, uaddr, len));
            Ok(len as isize)
        }
        fn close(&self, fd: i32) -> ax_abi_port::SysResult {
            *self.closed.borrow_mut() = Some(fd);
            Ok(0)
        }
        fn dup(&self, _fd: i32) -> ax_abi_port::SysResult {
            Ok(0)
        }
        fn seek(&self, _fd: i32, o: isize, _f: ax_abi_port::SeekFrom) -> ax_abi_port::SysResult {
            Ok(o)
        }
        fn validate(&self, _fd: i32) -> ax_abi_port::SysResult {
            Ok(0)
        }
        fn seekable(&self, _fd: i32) -> ax_abi_port::SysResult {
            Ok(0)
        }
        fn readv(&self, _fd: i32, _segs: &[ax_abi_port::Segment]) -> ax_abi_port::SysResult {
            Ok(0)
        }
        fn preadv(
            &self,
            _fd: i32,
            _segs: &[ax_abi_port::Segment],
            _offset: u64,
        ) -> ax_abi_port::SysResult {
            Ok(0)
        }
        fn writev(&self, _fd: i32, _segs: &[ax_abi_port::Segment]) -> ax_abi_port::SysResult {
            Ok(0)
        }
        fn pwritev(
            &self,
            _fd: i32,
            _segs: &[ax_abi_port::Segment],
            _offset: u64,
        ) -> ax_abi_port::SysResult {
            Ok(0)
        }
        fn pread(&self, _fd: i32, _u: usize, len: usize, _o: u64) -> ax_abi_port::SysResult {
            Ok(len as isize)
        }
        fn pwrite(&self, _fd: i32, _u: usize, len: usize, _o: u64) -> ax_abi_port::SysResult {
            Ok(len as isize)
        }
        fn dup_onto(&self, _old: i32, new: i32, _cloexec: bool) -> ax_abi_port::SysResult {
            Ok(new as isize)
        }
        fn fsync(&self, _fd: i32, _datasync: bool) -> ax_abi_port::SysResult {
            Ok(0)
        }
        fn ftruncate(&self, _fd: i32, _len: u64) -> ax_abi_port::SysResult {
            Ok(0)
        }
    }

    impl ax_abi_port::Mem for MockHost {
        fn brk(&self) -> usize {
            0
        }
        fn set_brk(&self, _addr: usize) -> ax_abi_port::SysResult {
            Ok(0)
        }
        fn map(&self, req: &MapRequest) -> ax_abi_port::SysResult {
            *self.mapped.borrow_mut() = Some(*req);
            Ok(0x4000)
        }
        fn unmap(&self, _addr: usize, _len: usize) -> ax_abi_port::SysResult {
            Ok(0)
        }
        fn protect(&self, _a: usize, _l: usize, _p: Prot) -> ax_abi_port::SysResult {
            Ok(0)
        }
        fn advise(&self, _a: usize, _l: usize, _adv: i32) -> ax_abi_port::SysResult {
            Ok(0)
        }
        fn writeback(&self, _a: usize, _l: usize) -> ax_abi_port::SysResult {
            Ok(0)
        }
    }

    impl Host for MockHost {
        fn platform(&self) -> &dyn ax_abi_port::Platform {
            self
        }
        fn files(&self) -> Option<&dyn ax_abi_port::Files> {
            Some(self)
        }
        fn mem(&self) -> Option<&dyn ax_abi_port::Mem> {
            Some(self)
        }
    }

    // The personality resolves its host through the platform binding, so the
    // test binary provides one; these tests pass their own host directly.
    struct StaticHost;
    impl ax_abi_port::Platform for StaticHost {
        fn read_user(&self, _u: usize, _o: &mut [u8]) -> ax_abi_port::SysResult {
            Ok(0)
        }
        fn write_user(&self, _u: usize, _d: &[u8]) -> ax_abi_port::SysResult {
            Ok(0)
        }
    }
    impl Host for StaticHost {
        fn platform(&self) -> &dyn ax_abi_port::Platform {
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

    fn trap(call: NtSyscall, args: [usize; 9]) -> FakeTrap {
        FakeTrap {
            nr: call.nr() as usize,
            args,
            result: None,
        }
    }

    #[test]
    fn write_file_moves_bytes_through_the_file_port() {
        let host = MockHost {
            mem: RefCell::new(vec![0u8; 0x100]),
            ..MockHost::default()
        };
        // NtWriteFile(handle 4 = descriptor 0, buffer 0x40, 8 bytes, iosb 0x80).
        let mut env = trap(NtSyscall::WriteFile, [4, 0x40, 8, 0x80, 0, 0, 0, 0, 0]);
        assert_eq!(dispatch(&mut env, &host), Dispatch::Handled);
        assert_eq!(env.result, Some(Ntstatus::SUCCESS.0 as usize));
        assert_eq!(*host.wrote.borrow(), Some((0, 0x40, 8)));
        // The IO_STATUS_BLOCK carries the status and the byte count.
        let mem = host.mem.borrow();
        assert_eq!(u64::from_le_bytes(mem[0x80..0x88].try_into().unwrap()), 0);
        assert_eq!(u64::from_le_bytes(mem[0x88..0x90].try_into().unwrap()), 8);
    }

    #[test]
    fn close_takes_the_descriptor_the_handle_names() {
        let host = MockHost::default();
        // Handle 8 is the second slot, which is descriptor 1.
        let mut env = trap(NtSyscall::Close, [8, 0, 0, 0, 0, 0, 0, 0, 0]);
        assert_eq!(dispatch(&mut env, &host), Dispatch::Handled);
        assert_eq!(*host.closed.borrow(), Some(1));
        // A misaligned handle is not a descriptor.
        let mut bad = trap(NtSyscall::Close, [3, 0, 0, 0, 0, 0, 0, 0, 0]);
        assert_eq!(dispatch(&mut bad, &host), Dispatch::Handled);
        assert_eq!(bad.result, Some(Ntstatus::INVALID_HANDLE.0 as usize));
    }

    #[test]
    fn allocate_virtual_memory_asks_for_an_anonymous_mapping() {
        let host = MockHost {
            mem: RefCell::new(vec![0u8; 0x100]),
            ..MockHost::default()
        };
        // *base = 0 asks the host to choose; PAGE_READWRITE is 0x04.
        let mut env = trap(
            NtSyscall::AllocateVirtualMemory,
            [0, 0x10, 0x2000, 0x04, 0, 0, 0, 0, 0],
        );
        assert_eq!(dispatch(&mut env, &host), Dispatch::Handled);
        assert_eq!(env.result, Some(Ntstatus::SUCCESS.0 as usize));
        let request = host.mapped.borrow().unwrap();
        assert_eq!(request.len, 0x2000);
        assert_eq!(request.prot, Prot::READ | Prot::WRITE);
        assert_eq!(request.source, MapSource::Anonymous);
        assert!(!request.fixed);
        // The chosen address is written back to *base.
        let mem = host.mem.borrow();
        assert_eq!(
            u64::from_le_bytes(mem[0x10..0x18].try_into().unwrap()),
            0x4000
        );
    }

    #[test]
    fn a_call_without_a_port_stays_with_the_caller() {
        let host = MockHost::default();
        // Opening by name needs a capability this platform has no port for.
        let mut env = trap(NtSyscall::CreateFile, [0; 9]);
        assert_eq!(dispatch(&mut env, &host), Dispatch::Passthrough);
        assert_eq!(env.result, None);
    }
}
