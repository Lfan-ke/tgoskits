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

use ax_binfmt::TrapEnv;

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

/// The kernel-provided implementation of the NT system calls, each mapping onto
/// the shared `ax-*` primitives. A small capability boundary, like the Linux
/// personality's `sys_*` layer; pointer arguments are raw user addresses the
/// implementor reads or writes.
pub trait NtApi {
    /// `NtClose(Handle)`.
    fn nt_close(&mut self, handle: usize) -> Ntstatus;
    /// `NtWriteFile`: write `length` bytes at `buffer` to `handle`, reporting
    /// through `io_status`.
    fn nt_write_file(
        &mut self,
        handle: usize,
        buffer: usize,
        length: usize,
        io_status: usize,
    ) -> Ntstatus;
    /// `NtReadFile`: read up to `length` bytes from `handle` into `buffer`.
    fn nt_read_file(
        &mut self,
        handle: usize,
        buffer: usize,
        length: usize,
        io_status: usize,
    ) -> Ntstatus;
    /// `NtCreateFile`: open/create, storing the handle at `out_handle`.
    fn nt_create_file(
        &mut self,
        out_handle: usize,
        access: usize,
        obj_attr: usize,
        io_status: usize,
    ) -> Ntstatus;
    /// `NtAllocateVirtualMemory`: reserve/commit `size` at `*base` in `process`.
    fn nt_allocate_virtual_memory(
        &mut self,
        process: usize,
        base: usize,
        size: usize,
        protect: usize,
    ) -> Ntstatus;
    /// `NtProtectVirtualMemory`: change protection of `size` at `*base`.
    fn nt_protect_virtual_memory(
        &mut self,
        process: usize,
        base: usize,
        size: usize,
        protect: usize,
    ) -> Ntstatus;
    /// `NtFreeVirtualMemory`: release `size` at `*base` in `process`.
    fn nt_free_virtual_memory(&mut self, process: usize, base: usize, size: usize) -> Ntstatus;
    /// `NtTerminateProcess`: end `process` with `status`.
    fn nt_terminate_process(&mut self, process: usize, status: usize) -> Ntstatus;
    /// `NtQueryInformationProcess`: fill `buffer` for information `class`.
    fn nt_query_information_process(
        &mut self,
        process: usize,
        class: usize,
        buffer: usize,
        length: usize,
    ) -> Ntstatus;
}

/// Route one trapped NT syscall to `api` and write back its NTSTATUS.
///
/// Returns `false` (leaving the result unset) when `env.nr()` names no
/// implemented call, so the caller can raise the personality's own "unknown
/// syscall" path. Argument indices follow each call's NT prototype.
pub fn dispatch(env: &mut dyn TrapEnv, api: &mut dyn NtApi) -> bool {
    let Some(call) = NtSyscall::from_nr(env.nr() as u32) else {
        return false;
    };
    let a = |i| env.arg(i);
    let status = match call {
        NtSyscall::Close => api.nt_close(a(0)),
        // NtWriteFile(FileHandle, Event, Apc, ApcCtx, IoStatusBlock, Buffer, Length, ...).
        NtSyscall::WriteFile => api.nt_write_file(a(0), a(5), a(6), a(4)),
        NtSyscall::ReadFile => api.nt_read_file(a(0), a(5), a(6), a(4)),
        // NtCreateFile(FileHandle*, DesiredAccess, ObjectAttributes, IoStatusBlock, ...).
        NtSyscall::CreateFile => api.nt_create_file(a(0), a(1), a(2), a(3)),
        // NtAllocateVirtualMemory(Process, BaseAddress*, ZeroBits, RegionSize*, Type, Protect).
        NtSyscall::AllocateVirtualMemory => api.nt_allocate_virtual_memory(a(0), a(1), a(3), a(5)),
        // NtProtectVirtualMemory(Process, BaseAddress*, RegionSize*, NewProtect, OldProtect*).
        NtSyscall::ProtectVirtualMemory => api.nt_protect_virtual_memory(a(0), a(1), a(2), a(3)),
        // NtFreeVirtualMemory(Process, BaseAddress*, RegionSize*, FreeType).
        NtSyscall::FreeVirtualMemory => api.nt_free_virtual_memory(a(0), a(1), a(2)),
        NtSyscall::TerminateProcess => api.nt_terminate_process(a(0), a(1)),
        // NtQueryInformationProcess(Process, Class, Buffer, Length, ReturnLength*).
        NtSyscall::QueryInformationProcess => {
            api.nt_query_information_process(a(0), a(1), a(2), a(3))
        }
    };
    env.set_result(status.0 as usize);
    true
}

#[cfg(test)]
mod tests {
    use alloc::vec::Vec;

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

    // Records which NtApi method ran, so dispatch's routing is observable.
    #[derive(Default)]
    struct SpyApi {
        calls: Vec<(&'static str, [usize; 4])>,
    }
    impl SpyApi {
        fn note(&mut self, name: &'static str, a: [usize; 4]) -> Ntstatus {
            self.calls.push((name, a));
            Ntstatus::SUCCESS
        }
    }
    impl NtApi for SpyApi {
        fn nt_close(&mut self, h: usize) -> Ntstatus {
            self.note("close", [h, 0, 0, 0])
        }
        fn nt_write_file(&mut self, h: usize, b: usize, l: usize, s: usize) -> Ntstatus {
            self.note("write", [h, b, l, s])
        }
        fn nt_read_file(&mut self, h: usize, b: usize, l: usize, s: usize) -> Ntstatus {
            self.note("read", [h, b, l, s])
        }
        fn nt_create_file(&mut self, o: usize, a: usize, oa: usize, s: usize) -> Ntstatus {
            self.note("create", [o, a, oa, s])
        }
        fn nt_allocate_virtual_memory(
            &mut self,
            p: usize,
            b: usize,
            s: usize,
            pr: usize,
        ) -> Ntstatus {
            self.note("alloc", [p, b, s, pr])
        }
        fn nt_protect_virtual_memory(
            &mut self,
            p: usize,
            b: usize,
            s: usize,
            pr: usize,
        ) -> Ntstatus {
            self.note("protect", [p, b, s, pr])
        }
        fn nt_free_virtual_memory(&mut self, p: usize, b: usize, s: usize) -> Ntstatus {
            self.note("free", [p, b, s, 0])
        }
        fn nt_terminate_process(&mut self, p: usize, s: usize) -> Ntstatus {
            self.note("terminate", [p, s, 0, 0])
        }
        fn nt_query_information_process(
            &mut self,
            p: usize,
            c: usize,
            b: usize,
            l: usize,
        ) -> Ntstatus {
            self.note("query", [p, c, b, l])
        }
    }

    #[test]
    fn dispatch_routes_write_file_args() {
        // NtWriteFile: buffer is arg5, length arg6, io_status arg4.
        let mut trap = FakeTrap {
            nr: NtSyscall::WriteFile.nr() as usize,
            args: [10, 0, 0, 0, 44, 55, 66, 0, 0],
            result: None,
        };
        let mut api = SpyApi::default();
        assert!(dispatch(&mut trap, &mut api));
        assert_eq!(api.calls, [("write", [10, 55, 66, 44])]);
        assert_eq!(trap.result, Some(Ntstatus::SUCCESS.0 as usize));
    }

    #[test]
    fn dispatch_rejects_unknown_number() {
        let mut trap = FakeTrap {
            nr: 999,
            args: [0; 9],
            result: None,
        };
        let mut api = SpyApi::default();
        assert!(!dispatch(&mut trap, &mut api));
        assert!(trap.result.is_none());
        assert!(api.calls.is_empty());
    }
}
