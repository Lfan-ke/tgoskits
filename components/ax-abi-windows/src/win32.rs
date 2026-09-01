//! Win32 entry points, layered on the NT calls the way kernel32 is.
//!
//! On Windows these live in kernel32 and kernelbase, ordinary user-mode DLLs
//! that call down into ntdll: `WriteFile` is `NtWriteFile` plus the Win32
//! conventions - clear the out-parameter first, turn the `NTSTATUS` into a
//! `BOOL`, and record the failure where `GetLastError` reads it (Wine
//! `dlls/kernelbase/file.c`, `dlls/ntdll/error.c`). There is no ntdll here to
//! carry them, so an image's imports bind to stubs synthesized into the image
//! and each stub traps on a number reserved below. The layering is kept all
//! the same: the work stays in [`crate::nt`] and the ports, and this module
//! only applies the conventions.
//!
//! Every function a C runtime imports on its way to `main` is in the table, so
//! an image binds; the ones not yet given their meaning fail when called, with
//! `ERROR_CALL_NOT_IMPLEMENTED` where `GetLastError` reads it, which is how
//! Wine's own stubs answer. Nothing here succeeds without doing the work.
//!
//! Every argument is read from the trap frame, none from the stack: the stub
//! an import binds to ([`crate::thunk`]) has already moved the Windows
//! registers and the two stack arguments into the registers a trap carries.
//!
//! State that Windows keeps in the process - the last error, TLS slots, the
//! loaded-module list, the heap - is kept where Windows keeps it, in the TEB
//! and PEB and the structures they point at, so a program reading them
//! directly sees what the functions report.

use ax_abi_port::{Host, MapRequest, MapSource, Prot};
use ax_dispatch::{Dispatch, TrapEnv};

use crate::{
    handle::Handle,
    nt::{self, Ntstatus},
    teb_peb::{
        PEB_BEING_DEBUGGED, PEB_IMAGE_BASE, PEB_LDR, PEB_PROCESS_HEAP, PEB_TLS_BITMAP_BITS,
        TEB_LAST_ERROR, TEB_PEB, TEB_TLS_SLOTS,
    },
};

/// First trap number reserved for a Win32 entry point.
///
/// NT call numbers are small and dense, so starting well above them keeps the
/// two vocabularies apart and lets a trap say which layer it came from.
pub const WIN32_BASE: u32 = 0x1000;

/// A Win32 `BOOL` that says the call succeeded.
const TRUE: usize = 1;
/// A Win32 `BOOL` that says the call failed; the reason is in the last error.
const FALSE: usize = 0;

// `GetStdHandle` selectors and its failure value (`winbase.h`).
const STD_INPUT_HANDLE: u32 = -10i32 as u32;
const STD_OUTPUT_HANDLE: u32 = -11i32 as u32;
const STD_ERROR_HANDLE: u32 = -12i32 as u32;
const INVALID_HANDLE_VALUE: usize = usize::MAX;

// Win32 error codes (`winerror.h`).
const ERROR_INVALID_PARAMETER: u32 = 87;
const ERROR_CALL_NOT_IMPLEMENTED: u32 = 120;
const ERROR_NOT_ENOUGH_MEMORY: u32 = 8;
const ERROR_NO_MORE_ITEMS: u32 = 259;
const ERROR_MOD_NOT_FOUND: u32 = 126;
const ERROR_PROC_NOT_FOUND: u32 = 127;

/// `TLS_MINIMUM_AVAILABLE`: slots in the TEB itself; more would live in the
/// expansion array, which nothing here allocates yet.
const TLS_SLOTS: u32 = 64;

/// `HEAP_ZERO_MEMORY`.
const HEAP_ZERO_MEMORY: usize = 0x8;

/// `PROCESSOR_FEATURE_MAX`.
const PROCESSOR_FEATURE_MAX: u32 = 64;

/// Wine's `TICKSPERSEC`: the performance counter, like the system time, counts
/// hundred-nanosecond ticks.
const TICKS_PER_SEC: u64 = 10_000_000;

/// Hundred-nanosecond ticks from 1601-01-01 to 1970-01-01 - the gap between a
/// `FILETIME` and a Unix clock.
const TICKS_1601_TO_1970: u64 = 116_444_736_000_000_000;

/// The Win32 entry points this package binds, by name.
///
/// The position in this table is the call's number above [`WIN32_BASE`], so a
/// stub can be told which entry it stands for and a trap can be routed back.
/// Every name a C runtime and CPython's launcher import from kernel32 is here,
/// so such an image links; [`dispatch`] says which of them do their work.
const TABLE: &[&str] = &[
    "WriteFile",
    "GetStdHandle",
    "GetLastError",
    "SetLastError",
    "ExitProcess",
    "GetCurrentProcessId",
    "GetCurrentThreadId",
    "GetCurrentProcess",
    "GetCurrentThread",
    "GetSystemTimeAsFileTime",
    "QueryPerformanceCounter",
    "QueryPerformanceFrequency",
    "IsProcessorFeaturePresent",
    "IsDebuggerPresent",
    "SetUnhandledExceptionFilter",
    "UnhandledExceptionFilter",
    "EncodePointer",
    "DecodePointer",
    "InitializeSListHead",
    "TlsAlloc",
    "TlsGetValue",
    "TlsSetValue",
    "TlsFree",
    "GetProcessHeap",
    "HeapAlloc",
    "HeapFree",
    "HeapReAlloc",
    "HeapSize",
    "InitializeCriticalSectionAndSpinCount",
    "InitializeCriticalSectionEx",
    "EnterCriticalSection",
    "LeaveCriticalSection",
    "DeleteCriticalSection",
    "GetModuleHandleW",
    "GetProcAddress",
    "TerminateProcess",
    "CloseHandle",
    "Sleep",
    "VirtualAlloc",
    "VirtualProtect",
    // Bound so the runtime links; each fails with ERROR_CALL_NOT_IMPLEMENTED
    // when reached, until it is given its meaning.
    "Beep",
    "CompareStringW",
    "CreateDirectoryW",
    "CreateFileW",
    "CreatePipe",
    "CreateProcessW",
    "CreateThread",
    "DeleteFileW",
    "DuplicateHandle",
    "EnumSystemLocalesW",
    "ExitThread",
    "FileTimeToSystemTime",
    "FindClose",
    "FindFirstFileExW",
    "FindNextFileW",
    "FlsAlloc",
    "FlsFree",
    "FlsGetValue",
    "FlsSetValue",
    "FlushFileBuffers",
    "FreeEnvironmentStringsW",
    "FreeLibrary",
    "FreeLibraryAndExitThread",
    "GetACP",
    "GetCPInfo",
    "GetCommandLineA",
    "GetCommandLineW",
    "GetConsoleCP",
    "GetConsoleMode",
    "GetConsoleOutputCP",
    "GetCurrentDirectoryW",
    "GetDateFormatW",
    "GetDiskFreeSpaceW",
    "GetDriveTypeW",
    "GetEnvironmentStringsW",
    "GetExitCodeProcess",
    "GetFileAttributesExW",
    "GetFileInformationByHandle",
    "GetFileSizeEx",
    "GetFileType",
    "GetFullPathNameW",
    "GetLocalTime",
    "GetLocaleInfoW",
    "GetLogicalDrives",
    "GetModuleFileNameW",
    "GetModuleHandleExW",
    "GetNumberOfConsoleInputEvents",
    "GetOEMCP",
    "GetStartupInfoW",
    "GetStringTypeW",
    "GetSystemInfo",
    "GetTempPathW",
    "GetTimeFormatW",
    "GetTimeZoneInformation",
    "GetUserDefaultLCID",
    "HeapCompact",
    "HeapQueryInformation",
    "HeapValidate",
    "HeapWalk",
    "InterlockedFlushSList",
    "InterlockedPushEntrySList",
    "IsThreadAFiber",
    "IsValidCodePage",
    "IsValidLocale",
    "LCMapStringW",
    "LoadLibraryExW",
    "LockFileEx",
    "MoveFileExW",
    "MultiByteToWideChar",
    "OutputDebugStringW",
    "PeekConsoleInputA",
    "PeekNamedPipe",
    "RaiseException",
    "ReadConsoleInputW",
    "ReadConsoleW",
    "ReadFile",
    "RemoveDirectoryW",
    "ResumeThread",
    "RtlCaptureContext",
    "RtlLookupFunctionEntry",
    "RtlPcToFileHeader",
    "RtlUnwind",
    "RtlUnwindEx",
    "RtlVirtualUnwind",
    "SetConsoleCtrlHandler",
    "SetConsoleMode",
    "SetCurrentDirectoryW",
    "SetEndOfFile",
    "SetEnvironmentVariableW",
    "SetErrorMode",
    "SetFileAttributesW",
    "SetFilePointerEx",
    "SetFileTime",
    "SetLocalTime",
    "SetStdHandle",
    "SystemTimeToFileTime",
    "SystemTimeToTzSpecificLocalTime",
    "TzSpecificLocalTimeToSystemTime",
    "UnlockFileEx",
    "VerSetConditionMask",
    "VerifyVersionInfoW",
    "VirtualQuery",
    "WaitForSingleObject",
    "WideCharToMultiByte",
    "WriteConsoleW",
];

/// A Win32 entry point this package binds: an index into [`TABLE`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Win32Call(u32);

impl Win32Call {
    /// The call a trap number names, or `None` for a number outside this layer.
    pub fn from_nr(nr: u32) -> Option<Win32Call> {
        let index = nr.checked_sub(WIN32_BASE)?;
        (index < TABLE.len() as u32).then_some(Win32Call(index))
    }

    /// The trap number a stub for this call raises.
    pub fn nr(self) -> u32 {
        WIN32_BASE + self.0
    }

    /// The exported name an image imports this call by.
    pub fn symbol(self) -> &'static str {
        TABLE[self.0 as usize]
    }

    /// The library an image expects to import this call from.
    pub fn library(self) -> &'static str {
        "KERNEL32.dll"
    }

    /// The call an import names, or `None` for one no stub is synthesized for.
    ///
    /// A library name is matched without regard to case, as the loader matches
    /// it; an export name is matched exactly, as the linker wrote it.
    pub fn resolve(library: &str, symbol: &str) -> Option<Win32Call> {
        if !library.eq_ignore_ascii_case("KERNEL32.dll") {
            return None;
        }
        Self::named(symbol)
    }

    /// The call with exactly this export name.
    pub fn named(symbol: &str) -> Option<Win32Call> {
        TABLE
            .iter()
            .position(|name| *name == symbol)
            .map(|at| Win32Call(at as u32))
    }

    /// Well-known calls, by name, for code that needs one in particular.
    pub const EXIT_PROCESS: Win32Call = Win32Call(4);
    pub const WRITE_FILE: Win32Call = Win32Call(0);
}

/// What a trap is looking at: the frame, the host, and the thread's block.
struct Call<'a> {
    env: &'a mut dyn TrapEnv,
    host: &'a dyn Host,
    teb: usize,
}

impl Call<'_> {
    fn arg(&self, i: usize) -> usize {
        self.env.arg(i)
    }

    fn read<const N: usize>(&self, at: usize) -> Option<[u8; N]> {
        let mut out = [0u8; N];
        self.host.platform().read_user(at, &mut out).ok()?;
        Some(out)
    }

    fn read_u32(&self, at: usize) -> Option<u32> {
        self.read::<4>(at).map(u32::from_le_bytes)
    }

    fn read_u64(&self, at: usize) -> Option<u64> {
        self.read::<8>(at).map(u64::from_le_bytes)
    }

    fn write(&self, at: usize, bytes: &[u8]) -> bool {
        self.host.platform().write_user(at, bytes).is_ok()
    }

    fn write_u32(&self, at: usize, value: u32) -> bool {
        self.write(at, &value.to_le_bytes())
    }

    fn write_u64(&self, at: usize, value: u64) -> bool {
        self.write(at, &value.to_le_bytes())
    }

    /// The PEB, through the TEB, as `NtCurrentTeb()->Peb`.
    fn peb(&self) -> Option<usize> {
        (self.teb != 0)
            .then(|| self.read_u64(self.teb + TEB_PEB))
            .flatten()
            .map(|va| va as usize)
    }

    fn set_last_error(&self, error: u32) {
        if self.teb != 0 {
            self.write_u32(self.teb + TEB_LAST_ERROR, error);
        }
    }

    fn last_error(&self) -> u32 {
        (self.teb != 0)
            .then(|| self.read_u32(self.teb + TEB_LAST_ERROR))
            .flatten()
            .unwrap_or(0)
    }

    /// Answer `result` after recording why the call failed.
    fn fail(&mut self, error: u32, result: usize) -> Dispatch {
        self.set_last_error(error);
        self.finish(result)
    }

    /// Answer `result` after recording the Win32 error an NT status maps to.
    fn fail_status(&mut self, status: Ntstatus, result: usize) -> Dispatch {
        self.fail(status.dos_error(), result)
    }

    fn finish(&mut self, value: usize) -> Dispatch {
        self.env.set_result(value);
        Dispatch::Handled
    }
}

/// Serve a Win32 entry point, or decline a number that names none.
pub fn dispatch(env: &mut dyn TrapEnv, host: &dyn Host) -> Dispatch {
    let Some(call) = Win32Call::from_nr(env.nr() as u32) else {
        return Dispatch::Passthrough;
    };
    let teb = env.thread_pointer();
    let mut c = Call { env, host, teb };
    match call.symbol() {
        "WriteFile" => write_file(&mut c),
        "GetStdHandle" => get_std_handle(&mut c),
        "GetLastError" => {
            let error = c.last_error() as usize;
            c.finish(error)
        }
        "SetLastError" => {
            c.set_last_error(c.arg(0) as u32);
            c.finish(0)
        }
        // ExitProcess ends every thread in the process, which is exit_group and
        // not exit. A host that returns from it leaves the caller holding a
        // value, so say the call did not succeed.
        "ExitProcess" | "TerminateProcess" => {
            let code = if call.symbol() == "ExitProcess" {
                c.arg(0)
            } else {
                c.arg(1)
            };
            let Some(tasks) = host.tasks() else {
                return c.fail(ERROR_CALL_NOT_IMPLEMENTED, FALSE);
            };
            let _ = tasks.exit_group(code as i32);
            c.finish(FALSE)
        }
        // Windows reads both out of the TEB's ClientId; the host is the one
        // that knows them here, and the answer is the same.
        "GetCurrentProcessId" => match host.tasks().map(|t| t.getpid()) {
            Some(Ok(pid)) => c.finish(pid as usize),
            _ => c.fail(ERROR_CALL_NOT_IMPLEMENTED, 0),
        },
        "GetCurrentThreadId" => match host.tasks() {
            Some(tasks) => {
                let tid = tasks.gettid() as usize;
                c.finish(tid)
            }
            None => c.fail(ERROR_CALL_NOT_IMPLEMENTED, 0),
        },
        // The pseudo-handles, as `NtCurrentProcess()` and `NtCurrentThread()`.
        "GetCurrentProcess" => c.finish(Handle::CURRENT_PROCESS.0 as usize),
        "GetCurrentThread" => c.finish(Handle::CURRENT_THREAD.0 as usize),
        "GetSystemTimeAsFileTime" => {
            let Some(clock) = host.clock() else {
                return c.fail(ERROR_CALL_NOT_IMPLEMENTED, 0);
            };
            // A FILETIME counts hundred-nanosecond ticks from 1601.
            let ticks = clock.wall_ns() / 100 + TICKS_1601_TO_1970;
            if !c.write_u64(c.arg(0), ticks) {
                return c.fail_status(Ntstatus::ACCESS_VIOLATION, 0);
            }
            c.finish(0)
        }
        "QueryPerformanceCounter" => {
            let Some(clock) = host.clock() else {
                return c.fail(ERROR_CALL_NOT_IMPLEMENTED, FALSE);
            };
            let ticks = clock.monotonic_ns() / 100;
            if !c.write_u64(c.arg(0), ticks) {
                return c.fail_status(Ntstatus::ACCESS_VIOLATION, FALSE);
            }
            c.finish(TRUE)
        }
        "QueryPerformanceFrequency" => {
            if !c.write_u64(c.arg(0), TICKS_PER_SEC) {
                return c.fail_status(Ntstatus::ACCESS_VIOLATION, FALSE);
            }
            c.finish(TRUE)
        }
        "IsProcessorFeaturePresent" => {
            let present = processor_feature_present(c.arg(0) as u32);
            c.finish(present as usize)
        }
        "IsDebuggerPresent" => {
            let debugged = c
                .peb()
                .and_then(|peb| c.read::<1>(peb + PEB_BEING_DEBUGGED))
                .is_some_and(|b| b[0] != 0);
            c.finish(debugged as usize)
        }
        // The filter is a per-process pointer; Windows keeps it in kernelbase's
        // data, this keeps it in the PEB's spare word for it. The old value
        // comes back, as InterlockedExchangePointer would return it.
        "SetUnhandledExceptionFilter" => {
            let Some(peb) = c.peb() else {
                return c.finish(0);
            };
            let previous = c.read_u64(peb + PEB_EXCEPTION_FILTER).unwrap_or(0) as usize;
            c.write_u64(peb + PEB_EXCEPTION_FILTER, c.arg(0) as u64);
            c.finish(previous)
        }
        // EXCEPTION_CONTINUE_SEARCH: nothing here handles it either.
        "UnhandledExceptionFilter" => c.finish(0),
        // RtlEncodePointer: xor with the process cookie, then rotate right by
        // the cookie's low bits; decoding undoes it in the other order.
        "EncodePointer" => {
            let cookie = process_cookie(&c);
            let rotate = cookie % 64;
            let value = (c.arg(0) as u64 ^ u64::from(cookie)).rotate_right(rotate);
            c.finish(value as usize)
        }
        "DecodePointer" => {
            let cookie = process_cookie(&c);
            let rotate = cookie % 64;
            let value = (c.arg(0) as u64).rotate_left(rotate) ^ u64::from(cookie);
            c.finish(value as usize)
        }
        // An SLIST_HEADER is sixteen zero bytes when empty.
        "InitializeSListHead" => {
            c.write(c.arg(0), &[0u8; 16]);
            c.finish(0)
        }
        "TlsAlloc" => tls_alloc(&mut c),
        "TlsGetValue" => {
            let index = c.arg(0) as u32;
            if index >= TLS_SLOTS || c.teb == 0 {
                return c.fail(ERROR_INVALID_PARAMETER, 0);
            }
            // Success is recorded too: a slot may legitimately hold NULL, and
            // the caller tells the two apart by the last error.
            c.set_last_error(0);
            let value = c
                .read_u64(c.teb + TEB_TLS_SLOTS + index as usize * 8)
                .unwrap_or(0) as usize;
            c.finish(value)
        }
        "TlsSetValue" => {
            let index = c.arg(0) as u32;
            if index >= TLS_SLOTS || c.teb == 0 {
                return c.fail(ERROR_INVALID_PARAMETER, FALSE);
            }
            c.write_u64(c.teb + TEB_TLS_SLOTS + index as usize * 8, c.arg(1) as u64);
            c.finish(TRUE)
        }
        "TlsFree" => tls_free(&mut c),
        "GetProcessHeap" => {
            let heap = c
                .peb()
                .and_then(|peb| c.read_u64(peb + PEB_PROCESS_HEAP))
                .unwrap_or(0) as usize;
            c.finish(heap)
        }
        "HeapAlloc" => heap_alloc(&mut c),
        "HeapReAlloc" => heap_realloc(&mut c),
        "HeapSize" => {
            let block = c.arg(2);
            let size = heap::size_of(&c, block);
            match size {
                Some(n) => c.finish(n),
                None => c.fail(ERROR_INVALID_PARAMETER, usize::MAX),
            }
        }
        // Blocks are not returned to the arena yet; freeing is the record that
        // the caller is done with it, which HeapSize and HeapReAlloc respect.
        "HeapFree" => {
            let block = c.arg(2);
            if block == 0 || heap::size_of(&c, block).is_none() {
                return c.fail(ERROR_INVALID_PARAMETER, FALSE);
            }
            heap::mark_free(&c, block);
            c.finish(TRUE)
        }
        "InitializeCriticalSectionAndSpinCount" | "InitializeCriticalSectionEx" => {
            init_critical_section(&mut c)
        }
        "EnterCriticalSection" => enter_critical_section(&mut c),
        "LeaveCriticalSection" => leave_critical_section(&mut c),
        "DeleteCriticalSection" => {
            let at = c.arg(0);
            // Back to the initialized-and-free state, with no debug info.
            c.write_u64(at, 0);
            c.write_u32(at + 8, -1i32 as u32);
            c.write_u32(at + 12, 0);
            c.write_u64(at + 16, 0);
            c.write_u64(at + 24, 0);
            c.finish(0)
        }
        "GetModuleHandleW" => get_module_handle(&mut c),
        "GetProcAddress" => get_proc_address(&mut c),
        "CloseHandle" => {
            let (Some(files), Ok(fd)) = (host.files(), nt::descriptor(c.arg(0))) else {
                return c.fail_status(Ntstatus::INVALID_HANDLE, FALSE);
            };
            match files.close(fd) {
                Ok(_) => c.finish(TRUE),
                Err(errno) => c.fail_status(nt::status_from_errno(errno), FALSE),
            }
        }
        "Sleep" => {
            if let Some(clock) = host.clock() {
                let _ = clock.sleep_ns(c.arg(0) as u64 * 1_000_000);
            }
            c.finish(0)
        }
        "VirtualAlloc" => virtual_alloc(&mut c),
        "VirtualProtect" => {
            let Some(mem) = host.mem() else {
                return c.fail(ERROR_CALL_NOT_IMPLEMENTED, FALSE);
            };
            let (at, len, protect, old_ptr) = (c.arg(0), c.arg(1), c.arg(2), c.arg(3));
            let prot = nt::prot_from_page(protect);
            match mem.protect(
                at & !0xFFF,
                (len + (at & 0xFFF)).next_multiple_of(0x1000),
                prot,
            ) {
                Ok(_) => {
                    // The previous protection is not tracked; PAGE_READWRITE
                    // is what an anonymous mapping starts as.
                    if old_ptr != 0 {
                        c.write_u32(old_ptr, 0x04);
                    }
                    c.finish(TRUE)
                }
                Err(errno) => c.fail_status(nt::status_from_errno(errno), FALSE),
            }
        }
        // Bound so the runtime links; reached, it says so rather than pretend.
        _ => c.fail(ERROR_CALL_NOT_IMPLEMENTED, 0),
    }
}

/// Where the top-level exception filter is kept: a word of the PEB's reserved
/// area that nothing else here uses.
const PEB_EXCEPTION_FILTER: usize = 0x3F8;

/// WriteFile(hFile, lpBuffer, nNumberOfBytesToWrite, lpNumberOfBytesWritten,
/// lpOverlapped).
fn write_file(c: &mut Call<'_>) -> Dispatch {
    let (handle, buffer, length, written, overlapped) =
        (c.arg(0), c.arg(1), c.arg(2), c.arg(3), c.arg(4));
    // The count is cleared before the transfer, so a caller reading it after
    // a failure sees zero rather than a stale value.
    if written != 0 && !c.write_u32(written, 0) {
        return c.fail_status(Ntstatus::ACCESS_VIOLATION, FALSE);
    }
    // An OVERLAPPED asks for asynchronous delivery, which the NT layer refuses
    // too rather than quietly serving it synchronously.
    if overlapped != 0 {
        return c.fail_status(Ntstatus::NOT_IMPLEMENTED, FALSE);
    }
    let (status, information) =
        nt::transfer(c.host, true, handle, buffer, length, None).unwrap_or_else(|s| (s, 0));
    if status != Ntstatus::SUCCESS {
        return c.fail_status(status, FALSE);
    }
    if written != 0 && !c.write_u32(written, information as u32) {
        return c.fail_status(Ntstatus::ACCESS_VIOLATION, FALSE);
    }
    c.finish(TRUE)
}

/// Windows answers this from the process parameters block, which nothing
/// populates yet; until something does, the three standard streams answer with
/// the handles for the descriptors a process starts with.
fn get_std_handle(c: &mut Call<'_>) -> Dispatch {
    let handle = match c.arg(0) as u32 {
        STD_INPUT_HANDLE => Handle::from_slot(0),
        STD_OUTPUT_HANDLE => Handle::from_slot(1),
        STD_ERROR_HANDLE => Handle::from_slot(2),
        _ => return c.fail_status(Ntstatus::INVALID_HANDLE, INVALID_HANDLE_VALUE),
    };
    c.finish(handle.0 as usize)
}

/// The processor features a 64-bit x86 always has, by `PF_*` index
/// (`winnt.h`): the ones a runtime checks before using an instruction set the
/// architecture guarantees. Anything optional reads as absent, which is the
/// conservative answer.
fn processor_feature_present(feature: u32) -> bool {
    const PRESENT: &[u32] = &[
        2,  // PF_COMPARE_EXCHANGE_DOUBLE
        3,  // PF_MMX_INSTRUCTIONS_AVAILABLE
        6,  // PF_XMMI_INSTRUCTIONS_AVAILABLE (SSE)
        8,  // PF_RDTSC_INSTRUCTION_AVAILABLE
        9,  // PF_PAE_ENABLED
        10, // PF_XMMI64_INSTRUCTIONS_AVAILABLE (SSE2)
        12, // PF_NX_ENABLED
        14, // PF_COMPARE_EXCHANGE128
        23, // PF_FASTFAIL_AVAILABLE
    ];
    feature < PROCESSOR_FEATURE_MAX && PRESENT.contains(&feature)
}

/// The per-process pointer-encoding cookie: Windows draws it at process
/// creation and keeps it in the kernel; this keeps it in the PEB, drawn when
/// first asked for.
fn process_cookie(c: &Call<'_>) -> u32 {
    let Some(peb) = c.peb() else {
        return 0;
    };
    match c.read_u32(peb + PEB_COOKIE) {
        Some(0) | None => {
            let mut bytes = [0u8; 4];
            // With no random source the cookie is still nonzero, so a program
            // cannot observe encoded pointers equal to raw ones.
            if c.host
                .random()
                .map(|r| r.fill(peb + PEB_COOKIE, 4, false))
                .is_none_or(|r| r.is_err())
                || c.read::<4>(peb + PEB_COOKIE).is_none_or(|b| b == [0; 4])
            {
                bytes = 0x2545_F491u32.to_le_bytes();
                c.write(peb + PEB_COOKIE, &bytes);
            } else {
                bytes = c.read::<4>(peb + PEB_COOKIE).unwrap_or(bytes);
            }
            u32::from_le_bytes(bytes)
        }
        Some(cookie) => cookie,
    }
}

/// Where the cookie is kept: another reserved word of the PEB.
const PEB_COOKIE: usize = 0x3F0;

/// TlsAlloc: the first clear bit of the PEB's TLS bitmap, set, with the slot
/// cleared in this thread's TEB.
fn tls_alloc(c: &mut Call<'_>) -> Dispatch {
    let Some(peb) = c.peb() else {
        return c.fail(ERROR_NO_MORE_ITEMS, u32::MAX as usize);
    };
    let Some(bits) = c.read_u64(peb + PEB_TLS_BITMAP_BITS) else {
        return c.fail(ERROR_NO_MORE_ITEMS, u32::MAX as usize);
    };
    let index = (!bits).trailing_zeros();
    if index >= TLS_SLOTS {
        return c.fail(ERROR_NO_MORE_ITEMS, u32::MAX as usize);
    }
    c.write_u64(peb + PEB_TLS_BITMAP_BITS, bits | (1 << index));
    c.write_u64(c.teb + TEB_TLS_SLOTS + index as usize * 8, 0);
    c.finish(index as usize)
}

/// TlsFree: clear the bit, or say the index was never allocated.
fn tls_free(c: &mut Call<'_>) -> Dispatch {
    let index = c.arg(0) as u32;
    let Some(peb) = c.peb() else {
        return c.fail(ERROR_INVALID_PARAMETER, FALSE);
    };
    let bits = c.read_u64(peb + PEB_TLS_BITMAP_BITS).unwrap_or(0);
    if index >= TLS_SLOTS || bits & (1 << index) == 0 {
        return c.fail(ERROR_INVALID_PARAMETER, FALSE);
    }
    c.write_u64(peb + PEB_TLS_BITMAP_BITS, bits & !(1 << index));
    c.write_u64(c.teb + TEB_TLS_SLOTS + index as usize * 8, 0);
    c.finish(TRUE)
}

/// The process heap.
///
/// Windows's heap is a general allocator in ntdll; this is the smallest thing
/// that serves the same calls honestly: an arena the loader mapped, handed out
/// front to back with a header per block that remembers the block's size, so
/// `HeapSize` and `HeapReAlloc` can answer. Freed blocks are marked and not
/// reused, which is a limit to lift, not a lie: nothing is ever handed out
/// twice.
pub mod heap {
    use super::Call;

    /// The arena's header: a magic word, its end, and where the next block goes.
    pub const MAGIC: u64 = 0x5041_4548_5859_4152; // "RAXYHEAP"
    pub const LIMIT: usize = 8;
    pub const NEXT: usize = 16;
    pub const HEADER: usize = 32;

    /// Each block is preceded by its size and a state word.
    const BLOCK_HEADER: usize = 16;
    const IN_USE: u64 = 1;
    const FREE: u64 = 2;

    /// Lay out an empty arena of `len` bytes to be placed at `at`.
    pub fn arena(at: u64, len: u64) -> [u8; HEADER] {
        let mut header = [0u8; HEADER];
        header[..8].copy_from_slice(&MAGIC.to_le_bytes());
        header[LIMIT..LIMIT + 8].copy_from_slice(&(at + len).to_le_bytes());
        header[NEXT..NEXT + 8].copy_from_slice(&(at + HEADER as u64).to_le_bytes());
        header
    }

    /// Carve `size` bytes from the arena at `heap`, sixteen-byte aligned.
    pub(super) fn alloc(c: &Call<'_>, heap: usize, size: usize) -> Option<usize> {
        if c.read_u64(heap)? != MAGIC {
            return None;
        }
        let limit = c.read_u64(heap + LIMIT)? as usize;
        let next = c.read_u64(heap + NEXT)? as usize;
        let block = next + BLOCK_HEADER;
        let end = block.checked_add(size.max(1))?.next_multiple_of(16);
        if end > limit {
            return None;
        }
        c.write_u64(next, size as u64).then_some(())?;
        c.write_u64(next + 8, IN_USE).then_some(())?;
        c.write_u64(heap + NEXT, end as u64).then_some(())?;
        Some(block)
    }

    /// The size a block was allocated with, if `block` is one that is in use.
    pub(super) fn size_of(c: &Call<'_>, block: usize) -> Option<usize> {
        if block < BLOCK_HEADER {
            return None;
        }
        (c.read_u64(block - 8)? == IN_USE)
            .then(|| c.read_u64(block - BLOCK_HEADER).map(|n| n as usize))?
    }

    pub(super) fn mark_free(c: &Call<'_>, block: usize) {
        c.write_u64(block - 8, FREE);
    }
}

/// HeapAlloc(hHeap, dwFlags, dwBytes).
fn heap_alloc(c: &mut Call<'_>) -> Dispatch {
    let (heap, flags, size) = (c.arg(0), c.arg(1), c.arg(2));
    let Some(block) = heap::alloc(c, heap, size) else {
        return c.fail(ERROR_NOT_ENOUGH_MEMORY, 0);
    };
    if flags & HEAP_ZERO_MEMORY != 0 && !zero(c, block, size) {
        return c.fail(ERROR_NOT_ENOUGH_MEMORY, 0);
    }
    c.finish(block)
}

/// HeapReAlloc(hHeap, dwFlags, lpMem, dwBytes): a new block with the old
/// contents, since blocks do not grow in place here.
fn heap_realloc(c: &mut Call<'_>) -> Dispatch {
    let (heap, flags, old, size) = (c.arg(0), c.arg(1), c.arg(2), c.arg(3));
    let Some(old_size) = heap::size_of(c, old) else {
        return c.fail(ERROR_INVALID_PARAMETER, 0);
    };
    let Some(block) = heap::alloc(c, heap, size) else {
        return c.fail(ERROR_NOT_ENOUGH_MEMORY, 0);
    };
    let keep = old_size.min(size);
    let mut chunk = [0u8; 256];
    let mut moved = 0;
    while moved < keep {
        let n = (keep - moved).min(chunk.len());
        if c.host
            .platform()
            .read_user(old + moved, &mut chunk[..n])
            .is_err()
            || !c.write(block + moved, &chunk[..n])
        {
            return c.fail_status(Ntstatus::ACCESS_VIOLATION, 0);
        }
        moved += n;
    }
    if flags & HEAP_ZERO_MEMORY != 0 && size > keep && !zero(c, block + keep, size - keep) {
        return c.fail(ERROR_NOT_ENOUGH_MEMORY, 0);
    }
    heap::mark_free(c, old);
    c.finish(block)
}

fn zero(c: &Call<'_>, at: usize, len: usize) -> bool {
    let zeros = [0u8; 256];
    let mut done = 0;
    while done < len {
        let n = (len - done).min(zeros.len());
        if !c.write(at + done, &zeros[..n]) {
            return false;
        }
        done += n;
    }
    true
}

/// RtlInitializeCriticalSectionEx: no debug info, free, unowned, and no
/// spinning on a single processor - the state a section starts in.
fn init_critical_section(c: &mut Call<'_>) -> Dispatch {
    let at = c.arg(0);
    // DebugInfo is the no-debug-info marker, (PVOID)-1.
    c.write_u64(at, u64::MAX);
    c.write_u32(at + 8, -1i32 as u32); // LockCount
    c.write_u32(at + 12, 0); // RecursionCount
    c.write_u64(at + 16, 0); // OwningThread
    c.write_u64(at + 24, 0); // LockSemaphore
    c.write_u64(at + 32, 0); // SpinCount: one processor, no spinning
    // The AndSpinCount form returns a BOOL, the Ex form an NTSTATUS-shaped
    // BOOL as well; both say success the same way.
    c.finish(TRUE)
}

/// RtlEnterCriticalSection on a process with one thread: take it, or recurse
/// if this thread already owns it. Contention cannot arise until a second
/// thread exists, and then a wait will be needed here.
fn enter_critical_section(c: &mut Call<'_>) -> Dispatch {
    let at = c.arg(0);
    let tid = c.host.tasks().map_or(1, |t| u64::from(t.gettid()));
    let lock = c.read_u32(at + 8).unwrap_or(-1i32 as u32) as i32;
    let owner = c.read_u64(at + 16).unwrap_or(0);
    if lock >= 0 && owner == tid {
        let depth = c.read_u32(at + 12).unwrap_or(0);
        c.write_u32(at + 12, depth + 1);
        c.write_u32(at + 8, (lock + 1) as u32);
        return c.finish(0);
    }
    c.write_u32(at + 8, (lock + 1) as u32);
    c.write_u64(at + 16, tid);
    c.write_u32(at + 12, 1);
    c.finish(0)
}

/// RtlLeaveCriticalSection: unwind one level; the last one releases it.
fn leave_critical_section(c: &mut Call<'_>) -> Dispatch {
    let at = c.arg(0);
    let depth = c.read_u32(at + 12).unwrap_or(0);
    let lock = c.read_u32(at + 8).unwrap_or(0) as i32;
    if depth > 1 {
        c.write_u32(at + 12, depth - 1);
    } else {
        c.write_u32(at + 12, 0);
        c.write_u64(at + 16, 0);
    }
    c.write_u32(at + 8, (lock - 1) as u32);
    c.finish(0)
}

/// GetModuleHandleW(lpModuleName): NULL is the program; a name is looked up in
/// the loader's module list, without its extension and without regard to case,
/// as the loader compares names.
fn get_module_handle(c: &mut Call<'_>) -> Dispatch {
    let Some(peb) = c.peb() else {
        return c.fail(ERROR_MOD_NOT_FOUND, 0);
    };
    let name_ptr = c.arg(0);
    if name_ptr == 0 {
        let base = c.read_u64(peb + PEB_IMAGE_BASE).unwrap_or(0) as usize;
        return c.finish(base);
    }
    let Some(wanted) = read_wide(c, name_ptr, 260) else {
        return c.fail(ERROR_INVALID_PARAMETER, 0);
    };
    match find_module(c, peb, &wanted) {
        Some(base) => c.finish(base),
        None => c.fail(ERROR_MOD_NOT_FOUND, 0),
    }
}

/// GetProcAddress(hModule, lpProcName): by name, or by ordinal when the high
/// word is zero, out of the mapped image's export directory.
fn get_proc_address(c: &mut Call<'_>) -> Dispatch {
    let (base, name) = (c.arg(0), c.arg(1));
    let Some(exports) = mapped::exports(c, base) else {
        return c.fail(ERROR_PROC_NOT_FOUND, 0);
    };
    let found = if name >> 16 == 0 {
        mapped::by_ordinal(c, base, &exports, name as u32)
    } else {
        let mut buf = [0u8; 256];
        match c.host.platform().read_user_cstr(name, &mut buf) {
            Ok(_) => {
                let end = buf.iter().position(|b| *b == 0).unwrap_or(buf.len());
                mapped::by_name(c, base, &exports, &buf[..end])
            }
            Err(_) => None,
        }
    };
    match found {
        Some(at) => c.finish(at),
        None => c.fail(ERROR_PROC_NOT_FOUND, 0),
    }
}

/// VirtualAlloc(lpAddress, dwSize, flAllocationType, flProtect), as
/// NtAllocateVirtualMemory serves it.
fn virtual_alloc(c: &mut Call<'_>) -> Dispatch {
    let Some(mem) = c.host.mem() else {
        return c.fail(ERROR_CALL_NOT_IMPLEMENTED, 0);
    };
    let (at, size, protect) = (c.arg(0), c.arg(1), c.arg(3));
    let base = at & !0xFFF;
    let len = (size + (at & 0xFFF)).next_multiple_of(0x1000);
    let request = MapRequest {
        addr: base,
        len,
        prot: if protect == 0 {
            Prot::READ | Prot::WRITE
        } else {
            nt::prot_from_page(protect)
        },
        fixed: base != 0,
        shared: false,
        source: MapSource::Anonymous,
    };
    match mem.map(&request) {
        Ok(va) => c.finish(va as usize),
        Err(errno) => c.fail_status(nt::status_from_errno(errno), 0),
    }
}

/// A NUL-terminated UTF-16 string, up to `max` code units, as bytes of ASCII
/// where it is ASCII; anything wider is kept as a marker so it never matches
/// an ASCII module name by accident.
fn read_wide(c: &Call<'_>, at: usize, max: usize) -> Option<alloc::vec::Vec<u8>> {
    let mut out = alloc::vec::Vec::new();
    for i in 0..max {
        let unit = u16::from_le_bytes(c.read::<2>(at + i * 2)?);
        if unit == 0 {
            return Some(out);
        }
        out.push(if unit < 0x80 { unit as u8 } else { 0xFF });
    }
    Some(out)
}

/// Find a module by name in the PEB's load-order list: the base name matches
/// case-insensitively, with or without a `.dll` extension.
fn find_module(c: &Call<'_>, peb: usize, wanted: &[u8]) -> Option<usize> {
    use crate::teb_peb::{LDR_BASE_NAME, LDR_DLL_BASE, LDR_IN_LOAD_ORDER};
    let ldr = c.read_u64(peb + PEB_LDR)? as usize;
    if ldr == 0 {
        return None;
    }
    let head = ldr + LDR_IN_LOAD_ORDER;
    let mut link = c.read_u64(head)? as usize;
    let stem = |name: &[u8]| -> alloc::vec::Vec<u8> {
        let lower: alloc::vec::Vec<u8> = name.iter().map(|b| b.to_ascii_lowercase()).collect();
        match lower.strip_suffix(b".dll") {
            Some(s) => s.to_vec(),
            None => lower,
        }
    };
    let wanted = stem(wanted);
    for _ in 0..1024 {
        if link == head || link == 0 {
            return None;
        }
        let entry = link;
        let base = c.read_u64(entry + LDR_DLL_BASE)? as usize;
        let len = u16::from_le_bytes(c.read::<2>(entry + LDR_BASE_NAME)?) as usize / 2;
        let buffer = c.read_u64(entry + LDR_BASE_NAME + 8)? as usize;
        if let Some(name) = read_wide(c, buffer, len)
            && stem(&name) == wanted
        {
            return Some(base);
        }
        link = c.read_u64(entry)? as usize;
    }
    None
}

/// Reading a PE image where it is mapped: an RVA is an offset from the base,
/// which is simpler than the file, where a section table stands between.
mod mapped {
    use super::Call;

    /// The export directory's tables, as addresses.
    pub struct Exports {
        pub dir: (usize, usize),
        pub base: u32,
        pub functions: (usize, u32),
        pub names: (usize, u32),
        pub ordinals: usize,
    }

    pub fn exports(c: &Call<'_>, base: usize) -> Option<Exports> {
        let pe = c.read_u32(base + 0x3C)? as usize;
        if &c.read::<4>(base + pe)? != b"PE\0\0" {
            return None;
        }
        let opt = base + pe + 24;
        // PE32+ only; DataDirectory[0] is the export directory.
        let dd = opt + 112;
        let rva = c.read_u32(dd)? as usize;
        let size = c.read_u32(dd + 4)? as usize;
        if rva == 0 {
            return None;
        }
        let dir = base + rva;
        Some(Exports {
            dir: (rva, size),
            base: c.read_u32(dir + 16)?,
            functions: (base + c.read_u32(dir + 28)? as usize, c.read_u32(dir + 20)?),
            names: (base + c.read_u32(dir + 32)? as usize, c.read_u32(dir + 24)?),
            ordinals: base + c.read_u32(dir + 36)? as usize,
        })
    }

    pub fn by_name(c: &Call<'_>, base: usize, x: &Exports, wanted: &[u8]) -> Option<usize> {
        for i in 0..x.names.1 as usize {
            let name_rva = c.read_u32(x.names.0 + i * 4)? as usize;
            let mut buf = [0u8; 256];
            if c.host
                .platform()
                .read_user_cstr(base + name_rva, &mut buf)
                .is_err()
            {
                continue;
            }
            let end = buf.iter().position(|b| *b == 0).unwrap_or(buf.len());
            if &buf[..end] == wanted {
                let slot = u16::from_le_bytes(c.read::<2>(x.ordinals + i * 2)?) as usize;
                return target(c, base, x, slot);
            }
        }
        None
    }

    pub fn by_ordinal(c: &Call<'_>, base: usize, x: &Exports, ordinal: u32) -> Option<usize> {
        let slot = ordinal.checked_sub(x.base)? as usize;
        target(c, base, x, slot)
    }

    /// Where function-table `slot` leads. A forwarder - an address inside the
    /// export directory - names another module's export, which is not chased
    /// here yet.
    fn target(c: &Call<'_>, base: usize, x: &Exports, slot: usize) -> Option<usize> {
        if slot >= x.functions.1 as usize {
            return None;
        }
        let rva = c.read_u32(x.functions.0 + slot * 4)? as usize;
        if rva == 0 || (rva >= x.dir.0 && rva < x.dir.0 + x.dir.1) {
            return None;
        }
        Some(base + rva)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn numbers_round_trip_and_stop_where_the_table_ends() {
        let mut nr = WIN32_BASE;
        while let Some(call) = Win32Call::from_nr(nr) {
            assert_eq!(call.nr(), nr);
            assert_eq!(Win32Call::named(call.symbol()), Some(call));
            nr += 1;
        }
        assert_eq!(nr - WIN32_BASE, TABLE.len() as u32);
    }

    #[test]
    fn an_nt_number_is_not_a_win32_entry_point() {
        // The two ranges must not overlap, or a trap would reach the wrong one.
        assert_eq!(Win32Call::from_nr(0), None);
        assert_eq!(Win32Call::from_nr(WIN32_BASE - 1), None);
    }

    #[test]
    fn resolves_an_import_by_library_and_name() {
        assert_eq!(
            Win32Call::resolve("KERNEL32.dll", "WriteFile"),
            Some(Win32Call::WRITE_FILE)
        );
        // Import tables vary in how they spell the library; the loader does not
        // care about its case.
        assert_eq!(
            Win32Call::resolve("kernel32.DLL", "ExitProcess"),
            Some(Win32Call::EXIT_PROCESS)
        );
        // An export name is case-sensitive, as the linker wrote it.
        assert_eq!(Win32Call::resolve("KERNEL32.dll", "writefile"), None);
        assert_eq!(Win32Call::resolve("KERNEL32.dll", "CreateMutexW"), None);
        assert_eq!(Win32Call::resolve("USER32.dll", "WriteFile"), None);
    }

    #[test]
    fn the_table_names_each_function_once() {
        for (i, name) in TABLE.iter().enumerate() {
            assert_eq!(
                TABLE.iter().position(|n| n == name),
                Some(i),
                "{name} twice"
            );
        }
    }

    #[test]
    fn everything_a_c_runtime_imports_on_its_way_to_main_is_bound() {
        // The union of what vcruntime140.dll, ucrtbase.dll and python.exe import
        // from kernel32 and its api-set forwarders, read out of the real files.
        const CRT_START: &[&str] = &[
            "Beep",
            "CloseHandle",
            "CompareStringW",
            "CreateDirectoryW",
            "CreateFileW",
            "CreatePipe",
            "CreateProcessW",
            "CreateThread",
            "DeleteCriticalSection",
            "DeleteFileW",
            "DuplicateHandle",
            "EncodePointer",
            "EnterCriticalSection",
            "EnumSystemLocalesW",
            "ExitProcess",
            "ExitThread",
            "FileTimeToSystemTime",
            "FindClose",
            "FindFirstFileExW",
            "FindNextFileW",
            "FlsAlloc",
            "FlsFree",
            "FlsGetValue",
            "FlsSetValue",
            "FlushFileBuffers",
            "FreeEnvironmentStringsW",
            "FreeLibrary",
            "FreeLibraryAndExitThread",
            "GetACP",
            "GetCPInfo",
            "GetCommandLineA",
            "GetCommandLineW",
            "GetConsoleCP",
            "GetConsoleMode",
            "GetConsoleOutputCP",
            "GetCurrentDirectoryW",
            "GetCurrentProcess",
            "GetCurrentProcessId",
            "GetCurrentThread",
            "GetCurrentThreadId",
            "GetDateFormatW",
            "GetDiskFreeSpaceW",
            "GetDriveTypeW",
            "GetEnvironmentStringsW",
            "GetExitCodeProcess",
            "GetFileAttributesExW",
            "GetFileInformationByHandle",
            "GetFileSizeEx",
            "GetFileType",
            "GetFullPathNameW",
            "GetLastError",
            "GetLocalTime",
            "GetLocaleInfoW",
            "GetLogicalDrives",
            "GetModuleFileNameW",
            "GetModuleHandleExW",
            "GetModuleHandleW",
            "GetNumberOfConsoleInputEvents",
            "GetOEMCP",
            "GetProcAddress",
            "GetProcessHeap",
            "GetStartupInfoW",
            "GetStdHandle",
            "GetStringTypeW",
            "GetSystemInfo",
            "GetSystemTimeAsFileTime",
            "GetTempPathW",
            "GetTimeFormatW",
            "GetTimeZoneInformation",
            "GetUserDefaultLCID",
            "HeapAlloc",
            "HeapCompact",
            "HeapFree",
            "HeapQueryInformation",
            "HeapReAlloc",
            "HeapSize",
            "HeapValidate",
            "HeapWalk",
            "InitializeCriticalSectionAndSpinCount",
            "InitializeCriticalSectionEx",
            "InitializeSListHead",
            "InterlockedFlushSList",
            "InterlockedPushEntrySList",
            "IsDebuggerPresent",
            "IsProcessorFeaturePresent",
            "IsThreadAFiber",
            "IsValidCodePage",
            "IsValidLocale",
            "LCMapStringW",
            "LeaveCriticalSection",
            "LoadLibraryExW",
            "LockFileEx",
            "MoveFileExW",
            "MultiByteToWideChar",
            "OutputDebugStringW",
            "PeekConsoleInputA",
            "PeekNamedPipe",
            "QueryPerformanceCounter",
            "QueryPerformanceFrequency",
            "RaiseException",
            "ReadConsoleInputW",
            "ReadConsoleW",
            "ReadFile",
            "RemoveDirectoryW",
            "ResumeThread",
            "RtlCaptureContext",
            "RtlLookupFunctionEntry",
            "RtlPcToFileHeader",
            "RtlUnwind",
            "RtlUnwindEx",
            "RtlVirtualUnwind",
            "SetConsoleCtrlHandler",
            "SetConsoleMode",
            "SetCurrentDirectoryW",
            "SetEndOfFile",
            "SetEnvironmentVariableW",
            "SetErrorMode",
            "SetFileAttributesW",
            "SetFilePointerEx",
            "SetFileTime",
            "SetLastError",
            "SetLocalTime",
            "SetStdHandle",
            "SetUnhandledExceptionFilter",
            "Sleep",
            "SystemTimeToFileTime",
            "SystemTimeToTzSpecificLocalTime",
            "TerminateProcess",
            "TlsAlloc",
            "TlsFree",
            "TlsGetValue",
            "TlsSetValue",
            "TzSpecificLocalTimeToSystemTime",
            "UnhandledExceptionFilter",
            "UnlockFileEx",
            "VerSetConditionMask",
            "VerifyVersionInfoW",
            "VirtualAlloc",
            "VirtualProtect",
            "VirtualQuery",
            "WaitForSingleObject",
            "WideCharToMultiByte",
            "WriteConsoleW",
            "WriteFile",
        ];
        assert_eq!(CRT_START.len(), 144);
        for name in CRT_START {
            assert!(Win32Call::named(name).is_some(), "{name} is not bound");
        }
    }

    #[test]
    fn the_architecture_guarantees_sse2_and_nothing_optional() {
        assert!(
            processor_feature_present(10),
            "PF_XMMI64_INSTRUCTIONS_AVAILABLE"
        );
        assert!(processor_feature_present(23), "PF_FASTFAIL_AVAILABLE");
        assert!(
            !processor_feature_present(39),
            "PF_AVX_INSTRUCTIONS_AVAILABLE"
        );
        assert!(!processor_feature_present(64), "past PROCESSOR_FEATURE_MAX");
    }
}
