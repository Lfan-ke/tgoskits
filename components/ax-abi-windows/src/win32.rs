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
        PARAMS_COMMAND_LINE, PARAMS_COMMAND_LINE_A, PARAMS_CURRENT_DIRECTORY, PARAMS_ENVIRONMENT,
        PARAMS_ENVIRONMENT_SIZE, PARAMS_FLAGS, PARAMS_SHOW_WINDOW, PARAMS_STD_INPUT,
        PEB_BEING_DEBUGGED, PEB_IMAGE_BASE, PEB_LDR, PEB_PROCESS_HEAP, PEB_PROCESS_PARAMS,
        PEB_TLS_BITMAP_BITS, TEB_LAST_ERROR, TEB_PEB, TEB_TLS_SLOTS,
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
const ERROR_INSUFFICIENT_BUFFER: u32 = 122;

/// `sizeof(STARTUPINFOW)` on x86-64.
const STARTUPINFO_SIZE: u32 = 104;

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

/// The entry points this package binds, by library and by name.
///
/// Each library is synthesized as a module of its own - a header page with an
/// export directory, then a stub per entry - so a program finds it in the
/// module list and takes addresses out of it the way it would out of the real
/// one. The position across all libraries is the call's number above
/// [`WIN32_BASE`]; the position within a library is its stub's index. Every
/// name a C runtime and CPython import from these libraries is here, so such
/// an image links; [`dispatch`] says which of them do their work.
pub struct Library {
    /// The name imports spell, as the export directory will name it.
    pub name: &'static str,
    /// Exported names, and the ordinal each is exported under; zero means
    /// "the position plus one", which is what an ordinary library has.
    pub exports: &'static [(&'static str, u16)],
}

pub const LIBRARIES: &[Library] = &[
    Library {
        name: "KERNEL32.dll",
        exports: KERNEL32,
    },
    Library {
        name: "ADVAPI32.dll",
        exports: ADVAPI32,
    },
    Library {
        name: "VERSION.dll",
        exports: VERSION,
    },
    Library {
        name: "bcrypt.dll",
        exports: BCRYPT,
    },
    // Imported by ordinal, so the ordinals are the real library's, read out
    // of its export table.
    Library {
        name: "WS2_32.dll",
        exports: WS2_32,
    },
];

const KERNEL32: &[(&str, u16)] = &[
    ("WriteFile", 0),
    ("GetStdHandle", 0),
    ("GetLastError", 0),
    ("SetLastError", 0),
    ("ExitProcess", 0),
    ("GetCurrentProcessId", 0),
    ("GetCurrentThreadId", 0),
    ("GetCurrentProcess", 0),
    ("GetCurrentThread", 0),
    ("GetSystemTimeAsFileTime", 0),
    ("QueryPerformanceCounter", 0),
    ("QueryPerformanceFrequency", 0),
    ("IsProcessorFeaturePresent", 0),
    ("IsDebuggerPresent", 0),
    ("SetUnhandledExceptionFilter", 0),
    ("UnhandledExceptionFilter", 0),
    ("EncodePointer", 0),
    ("DecodePointer", 0),
    ("InitializeSListHead", 0),
    ("TlsAlloc", 0),
    ("TlsGetValue", 0),
    ("TlsSetValue", 0),
    ("TlsFree", 0),
    ("GetProcessHeap", 0),
    ("HeapAlloc", 0),
    ("HeapFree", 0),
    ("HeapReAlloc", 0),
    ("HeapSize", 0),
    ("InitializeCriticalSectionAndSpinCount", 0),
    ("InitializeCriticalSectionEx", 0),
    ("EnterCriticalSection", 0),
    ("LeaveCriticalSection", 0),
    ("DeleteCriticalSection", 0),
    ("GetModuleHandleW", 0),
    ("GetProcAddress", 0),
    ("TerminateProcess", 0),
    ("CloseHandle", 0),
    ("Sleep", 0),
    ("VirtualAlloc", 0),
    ("VirtualProtect", 0),
    ("Beep", 0),
    ("CompareStringW", 0),
    ("CreateDirectoryW", 0),
    ("CreateFileW", 0),
    ("CreatePipe", 0),
    ("CreateProcessW", 0),
    ("CreateThread", 0),
    ("DeleteFileW", 0),
    ("DuplicateHandle", 0),
    ("EnumSystemLocalesW", 0),
    ("ExitThread", 0),
    ("FileTimeToSystemTime", 0),
    ("FindClose", 0),
    ("FindFirstFileExW", 0),
    ("FindNextFileW", 0),
    ("FlsAlloc", 0),
    ("FlsFree", 0),
    ("FlsGetValue", 0),
    ("FlsSetValue", 0),
    ("FlushFileBuffers", 0),
    ("FreeEnvironmentStringsW", 0),
    ("FreeLibrary", 0),
    ("FreeLibraryAndExitThread", 0),
    ("GetACP", 0),
    ("GetCPInfo", 0),
    ("GetCommandLineA", 0),
    ("GetCommandLineW", 0),
    ("GetConsoleCP", 0),
    ("GetConsoleMode", 0),
    ("GetConsoleOutputCP", 0),
    ("GetCurrentDirectoryW", 0),
    ("GetDateFormatW", 0),
    ("GetDiskFreeSpaceW", 0),
    ("GetDriveTypeW", 0),
    ("GetEnvironmentStringsW", 0),
    ("GetExitCodeProcess", 0),
    ("GetFileAttributesExW", 0),
    ("GetFileInformationByHandle", 0),
    ("GetFileSizeEx", 0),
    ("GetFileType", 0),
    ("GetFullPathNameW", 0),
    ("GetLocalTime", 0),
    ("GetLocaleInfoW", 0),
    ("GetLogicalDrives", 0),
    ("GetModuleFileNameW", 0),
    ("GetModuleHandleExW", 0),
    ("GetNumberOfConsoleInputEvents", 0),
    ("GetOEMCP", 0),
    ("GetStartupInfoW", 0),
    ("GetStringTypeW", 0),
    ("GetSystemInfo", 0),
    ("GetTempPathW", 0),
    ("GetTimeFormatW", 0),
    ("GetTimeZoneInformation", 0),
    ("GetUserDefaultLCID", 0),
    ("HeapCompact", 0),
    ("HeapQueryInformation", 0),
    ("HeapValidate", 0),
    ("HeapWalk", 0),
    ("InterlockedFlushSList", 0),
    ("InterlockedPushEntrySList", 0),
    ("IsThreadAFiber", 0),
    ("IsValidCodePage", 0),
    ("IsValidLocale", 0),
    ("LCMapStringW", 0),
    ("LoadLibraryExW", 0),
    ("LockFileEx", 0),
    ("MoveFileExW", 0),
    ("MultiByteToWideChar", 0),
    ("OutputDebugStringW", 0),
    ("PeekConsoleInputA", 0),
    ("PeekNamedPipe", 0),
    ("RaiseException", 0),
    ("ReadConsoleInputW", 0),
    ("ReadConsoleW", 0),
    ("ReadFile", 0),
    ("RemoveDirectoryW", 0),
    ("ResumeThread", 0),
    ("RtlCaptureContext", 0),
    ("RtlLookupFunctionEntry", 0),
    ("RtlPcToFileHeader", 0),
    ("RtlUnwind", 0),
    ("RtlUnwindEx", 0),
    ("RtlVirtualUnwind", 0),
    ("SetConsoleCtrlHandler", 0),
    ("SetConsoleMode", 0),
    ("SetCurrentDirectoryW", 0),
    ("SetEndOfFile", 0),
    ("SetEnvironmentVariableW", 0),
    ("SetErrorMode", 0),
    ("SetFileAttributesW", 0),
    ("SetFilePointerEx", 0),
    ("SetFileTime", 0),
    ("SetLocalTime", 0),
    ("SetStdHandle", 0),
    ("SystemTimeToFileTime", 0),
    ("SystemTimeToTzSpecificLocalTime", 0),
    ("TzSpecificLocalTimeToSystemTime", 0),
    ("UnlockFileEx", 0),
    ("VerSetConditionMask", 0),
    ("VerifyVersionInfoW", 0),
    ("VirtualQuery", 0),
    ("WaitForSingleObject", 0),
    ("WideCharToMultiByte", 0),
    ("WriteConsoleW", 0),
    ("AcquireSRWLockExclusive", 0),
    ("TryAcquireSRWLockExclusive", 0),
    ("AddDllDirectory", 0),
    ("AddVectoredExceptionHandler", 0),
    ("CancelIoEx", 0),
    ("CompareStringOrdinal", 0),
    ("ConnectNamedPipe", 0),
    ("CopyFile2", 0),
    ("CreateEventA", 0),
    ("CreateEventW", 0),
    ("CreateFileMappingW", 0),
    ("CreateHardLinkW", 0),
    ("CreateMutexW", 0),
    ("CreateNamedPipeW", 0),
    ("CreateSemaphoreA", 0),
    ("CreateSymbolicLinkW", 0),
    ("CreateWaitableTimerExW", 0),
    ("DeleteProcThreadAttributeList", 0),
    ("DeviceIoControl", 0),
    ("ExpandEnvironmentStringsW", 0),
    ("FindFirstFileW", 0),
    ("FindFirstVolumeW", 0),
    ("FindNextVolumeW", 0),
    ("FindVolumeClose", 0),
    ("FlushViewOfFile", 0),
    ("FormatMessageW", 0),
    ("GenerateConsoleCtrlEvent", 0),
    ("GetActiveProcessorCount", 0),
    ("GetConsoleScreenBufferInfo", 0),
    ("GetCurrentProcessorNumber", 0),
    ("GetDiskFreeSpaceExW", 0),
    ("GetEnvironmentVariableA", 0),
    ("GetErrorMode", 0),
    ("GetExitCodeThread", 0),
    ("GetFileAttributesW", 0),
    ("GetFileInformationByHandleEx", 0),
    ("GetFileSize", 0),
    ("GetFinalPathNameByHandleW", 0),
    ("GetHandleInformation", 0),
    ("GetLargePageMinimum", 0),
    ("GetLocaleInfoA", 0),
    ("GetLogicalDriveStringsW", 0),
    ("GetLongPathNameW", 0),
    ("GetNamedPipeHandleStateW", 0),
    ("GetNumaHighestNodeNumber", 0),
    ("GetNumaNodeProcessorMask", 0),
    ("GetOverlappedResult", 0),
    ("GetProcessTimes", 0),
    ("GetShortPathNameW", 0),
    ("GetSystemTimePreciseAsFileTime", 0),
    ("GetThreadTimes", 0),
    ("GetTickCount64", 0),
    ("GetVersion", 0),
    ("GetVersionExW", 0),
    ("GetVolumePathNameW", 0),
    ("GetVolumePathNamesForVolumeNameW", 0),
    ("InitializeConditionVariable", 0),
    ("InitializeProcThreadAttributeList", 0),
    ("InitializeSRWLock", 0),
    ("LCMapStringEx", 0),
    ("LoadLibraryA", 0),
    ("LoadLibraryW", 0),
    ("LocalFree", 0),
    ("MapViewOfFile", 0),
    ("NeedCurrentDirectoryForExePathW", 0),
    ("OpenEventW", 0),
    ("OpenFileMappingW", 0),
    ("OpenMutexW", 0),
    ("OpenProcess", 0),
    ("PathCchCombineEx", 0),
    ("PathCchSkipRoot", 0),
    ("PssCaptureSnapshot", 0),
    ("PssFreeSnapshot", 0),
    ("PssQuerySnapshot", 0),
    ("ReleaseMutex", 0),
    ("ReleaseSRWLockExclusive", 0),
    ("ReleaseSemaphore", 0),
    ("RemoveDllDirectory", 0),
    ("RemoveVectoredExceptionHandler", 0),
    ("ResetEvent", 0),
    ("SetEvent", 0),
    ("SetFileInformationByHandle", 0),
    ("SetHandleInformation", 0),
    ("SetNamedPipeHandleState", 0),
    ("SetWaitableTimerEx", 0),
    ("SleepConditionVariableSRW", 0),
    ("SwitchToThread", 0),
    ("TerminateThread", 0),
    ("UnmapViewOfFile", 0),
    ("UpdateProcThreadAttribute", 0),
    ("VirtualFree", 0),
    ("WaitForMultipleObjects", 0),
    ("WaitForSingleObjectEx", 0),
    ("WaitNamedPipeW", 0),
    ("WakeConditionVariable", 0),
    ("WriteConsoleA", 0),
];

const ADVAPI32: &[(&str, u16)] = &[
    ("AdjustTokenPrivileges", 0),
    ("ConvertStringSecurityDescriptorToSecurityDescriptorW", 0),
    ("GetUserNameW", 0),
    ("LookupPrivilegeValueA", 0),
    ("LsaNtStatusToWinError", 0),
    ("OpenProcessToken", 0),
    ("RegCloseKey", 0),
    ("RegConnectRegistryW", 0),
    ("RegCreateKeyExW", 0),
    ("RegCreateKeyW", 0),
    ("RegDeleteKeyExW", 0),
    ("RegDeleteKeyW", 0),
    ("RegDeleteValueW", 0),
    ("RegEnumKeyExW", 0),
    ("RegEnumValueW", 0),
    ("RegFlushKey", 0),
    ("RegLoadKeyW", 0),
    ("RegOpenKeyExW", 0),
    ("RegQueryInfoKeyW", 0),
    ("RegQueryValueExW", 0),
    ("RegSaveKeyW", 0),
    ("RegSetValueExW", 0),
];

const VERSION: &[(&str, u16)] = &[
    ("GetFileVersionInfoSizeW", 0),
    ("GetFileVersionInfoW", 0),
    ("VerQueryValueW", 0),
];

const BCRYPT: &[(&str, u16)] = &[("BCryptGenRandom", 0)];

const WS2_32: &[(&str, u16)] = &[
    ("closesocket", 3),
    ("getsockopt", 7),
    ("send", 19),
    ("socket", 23),
    ("WSAGetLastError", 111),
    ("WSAStartup", 115),
    ("WSACleanup", 116),
];

/// A Win32 entry point this package binds: a position across [`LIBRARIES`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Win32Call(u32);

/// How many entry points the libraries bind in all - the number of stubs a
/// process gets.
pub fn table_len() -> usize {
    LIBRARIES.iter().map(|lib| lib.exports.len()).sum()
}

impl Win32Call {
    /// The call a trap number names, or `None` for a number outside this layer.
    pub fn from_nr(nr: u32) -> Option<Win32Call> {
        let index = nr.checked_sub(WIN32_BASE)?;
        (index < table_len() as u32).then_some(Win32Call(index))
    }

    /// The trap number a stub for this call raises.
    pub fn nr(self) -> u32 {
        WIN32_BASE + self.0
    }

    /// Which library this call belongs to, and its position in it.
    pub fn place(self) -> (usize, usize) {
        let mut index = self.0 as usize;
        for (at, lib) in LIBRARIES.iter().enumerate() {
            if index < lib.exports.len() {
                return (at, index);
            }
            index -= lib.exports.len();
        }
        unreachable!("a call is always inside the table")
    }

    /// The first call of library `lib`.
    pub fn first_of(lib: usize) -> Win32Call {
        let before: usize = LIBRARIES[..lib].iter().map(|l| l.exports.len()).sum();
        Win32Call(before as u32)
    }

    /// The exported name an image imports this call by.
    pub fn symbol(self) -> &'static str {
        let (lib, at) = self.place();
        LIBRARIES[lib].exports[at].0
    }

    /// The ordinal this call is exported under.
    pub fn ordinal(self) -> u16 {
        let (lib, at) = self.place();
        match LIBRARIES[lib].exports[at].1 {
            0 => at as u16 + 1,
            ordinal => ordinal,
        }
    }

    /// The library an image expects to import this call from.
    pub fn library(self) -> &'static str {
        LIBRARIES[self.place().0].name
    }

    /// The library `name` is, without regard to case, if it is one of these.
    pub fn library_index(name: &str) -> Option<usize> {
        LIBRARIES
            .iter()
            .position(|lib| lib.name.eq_ignore_ascii_case(name))
    }

    /// The call an import names, or `None` for one no stub is synthesized for.
    ///
    /// A library name is matched without regard to case, as the loader matches
    /// it; an export name is matched exactly, as the linker wrote it.
    pub fn resolve(library: &str, symbol: &str) -> Option<Win32Call> {
        let lib = Self::library_index(library)?;
        let at = LIBRARIES[lib]
            .exports
            .iter()
            .position(|(name, _)| *name == symbol)?;
        Some(Win32Call(Self::first_of(lib).0 + at as u32))
    }

    /// The call `library` exports under `ordinal`.
    pub fn by_ordinal(library: &str, ordinal: u16) -> Option<Win32Call> {
        let lib = Self::library_index(library)?;
        let first = Self::first_of(lib).0;
        LIBRARIES[lib]
            .exports
            .iter()
            .enumerate()
            .find(|(at, (_, fixed))| match *fixed {
                0 => *at as u16 + 1 == ordinal,
                fixed => fixed == ordinal,
            })
            .map(|(at, _)| Win32Call(first + at as u32))
    }

    /// The call with exactly this export name, in whichever library has it.
    pub fn named(symbol: &str) -> Option<Win32Call> {
        LIBRARIES
            .iter()
            .find_map(|lib| Self::resolve(lib.name, symbol))
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
    /// Argument `i`. The stub moved the first six into the trap frame; a
    /// function with more leaves the rest where the caller put them, above
    /// the return address and the spill space on its stack - and above the
    /// two registers the stub pushed to keep for the caller.
    fn arg(&self, i: usize) -> usize {
        if i < 6 {
            return self.env.arg(i);
        }
        let sp = self.env.stack_pointer();
        if sp == 0 {
            return 0;
        }
        self.read_u64(sp + 0x38 + (i - 4) * 8).unwrap_or(0) as usize
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

    /// The process parameters, through the PEB.
    fn params(&self) -> Option<usize> {
        let at = self.read_u64(self.peb()? + PEB_PROCESS_PARAMS)? as usize;
        (at != 0).then_some(at)
    }

    /// A `UNICODE_STRING` at `at`: its length in bytes and its buffer.
    fn unicode(&self, at: usize) -> Option<(usize, usize)> {
        let len = u16::from_le_bytes(self.read::<2>(at)?) as usize;
        let buf = self.read_u64(at + 8)? as usize;
        Some((len, buf))
    }

    /// `len` bytes at `at`.
    fn read_bytes(&self, at: usize, len: usize) -> Option<alloc::vec::Vec<u8>> {
        let mut out = alloc::vec![0u8; len];
        self.host.platform().read_user(at, &mut out).ok()?;
        Some(out)
    }

    /// A NUL-terminated byte string at `at`, terminator included, as a C
    /// runtime hands one to a conversion with a length of -1.
    fn read_cstr(&self, at: usize) -> Option<alloc::vec::Vec<u8>> {
        let mut out = alloc::vec::Vec::new();
        loop {
            let byte = self.read::<1>(at + out.len())?[0];
            out.push(byte);
            if byte == 0 || out.len() > 0x10000 {
                return Some(out);
            }
        }
    }

    /// `units` UTF-16 code units at `at`.
    fn read_wide_n(&self, at: usize, units: usize) -> Option<alloc::vec::Vec<u16>> {
        let bytes = self.read_bytes(at, units * 2)?;
        Some(
            bytes
                .chunks(2)
                .map(|c| u16::from_le_bytes([c[0], c[1]]))
                .collect(),
        )
    }

    /// A NUL-terminated UTF-16 string at `at`, terminator excluded.
    fn read_wstr(&self, at: usize) -> Option<alloc::vec::Vec<u16>> {
        let mut out = alloc::vec::Vec::new();
        loop {
            let unit = u16::from_le_bytes(self.read::<2>(at + out.len() * 2)?);
            if unit == 0 || out.len() > 0x8000 {
                return Some(out);
            }
            out.push(unit);
        }
    }

    /// Copy `len` bytes from `from` to `to` through user memory.
    fn copy(&self, from: usize, to: usize, len: usize) -> bool {
        let mut chunk = [0u8; 256];
        let mut moved = 0;
        while moved < len {
            let n = (len - moved).min(chunk.len());
            if self
                .host
                .platform()
                .read_user(from + moved, &mut chunk[..n])
                .is_err()
                || !self.write(to + moved, &chunk[..n])
            {
                return false;
            }
            moved += n;
        }
        true
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
        "GetModuleFileNameW" => get_module_file_name(&mut c),
        // Both hand out the block itself, as Windows does; a program must not
        // free what it gets.
        "GetCommandLineW" => {
            let line = c
                .params()
                .and_then(|p| c.unicode(p + PARAMS_COMMAND_LINE))
                .map_or(0, |(_, buf)| buf);
            c.finish(line)
        }
        "GetCommandLineA" => {
            let line = c
                .params()
                .and_then(|p| c.read_u64(p + PARAMS_COMMAND_LINE_A))
                .unwrap_or(0) as usize;
            c.finish(line)
        }
        // A copy of the environment block from the process heap, which the
        // caller returns through FreeEnvironmentStringsW.
        "GetEnvironmentStringsW" => {
            let Some(params) = c.params() else {
                return c.fail(ERROR_CALL_NOT_IMPLEMENTED, 0);
            };
            let (Some(env), Some(size)) = (
                c.read_u64(params + PARAMS_ENVIRONMENT),
                c.read_u64(params + PARAMS_ENVIRONMENT_SIZE),
            ) else {
                return c.fail(ERROR_CALL_NOT_IMPLEMENTED, 0);
            };
            let heap = c
                .peb()
                .and_then(|peb| c.read_u64(peb + PEB_PROCESS_HEAP))
                .unwrap_or(0) as usize;
            let Some(block) = heap::alloc(&c, heap, size as usize) else {
                return c.fail(ERROR_NOT_ENOUGH_MEMORY, 0);
            };
            if !c.copy(env as usize, block, size as usize) {
                return c.fail_status(Ntstatus::ACCESS_VIOLATION, 0);
            }
            c.finish(block)
        }
        "FreeEnvironmentStringsW" => {
            let block = c.arg(0);
            if heap::size_of(&c, block).is_none() {
                return c.fail(ERROR_INVALID_PARAMETER, FALSE);
            }
            heap::mark_free(&c, block);
            c.finish(TRUE)
        }
        "GetStartupInfoW" => get_startup_info(&mut c),
        "GetCurrentDirectoryW" => get_current_directory(&mut c),
        "GetACP" | "GetOEMCP" | "GetConsoleCP" | "GetConsoleOutputCP" => {
            c.finish(locale::ACP as usize)
        }
        "IsValidCodePage" => locale::is_valid_code_page(&mut c),
        "GetCPInfo" => locale::get_cp_info(&mut c),
        "MultiByteToWideChar" => locale::multi_byte_to_wide_char(&mut c),
        "WideCharToMultiByte" => locale::wide_char_to_multi_byte(&mut c),
        "GetStringTypeW" => locale::get_string_type(&mut c),
        "LCMapStringW" => locale::lc_map_string(&mut c),
        "CompareStringW" => locale::compare_string(&mut c),
        "GetUserDefaultLCID" => c.finish(locale::USER_LCID as usize),
        "IsValidLocale" => locale::is_valid_locale(&mut c),
        "CreateFileW" => file::create_file(&mut c),
        "ReadFile" => file::read_file(&mut c),
        "GetFileType" => file::get_file_type(&mut c),
        "SetFilePointerEx" => file::set_file_pointer_ex(&mut c),
        "GetFileSizeEx" => file::get_file_size_ex(&mut c),
        "FlushFileBuffers" => file::flush_file_buffers(&mut c),
        "SetEndOfFile" => file::set_end_of_file(&mut c),
        "GetFileAttributesExW" => file::get_file_attributes_ex(&mut c),
        "GetFileInformationByHandle" => file::get_file_information_by_handle(&mut c),
        "DuplicateHandle" => file::duplicate_handle(&mut c),
        "GetFullPathNameW" => file::get_full_path_name(&mut c),
        "GetTempPathW" => file::get_temp_path(&mut c),
        "SetCurrentDirectoryW" => file::set_current_directory(&mut c),
        "FlsAlloc" => runtime::fls_alloc(&mut c),
        "FlsGetValue" => runtime::fls_get_value(&mut c),
        "FlsSetValue" => runtime::fls_set_value(&mut c),
        "FlsFree" => runtime::fls_free(&mut c),
        "VerSetConditionMask" => runtime::ver_set_condition_mask(&mut c),
        "VerifyVersionInfoW" => runtime::verify_version_info(&mut c),
        "LoadLibraryExW" => runtime::load_library_ex(&mut c),
        "InitializeSRWLock" | "InitializeConditionVariable" => runtime::init_sync_word(&mut c),
        "AcquireSRWLockExclusive" => runtime::acquire_srw_lock_exclusive(&mut c),
        "ReleaseSRWLockExclusive" => runtime::release_srw_lock_exclusive(&mut c),
        "TryAcquireSRWLockExclusive" => runtime::try_acquire_srw_lock_exclusive(&mut c),
        "AcquireSRWLockShared" => runtime::acquire_srw_lock_shared(&mut c),
        "ReleaseSRWLockShared" => runtime::release_srw_lock_shared(&mut c),
        "WakeConditionVariable" | "WakeAllConditionVariable" => {
            runtime::wake_condition_variable(&mut c)
        }
        "SleepConditionVariableSRW" => runtime::sleep_condition_variable_srw(&mut c),
        "OutputDebugStringW" | "OutputDebugStringA" => runtime::output_debug_string(&mut c),
        "GetEnvironmentVariableA" => runtime::get_environment_variable_a(&mut c),
        "PathCchSkipRoot" => file::path_cch_skip_root(&mut c),
        "PathCchCombineEx" => file::path_cch_combine_ex(&mut c),
        "GetFileAttributesW" => file::get_file_attributes_w(&mut c),
        "GetFileInformationByHandleEx" => file::get_file_information_by_handle_ex(&mut c),
        "GetTimeZoneInformation" => runtime::get_time_zone_information(&mut c),
        "CreateWaitableTimerExW" => runtime::create_waitable_timer(&mut c),
        "LoadLibraryW" => runtime::load_library_ex_w(&mut c),
        "LCMapStringEx" => locale::lc_map_string_ex(&mut c),
        "GetLocaleInfoW" => locale::get_locale_info_w(&mut c),
        "GetSystemInfo" | "GetNativeSystemInfo" => runtime::get_system_info(&mut c),
        "LocalFree" => runtime::local_free(&mut c),
        "LoadLibraryA" => runtime::load_library_a(&mut c),
        "BCryptGenRandom" => runtime::bcrypt_gen_random(&mut c),
        "FormatMessageW" => runtime::format_message_w(&mut c),
        "RegOpenKeyExW" | "RegOpenKeyExA" | "RegCreateKeyExW" | "RegCreateKeyW" => {
            runtime::reg_open_key(&mut c)
        }
        "RegCloseKey" => runtime::reg_close_key(&mut c),
        "RegQueryValueExW" | "RegQueryInfoKeyW" | "RegEnumKeyExW" | "RegEnumValueW" => {
            runtime::reg_not_found(&mut c)
        }
        "FreeLibrary" => runtime::free_library(&mut c),
        "GetModuleHandleExW" => runtime::get_module_handle_ex(&mut c),
        // No thread here was converted to a fiber.
        "IsThreadAFiber" => c.finish(FALSE),
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
        // Bound so the runtime links; reached, it says so rather than pretend,
        // and names itself for whoever reads the host's log.
        _ => {
            c.host
                .platform()
                .trace(&alloc::format!("{} is not implemented", call.symbol()));
            c.fail(ERROR_CALL_NOT_IMPLEMENTED, 0)
        }
    }
}

mod file;
mod locale;
mod runtime;

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

/// GetModuleFileNameW(hModule, lpFilename, nSize): the module's full name out
/// of the loader list, NULL meaning the program. A name that does not fit is
/// cut to fit, terminated, and reported with ERROR_INSUFFICIENT_BUFFER.
fn get_module_file_name(c: &mut Call<'_>) -> Dispatch {
    use crate::teb_peb::{LDR_DLL_BASE, LDR_FULL_NAME, LDR_IN_LOAD_ORDER};
    let (module, out, size) = (c.arg(0), c.arg(1), c.arg(2));
    let Some(peb) = c.peb() else {
        return c.fail(ERROR_MOD_NOT_FOUND, 0);
    };
    let module = if module == 0 {
        c.read_u64(peb + PEB_IMAGE_BASE).unwrap_or(0) as usize
    } else {
        module
    };
    let Some(ldr) = c
        .read_u64(peb + PEB_LDR)
        .map(|v| v as usize)
        .filter(|v| *v != 0)
    else {
        return c.fail(ERROR_MOD_NOT_FOUND, 0);
    };
    let head = ldr + LDR_IN_LOAD_ORDER;
    let mut link = c.read_u64(head).unwrap_or(0) as usize;
    let mut found = None;
    for _ in 0..1024 {
        if link == head || link == 0 {
            break;
        }
        if c.read_u64(link + LDR_DLL_BASE) == Some(module as u64) {
            found = c.unicode(link + LDR_FULL_NAME);
            break;
        }
        link = c.read_u64(link).unwrap_or(0) as usize;
    }
    let Some((len, buf)) = found else {
        return c.fail(ERROR_MOD_NOT_FOUND, 0);
    };
    let units = len / 2;
    if size == 0 {
        return c.fail(ERROR_INSUFFICIENT_BUFFER, 0);
    }
    let copied = units.min(size - 1);
    if !c.copy(buf, out, copied * 2) || !c.write(out + copied * 2, &[0, 0]) {
        return c.fail_status(Ntstatus::ACCESS_VIOLATION, 0);
    }
    if units >= size {
        return c.fail(ERROR_INSUFFICIENT_BUFFER, size);
    }
    c.set_last_error(0);
    c.finish(copied)
}

/// GetStartupInfoW(lpStartupInfo): what the parameters block says, as Wine
/// copies it field by field; the standard handles come along because the
/// block marks them as meant.
fn get_startup_info(c: &mut Call<'_>) -> Dispatch {
    let info = c.arg(0);
    let Some(params) = c.params() else {
        return c.fail(ERROR_CALL_NOT_IMPLEMENTED, 0);
    };
    let mut block = [0u8; STARTUPINFO_SIZE as usize];
    block[..4].copy_from_slice(&STARTUPINFO_SIZE.to_le_bytes());
    let flags = c.read_u32(params + PARAMS_FLAGS).unwrap_or(0);
    block[0x3C..0x40].copy_from_slice(&flags.to_le_bytes());
    let show = c.read_u32(params + PARAMS_SHOW_WINDOW).unwrap_or(0) as u16;
    block[0x40..0x42].copy_from_slice(&show.to_le_bytes());
    for (i, field) in [0x50usize, 0x58, 0x60].into_iter().enumerate() {
        let handle = c.read_u64(params + PARAMS_STD_INPUT + i * 8).unwrap_or(0);
        block[field..field + 8].copy_from_slice(&handle.to_le_bytes());
    }
    if !c.write(info, &block) {
        return c.fail_status(Ntstatus::ACCESS_VIOLATION, 0);
    }
    c.finish(0)
}

/// GetCurrentDirectoryW(nBufferLength, lpBuffer): the directory without its
/// trailing separator unless it is a drive's root; too small a buffer is told
/// how much it needs, terminator included.
fn get_current_directory(c: &mut Call<'_>) -> Dispatch {
    let (size, out) = (c.arg(0), c.arg(1));
    let Some((len, buf)) = c
        .params()
        .and_then(|p| c.unicode(p + PARAMS_CURRENT_DIRECTORY))
    else {
        return c.fail(ERROR_CALL_NOT_IMPLEMENTED, 0);
    };
    let mut units = len / 2;
    // "Z:\" keeps its separator; "Z:\app\" does not.
    if units > 3 && c.read::<2>(buf + (units - 1) * 2) == Some([b'\\', 0]) {
        units -= 1;
    }
    if size <= units {
        return c.finish(units + 1);
    }
    if !c.copy(buf, out, units * 2) || !c.write(out + units * 2, &[0, 0]) {
        return c.fail_status(Ntstatus::ACCESS_VIOLATION, 0);
    }
    c.finish(units)
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
        assert_eq!(nr - WIN32_BASE, table_len() as u32);
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
        // A real kernel32 export nothing here binds is not found either.
        assert_eq!(Win32Call::resolve("KERNEL32.dll", "NoSuchFunctionW"), None);
        assert_eq!(Win32Call::resolve("USER32.dll", "WriteFile"), None);
    }

    #[test]
    fn each_library_names_each_function_once() {
        for lib in LIBRARIES {
            for (i, (name, _)) in lib.exports.iter().enumerate() {
                assert_eq!(
                    lib.exports.iter().position(|(n, _)| n == name),
                    Some(i),
                    "{name} twice in {}",
                    lib.name
                );
            }
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
