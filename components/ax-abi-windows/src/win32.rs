//! Win32 entry points, layered on the NT calls the way kernel32 is.
//!
//! On Windows these live in kernel32 and kernelbase, ordinary user-mode DLLs
//! that call down into ntdll: `WriteFile` is `NtWriteFile` plus the Win32
//! conventions - clear the out-parameter first, turn the `NTSTATUS` into a
//! `BOOL`, and record the failure where `GetLastError` reads it (Wine
//! `dlls/kernelbase/file.c`, `dlls/ntdll/error.c`). There is no ntdll here to
//! carry them, so an image's imports bind to stubs synthesized into the image
//! and each stub traps on a number reserved below. The layering is kept all
//! the same: the work stays in [`crate::nt`], and this module only applies the
//! conventions.
//!
//! Every argument is read from the trap frame, none from the stack: the stub
//! an import binds to ([`crate::thunk`]) has already moved the Windows
//! registers and the two stack arguments into the registers a trap carries.

use ax_abi_port::Host;
use ax_dispatch::{Dispatch, TrapEnv};

use crate::{
    handle::Handle,
    nt::{self, Ntstatus},
    teb_peb::TEB_LAST_ERROR,
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

/// The Win32 entry points this package serves.
///
/// Each is a function an image imports by name; [`Win32Call::resolve`] turns
/// such an import into the number its stub traps on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Win32Call {
    WriteFile,
    GetStdHandle,
    GetLastError,
    SetLastError,
    ExitProcess,
}

impl Win32Call {
    /// The call a trap number names, or `None` for a number outside this layer.
    pub fn from_nr(nr: u32) -> Option<Win32Call> {
        Some(match nr.checked_sub(WIN32_BASE)? {
            0 => Win32Call::WriteFile,
            1 => Win32Call::GetStdHandle,
            2 => Win32Call::GetLastError,
            3 => Win32Call::SetLastError,
            4 => Win32Call::ExitProcess,
            _ => return None,
        })
    }

    /// The trap number a stub for this call raises.
    pub fn nr(self) -> u32 {
        WIN32_BASE
            + match self {
                Win32Call::WriteFile => 0,
                Win32Call::GetStdHandle => 1,
                Win32Call::GetLastError => 2,
                Win32Call::SetLastError => 3,
                Win32Call::ExitProcess => 4,
            }
    }

    /// The exported name an image imports this call by.
    pub fn symbol(self) -> &'static str {
        match self {
            Win32Call::WriteFile => "WriteFile",
            Win32Call::GetStdHandle => "GetStdHandle",
            Win32Call::GetLastError => "GetLastError",
            Win32Call::SetLastError => "SetLastError",
            Win32Call::ExitProcess => "ExitProcess",
        }
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
        const CALLS: [Win32Call; 5] = [
            Win32Call::WriteFile,
            Win32Call::GetStdHandle,
            Win32Call::GetLastError,
            Win32Call::SetLastError,
            Win32Call::ExitProcess,
        ];
        CALLS
            .into_iter()
            .find(|call| call.symbol() == symbol && call.library().eq_ignore_ascii_case(library))
    }
}

/// Serve a Win32 entry point, or decline a number that names none.
pub fn dispatch(env: &mut dyn TrapEnv, host: &dyn Host) -> Dispatch {
    let Some(call) = Win32Call::from_nr(env.nr() as u32) else {
        return Dispatch::Passthrough;
    };
    let teb = env.thread_pointer();
    let a = |i: usize| env.arg(i);
    let result = match call {
        // WriteFile(hFile, lpBuffer, nNumberOfBytesToWrite,
        // lpNumberOfBytesWritten, lpOverlapped).
        Win32Call::WriteFile => {
            let (handle, buffer, length, written, overlapped) = (a(0), a(1), a(2), a(3), a(4));
            // The count is cleared before the transfer, so a caller reading it
            // after a failure sees zero rather than a stale value.
            if written != 0 && write_u32(host, written, 0).is_err() {
                return fail(env, host, teb, Ntstatus::ACCESS_VIOLATION, FALSE);
            }
            // An OVERLAPPED asks for asynchronous delivery, which the NT layer
            // refuses too rather than quietly serving it synchronously.
            if overlapped != 0 {
                return fail(env, host, teb, Ntstatus::NOT_IMPLEMENTED, FALSE);
            }
            let (status, information) =
                nt::transfer(host, true, handle, buffer, length, None).unwrap_or_else(|s| (s, 0));
            if status != Ntstatus::SUCCESS {
                return fail(env, host, teb, status, FALSE);
            }
            if written != 0 && write_u32(host, written, information as u32).is_err() {
                return fail(env, host, teb, Ntstatus::ACCESS_VIOLATION, FALSE);
            }
            TRUE
        }
        // Windows answers this from the process parameters block, which nothing
        // populates yet; until something does, the three standard streams
        // answer with the handles for the descriptors a process starts with.
        Win32Call::GetStdHandle => match a(0) as u32 {
            STD_INPUT_HANDLE => Handle::from_slot(0).0 as usize,
            STD_OUTPUT_HANDLE => Handle::from_slot(1).0 as usize,
            STD_ERROR_HANDLE => Handle::from_slot(2).0 as usize,
            _ => {
                return fail(
                    env,
                    host,
                    teb,
                    Ntstatus::INVALID_HANDLE,
                    INVALID_HANDLE_VALUE,
                );
            }
        },
        Win32Call::GetLastError => last_error(host, teb) as usize,
        Win32Call::SetLastError => {
            set_last_error(host, teb, a(0) as u32);
            // The function returns void; the trap still has to leave a value.
            0
        }
        // ExitProcess ends every thread in the process, which is exit_group and
        // not exit. A host that returns from it leaves the caller holding a
        // value, so say the call did not succeed.
        Win32Call::ExitProcess => {
            let Some(tasks) = host.tasks() else {
                return fail(env, host, teb, Ntstatus::NOT_IMPLEMENTED, FALSE);
            };
            let _ = tasks.exit_group(a(0) as i32);
            FALSE
        }
    };
    finish(env, result)
}

/// Record why a call failed where `GetLastError` reads it, then answer with the
/// value this particular function reports failure as.
fn fail(
    env: &mut dyn TrapEnv,
    host: &dyn Host,
    teb: usize,
    status: Ntstatus,
    result: usize,
) -> Dispatch {
    set_last_error(host, teb, status.dos_error());
    finish(env, result)
}

fn finish(env: &mut dyn TrapEnv, value: usize) -> Dispatch {
    env.set_result(value);
    Dispatch::Handled
}

/// The thread's last error, which lives in its own control block so a program
/// reading `gs:[0x68]` sees the same word this returns. A host that cannot say
/// where the block is keeps no value, and the thread reads a clean one.
fn last_error(host: &dyn Host, teb: usize) -> u32 {
    if teb == 0 {
        return 0;
    }
    let mut word = [0u8; 4];
    match host.platform().read_user(teb + TEB_LAST_ERROR, &mut word) {
        Ok(_) => u32::from_le_bytes(word),
        Err(_) => 0,
    }
}

fn set_last_error(host: &dyn Host, teb: usize, error: u32) {
    if teb != 0 {
        let _ = write_u32(host, teb + TEB_LAST_ERROR, error);
    }
}

fn write_u32(host: &dyn Host, at: usize, value: u32) -> Result<(), i32> {
    host.platform()
        .write_user(at, &value.to_le_bytes())
        .map(|_| ())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn numbers_round_trip_and_stop_where_the_table_ends() {
        // Walked rather than written down, so adding a function needs no edit
        // here.
        let mut nr = WIN32_BASE;
        while let Some(call) = Win32Call::from_nr(nr) {
            assert_eq!(call.nr(), nr);
            nr += 1;
        }
        assert!(nr > WIN32_BASE, "the table claims at least one number");
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
            Some(Win32Call::WriteFile)
        );
        // Import tables vary in how they spell the library; the loader does not
        // care about its case.
        assert_eq!(
            Win32Call::resolve("kernel32.DLL", "ExitProcess"),
            Some(Win32Call::ExitProcess)
        );
        // An export name is case-sensitive, as the linker wrote it.
        assert_eq!(Win32Call::resolve("KERNEL32.dll", "writefile"), None);
        assert_eq!(Win32Call::resolve("KERNEL32.dll", "CreateMutexW"), None);
        assert_eq!(Win32Call::resolve("USER32.dll", "WriteFile"), None);
    }
}
