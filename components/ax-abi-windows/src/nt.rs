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

use ax_abi_port::{
    At, Attributes, Create, Host, MapRequest, MapSource, NodeKind, OpenHow, Prot, SeekFrom,
};
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
    /// The Win32 error code `RtlNtStatusToDosError` maps this status to, which
    /// is what `GetLastError` reports after a Win32 wrapper fails.
    ///
    /// Only the statuses this package produces are listed; each pair is read
    /// from Wine's generated table (`dlls/ntdll/error.h`) rather than guessed,
    /// and anything unlisted takes the catch-all an unmapped failure gets.
    pub(crate) fn dos_error(self) -> u32 {
        const ERROR_GEN_FAILURE: u32 = 31;
        const MAP: &[(Ntstatus, u32)] = &[
            (Ntstatus::SUCCESS, 0),
            (Ntstatus::NOT_IMPLEMENTED, 1),
            (Ntstatus::INVALID_HANDLE, 6),
            (Ntstatus::INFO_LENGTH_MISMATCH, 24),
            (Ntstatus::UNSUCCESSFUL, ERROR_GEN_FAILURE),
            (Ntstatus::INVALID_PARAMETER, 87),
            (Ntstatus::OBJECT_NAME_INVALID, 123),
            (Ntstatus::NAME_TOO_LONG, 206),
            (Ntstatus::NO_YIELD_PERFORMED, 721),
            (Ntstatus::ACCESS_VIOLATION, 998),
            (Ntstatus::SHARING_VIOLATION, 32),
            (Ntstatus::DEVICE_BUSY, 170),
            (Ntstatus::DISK_FULL, 112),
            (Ntstatus::ACCESS_DENIED, 5),
            (Ntstatus::OBJECT_PATH_NOT_FOUND, 3),
            (Ntstatus::OBJECT_NAME_NOT_FOUND, 2),
            (Ntstatus::OBJECT_NAME_COLLISION, 183),
            (Ntstatus::INVALID_DEVICE_REQUEST, 1),
            (Ntstatus::TOO_MANY_OPENED_FILES, 4),
            (Ntstatus::DIRECTORY_NOT_EMPTY, 145),
            (Ntstatus::PIPE_DISCONNECTED, 233),
            (Ntstatus::DEVICE_NOT_READY, 21),
            (Ntstatus::NO_SUCH_DEVICE, 433),
            (Ntstatus::NOT_SUPPORTED, 50),
            (Ntstatus::ILLEGAL_FUNCTION, 1),
            (Ntstatus::REPARSE_POINT_NOT_RESOLVED, 1921),
            (Ntstatus::IO_TIMEOUT, 121),
            (Ntstatus::NO_MEMORY, 8),
            (Ntstatus::END_OF_FILE, 38),
            (Ntstatus::BUFFER_TOO_SMALL, 122),
        ];
        MAP.iter()
            .find(|(status, _)| *status == self)
            .map_or(ERROR_GEN_FAILURE, |(_, error)| *error)
    }
    /// `STATUS_NOT_IMPLEMENTED`.
    pub const NOT_IMPLEMENTED: Ntstatus = Ntstatus(0xC000_0002);
    /// `STATUS_INVALID_HANDLE`.
    pub const INVALID_HANDLE: Ntstatus = Ntstatus(0xC000_0008);
    /// `STATUS_NO_YIELD_PERFORMED`, which a yield reports when nothing else
    /// was waiting. It is a success code, not a failure.
    pub const NO_YIELD_PERFORMED: Ntstatus = Ntstatus(0x4000_0024);
    /// `STATUS_INFO_LENGTH_MISMATCH`, for a buffer too small for the class
    /// that was asked for.
    pub const INFO_LENGTH_MISMATCH: Ntstatus = Ntstatus(0xC000_0004);
    /// `STATUS_INVALID_PARAMETER`.
    pub const INVALID_PARAMETER: Ntstatus = Ntstatus(0xC000_000D);
    /// `STATUS_ACCESS_VIOLATION`.
    pub const ACCESS_VIOLATION: Ntstatus = Ntstatus(0xC000_0005);
    /// `STATUS_UNSUCCESSFUL`.
    pub const UNSUCCESSFUL: Ntstatus = Ntstatus(0xC000_0001);
    /// `STATUS_OBJECT_NAME_INVALID`: the name is not one this namespace can express.
    pub const OBJECT_NAME_INVALID: Ntstatus = Ntstatus(0xC000_0033);
    /// `STATUS_NAME_TOO_LONG`: the name is longer than this package will resolve.
    pub const NAME_TOO_LONG: Ntstatus = Ntstatus(0xC000_0106);
    // What a host's errno turns into, as `errno_to_status` in Wine's ntdll
    // maps it; the values are those of `ntstatus.h`.
    pub const SHARING_VIOLATION: Ntstatus = Ntstatus(0xC000_0043);
    pub const DEVICE_BUSY: Ntstatus = Ntstatus(0x8000_0011);
    pub const DISK_FULL: Ntstatus = Ntstatus(0xC000_007F);
    pub const ACCESS_DENIED: Ntstatus = Ntstatus(0xC000_0022);
    pub const OBJECT_PATH_NOT_FOUND: Ntstatus = Ntstatus(0xC000_003A);
    pub const OBJECT_NAME_NOT_FOUND: Ntstatus = Ntstatus(0xC000_0034);
    pub const OBJECT_NAME_COLLISION: Ntstatus = Ntstatus(0xC000_0035);
    pub const INVALID_DEVICE_REQUEST: Ntstatus = Ntstatus(0xC000_0010);
    pub const TOO_MANY_OPENED_FILES: Ntstatus = Ntstatus(0xC000_011F);
    pub const DIRECTORY_NOT_EMPTY: Ntstatus = Ntstatus(0xC000_0101);
    pub const PIPE_DISCONNECTED: Ntstatus = Ntstatus(0xC000_00B0);
    pub const DEVICE_NOT_READY: Ntstatus = Ntstatus(0xC000_00A3);
    pub const NO_SUCH_DEVICE: Ntstatus = Ntstatus(0xC000_000E);
    pub const NOT_SUPPORTED: Ntstatus = Ntstatus(0xC000_00BB);
    pub const ILLEGAL_FUNCTION: Ntstatus = Ntstatus(0xC000_00AF);
    pub const REPARSE_POINT_NOT_RESOLVED: Ntstatus = Ntstatus(0xC000_0280);
    pub const IO_TIMEOUT: Ntstatus = Ntstatus(0xC000_00B5);
    pub const NO_MEMORY: Ntstatus = Ntstatus(0xC000_0017);
    pub const END_OF_FILE: Ntstatus = Ntstatus(0xC000_0011);
    pub const BUFFER_TOO_SMALL: Ntstatus = Ntstatus(0xC000_0023);

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
    /// `NtYieldExecution()`.
    YieldExecution,
    /// `NtQueryAttributesFile(ObjectAttributes, FileInformation)`.
    QueryAttributesFile,
    /// `NtQueryInformationFile(...)`.
    QueryInformationFile,
    /// `NtSetInformationFile(...)`.
    SetInformationFile,
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
            9 => NtSyscall::YieldExecution,
            10 => NtSyscall::QueryAttributesFile,
            11 => NtSyscall::QueryInformationFile,
            12 => NtSyscall::SetInformationFile,
            _ => return None,
        })
    }

    /// The system-service number for this call.
    pub const fn nr(self) -> u32 {
        self as u32
    }
}

/// Translate a port error into the NTSTATUS a Windows program expects.
/// The status a host's errno means, as Wine's `errno_to_status` maps it,
/// with the two it leaves to the callers - a name that exists, and no memory -
/// given their own statuses here since nothing else can tell them apart later.
pub(crate) fn status_from_errno(errno: i32) -> Ntstatus {
    use ax_abi_port::*;
    match errno {
        EBADF => Ntstatus::INVALID_HANDLE,
        EINVAL => Ntstatus::INVALID_PARAMETER,
        EFAULT => Ntstatus::ACCESS_VIOLATION,
        ENOSYS => Ntstatus::NOT_IMPLEMENTED,
        EAGAIN => Ntstatus::SHARING_VIOLATION,
        EBUSY => Ntstatus::DEVICE_BUSY,
        ENOSPC => Ntstatus::DISK_FULL,
        EPERM | EROFS | EACCES => Ntstatus::ACCESS_DENIED,
        ENOTDIR => Ntstatus::OBJECT_PATH_NOT_FOUND,
        ENOENT => Ntstatus::OBJECT_NAME_NOT_FOUND,
        EEXIST => Ntstatus::OBJECT_NAME_COLLISION,
        EISDIR => Ntstatus::INVALID_DEVICE_REQUEST,
        EMFILE | ENFILE => Ntstatus::TOO_MANY_OPENED_FILES,
        ENOTEMPTY => Ntstatus::DIRECTORY_NOT_EMPTY,
        EPIPE | ECONNRESET => Ntstatus::PIPE_DISCONNECTED,
        EIO => Ntstatus::DEVICE_NOT_READY,
        ENXIO => Ntstatus::NO_SUCH_DEVICE,
        ENOTTY | EOPNOTSUPP => Ntstatus::NOT_SUPPORTED,
        ESPIPE => Ntstatus::ILLEGAL_FUNCTION,
        ELOOP => Ntstatus::REPARSE_POINT_NOT_RESOLVED,
        ETIME => Ntstatus::IO_TIMEOUT,
        ENOMEM => Ntstatus::NO_MEMORY,
        _ => Ntstatus::UNSUCCESSFUL,
    }
}

/// The 64-bit `IO_STATUS_BLOCK`: the status word, then the byte count.
/// The body of `NtReadFile`/`NtWriteFile`: resolve the handle and move the
/// bytes, reporting how many moved.
///
/// `Err` is a handle that names nothing, which happens before any transfer is
/// attempted and so leaves the caller's status block untouched; `Ok` carries
/// the status the transfer itself produced. The Win32 entry points reach the
/// same work through here, the way kernelbase reaches it through ntdll.
pub(crate) fn transfer(
    host: &dyn Host,
    write: bool,
    handle: usize,
    buffer: usize,
    length: usize,
    at: Option<u64>,
) -> Result<(Ntstatus, usize), Ntstatus> {
    let (Some(files), Ok(fd)) = (host.files(), descriptor(handle)) else {
        return Err(Ntstatus::INVALID_HANDLE);
    };
    let transferred = match (write, at) {
        (true, None) => files.write(fd, buffer, length),
        (true, Some(at)) => files.pwrite(fd, buffer, length, at),
        (false, None) => files.read(fd, buffer, length),
        (false, Some(at)) => files.pread(fd, buffer, length, at),
    };
    Ok(match transferred {
        Ok(n) => (Ntstatus::SUCCESS, n as usize),
        Err(errno) => (status_from_errno(errno), 0),
    })
}

fn write_io_status(host: &dyn Host, at: usize, status: Ntstatus, information: usize) -> Ntstatus {
    if at == 0 {
        return status;
    }
    let mut block = [0u8; IO_STATUS_BLOCK_LEN];
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

/// `OBJECT_ATTRIBUTES` as x64 lays it out: `Length`, `RootDirectory`,
/// `ObjectName`, `Attributes`, and two pointers this package does not read.
const OBJECT_ATTRIBUTES_LEN: usize = 48;
const OA_ROOT_DIRECTORY: usize = 8;
const OA_OBJECT_NAME: usize = 16;

/// `UNICODE_STRING`: a UTF-16 run given by byte length, not by a terminator.
const UNICODE_STRING_LEN: usize = 16;

/// `IO_STATUS_BLOCK`: the status, then what the operation did.
const IO_STATUS_BLOCK_LEN: usize = 16;
/// The `Information` values `NtCreateFile` reports.
const FILE_SUPERSEDED: usize = 0;
const FILE_OPENED: usize = 1;
const FILE_CREATED: usize = 2;
const FILE_OVERWRITTEN: usize = 3;

/// `CreateDisposition`: what to do about the file already existing, or not.
const FILE_SUPERSEDE: usize = 0;
const FILE_OPEN: usize = 1;
const FILE_CREATE: usize = 2;
const FILE_OPEN_IF: usize = 3;
const FILE_OVERWRITE: usize = 4;
const FILE_OVERWRITE_IF: usize = 5;

/// `CreateOptions` bits that change what is opened rather than how it is cached.
const FILE_DIRECTORY_FILE: usize = 0x0000_0001;
const FILE_OPEN_REPARSE_POINT: usize = 0x0020_0000;

/// `DesiredAccess` bits that decide which way the file is opened.
const FILE_READ_DATA: usize = 0x0000_0001;
const FILE_WRITE_DATA: usize = 0x0000_0002;
const FILE_APPEND_DATA: usize = 0x0000_0004;
const GENERIC_WRITE: usize = 0x4000_0000;
const GENERIC_READ: usize = 0x8000_0000;
const GENERIC_ALL: usize = 0x1000_0000;

/// `OBJ_INHERIT`, which decides whether the handle survives a spawn.
const OBJ_INHERIT: u32 = 0x0000_0002;

/// The longest path this package resolves, in bytes of UTF-8. Windows itself
/// stops at 32767 UTF-16 units; a smaller bound keeps the buffer on the stack,
/// and a name past it is refused rather than truncated.
const PATH_MAX: usize = 1024;

/// Decode a UTF-16 path from user memory into `out`, and hand back the part of
/// it that names a file.
///
/// The caller writes an NT path: the object namespace prefix `\??\`, then a DOS
/// drive, then the path itself with backslashes. Windows does the DOS-to-NT
/// rewrite in user space before the call, so what arrives is already in this
/// form. What comes back is the path with a single root, which is what every
/// host here means by the same name.
fn read_nt_path<'a>(
    host: &dyn Host,
    at: usize,
    out: &'a mut [u8; PATH_MAX],
) -> Result<&'a str, Ntstatus> {
    let mut header = [0u8; UNICODE_STRING_LEN];
    host.platform()
        .read_user(at, &mut header)
        .map_err(status_from_errno)?;
    let len = u16::from_le_bytes([header[0], header[1]]) as usize;
    let buffer = u64::from_le_bytes(header[8..16].try_into().unwrap()) as usize;
    if len == 0 || buffer == 0 || !len.is_multiple_of(2) {
        return Err(Ntstatus::OBJECT_NAME_INVALID);
    }
    if len / 2 > PATH_MAX {
        return Err(Ntstatus::NAME_TOO_LONG);
    }

    // Read the UTF-16 in place at the tail of the output buffer, so decoding
    // into the front of it needs no second buffer: UTF-8 is never longer than
    // UTF-16 for the ASCII a path is written in, and a non-ASCII name that
    // would grow is refused below rather than overrunning.
    let (utf8, utf16) = out.split_at_mut(PATH_MAX - len);
    host.platform()
        .read_user(buffer, &mut utf16[..len])
        .map_err(status_from_errno)?;

    let units = (0..len / 2).map(|i| u16::from_le_bytes([utf16[i * 2], utf16[i * 2 + 1]]));
    let mut written = 0;
    for unit in char::decode_utf16(units) {
        let ch = unit.map_err(|_| Ntstatus::OBJECT_NAME_INVALID)?;
        // A backslash separates in the caller's namespace and in no other, so
        // it becomes the separator the host resolves with.
        let ch = if ch == '\\' { '/' } else { ch };
        let room = utf8.len().saturating_sub(written);
        if ch.len_utf8() > room {
            return Err(Ntstatus::NAME_TOO_LONG);
        }
        written += ch.encode_utf8(&mut utf8[written..]).len();
    }

    let path = core::str::from_utf8(&utf8[..written]).map_err(|_| Ntstatus::OBJECT_NAME_INVALID)?;
    // Strip the object-namespace prefix and the DOS drive behind it. There is
    // one filesystem here, so a drive letter names its root and nothing else.
    let path = path.strip_prefix("/??/").unwrap_or(path);
    let path = match path.as_bytes() {
        [drive, b':', ..] if drive.is_ascii_alphabetic() => &path[2..],
        _ => path,
    };
    if path.is_empty() {
        return Ok("/");
    }
    Ok(path)
}

/// Turn `DesiredAccess`, `CreateDisposition` and `CreateOptions` into the
/// neutral request the host resolves, or say why the combination means nothing.
pub(crate) fn open_request(
    access: usize,
    disposition: usize,
    options: usize,
    attributes: u32,
) -> Result<(OpenHow, usize), Ntstatus> {
    let read = access & (FILE_READ_DATA | GENERIC_READ | GENERIC_ALL) != 0;
    let write = access & (FILE_WRITE_DATA | FILE_APPEND_DATA | GENERIC_WRITE | GENERIC_ALL) != 0;
    let (create, truncate, information) = match disposition {
        FILE_OPEN => (Create::Never, false, FILE_OPENED),
        FILE_CREATE => (Create::Exclusive, false, FILE_CREATED),
        FILE_OPEN_IF => (Create::IfAbsent, false, FILE_OPENED),
        FILE_OVERWRITE => (Create::Never, true, FILE_OVERWRITTEN),
        FILE_OVERWRITE_IF => (Create::IfAbsent, true, FILE_OVERWRITTEN),
        FILE_SUPERSEDE => (Create::IfAbsent, true, FILE_SUPERSEDED),
        _ => return Err(Ntstatus::INVALID_PARAMETER),
    };
    // Creating or truncating without having asked to write is a contradiction,
    // not something to paper over by opening read-only.
    if (truncate || create != Create::Never) && !write {
        return Err(Ntstatus::INVALID_PARAMETER);
    }
    Ok((
        OpenHow {
            read: read || !write,
            write,
            append: access & FILE_APPEND_DATA != 0 && access & FILE_WRITE_DATA == 0,
            truncate,
            create,
            directory: options & FILE_DIRECTORY_FILE != 0,
            // A reparse point is the caller asking for the link itself.
            follow: options & FILE_OPEN_REPARSE_POINT == 0,
            // A handle is inheritable only when asked for, which is the
            // opposite of the default a descriptor is installed with.
            close_on_exec: attributes & OBJ_INHERIT == 0,
            mode: 0o666,
        },
        information,
    ))
}

/// `FILE_BASIC_INFORMATION`: four timestamps and the attribute word.
const FILE_BASIC_INFORMATION_LEN: usize = 40;
/// `FILE_STANDARD_INFORMATION`: allocation, size, links, and two flags.
const FILE_STANDARD_INFORMATION_LEN: usize = 24;
/// The information classes `NtQueryInformationFile` answers.
const FILE_BASIC_INFORMATION_CLASS: usize = 4;
const FILE_STANDARD_INFORMATION_CLASS: usize = 5;
/// The classes `NtSetInformationFile` accepts: where the next transfer starts,
/// and how long the file is. Both carry a single 64-bit value.
const FILE_POSITION_INFORMATION_CLASS: usize = 14;
const FILE_END_OF_FILE_INFORMATION_CLASS: usize = 20;
/// `FILE_POSITION_INFORMATION` / `FILE_END_OF_FILE_INFORMATION`: one LARGE_INTEGER.
const FILE_OFFSET_INFORMATION_LEN: usize = 8;

/// `FILE_ATTRIBUTE_*`, the ones a node's kind and mode decide.
const FILE_ATTRIBUTE_READONLY: u32 = 0x0000_0001;
const FILE_ATTRIBUTE_DIRECTORY: u32 = 0x0000_0010;
const FILE_ATTRIBUTE_NORMAL: u32 = 0x0000_0080;
const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0000_0400;

/// Convert an epoch time to NT's, which counts 100-nanosecond intervals from
/// 1601 rather than seconds from 1970.
pub(crate) fn nt_time(ns: u64) -> u64 {
    const EPOCH_DIFFERENCE_100NS: u64 = 116_444_736_000_000_000;
    EPOCH_DIFFERENCE_100NS + ns / 100
}

/// The attribute word a node's kind and mode amount to.
pub(crate) fn file_attributes(attr: &Attributes) -> u32 {
    let mut flags = match attr.kind {
        NodeKind::Directory => FILE_ATTRIBUTE_DIRECTORY,
        NodeKind::Symlink => FILE_ATTRIBUTE_REPARSE_POINT,
        _ => FILE_ATTRIBUTE_NORMAL,
    };
    // Nothing here has an access-control list, so "can the owner write it"
    // is the closest thing to the read-only attribute a caller asks about.
    if attr.mode & 0o200 == 0 {
        flags |= FILE_ATTRIBUTE_READONLY;
    }
    flags
}

/// Lay attributes out as `FILE_BASIC_INFORMATION`.
fn basic_information(attr: &Attributes) -> [u8; FILE_BASIC_INFORMATION_LEN] {
    let mut buf = [0u8; FILE_BASIC_INFORMATION_LEN];
    // Creation time has no counterpart in what the host reports, so it carries
    // the status-change time rather than an invented one.
    for (at, ns) in [
        (0, attr.changed_ns),
        (8, attr.accessed_ns),
        (16, attr.modified_ns),
        (24, attr.changed_ns),
    ] {
        buf[at..at + 8].copy_from_slice(&nt_time(ns).to_le_bytes());
    }
    buf[32..36].copy_from_slice(&file_attributes(attr).to_le_bytes());
    buf
}

/// The `PAGE_*` protections a caller may ask for.
const PAGE_READONLY: usize = 0x02;
const PAGE_READWRITE: usize = 0x04;
const PAGE_EXECUTE: usize = 0x10;
const PAGE_EXECUTE_READ: usize = 0x20;
const PAGE_EXECUTE_READWRITE: usize = 0x40;

/// `ProcessBasicInformation`, the only information class answered here.
const PROCESS_BASIC_INFORMATION: usize = 0;
/// How long `PROCESS_BASIC_INFORMATION` is: exit status, PEB pointer, affinity
/// mask, base priority, then the process id and its parent's.
const PROCESS_BASIC_INFORMATION_LEN: usize = 48;

/// The `MEM_*` allocation and release kinds.
const MEM_COMMIT: usize = 0x1000;
const MEM_RESERVE: usize = 0x2000;
const MEM_DECOMMIT: usize = 0x4000;
const MEM_RELEASE: usize = 0x8000;
const MEM_TOP_DOWN: usize = 0x0010_0000;

/// Translate the `PAGE_*` protection constants a Windows caller passes.
pub(crate) fn prot_from_page(protect: usize) -> Prot {
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
pub(crate) fn descriptor(handle: usize) -> Result<i32, Ntstatus> {
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
    // An NT call takes up to eleven arguments. The first four arrive in the
    // registers the trap frame exposes; the rest are on the caller's stack,
    // which is where a Windows kernel reads them from too. A host that cannot
    // say where the stack is gets a call that needs one refused rather than
    // served with whatever happened to be in a register.
    let sp = env.stack_pointer();
    let a = |i: usize| -> usize {
        if i < 4 {
            env.arg(i)
        } else if sp == 0 {
            0
        } else {
            let mut word = [0u8; size_of::<usize>()];
            match host
                .platform()
                .read_user(sp + (i - 4) * size_of::<usize>(), &mut word)
            {
                Ok(_) => usize::from_ne_bytes(word),
                Err(_) => 0,
            }
        }
    };
    let status = match call {
        NtSyscall::Close => match (descriptor(a(0)), host.files()) {
            (Ok(fd), Some(files)) => files
                .close(fd)
                .map_or_else(status_from_errno, |_| Ntstatus::SUCCESS),
            (Err(status), _) => status,
            (_, None) => Ntstatus::NOT_IMPLEMENTED,
        },
        // NtReadFile/NtWriteFile(FileHandle, Event, ApcRoutine, ApcContext,
        // IoStatusBlock, Buffer, Length, ByteOffset, Key). The completion
        // arguments describe asynchronous delivery, which nothing here can do,
        // so a caller asking for it is refused rather than served synchronously
        // behind its back.
        NtSyscall::WriteFile | NtSyscall::ReadFile if sp == 0 => Ntstatus::NOT_IMPLEMENTED,
        NtSyscall::WriteFile | NtSyscall::ReadFile => {
            if a(1) != 0 || a(2) != 0 {
                return finish(env, Ntstatus::NOT_IMPLEMENTED);
            }
            let (io_status, buffer, length, offset_ptr) = (a(4), a(5), a(6), a(7));
            // A null ByteOffset means "wherever the file is now"; otherwise it
            // points at the offset to transfer at.
            let at = if offset_ptr == 0 {
                None
            } else {
                match read_pointer(host, offset_ptr) {
                    Ok(offset) => Some(offset as u64),
                    Err(status) => return finish(env, status),
                }
            };
            let write = matches!(call, NtSyscall::WriteFile);
            match transfer(host, write, a(0), buffer, length, at) {
                Ok((status, information)) => write_io_status(host, io_status, status, information),
                Err(status) => return finish(env, status),
            }
        }
        NtSyscall::AllocateVirtualMemory => {
            let Some(mem) = host.mem() else {
                return finish(env, Ntstatus::NOT_IMPLEMENTED);
            };
            // NtAllocateVirtualMemory(ProcessHandle, *BaseAddress, ZeroBits,
            // *RegionSize, AllocationType, Protect). Both the base and the size
            // are in-out: the caller passes what it wants and reads back what
            // it got.
            let (base_ptr, size_ptr, alloc_type, protect) = (a(1), a(3), a(4), a(5));
            if alloc_type & !(MEM_COMMIT | MEM_RESERVE | MEM_TOP_DOWN) != 0 {
                return finish(env, Ntstatus::INVALID_PARAMETER);
            }
            let base = match read_pointer(host, base_ptr) {
                Ok(base) => base,
                Err(status) => return finish(env, status),
            };
            let size = match read_pointer(host, size_ptr) {
                Ok(size) => size,
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
            // NtProtectVirtualMemory(ProcessHandle, *BaseAddress, *RegionSize,
            // NewProtect, *OldProtect). The old protection is an output the
            // caller relies on to put things back.
            let (base_ptr, size_ptr, new_protect, old_ptr) = (a(1), a(2), a(3), a(4));
            let base = match read_pointer(host, base_ptr) {
                Ok(base) => base,
                Err(status) => return finish(env, status),
            };
            let size = match read_pointer(host, size_ptr) {
                Ok(size) => size,
                Err(status) => return finish(env, status),
            };
            match mem.protect(base, size, prot_from_page(new_protect)) {
                Ok(_) => {
                    // The port does not report what the protection was, so say
                    // the most permissive thing that cannot mislead a caller
                    // into restoring less than it had.
                    if old_ptr != 0
                        && let Err(errno) = host
                            .platform()
                            .write_user(old_ptr, &PAGE_EXECUTE_READWRITE.to_le_bytes())
                    {
                        return finish(env, status_from_errno(errno));
                    }
                    Ntstatus::SUCCESS
                }
                Err(errno) => status_from_errno(errno),
            }
        }
        NtSyscall::FreeVirtualMemory => {
            let Some(mem) = host.mem() else {
                return finish(env, Ntstatus::NOT_IMPLEMENTED);
            };
            // NtFreeVirtualMemory(ProcessHandle, *BaseAddress, *RegionSize,
            // FreeType). MEM_RELEASE gives the range back and requires a zero
            // size; MEM_DECOMMIT only drops the pages, which this unmaps too.
            let (base_ptr, size_ptr, free_type) = (a(1), a(2), a(3));
            let base = match read_pointer(host, base_ptr) {
                Ok(base) => base,
                Err(status) => return finish(env, status),
            };
            let size = match read_pointer(host, size_ptr) {
                Ok(size) => size,
                Err(status) => return finish(env, status),
            };
            match free_type {
                MEM_RELEASE if size != 0 => Ntstatus::INVALID_PARAMETER,
                MEM_RELEASE | MEM_DECOMMIT => mem
                    .unmap(base, size)
                    .map_or_else(status_from_errno, |_| Ntstatus::SUCCESS),
                _ => Ntstatus::INVALID_PARAMETER,
            }
        }
        // NtYieldExecution() gives up the rest of the time slice. It reports
        // whether anything else was waiting; saying nothing was is honest and
        // is what a caller treats as "keep going".
        NtSyscall::YieldExecution => match host.tasks() {
            Some(tasks) => tasks
                .sched_yield()
                .map_or_else(status_from_errno, |_| Ntstatus::NO_YIELD_PERFORMED),
            None => Ntstatus::NOT_IMPLEMENTED,
        },
        NtSyscall::TerminateProcess => match host.tasks() {
            Some(tasks) => tasks
                .exit_group(a(1) as i32)
                .map_or_else(status_from_errno, |_| Ntstatus::SUCCESS),
            None => Ntstatus::NOT_IMPLEMENTED,
        },
        // NtQueryInformationProcess(ProcessHandle, InformationClass,
        // Information, InformationLength, ReturnLength). Only the basic class
        // is answered; the rest describe things this package does not have.
        NtSyscall::QueryInformationProcess if a(1) == PROCESS_BASIC_INFORMATION => {
            let Some(tasks) = host.tasks() else {
                return finish(env, Ntstatus::NOT_IMPLEMENTED);
            };
            let (buffer, length, returned) = (a(2), a(3), a(4));
            if length < PROCESS_BASIC_INFORMATION_LEN {
                return finish(env, Ntstatus::INFO_LENGTH_MISMATCH);
            }
            let (Ok(pid), Ok(parent)) = (tasks.getpid(), tasks.getppid()) else {
                return finish(env, Ntstatus::NOT_IMPLEMENTED);
            };
            // The identity is the host's; this only lays it out the way a
            // Windows program reads it.
            let mut block = [0u8; PROCESS_BASIC_INFORMATION_LEN];
            block[32..40].copy_from_slice(&(pid as u64).to_le_bytes());
            block[40..48].copy_from_slice(&(parent as u64).to_le_bytes());
            if let Err(errno) = host.platform().write_user(buffer, &block) {
                return finish(env, status_from_errno(errno));
            }
            if returned != 0
                && let Err(errno) = host.platform().write_user(
                    returned,
                    &(PROCESS_BASIC_INFORMATION_LEN as u32).to_le_bytes(),
                )
            {
                return finish(env, status_from_errno(errno));
            }
            Ntstatus::SUCCESS
        }
        // NtCreateFile(FileHandle, DesiredAccess, ObjectAttributes,
        // IoStatusBlock, AllocationSize, FileAttributes, ShareAccess,
        // CreateDisposition, CreateOptions, EaBuffer, EaLength). The name is
        // decoded here because its encoding and its namespace are this ABI's;
        // resolving it is the host's.
        NtSyscall::CreateFile => {
            let Some(paths) = host.paths() else {
                return finish(env, Ntstatus::NOT_IMPLEMENTED);
            };
            let (handle_out, access, object_attributes, io_status) = (a(0), a(1), a(2), a(3));
            if handle_out == 0 || object_attributes == 0 {
                return finish(env, Ntstatus::INVALID_PARAMETER);
            }

            let mut oa = [0u8; OBJECT_ATTRIBUTES_LEN];
            if let Err(errno) = host.platform().read_user(object_attributes, &mut oa) {
                return finish(env, status_from_errno(errno));
            }
            let root = u64::from_le_bytes(
                oa[OA_ROOT_DIRECTORY..OA_ROOT_DIRECTORY + 8]
                    .try_into()
                    .unwrap(),
            ) as usize;
            let name =
                u64::from_le_bytes(oa[OA_OBJECT_NAME..OA_OBJECT_NAME + 8].try_into().unwrap())
                    as usize;
            let attributes = u32::from_le_bytes(oa[24..28].try_into().unwrap());
            if name == 0 {
                return finish(env, Ntstatus::OBJECT_NAME_INVALID);
            }

            let mut buf = [0u8; PATH_MAX];
            let path = match read_nt_path(host, name, &mut buf) {
                Ok(path) => path,
                Err(status) => return finish(env, status),
            };
            let (how, information) = match open_request(access, a(7), a(8), attributes) {
                Ok(request) => request,
                Err(status) => return finish(env, status),
            };
            // A relative name is resolved against the directory the caller
            // named, which is the one thing `RootDirectory` is for.
            let at = match root {
                0 => At::Cwd,
                _ => match descriptor(root) {
                    Ok(fd) => At::Dir(fd),
                    Err(status) => return finish(env, status),
                },
            };

            let fd = match paths.open(at, path, &how) {
                Ok(fd) => fd,
                Err(errno) => return finish(env, status_from_errno(errno)),
            };
            let Ok(slot) = usize::try_from(fd) else {
                return finish(env, Ntstatus::UNSUCCESSFUL);
            };
            let handle = Handle::from_slot(slot);
            if let Err(errno) = host
                .platform()
                .write_user(handle_out, &(handle.0 as u64).to_le_bytes())
            {
                return finish(env, status_from_errno(errno));
            }
            write_io_status(host, io_status, Ntstatus::SUCCESS, information)
        }
        // NtQueryAttributesFile(ObjectAttributes, FileInformation) answers
        // without opening anything, which is what a caller probing a path does.
        NtSyscall::QueryAttributesFile => {
            let Some(paths) = host.paths() else {
                return finish(env, Ntstatus::NOT_IMPLEMENTED);
            };
            let (object_attributes, out) = (a(0), a(1));
            if object_attributes == 0 || out == 0 {
                return finish(env, Ntstatus::INVALID_PARAMETER);
            }
            let mut oa = [0u8; OBJECT_ATTRIBUTES_LEN];
            if let Err(errno) = host.platform().read_user(object_attributes, &mut oa) {
                return finish(env, status_from_errno(errno));
            }
            let name =
                u64::from_le_bytes(oa[OA_OBJECT_NAME..OA_OBJECT_NAME + 8].try_into().unwrap())
                    as usize;
            if name == 0 {
                return finish(env, Ntstatus::OBJECT_NAME_INVALID);
            }
            let mut buf = [0u8; PATH_MAX];
            let path = match read_nt_path(host, name, &mut buf) {
                Ok(path) => path,
                Err(status) => return finish(env, status),
            };
            match paths.attributes(At::Cwd, path, true) {
                Ok(attr) => match host.platform().write_user(out, &basic_information(&attr)) {
                    Ok(_) => Ntstatus::SUCCESS,
                    Err(errno) => status_from_errno(errno),
                },
                Err(errno) => status_from_errno(errno),
            }
        }
        // NtQueryInformationFile(FileHandle, IoStatusBlock, FileInformation,
        // Length, FileInformationClass). Only the two classes that describe
        // what the file is are answered.
        NtSyscall::QueryInformationFile => {
            let Some(paths) = host.paths() else {
                return finish(env, Ntstatus::NOT_IMPLEMENTED);
            };
            let (io_status, out, length, class) = (a(1), a(2), a(3), a(4));
            let Ok(fd) = descriptor(a(0)) else {
                return finish(env, Ntstatus::INVALID_HANDLE);
            };
            let attr = match paths.attributes_of(fd) {
                Ok(attr) => attr,
                Err(errno) => return finish(env, status_from_errno(errno)),
            };
            let written = match class {
                FILE_BASIC_INFORMATION_CLASS => {
                    if length < FILE_BASIC_INFORMATION_LEN {
                        return finish(env, Ntstatus::INFO_LENGTH_MISMATCH);
                    }
                    host.platform()
                        .write_user(out, &basic_information(&attr))
                        .map(|_| FILE_BASIC_INFORMATION_LEN)
                }
                FILE_STANDARD_INFORMATION_CLASS => {
                    if length < FILE_STANDARD_INFORMATION_LEN {
                        return finish(env, Ntstatus::INFO_LENGTH_MISMATCH);
                    }
                    let mut buf = [0u8; FILE_STANDARD_INFORMATION_LEN];
                    // AllocationSize is what the file occupies, which is the
                    // block count rather than the length.
                    buf[0..8].copy_from_slice(&(attr.blocks * 512).to_le_bytes());
                    buf[8..16].copy_from_slice(&attr.size.to_le_bytes());
                    buf[16..20].copy_from_slice(&(attr.links as u32).to_le_bytes());
                    buf[21] = u8::from(attr.kind == NodeKind::Directory);
                    host.platform()
                        .write_user(out, &buf)
                        .map(|_| FILE_STANDARD_INFORMATION_LEN)
                }
                // The rest describe things this package does not have.
                _ => return Dispatch::Passthrough,
            };
            match written {
                Ok(n) => write_io_status(host, io_status, Ntstatus::SUCCESS, n),
                Err(errno) => status_from_errno(errno),
            }
        }
        // The remaining information classes describe things this package does
        // NtSetInformationFile(FileHandle, IoStatusBlock, FileInformation,
        // Length, FileInformationClass). Windows moves the file pointer and
        // sets the length through the same call that Linux spells lseek and
        // ftruncate, so both classes land on those primitives.
        NtSyscall::SetInformationFile => {
            let Some(files) = host.files() else {
                return finish(env, Ntstatus::NOT_IMPLEMENTED);
            };
            let (io_status, input, length, class) = (a(1), a(2), a(3), a(4));
            let Ok(fd) = descriptor(a(0)) else {
                return finish(env, Ntstatus::INVALID_HANDLE);
            };
            if !matches!(
                class,
                FILE_POSITION_INFORMATION_CLASS | FILE_END_OF_FILE_INFORMATION_CLASS
            ) {
                return finish(env, Ntstatus::NOT_IMPLEMENTED);
            }
            if length < FILE_OFFSET_INFORMATION_LEN {
                return finish(env, Ntstatus::INFO_LENGTH_MISMATCH);
            }
            let mut raw = [0u8; FILE_OFFSET_INFORMATION_LEN];
            if let Err(errno) = host.platform().read_user(input, &mut raw) {
                return finish(env, status_from_errno(errno));
            }
            let value = i64::from_le_bytes(raw);
            // Both classes are absolute, and neither has a meaning for a
            // negative one.
            if value < 0 {
                return finish(env, Ntstatus::INVALID_PARAMETER);
            }
            let outcome = if class == FILE_POSITION_INFORMATION_CLASS {
                files.seek(fd, SeekFrom::Start(value as u64))
            } else {
                files.ftruncate(fd, value as u64)
            };
            match outcome {
                Ok(_) => write_io_status(host, io_status, Ntstatus::SUCCESS, 0),
                Err(errno) => status_from_errno(errno),
            }
        }
        // not have, and stay with the caller rather than being invented.
        NtSyscall::QueryInformationProcess => {
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
    use alloc::{
        string::{String, ToString},
        vec,
        vec::Vec,
    };
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
        // Every number the table claims maps back to itself, and the first one
        // it does not claim is refused - found by walking rather than written
        // down, so adding a call does not need this test edited.
        let mut nr = 0;
        while let Some(call) = NtSyscall::from_nr(nr) {
            assert_eq!(call.nr(), nr);
            nr += 1;
        }
        assert!(nr > 0, "the table claims nothing");
        assert_eq!(NtSyscall::from_nr(nr), None);
        assert_eq!(NtSyscall::from_nr(u32::MAX), None);
    }

    // A trap frame with preset syscall number and arguments.
    struct FakeTrap {
        nr: usize,
        /// The four the registers carry.
        args: [usize; 4],
        /// Where the rest of them are, as a real caller leaves them.
        sp: usize,
        result: Option<usize>,
    }
    impl TrapEnv for FakeTrap {
        fn nr(&self) -> usize {
            self.nr
        }
        fn arg(&self, i: usize) -> usize {
            self.args[i]
        }
        fn stack_pointer(&self) -> usize {
            self.sp
        }
        fn set_result(&mut self, value: usize) {
            self.result = Some(value);
        }
    }

    // A trap frame that also says where the caller's thread block is, which is
    // where the Win32 layer keeps the last error.
    struct Win32Trap {
        nr: usize,
        /// Six, as the stub leaves them: four from the Windows registers and
        /// two lifted off the caller's stack.
        args: [usize; 6],
        teb: usize,
        result: Option<usize>,
    }
    impl Win32Trap {
        fn new(call: crate::win32::Win32Call, args: [usize; 6], teb: usize) -> Self {
            Self {
                nr: call.nr() as usize,
                args,
                teb,
                result: None,
            }
        }
    }
    impl TrapEnv for Win32Trap {
        fn nr(&self) -> usize {
            self.nr
        }
        fn arg(&self, i: usize) -> usize {
            self.args[i]
        }
        fn thread_pointer(&self) -> usize {
            self.teb
        }
        fn set_result(&mut self, value: usize) {
            self.result = Some(value);
        }
    }

    // A host whose file port records what it was asked to move, and whose user
    // memory is one flat buffer at address zero.
    struct MockHost {
        mem: RefCell<Vec<u8>>,
        wrote: RefCell<Option<(i32, usize, usize)>>,
        closed: RefCell<Option<i32>>,
        mapped: RefCell<Option<MapRequest>>,
        opened: RefCell<Option<(At, String, OpenHow)>>,
        asked: RefCell<Option<String>>,
        sought: RefCell<Option<(i32, u64)>>,
        truncated: RefCell<Option<(i32, u64)>>,
        /// What the paths port describes a name as, or nothing for absent.
        describes: Option<Attributes>,
        /// What the paths port answers with, or the error it reports.
        opens_at: Result<i32, i32>,
        /// Whether the host offers a paths port at all.
        has_paths: bool,
        /// Directory entries the paths port enumerates.
        entries: Vec<(String, NodeKind)>,
    }
    impl Default for MockHost {
        fn default() -> Self {
            Self {
                mem: RefCell::default(),
                wrote: RefCell::default(),
                closed: RefCell::default(),
                mapped: RefCell::default(),
                opened: RefCell::default(),
                asked: RefCell::default(),
                sought: RefCell::default(),
                truncated: RefCell::default(),
                describes: None,
                opens_at: Ok(0),
                has_paths: false,
                entries: Vec::new(),
            }
        }
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
        fn read_user_cstr(&self, uaddr: usize, out: &mut [u8]) -> ax_abi_port::SysResult {
            // Reads one byte at a time so it stops at the terminator, which
            // is what a host with real mappings has to do anyway.
            for (i, slot) in out.iter_mut().enumerate() {
                let mut byte = [0u8; 1];
                self.read_user(uaddr + i, &mut byte)?;
                if byte[0] == 0 {
                    return Ok(i as isize);
                }
                *slot = byte[0];
            }
            Ok(out.len() as isize)
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
        fn seek(&self, fd: i32, to: ax_abi_port::SeekFrom) -> ax_abi_port::SysResult {
            if let ax_abi_port::SeekFrom::Start(at) = to {
                *self.sought.borrow_mut() = Some((fd, at));
            }
            Ok(match to {
                ax_abi_port::SeekFrom::Start(at) => at as isize,
                ax_abi_port::SeekFrom::Current(by) | ax_abi_port::SeekFrom::End(by) => by as isize,
            })
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
        fn ftruncate(&self, fd: i32, len: u64) -> ax_abi_port::SysResult {
            *self.truncated.borrow_mut() = Some((fd, len));
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
        fn advise(
            &self,
            _addr: usize,
            _len: usize,
            _advice: ax_abi_port::Advice,
        ) -> ax_abi_port::SysResult {
            Ok(0)
        }
        fn writeback(&self, _a: usize, _l: usize) -> ax_abi_port::SysResult {
            Ok(0)
        }
    }

    impl ax_abi_port::Paths for MockHost {
        fn open(&self, at: At, path: &str, how: &OpenHow) -> ax_abi_port::SysResult {
            *self.opened.borrow_mut() = Some((at, path.to_string(), *how));
            self.opens_at.map(|fd| fd as isize)
        }
        fn attributes(&self, _at: At, path: &str, _follow: bool) -> Result<Attributes, i32> {
            self.describes
                .clone()
                .map(|attr| {
                    *self.asked.borrow_mut() = Some(String::from(path));
                    attr
                })
                .ok_or(ax_abi_port::ENOENT)
        }
        fn attributes_of(&self, _fd: i32) -> Result<Attributes, i32> {
            self.describes.clone().ok_or(ax_abi_port::EBADF)
        }
        fn path_of(&self, _fd: i32, put: &mut dyn FnMut(&str)) -> Result<(), i32> {
            match &self.describes {
                Some(_) => {
                    put("/python/python.exe");
                    Ok(())
                }
                None => Err(ax_abi_port::EBADF),
            }
        }
        fn read_dir(
            &self,
            _fd: i32,
            sink: &mut dyn FnMut(&str, NodeKind) -> bool,
        ) -> Result<(), i32> {
            for (name, kind) in &self.entries {
                if !sink(name, *kind) {
                    break;
                }
            }
            Ok(())
        }

        fn permitted(
            &self,
            _at: ax_abi_port::At,
            _path: &str,
            _wants: ax_abi_port::Access,
            _follow: bool,
            _real_ids: bool,
        ) -> Result<(), i32> {
            Ok(())
        }

        fn permitted_of(
            &self,
            _fd: i32,
            _wants: ax_abi_port::Access,
            _real_ids: bool,
        ) -> Result<(), i32> {
            Ok(())
        }
    }

    impl Host for MockHost {
        fn platform(&self) -> &dyn ax_abi_port::Platform {
            self
        }
        fn paths(&self) -> Option<&dyn ax_abi_port::Paths> {
            self.has_paths.then_some(self as &dyn ax_abi_port::Paths)
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
        fn read_user_cstr(&self, uaddr: usize, out: &mut [u8]) -> ax_abi_port::SysResult {
            // Reads one byte at a time so it stops at the terminator, which
            // is what a host with real mappings has to do anyway.
            for (i, slot) in out.iter_mut().enumerate() {
                let mut byte = [0u8; 1];
                self.read_user(uaddr + i, &mut byte)?;
                if byte[0] == 0 {
                    return Ok(i as isize);
                }
                *slot = byte[0];
            }
            Ok(out.len() as isize)
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

    fn trap(call: NtSyscall, args: [usize; 4]) -> FakeTrap {
        FakeTrap {
            nr: call.nr() as usize,
            args,
            sp: 0,
            result: None,
        }
    }

    /// The same, with the arguments past the fourth left on a stack the host
    /// can read, which is where a caller puts them.
    fn trap_with_stack(
        call: NtSyscall,
        args: [usize; 4],
        stack: &[usize],
        host: &MockHost,
    ) -> FakeTrap {
        let sp = 0xC0;
        let mut mem = host.mem.borrow_mut();
        for (i, word) in stack.iter().enumerate() {
            let at = sp + i * size_of::<usize>();
            mem[at..at + size_of::<usize>()].copy_from_slice(&word.to_ne_bytes());
        }
        drop(mem);
        FakeTrap {
            nr: call.nr() as usize,
            args,
            sp,
            result: None,
        }
    }

    #[test]
    fn write_file_moves_bytes_through_the_file_port() {
        let host = MockHost {
            mem: RefCell::new(vec![0u8; 0x100]),
            ..MockHost::default()
        };
        // NtWriteFile(FileHandle, Event, ApcRoutine, ApcContext | IoStatusBlock,
        // Buffer, Length, ByteOffset, Key). Handle 4 is descriptor 0.
        let mut env = trap_with_stack(
            NtSyscall::WriteFile,
            [4, 0, 0, 0],
            &[0x80, 0x40, 8, 0, 0],
            &host,
        );
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
        let mut env = trap(NtSyscall::Close, [8, 0, 0, 0]);
        assert_eq!(dispatch(&mut env, &host), Dispatch::Handled);
        assert_eq!(*host.closed.borrow(), Some(1));
        // A misaligned handle is not a descriptor.
        let mut bad = trap(NtSyscall::Close, [3, 0, 0, 0]);
        assert_eq!(dispatch(&mut bad, &host), Dispatch::Handled);
        assert_eq!(bad.result, Some(Ntstatus::INVALID_HANDLE.0 as usize));
    }

    #[test]
    fn allocate_virtual_memory_asks_for_an_anonymous_mapping() {
        let host = MockHost {
            mem: RefCell::new(vec![0u8; 0x100]),
            ..MockHost::default()
        };
        // NtAllocateVirtualMemory(ProcessHandle, *BaseAddress, ZeroBits,
        // *RegionSize | AllocationType, Protect). *base = 0 asks the host to
        // choose; the size is read through its own pointer.
        host.mem.borrow_mut()[0x20..0x28].copy_from_slice(&0x2000usize.to_ne_bytes());
        let mut env = trap_with_stack(
            NtSyscall::AllocateVirtualMemory,
            [0, 0x10, 0, 0x20],
            &[MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE],
            &host,
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
    fn a_request_this_package_does_not_answer_stays_with_the_caller() {
        let host = MockHost::default();
        // An information class this package has nothing to say about is the
        // caller's to answer, not something to invent a reply for.
        let mut env = trap(
            NtSyscall::QueryInformationProcess,
            [0, PROCESS_BASIC_INFORMATION + 1, 0, 0],
        );
        assert_eq!(dispatch(&mut env, &host), Dispatch::Passthrough);
        assert_eq!(env.result, None);
    }

    /// Lay out the OBJECT_ATTRIBUTES and UNICODE_STRING a caller passes, with
    /// `name` as the UTF-16 the object name points at.
    fn object_attributes(host: &MockHost, name: &str, attributes: u32) -> usize {
        const OA: usize = 0x100;
        const US: usize = 0x200;
        const BUF: usize = 0x300;
        let utf16: Vec<u8> = name
            .encode_utf16()
            .flat_map(|unit| unit.to_le_bytes())
            .collect();
        let mut mem = host.mem.borrow_mut();
        mem[OA + OA_ROOT_DIRECTORY..OA + OA_ROOT_DIRECTORY + 8]
            .copy_from_slice(&0u64.to_le_bytes());
        mem[OA + OA_OBJECT_NAME..OA + OA_OBJECT_NAME + 8]
            .copy_from_slice(&(US as u64).to_le_bytes());
        mem[OA + 24..OA + 28].copy_from_slice(&attributes.to_le_bytes());
        mem[US..US + 2].copy_from_slice(&(utf16.len() as u16).to_le_bytes());
        mem[US + 8..US + 16].copy_from_slice(&(BUF as u64).to_le_bytes());
        mem[BUF..BUF + utf16.len()].copy_from_slice(&utf16);
        OA
    }

    fn create_file(host: &MockHost, name: &str, access: usize, disposition: usize) -> FakeTrap {
        let oa = object_attributes(host, name, 0);
        // NtCreateFile(FileHandle, DesiredAccess, ObjectAttributes,
        // IoStatusBlock | AllocationSize, FileAttributes, ShareAccess,
        // CreateDisposition, CreateOptions, ...): the rest arrive on the stack.
        let mut env = trap_with_stack(
            NtSyscall::CreateFile,
            [0x400, access, oa, 0x410],
            &[0, 0, 0, disposition, 0],
            host,
        );
        dispatch(&mut env, host);
        env
    }

    #[test]
    fn opens_a_name_from_the_nt_namespace() {
        let host = MockHost {
            mem: RefCell::new(vec![0u8; 0x500]),
            has_paths: true,
            opens_at: Ok(7),
            ..MockHost::default()
        };
        let env = create_file(&host, r"\??\C:\lib\os.py", GENERIC_READ, FILE_OPEN);
        assert_eq!(env.result, Some(Ntstatus::SUCCESS.0 as usize));

        // The object-namespace prefix and the drive name the one root there is,
        // and the separator becomes the one the host resolves with.
        let opened = host.opened.borrow();
        let (at, path, how) = opened.as_ref().unwrap();
        assert_eq!(*at, At::Cwd);
        assert_eq!(path, "/lib/os.py");
        assert!(how.read && !how.write);
        assert_eq!(how.create, Create::Never);
        // OBJ_INHERIT was not asked for, so the handle does not survive a spawn.
        assert!(how.close_on_exec);

        // The handle is the descriptor in the caller's own numbering, and the
        // status block says the file was opened rather than created.
        let mem = host.mem.borrow();
        assert_eq!(
            u64::from_le_bytes(mem[0x400..0x408].try_into().unwrap()),
            Handle::from_slot(7).0 as u64
        );
        assert_eq!(
            u64::from_le_bytes(mem[0x418..0x420].try_into().unwrap()),
            FILE_OPENED as u64
        );
    }

    #[test]
    fn each_disposition_asks_for_what_it_means() {
        for (disposition, create, truncate, information) in [
            (FILE_CREATE, Create::Exclusive, false, FILE_CREATED),
            (FILE_OPEN_IF, Create::IfAbsent, false, FILE_OPENED),
            (FILE_OVERWRITE, Create::Never, true, FILE_OVERWRITTEN),
            (FILE_OVERWRITE_IF, Create::IfAbsent, true, FILE_OVERWRITTEN),
            (FILE_SUPERSEDE, Create::IfAbsent, true, FILE_SUPERSEDED),
        ] {
            let host = MockHost {
                mem: RefCell::new(vec![0u8; 0x500]),
                has_paths: true,
                opens_at: Ok(3),
                ..MockHost::default()
            };
            let env = create_file(&host, r"\??\C:\f", GENERIC_WRITE, disposition);
            assert_eq!(env.result, Some(Ntstatus::SUCCESS.0 as usize));
            let opened = host.opened.borrow();
            let how = &opened.as_ref().unwrap().2;
            assert_eq!(how.create, create, "disposition {disposition}");
            assert_eq!(how.truncate, truncate, "disposition {disposition}");
            let mem = host.mem.borrow();
            assert_eq!(
                u64::from_le_bytes(mem[0x418..0x420].try_into().unwrap()),
                information as u64,
                "disposition {disposition}"
            );
        }
    }

    #[test]
    fn refuses_a_disposition_that_contradicts_the_access() {
        let host = MockHost {
            mem: RefCell::new(vec![0u8; 0x500]),
            has_paths: true,
            opens_at: Ok(3),
            ..MockHost::default()
        };
        // Creating a file without having asked to write it means nothing, and
        // is refused rather than quietly opened read-only.
        let env = create_file(&host, r"\??\C:\f", GENERIC_READ, FILE_CREATE);
        assert_eq!(env.result, Some(Ntstatus::INVALID_PARAMETER.0 as usize));
        assert!(host.opened.borrow().is_none());

        // An unnamed disposition is not guessed at either.
        let env = create_file(&host, r"\??\C:\f", GENERIC_WRITE, 99);
        assert_eq!(env.result, Some(Ntstatus::INVALID_PARAMETER.0 as usize));
    }

    #[test]
    fn reports_the_hosts_refusal_as_the_status_it_means() {
        let host = MockHost {
            mem: RefCell::new(vec![0u8; 0x500]),
            has_paths: true,
            opens_at: Err(ax_abi_port::ENOENT),
            ..MockHost::default()
        };
        let env = create_file(&host, r"\??\C:\missing", GENERIC_READ, FILE_OPEN);
        assert_eq!(
            env.result,
            Some(status_from_errno(ax_abi_port::ENOENT).0 as usize)
        );
    }

    #[test]
    fn a_platform_without_the_capability_says_so() {
        // The host has no paths port, which is a different answer from the ABI
        // declining the request: the call is this package's, the platform
        // cannot serve it.
        let host = MockHost {
            mem: RefCell::new(vec![0u8; 0x500]),
            ..MockHost::default()
        };
        let env = create_file(&host, r"\??\C:\f", GENERIC_READ, FILE_OPEN);
        assert_eq!(env.result, Some(Ntstatus::NOT_IMPLEMENTED.0 as usize));
    }

    fn sample_attributes() -> Attributes {
        Attributes {
            kind: NodeKind::File,
            mode: 0o644,
            size: 1234,
            block_size: 4096,
            blocks: 8,
            device: 1,
            rdev: 0,
            inode: 42,
            links: 1,
            uid: 0,
            gid: 0,
            // 2001-09-09T01:46:40Z, a time with no zero bytes to hide a bug in.
            accessed_ns: 1_000_000_000_000_000_000,
            modified_ns: 1_000_000_001_000_000_000,
            changed_ns: 1_000_000_002_000_000_000,
        }
    }

    #[test]
    fn describes_a_name_without_opening_it() {
        let host = MockHost {
            mem: RefCell::new(vec![0u8; 0x500]),
            has_paths: true,
            describes: Some(sample_attributes()),
            ..MockHost::default()
        };
        let oa = object_attributes(&host, r"\??\C:\lib\os.py", 0);
        let mut env = trap(NtSyscall::QueryAttributesFile, [oa, 0x400, 0, 0]);
        assert_eq!(dispatch(&mut env, &host), Dispatch::Handled);
        assert_eq!(env.result, Some(Ntstatus::SUCCESS.0 as usize));
        assert_eq!(host.asked.borrow().as_deref(), Some("/lib/os.py"));
        // Nothing was opened: this answers about the name itself.
        assert!(host.opened.borrow().is_none());

        let mem = host.mem.borrow();
        // NT counts 100-nanosecond intervals from 1601, not seconds from 1970.
        let modified = u64::from_le_bytes(mem[0x410..0x418].try_into().unwrap());
        assert_eq!(modified, 116_444_736_000_000_000 + 10_000_000_010_000_000);
        let flags = u32::from_le_bytes(mem[0x420..0x424].try_into().unwrap());
        assert_eq!(flags, FILE_ATTRIBUTE_NORMAL);
    }

    #[test]
    fn a_directory_and_a_read_only_file_say_so_in_the_attribute_word() {
        let mut dir = sample_attributes();
        dir.kind = NodeKind::Directory;
        assert_eq!(file_attributes(&dir), FILE_ATTRIBUTE_DIRECTORY);

        let mut link = sample_attributes();
        link.kind = NodeKind::Symlink;
        assert_eq!(file_attributes(&link), FILE_ATTRIBUTE_REPARSE_POINT);

        // With no access-control list anywhere, whether the owner may write is
        // the closest thing to the read-only attribute a caller asks about.
        let mut ro = sample_attributes();
        ro.mode = 0o444;
        assert_eq!(
            file_attributes(&ro),
            FILE_ATTRIBUTE_NORMAL | FILE_ATTRIBUTE_READONLY
        );
    }

    #[test]
    fn answers_the_standard_class_and_declines_the_rest() {
        let host = MockHost {
            mem: RefCell::new(vec![0u8; 0x500]),
            has_paths: true,
            describes: Some(sample_attributes()),
            ..MockHost::default()
        };
        // NtQueryInformationFile(FileHandle, IoStatusBlock, FileInformation,
        // Length | FileInformationClass on the stack).
        let mut env = trap_with_stack(
            NtSyscall::QueryInformationFile,
            [4, 0x400, 0x410, FILE_STANDARD_INFORMATION_LEN],
            &[FILE_STANDARD_INFORMATION_CLASS],
            &host,
        );
        assert_eq!(dispatch(&mut env, &host), Dispatch::Handled);
        assert_eq!(env.result, Some(Ntstatus::SUCCESS.0 as usize));
        let mem = host.mem.borrow();
        // AllocationSize is what the file occupies, which is its blocks, not
        // its length.
        assert_eq!(
            u64::from_le_bytes(mem[0x410..0x418].try_into().unwrap()),
            8 * 512
        );
        assert_eq!(
            u64::from_le_bytes(mem[0x418..0x420].try_into().unwrap()),
            1234
        );
        assert_eq!(mem[0x415 + 12], 0, "a file is not a directory");
        drop(mem);

        // A buffer too small for the class is refused rather than truncated.
        let mut short = trap_with_stack(
            NtSyscall::QueryInformationFile,
            [4, 0x400, 0x410, FILE_STANDARD_INFORMATION_LEN - 1],
            &[FILE_STANDARD_INFORMATION_CLASS],
            &host,
        );
        dispatch(&mut short, &host);
        assert_eq!(
            short.result,
            Some(Ntstatus::INFO_LENGTH_MISMATCH.0 as usize)
        );

        // A class this package has nothing to say about stays with the caller.
        let mut other = trap_with_stack(
            NtSyscall::QueryInformationFile,
            [4, 0x400, 0x410, 64],
            &[99],
            &host,
        );
        assert_eq!(dispatch(&mut other, &host), Dispatch::Passthrough);
    }

    /// Put a 64-bit value where `NtSetInformationFile` reads its argument from.
    fn with_offset(value: i64) -> MockHost {
        let host = MockHost {
            mem: RefCell::new(vec![0u8; 0x100]),
            ..MockHost::default()
        };
        host.mem.borrow_mut()[0x40..0x48].copy_from_slice(&value.to_le_bytes());
        host
    }

    #[test]
    fn set_information_file_moves_the_file_pointer() {
        let host = with_offset(1234);
        // NtSetInformationFile(FileHandle, IoStatusBlock, FileInformation,
        // Length, FileInformationClass). Handle 4 is descriptor 0.
        let mut env = trap_with_stack(
            NtSyscall::SetInformationFile,
            [4, 0x80, 0x40, 8],
            &[FILE_POSITION_INFORMATION_CLASS],
            &host,
        );

        assert_eq!(dispatch(&mut env, &host), Dispatch::Handled);
        assert_eq!(env.result, Some(Ntstatus::SUCCESS.0 as usize));
        assert_eq!(*host.sought.borrow(), Some((0, 1234)));
        assert!(host.truncated.borrow().is_none());
        // The IO_STATUS_BLOCK carries the status; nothing was transferred.
        let mem = host.mem.borrow();
        assert_eq!(u64::from_le_bytes(mem[0x80..0x88].try_into().unwrap()), 0);
    }

    #[test]
    fn set_information_file_sets_the_length() {
        let host = with_offset(4096);
        let mut env = trap_with_stack(
            NtSyscall::SetInformationFile,
            [4, 0, 0x40, 8],
            &[FILE_END_OF_FILE_INFORMATION_CLASS],
            &host,
        );

        assert_eq!(dispatch(&mut env, &host), Dispatch::Handled);
        assert_eq!(env.result, Some(Ntstatus::SUCCESS.0 as usize));
        assert_eq!(*host.truncated.borrow(), Some((0, 4096)));
        assert!(host.sought.borrow().is_none());
    }

    #[test]
    fn set_information_file_leaves_a_class_it_does_not_answer() {
        let host = with_offset(0);
        let mut env = trap_with_stack(
            NtSyscall::SetInformationFile,
            [4, 0, 0x40, 8],
            &[FILE_BASIC_INFORMATION_CLASS],
            &host,
        );

        assert_eq!(dispatch(&mut env, &host), Dispatch::Handled);
        assert_eq!(env.result, Some(Ntstatus::NOT_IMPLEMENTED.0 as usize));
        assert!(host.sought.borrow().is_none());
        assert!(host.truncated.borrow().is_none());
    }

    #[test]
    fn set_information_file_refuses_a_buffer_too_small_for_the_class() {
        let host = with_offset(8);
        let mut env = trap_with_stack(
            NtSyscall::SetInformationFile,
            [4, 0, 0x40, 4],
            &[FILE_POSITION_INFORMATION_CLASS],
            &host,
        );

        assert_eq!(dispatch(&mut env, &host), Dispatch::Handled);
        assert_eq!(env.result, Some(Ntstatus::INFO_LENGTH_MISMATCH.0 as usize));
        assert!(host.sought.borrow().is_none());
    }

    #[test]
    fn set_information_file_refuses_a_negative_offset() {
        let host = with_offset(-1);
        let mut env = trap_with_stack(
            NtSyscall::SetInformationFile,
            [4, 0, 0x40, 8],
            &[FILE_POSITION_INFORMATION_CLASS],
            &host,
        );

        assert_eq!(dispatch(&mut env, &host), Dispatch::Handled);
        assert_eq!(env.result, Some(Ntstatus::INVALID_PARAMETER.0 as usize));
        assert!(host.sought.borrow().is_none());
    }

    #[test]
    fn a_win32_write_moves_bytes_and_reports_the_count() {
        use crate::win32::{self, Win32Call};

        let host = MockHost {
            mem: RefCell::new(vec![0u8; 0x100]),
            ..MockHost::default()
        };
        // WriteFile(hFile, lpBuffer, nNumberOfBytesToWrite,
        // lpNumberOfBytesWritten, lpOverlapped). Handle 4 is descriptor 0.
        let mut env = Win32Trap::new(Win32Call::WRITE_FILE, [4, 0x40, 8, 0x80, 0, 0], 0);

        assert_eq!(win32::dispatch(&mut env, &host), Dispatch::Handled);
        // A Windows API function reports success as a nonzero return, where an
        // NT call would return a status.
        assert_eq!(env.result, Some(1));
        assert_eq!(*host.wrote.borrow(), Some((0, 0x40, 8)));
        let mem = host.mem.borrow();
        assert_eq!(u32::from_le_bytes(mem[0x80..0x84].try_into().unwrap()), 8);
    }

    #[test]
    fn a_win32_write_without_a_count_pointer_still_succeeds() {
        use crate::win32::{self, Win32Call};

        let host = MockHost {
            mem: RefCell::new(vec![0u8; 0x100]),
            ..MockHost::default()
        };
        let mut env = Win32Trap::new(Win32Call::WRITE_FILE, [4, 0x40, 4, 0, 0, 0], 0);

        assert_eq!(win32::dispatch(&mut env, &host), Dispatch::Handled);
        assert_eq!(env.result, Some(1));
        assert_eq!(*host.wrote.borrow(), Some((0, 0x40, 4)));
    }

    #[test]
    fn a_failed_win32_write_records_the_error_in_the_thread_block() {
        use crate::win32::{self, Win32Call};

        let host = MockHost {
            mem: RefCell::new(vec![0xFFu8; 0x200]),
            ..MockHost::default()
        };
        // A handle that is not a multiple of four names no slot, so the write
        // is refused before any bytes move.
        let teb = 0xC0;
        let mut env = Win32Trap::new(Win32Call::WRITE_FILE, [3, 0x40, 8, 0x80, 0, 0], teb);

        assert_eq!(win32::dispatch(&mut env, &host), Dispatch::Handled);
        assert_eq!(env.result, Some(0), "a Win32 failure is a zero BOOL");
        assert!(host.wrote.borrow().is_none(), "nothing was transferred");

        let mem = host.mem.borrow();
        // The count is cleared before the attempt, so the caller does not read
        // whatever happened to be there.
        assert_eq!(u32::from_le_bytes(mem[0x80..0x84].try_into().unwrap()), 0);
        // ERROR_INVALID_HANDLE, which is what RtlNtStatusToDosError maps
        // STATUS_INVALID_HANDLE to.
        let at = teb + crate::teb_peb::TEB_LAST_ERROR;
        assert_eq!(u32::from_le_bytes(mem[at..at + 4].try_into().unwrap()), 6);
    }

    #[test]
    fn the_last_error_survives_between_calls() {
        use crate::win32::{self, Win32Call};

        let host = MockHost {
            mem: RefCell::new(vec![0u8; 0x200]),
            ..MockHost::default()
        };
        let teb = 0xC0;

        let mut set = Win32Trap::new(
            Win32Call::named("SetLastError").unwrap(),
            [87, 0, 0, 0, 0, 0],
            teb,
        );
        assert_eq!(win32::dispatch(&mut set, &host), Dispatch::Handled);

        let mut get = Win32Trap::new(Win32Call::named("GetLastError").unwrap(), [0; 6], teb);
        assert_eq!(win32::dispatch(&mut get, &host), Dispatch::Handled);
        assert_eq!(get.result, Some(87));
    }

    #[test]
    fn a_thread_block_the_host_cannot_place_keeps_no_error() {
        use crate::win32::{self, Win32Call};

        // A host that cannot say where the block is must still answer, with a
        // clean error rather than a reading of unrelated memory.
        let host = MockHost::default();
        let mut env = Win32Trap::new(Win32Call::named("GetLastError").unwrap(), [0; 6], 0);

        assert_eq!(win32::dispatch(&mut env, &host), Dispatch::Handled);
        assert_eq!(env.result, Some(0));
    }

    #[test]
    fn get_std_handle_answers_the_three_streams_and_refuses_the_rest() {
        use crate::win32::{self, Win32Call};

        let host = MockHost {
            mem: RefCell::new(vec![0u8; 0x200]),
            ..MockHost::default()
        };
        // STD_INPUT_HANDLE, STD_OUTPUT_HANDLE and STD_ERROR_HANDLE arrive as
        // DWORDs, so each is the low half of a negative selector.
        for (selector, descriptor) in [(-10i32, 0usize), (-11, 1), (-12, 2)] {
            let mut env = Win32Trap::new(
                Win32Call::named("GetStdHandle").unwrap(),
                [selector as u32 as usize, 0, 0, 0, 0, 0],
                0xC0,
            );
            assert_eq!(win32::dispatch(&mut env, &host), Dispatch::Handled);
            let handle = env.result.expect("answered");
            // The handle must name the descriptor the stream starts on, or a
            // later WriteFile through it would reach the wrong file.
            assert_eq!(Handle(handle as u32).slot(), Some(descriptor));
        }

        let teb = 0xC0;
        let mut env = Win32Trap::new(Win32Call::named("GetStdHandle").unwrap(), [0; 6], teb);
        assert_eq!(win32::dispatch(&mut env, &host), Dispatch::Handled);
        assert_eq!(env.result, Some(usize::MAX), "INVALID_HANDLE_VALUE");
        let mem = host.mem.borrow();
        let at = teb + crate::teb_peb::TEB_LAST_ERROR;
        assert_eq!(u32::from_le_bytes(mem[at..at + 4].try_into().unwrap()), 6);
    }

    #[test]
    fn every_status_maps_to_the_error_wine_records() {
        // Read out of Wine's generated table (dlls/ntdll/error.h) with the
        // values from include/winerror.h, not from memory.
        for (status, error) in [
            (Ntstatus::SUCCESS, 0),
            (Ntstatus::NOT_IMPLEMENTED, 1),
            (Ntstatus::INVALID_HANDLE, 6),
            (Ntstatus::INFO_LENGTH_MISMATCH, 24),
            (Ntstatus::UNSUCCESSFUL, 31),
            (Ntstatus::INVALID_PARAMETER, 87),
            (Ntstatus::OBJECT_NAME_INVALID, 123),
            (Ntstatus::NAME_TOO_LONG, 206),
            (Ntstatus::NO_YIELD_PERFORMED, 721),
            (Ntstatus::ACCESS_VIOLATION, 998),
        ] {
            assert_eq!(status.dos_error(), error, "{status:?}");
        }
    }

    #[test]
    fn a_win32_write_asking_for_overlapped_delivery_is_refused() {
        use crate::win32::{self, Win32Call};

        let host = MockHost {
            mem: RefCell::new(vec![0u8; 0x200]),
            ..MockHost::default()
        };
        let teb = 0xC0;
        // The fifth argument is the OVERLAPPED; the stub lifted it off the
        // caller's stack into the fifth trap register.
        let mut env = Win32Trap::new(Win32Call::WRITE_FILE, [4, 0x40, 8, 0x80, 0x100, 0], teb);

        assert_eq!(win32::dispatch(&mut env, &host), Dispatch::Handled);
        assert_eq!(env.result, Some(0));
        assert!(
            host.wrote.borrow().is_none(),
            "not served synchronously behind its back"
        );
        let mem = host.mem.borrow();
        // ERROR_INVALID_FUNCTION, the mapping of STATUS_NOT_IMPLEMENTED.
        let at = teb + crate::teb_peb::TEB_LAST_ERROR;
        assert_eq!(u32::from_le_bytes(mem[at..at + 4].try_into().unwrap()), 1);
    }

    /// A thread block with a PEB behind it and a heap arena, as the loader lays
    /// them out: enough of the process for the Win32 layer to keep its state.
    fn process(host: &MockHost) -> (usize, usize) {
        use crate::{
            teb_peb::{self, PEB_PROCESS_HEAP, PEB_PROCESS_PARAMS, TEB_PEB},
            win32::heap,
        };
        let (teb, peb, arena, params) = (0x100usize, 0x2000usize, 0x3000usize, 0x5000usize);
        let mut mem = host.mem.borrow_mut();
        mem.resize(0x8000, 0);
        mem[teb + TEB_PEB..teb + TEB_PEB + 8].copy_from_slice(&(peb as u64).to_le_bytes());
        mem[peb + PEB_PROCESS_HEAP..peb + PEB_PROCESS_HEAP + 8]
            .copy_from_slice(&(arena as u64).to_le_bytes());
        mem[arena..arena + heap::HEADER].copy_from_slice(&heap::arena(arena as u64, 0x1000));
        let block = teb_peb::build_params(
            &teb_peb::ProcessInfo {
                image: "Z:\\app\\prog.exe",
                dir: "Z:\\app",
                args: &["prog.exe", "-v"],
                envs: &["A=1", "B=two"],
                std: [4, 8, 12],
            },
            params as u64,
        );
        mem[params..params + block.len()].copy_from_slice(&block);
        mem[peb + PEB_PROCESS_PARAMS..peb + PEB_PROCESS_PARAMS + 8]
            .copy_from_slice(&(params as u64).to_le_bytes());
        (teb, arena)
    }

    fn wide_at(host: &MockHost, at: usize) -> String {
        let mem = host.mem.borrow();
        let mut units = Vec::new();
        let mut p = at;
        loop {
            let unit = u16::from_le_bytes([mem[p], mem[p + 1]]);
            if unit == 0 {
                break;
            }
            units.push(unit);
            p += 2;
        }
        String::from_utf16_lossy(&units)
    }

    fn call(name: &str, args: [usize; 6], teb: usize) -> Win32Trap {
        Win32Trap::new(crate::win32::Win32Call::named(name).unwrap(), args, teb)
    }

    #[test]
    fn tls_slots_are_handed_out_once_and_hold_their_values() {
        use crate::win32;
        let host = MockHost::default();
        let (teb, _) = process(&host);

        let mut a = call("TlsAlloc", [0; 6], teb);
        win32::dispatch(&mut a, &host);
        let mut b = call("TlsAlloc", [0; 6], teb);
        win32::dispatch(&mut b, &host);
        let (a, b) = (a.result.unwrap(), b.result.unwrap());
        assert_ne!(a, b, "two live slots are distinct");

        let mut set = call("TlsSetValue", [a, 0xBEEF, 0, 0, 0, 0], teb);
        win32::dispatch(&mut set, &host);
        assert_eq!(set.result, Some(1));
        let mut get = call("TlsGetValue", [a, 0, 0, 0, 0, 0], teb);
        win32::dispatch(&mut get, &host);
        assert_eq!(get.result, Some(0xBEEF));
        let mut other = call("TlsGetValue", [b, 0, 0, 0, 0, 0], teb);
        win32::dispatch(&mut other, &host);
        assert_eq!(other.result, Some(0), "a fresh slot reads as NULL");

        // Freed, the slot is refused until allocated again - and then reused.
        let mut free = call("TlsFree", [a, 0, 0, 0, 0, 0], teb);
        win32::dispatch(&mut free, &host);
        assert_eq!(free.result, Some(1));
        let mut again = call("TlsFree", [a, 0, 0, 0, 0, 0], teb);
        win32::dispatch(&mut again, &host);
        assert_eq!(again.result, Some(0), "not allocated any more");
        let mut c = call("TlsAlloc", [0; 6], teb);
        win32::dispatch(&mut c, &host);
        assert_eq!(c.result, Some(a));
    }

    #[test]
    fn the_process_heap_hands_out_distinct_blocks_that_know_their_size() {
        use crate::win32;
        let host = MockHost::default();
        let (teb, arena) = process(&host);

        let mut get = call("GetProcessHeap", [0; 6], teb);
        win32::dispatch(&mut get, &host);
        assert_eq!(get.result, Some(arena));

        let mut first = call("HeapAlloc", [arena, 0, 24, 0, 0, 0], teb);
        win32::dispatch(&mut first, &host);
        let mut second = call("HeapAlloc", [arena, 8, 100, 0, 0, 0], teb);
        win32::dispatch(&mut second, &host);
        let (first, second) = (first.result.unwrap(), second.result.unwrap());
        assert!(first != 0 && second != 0 && first != second);
        assert_eq!(first % 16, 0, "blocks are paragraph aligned");
        assert!(second >= first + 24, "blocks do not overlap");

        let mut size = call("HeapSize", [arena, 0, second, 0, 0, 0], teb);
        win32::dispatch(&mut size, &host);
        assert_eq!(size.result, Some(100));

        let mut free = call("HeapFree", [arena, 0, first, 0, 0, 0], teb);
        win32::dispatch(&mut free, &host);
        assert_eq!(free.result, Some(1));
        let mut gone = call("HeapSize", [arena, 0, first, 0, 0, 0], teb);
        win32::dispatch(&mut gone, &host);
        assert_eq!(gone.result, Some(usize::MAX), "a freed block has no size");

        // Past the arena's end the heap says so rather than hand out memory
        // it does not have.
        let mut huge = call("HeapAlloc", [arena, 0, 0x2000, 0, 0, 0], teb);
        win32::dispatch(&mut huge, &host);
        assert_eq!(huge.result, Some(0));
    }

    #[test]
    fn a_critical_section_counts_recursion_and_releases_on_the_last_leave() {
        use crate::win32;
        let host = MockHost::default();
        let (teb, _) = process(&host);
        let cs = 0x4000usize;

        let mut init = call(
            "InitializeCriticalSectionAndSpinCount",
            [cs, 4000, 0, 0, 0, 0],
            teb,
        );
        win32::dispatch(&mut init, &host);
        assert_eq!(init.result, Some(1));
        let word = |off: usize| {
            let mem = host.mem.borrow();
            u32::from_le_bytes(mem[cs + off..cs + off + 4].try_into().unwrap())
        };
        assert_eq!(word(8), -1i32 as u32, "LockCount starts free");

        for _ in 0..2 {
            let mut enter = call("EnterCriticalSection", [cs, 0, 0, 0, 0, 0], teb);
            win32::dispatch(&mut enter, &host);
        }
        assert_eq!(word(12), 2, "RecursionCount");
        assert_eq!(word(8), 1, "LockCount: two enters from -1");

        let mut leave = call("LeaveCriticalSection", [cs, 0, 0, 0, 0, 0], teb);
        win32::dispatch(&mut leave, &host);
        assert_eq!(word(12), 1);
        let mut leave = call("LeaveCriticalSection", [cs, 0, 0, 0, 0, 0], teb);
        win32::dispatch(&mut leave, &host);
        assert_eq!(word(12), 0);
        assert_eq!(word(8), -1i32 as u32, "free again");
        let owner = {
            let mem = host.mem.borrow();
            u64::from_le_bytes(mem[cs + 16..cs + 24].try_into().unwrap())
        };
        assert_eq!(owner, 0, "no owner once released");
    }

    #[test]
    fn an_entry_point_without_its_meaning_yet_says_so_when_called() {
        use crate::win32;
        let host = MockHost::default();
        let (teb, _) = process(&host);

        let mut beep = call("Beep", [440, 100, 0, 0, 0, 0], teb);
        assert_eq!(win32::dispatch(&mut beep, &host), Dispatch::Handled);
        assert_eq!(beep.result, Some(0));
        let mut err = call("GetLastError", [0; 6], teb);
        win32::dispatch(&mut err, &host);
        // ERROR_CALL_NOT_IMPLEMENTED, as a Wine stub reports itself.
        assert_eq!(err.result, Some(120));
    }

    #[test]
    fn the_command_line_and_environment_come_out_of_the_parameters() {
        use crate::win32;
        let host = MockHost::default();
        let (teb, _) = process(&host);

        let mut line = call("GetCommandLineW", [0; 6], teb);
        win32::dispatch(&mut line, &host);
        assert_eq!(wide_at(&host, line.result.unwrap()), "\"prog.exe\" -v");

        let mut ansi = call("GetCommandLineA", [0; 6], teb);
        win32::dispatch(&mut ansi, &host);
        let at = ansi.result.unwrap();
        assert_eq!(&host.mem.borrow()[at..at + 13], b"\"prog.exe\" -v");

        // The environment is a heap block holding the whole double-terminated
        // list, which the caller gives back.
        let mut env = call("GetEnvironmentStringsW", [0; 6], teb);
        win32::dispatch(&mut env, &host);
        let block = env.result.unwrap();
        assert_eq!(wide_at(&host, block), "A=1");
        assert_eq!(wide_at(&host, block + 8), "B=two");
        let mut size = call("HeapSize", [0x3000, 0, block, 0, 0, 0], teb);
        win32::dispatch(&mut size, &host);
        assert_eq!(size.result, Some(22));
        let mut free = call("FreeEnvironmentStringsW", [block, 0, 0, 0, 0, 0], teb);
        win32::dispatch(&mut free, &host);
        assert_eq!(free.result, Some(1));

        let mut cwd = call("GetCurrentDirectoryW", [64, 0x7000, 0, 0, 0, 0], teb);
        win32::dispatch(&mut cwd, &host);
        assert_eq!(cwd.result, Some(6), "Z:\\app is six characters");
        assert_eq!(wide_at(&host, 0x7000), "Z:\\app");
        let mut small = call("GetCurrentDirectoryW", [3, 0x7100, 0, 0, 0, 0], teb);
        win32::dispatch(&mut small, &host);
        assert_eq!(small.result, Some(7), "what it needs, terminator included");
    }

    #[test]
    fn startup_info_carries_the_standard_handles() {
        use crate::win32;
        let host = MockHost::default();
        let (teb, _) = process(&host);

        let mut info = call("GetStartupInfoW", [0x7000, 0, 0, 0, 0, 0], teb);
        win32::dispatch(&mut info, &host);
        let mem = host.mem.borrow();
        let word = |off: usize| {
            u64::from_le_bytes(mem[0x7000 + off..0x7000 + off + 8].try_into().unwrap())
        };
        assert_eq!(
            u32::from_le_bytes(mem[0x7000..0x7004].try_into().unwrap()),
            104,
            "cb"
        );
        assert_eq!(
            u32::from_le_bytes(mem[0x703C..0x7040].try_into().unwrap()),
            0x100,
            "USESTDHANDLES"
        );
        assert_eq!((word(0x50), word(0x58), word(0x60)), (4, 8, 12));
    }

    #[test]
    fn pointers_encode_and_decode_back_to_themselves() {
        use crate::win32;
        let host = MockHost::default();
        let (teb, _) = process(&host);

        let mut enc = call("EncodePointer", [0x1234_5678_9ABC, 0, 0, 0, 0, 0], teb);
        win32::dispatch(&mut enc, &host);
        let encoded = enc.result.unwrap();
        assert_ne!(
            encoded, 0x1234_5678_9ABC,
            "an encoded pointer is not the raw one"
        );
        let mut dec = call("DecodePointer", [encoded, 0, 0, 0, 0, 0], teb);
        win32::dispatch(&mut dec, &host);
        assert_eq!(dec.result, Some(0x1234_5678_9ABC));
    }

    #[test]
    fn a_program_can_find_kernel32_and_a_function_in_it() {
        use crate::{teb_peb, thunk, win32};
        let host = MockHost::default();
        let (teb, _) = process(&host);
        // A module list with one entry, kernel32, whose image is the header
        // the loader synthesizes with the stubs behind it.
        let (ldr_va, k32_va) = (0x6000usize, 0x8000usize);
        let image = thunk::system_header(k32_va as u64, 0);
        let ldr = teb_peb::build_ldr(
            &[teb_peb::LdrModule {
                base: k32_va as u64,
                entry: 0,
                size: 0x2000,
                path: "Z:\\windows\\system32\\kernel32.dll",
                name: "kernel32.dll",
                tls_index: -1,
            }],
            &[],
            ldr_va as u64,
        );
        {
            let mut mem = host.mem.borrow_mut();
            mem.resize(0x12000, 0);
            mem[ldr_va..ldr_va + ldr.len()].copy_from_slice(&ldr);
            mem[k32_va..k32_va + image.len()].copy_from_slice(&image);
            let peb = 0x2000;
            mem[peb + teb_peb::PEB_LDR..peb + teb_peb::PEB_LDR + 8]
                .copy_from_slice(&(ldr_va as u64).to_le_bytes());
            // L"kernel32.dll" at 0x7000 for the lookup; the function names sit
            // above 64 KiB, where a pointer is told from an ordinal.
            let name: Vec<u8> = "kernel32.dll\0"
                .encode_utf16()
                .flat_map(u16::to_le_bytes)
                .collect();
            mem[0x7000..0x7000 + name.len()].copy_from_slice(&name);
            mem[0x10100..0x10100 + 10].copy_from_slice(b"WriteFile\0");
        }

        let mut module = call("GetModuleHandleW", [0x7000, 0, 0, 0, 0, 0], teb);
        win32::dispatch(&mut module, &host);
        assert_eq!(module.result, Some(k32_va));

        let mut proc_ = call("GetProcAddress", [k32_va, 0x10100, 0, 0, 0, 0], teb);
        win32::dispatch(&mut proc_, &host);
        // WriteFile is table entry 0: the first stub past the header.
        assert_eq!(proc_.result, Some(k32_va + thunk::MODULE_HEADER));

        // By ordinal, the same slot; an unknown name is refused.
        let mut ord = call("GetProcAddress", [k32_va, 1, 0, 0, 0, 0], teb);
        win32::dispatch(&mut ord, &host);
        assert_eq!(ord.result, Some(k32_va + thunk::MODULE_HEADER));
        {
            let mut mem = host.mem.borrow_mut();
            mem[0x10200..0x10200 + 16].copy_from_slice(b"NoSuchFunctionW ");
        }
        let mut missing = call("GetProcAddress", [k32_va, 0x10200, 0, 0, 0, 0], teb);
        win32::dispatch(&mut missing, &host);
        assert_eq!(missing.result, Some(0));
    }

    fn wide_bytes(text: &str) -> Vec<u8> {
        text.encode_utf16().flat_map(u16::to_le_bytes).collect()
    }

    #[test]
    fn utf8_and_utf16_convert_both_ways_with_the_windows_conventions() {
        use crate::win32;
        let host = MockHost::default();
        let (teb, _) = process(&host);
        {
            let mut mem = host.mem.borrow_mut();
            mem[0x7000..0x7007].copy_from_slice("h\u{e9}llo\0".as_bytes()); // 6 bytes + NUL
        }
        // Asked how much: five units for five characters, terminator excluded
        // because the length was given.
        let mut need = call("MultiByteToWideChar", [65001, 0, 0x7000, 6, 0, 0], teb);
        win32::dispatch(&mut need, &host);
        assert_eq!(need.result, Some(5));
        // With a buffer, the text arrives.
        let mut conv = call(
            "MultiByteToWideChar",
            [65001, 0, 0x7000, 6, 0x7100, 16],
            teb,
        );
        win32::dispatch(&mut conv, &host);
        assert_eq!(conv.result, Some(5));
        assert_eq!(wide_at(&host, 0x7100), "h\u{e9}llo");
        // Too small a buffer is refused with ERROR_INSUFFICIENT_BUFFER.
        let mut small = call("MultiByteToWideChar", [65001, 0, 0x7000, 6, 0x7100, 2], teb);
        win32::dispatch(&mut small, &host);
        assert_eq!(small.result, Some(0));
        let mut err = call("GetLastError", [0; 6], teb);
        win32::dispatch(&mut err, &host);
        assert_eq!(err.result, Some(122));
        // A -1 length takes the terminator along.
        let mut whole = call(
            "MultiByteToWideChar",
            [65001, 0, 0x7000, usize::MAX, 0, 0],
            teb,
        );
        win32::dispatch(&mut whole, &host);
        assert_eq!(whole.result, Some(6));

        // Back again, with a character outside the BMP: four UTF-8 bytes.
        {
            let mut mem = host.mem.borrow_mut();
            let text = wide_bytes("a\u{1F600}");
            mem[0x7200..0x7200 + text.len()].copy_from_slice(&text);
        }
        let mut back = call(
            "WideCharToMultiByte",
            [65001, 0, 0x7200, 3, 0x7300, 16],
            teb,
        );
        win32::dispatch(&mut back, &host);
        assert_eq!(back.result, Some(5));
        assert_eq!(&host.mem.borrow()[0x7300..0x7305], "a\u{1F600}".as_bytes());

        // Malformed input: replaced, unless the caller asked to be told.
        {
            let mut mem = host.mem.borrow_mut();
            mem[0x7400..0x7402].copy_from_slice(&[0xFF, b'x']);
        }
        let mut lax = call("MultiByteToWideChar", [65001, 0, 0x7400, 2, 0x7500, 4], teb);
        win32::dispatch(&mut lax, &host);
        assert_eq!(lax.result, Some(2));
        assert_eq!(wide_at(&host, 0x7500), "\u{FFFD}x");
        let mut strict = call("MultiByteToWideChar", [65001, 8, 0x7400, 2, 0x7500, 4], teb);
        win32::dispatch(&mut strict, &host);
        assert_eq!(strict.result, Some(0));
        let mut err = call("GetLastError", [0; 6], teb);
        win32::dispatch(&mut err, &host);
        assert_eq!(err.result, Some(1113), "ERROR_NO_UNICODE_TRANSLATION");
    }

    #[test]
    fn the_locale_answers_case_class_and_order() {
        use crate::win32;
        let host = MockHost::default();
        let (teb, _) = process(&host);
        {
            let mut mem = host.mem.borrow_mut();
            let text = wide_bytes("abC1 \0");
            mem[0x7000..0x7000 + text.len()].copy_from_slice(&text);
            let other = wide_bytes("ABC1 \0");
            mem[0x7200..0x7200 + other.len()].copy_from_slice(&other);
        }
        let mut upper = call("LCMapStringW", [0x0400, 0x200, 0x7000, 5, 0x7100, 8], teb);
        win32::dispatch(&mut upper, &host);
        assert_eq!(upper.result, Some(5));
        assert_eq!(wide_at(&host, 0x7100), "ABC1 ");

        let mut classes = call("GetStringTypeW", [1, 0x7000, 5, 0x7300, 0, 0], teb);
        win32::dispatch(&mut classes, &host);
        assert_eq!(classes.result, Some(1));
        let mem = host.mem.borrow();
        let class = |i: usize| u16::from_le_bytes([mem[0x7300 + i * 2], mem[0x7301 + i * 2]]);
        assert_eq!(class(0) & 0x0002, 0x0002, "a is lower");
        assert_eq!(class(2) & 0x0001, 0x0001, "C is upper");
        assert_eq!(class(3) & 0x0004, 0x0004, "1 is a digit");
        assert_eq!(class(4) & 0x0008, 0x0008, "space is space");
        drop(mem);

        let mut cmp = call(
            "CompareStringW",
            [0x0400, 0, 0x7000, usize::MAX, 0x7200, usize::MAX],
            teb,
        );
        win32::dispatch(&mut cmp, &host);
        assert_eq!(
            cmp.result,
            Some(3),
            "lower case sorts after upper, ordinally"
        );
        let mut fold = call(
            "CompareStringW",
            [0x0400, 1, 0x7000, usize::MAX, 0x7200, usize::MAX],
            teb,
        );
        win32::dispatch(&mut fold, &host);
        assert_eq!(fold.result, Some(2), "equal when case is ignored");

        let mut acp = call("GetACP", [0; 6], teb);
        win32::dispatch(&mut acp, &host);
        assert_eq!(acp.result, Some(65001));
        let mut info = call("GetCPInfo", [65001, 0x7400, 0, 0, 0, 0], teb);
        win32::dispatch(&mut info, &host);
        assert_eq!(info.result, Some(1));
        assert_eq!(host.mem.borrow()[0x7400], 4, "MaxCharSize");
    }

    fn node(kind: NodeKind, size: u64) -> Attributes {
        Attributes {
            kind,
            mode: 0o644,
            size,
            block_size: 4096,
            blocks: 0,
            device: 7,
            rdev: 0,
            inode: 42,
            links: 1,
            uid: 0,
            gid: 0,
            accessed_ns: 1_000_000_000,
            modified_ns: 2_000_000_000,
            changed_ns: 3_000_000_000,
        }
    }

    fn put_wide(host: &MockHost, at: usize, text: &str) {
        let bytes: Vec<u8> = text.encode_utf16().flat_map(u16::to_le_bytes).collect();
        host.mem.borrow_mut()[at..at + bytes.len()].copy_from_slice(&bytes);
    }

    #[test]
    fn create_file_opens_the_host_path_a_windows_name_means() {
        use crate::win32;
        let host = MockHost {
            opens_at: Ok(5),
            has_paths: true,
            ..MockHost::default()
        };
        let (teb, _) = process(&host);
        put_wide(&host, 0x7000, "Z:\\app\\data.txt\0");

        // GENERIC_READ, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL.
        let mut open = call("CreateFileW", [0x7000, 0x8000_0000, 1, 0, 3, 0x80], teb);
        win32::dispatch(&mut open, &host);
        assert_eq!(open.result, Some(Handle::from_slot(5).0 as usize));
        let (at, path, how) = host.opened.borrow().clone().expect("opened");
        assert_eq!(at, At::Cwd);
        assert_eq!(path, "/app/data.txt");
        assert!(how.read && !how.write && !how.truncate);
        assert_eq!(how.create, Create::Never);

        // A relative name goes against the current directory, Z:\app.
        put_wide(&host, 0x7100, "sub\\x.txt\0");
        let mut rel = call("CreateFileW", [0x7100, 0x8000_0000, 1, 0, 3, 0x80], teb);
        win32::dispatch(&mut rel, &host);
        assert_eq!(host.opened.borrow().as_ref().unwrap().1, "/app/sub/x.txt");
        put_wide(&host, 0x7200, "..\\etc\\hosts\0");
        let mut up = call("CreateFileW", [0x7200, 0x8000_0000, 1, 0, 3, 0x80], teb);
        win32::dispatch(&mut up, &host);
        assert_eq!(host.opened.borrow().as_ref().unwrap().1, "/etc/hosts");

        // CREATE_ALWAYS with GENERIC_WRITE creates if absent and truncates.
        let mut make = call("CreateFileW", [0x7000, 0x4000_0000, 0, 0, 2, 0x80], teb);
        win32::dispatch(&mut make, &host);
        let how = host.opened.borrow().as_ref().unwrap().2;
        assert!(how.write && how.truncate);
        assert_eq!(how.create, Create::IfAbsent);
    }

    #[test]
    fn create_file_reports_a_missing_file_the_windows_way() {
        use crate::win32;
        let host = MockHost {
            opens_at: Err(ax_abi_port::ENOENT),
            has_paths: true,
            ..MockHost::default()
        };
        let (teb, _) = process(&host);
        put_wide(&host, 0x7000, "Z:\\app\\missing.txt\0");
        let mut open = call("CreateFileW", [0x7000, 0x8000_0000, 1, 0, 3, 0x80], teb);
        win32::dispatch(&mut open, &host);
        assert_eq!(open.result, Some(usize::MAX), "INVALID_HANDLE_VALUE");
        let mut err = call("GetLastError", [0; 6], teb);
        win32::dispatch(&mut err, &host);
        assert_eq!(err.result, Some(2), "ERROR_FILE_NOT_FOUND");
        // A disposition Windows does not have is refused before anything opens.
        let mut bad = call("CreateFileW", [0x7000, 0x8000_0000, 1, 0, 9, 0x80], teb);
        win32::dispatch(&mut bad, &host);
        assert_eq!(bad.result, Some(usize::MAX));
        let mut err = call("GetLastError", [0; 6], teb);
        win32::dispatch(&mut err, &host);
        assert_eq!(err.result, Some(87));
    }

    #[test]
    fn a_file_is_described_by_kind_size_and_position() {
        use crate::win32;
        let host = MockHost {
            describes: Some(node(NodeKind::CharDevice, 0)),
            has_paths: true,
            ..MockHost::default()
        };
        let (teb, _) = process(&host);
        let mut kind = call("GetFileType", [8, 0, 0, 0, 0, 0], teb);
        win32::dispatch(&mut kind, &host);
        assert_eq!(kind.result, Some(2), "FILE_TYPE_CHAR for a terminal");
        let mut std = call("GetFileType", [-11i32 as u32 as usize, 0, 0, 0, 0, 0], teb);
        win32::dispatch(&mut std, &host);
        assert_eq!(
            std.result,
            Some(2),
            "the pseudo-handle names the same stream"
        );

        let host = MockHost {
            describes: Some(node(NodeKind::File, 1234)),
            has_paths: true,
            ..MockHost::default()
        };
        let (teb, _) = process(&host);
        let mut kind = call("GetFileType", [24, 0, 0, 0, 0, 0], teb);
        win32::dispatch(&mut kind, &host);
        assert_eq!(kind.result, Some(1), "FILE_TYPE_DISK");
        let mut size = call("GetFileSizeEx", [24, 0x7000, 0, 0, 0, 0], teb);
        win32::dispatch(&mut size, &host);
        assert_eq!(size.result, Some(1));
        let mem = host.mem.borrow();
        assert_eq!(
            u64::from_le_bytes(mem[0x7000..0x7008].try_into().unwrap()),
            1234
        );
        drop(mem);

        // FILE_BEGIN by 100 lands at 100 and says so; backwards past the
        // start is ERROR_NEGATIVE_SEEK.
        let mut seek = call("SetFilePointerEx", [24, 100, 0x7100, 0, 0, 0], teb);
        win32::dispatch(&mut seek, &host);
        assert_eq!(seek.result, Some(1));
        assert_eq!(*host.sought.borrow(), Some((5, 100)));
        let mem = host.mem.borrow();
        assert_eq!(
            u64::from_le_bytes(mem[0x7100..0x7108].try_into().unwrap()),
            100
        );
        drop(mem);
        let mut back = call("SetFilePointerEx", [24, (-5i64) as usize, 0, 0, 0, 0], teb);
        win32::dispatch(&mut back, &host);
        assert_eq!(back.result, Some(0));
        let mut err = call("GetLastError", [0; 6], teb);
        win32::dispatch(&mut err, &host);
        assert_eq!(err.result, Some(131));

        // Attributes by name: normal file, its size low word, its times as
        // FILETIMEs.
        put_wide(&host, 0x7400, "Z:\\app\\data.txt\0");
        let mut attrs = call("GetFileAttributesExW", [0x7400, 0, 0x7500, 0, 0, 0], teb);
        win32::dispatch(&mut attrs, &host);
        assert_eq!(attrs.result, Some(1));
        let mem = host.mem.borrow();
        assert_eq!(
            u32::from_le_bytes(mem[0x7500..0x7504].try_into().unwrap()),
            0x80
        );
        assert_eq!(
            u32::from_le_bytes(mem[0x7520..0x7524].try_into().unwrap()),
            1234
        );
        assert_eq!(
            u64::from_le_bytes(mem[0x7514..0x751C].try_into().unwrap()),
            crate::nt::nt_time(2_000_000_000),
            "last write time"
        );
    }

    #[test]
    fn full_path_names_are_normalized_against_the_current_directory() {
        use crate::win32;
        let host = MockHost::default();
        let (teb, _) = process(&host);
        put_wide(&host, 0x7000, "..\\lib\\..\\x.py\0");
        let mut full = call("GetFullPathNameW", [0x7000, 64, 0x7100, 0x7300, 0, 0], teb);
        win32::dispatch(&mut full, &host);
        assert_eq!(full.result, Some(7), "Z:\\x.py");
        assert_eq!(wide_at(&host, 0x7100), "Z:\\x.py");
        let part = u64::from_le_bytes(host.mem.borrow()[0x7300..0x7308].try_into().unwrap());
        assert_eq!(part, 0x7100 + 3 * 2, "the file part starts after Z:\\");
        // Too small a buffer is told what it needs, terminator included.
        let mut small = call("GetFullPathNameW", [0x7000, 3, 0x7100, 0, 0, 0], teb);
        win32::dispatch(&mut small, &host);
        assert_eq!(small.result, Some(8));

        let mut tmp = call("GetTempPathW", [64, 0x7400, 0, 0, 0, 0], teb);
        win32::dispatch(&mut tmp, &host);
        assert_eq!(tmp.result, Some(7));
        assert_eq!(wide_at(&host, 0x7400), "Z:\\tmp\\");
    }

    #[test]
    fn changing_directory_moves_where_relative_names_go() {
        use crate::win32;
        let host = MockHost {
            describes: Some(node(NodeKind::Directory, 0)),
            opens_at: Ok(5),
            has_paths: true,
            ..MockHost::default()
        };
        let (teb, _) = process(&host);
        put_wide(&host, 0x7000, "Z:\\work\0");
        let mut cd = call("SetCurrentDirectoryW", [0x7000, 0, 0, 0, 0, 0], teb);
        win32::dispatch(&mut cd, &host);
        assert_eq!(cd.result, Some(1));
        let mut cwd = call("GetCurrentDirectoryW", [64, 0x7100, 0, 0, 0, 0], teb);
        win32::dispatch(&mut cwd, &host);
        assert_eq!(wide_at(&host, 0x7100), "Z:\\work");
        put_wide(&host, 0x7200, "notes.txt\0");
        let mut open = call("CreateFileW", [0x7200, 0x8000_0000, 1, 0, 3, 0x80], teb);
        win32::dispatch(&mut open, &host);
        assert_eq!(host.opened.borrow().as_ref().unwrap().1, "/work/notes.txt");
    }

    /// The kernel32 image and a loader list naming it and the program, laid
    /// out in the mock's memory, as the loader would leave them.
    fn with_modules(host: &MockHost) -> usize {
        use crate::{teb_peb, thunk};
        let (ldr_va, k32_va, exe_va) = (0x6000usize, 0x8000usize, 0x40000usize);
        let image = thunk::system_header(k32_va as u64, 0);
        let ldr = teb_peb::build_ldr(
            &[
                teb_peb::LdrModule {
                    base: exe_va as u64,
                    entry: exe_va as u64 + 0x1000,
                    size: 0x3000,
                    path: "Z:\\app\\prog.exe",
                    name: "prog.exe",
                    tls_index: -1,
                },
                teb_peb::LdrModule {
                    base: k32_va as u64,
                    entry: 0,
                    size: 0x2000,
                    path: "Z:\\windows\\system32\\kernel32.dll",
                    name: "kernel32.dll",
                    tls_index: -1,
                },
            ],
            &[],
            ldr_va as u64,
        );
        let mut mem = host.mem.borrow_mut();
        mem.resize(0x50000, 0);
        mem[ldr_va..ldr_va + ldr.len()].copy_from_slice(&ldr);
        mem[k32_va..k32_va + image.len()].copy_from_slice(&image);
        let peb = 0x2000;
        mem[peb + teb_peb::PEB_LDR..peb + teb_peb::PEB_LDR + 8]
            .copy_from_slice(&(ldr_va as u64).to_le_bytes());
        mem[peb + teb_peb::PEB_IMAGE_BASE..peb + teb_peb::PEB_IMAGE_BASE + 8]
            .copy_from_slice(&(exe_va as u64).to_le_bytes());
        // The version the PEB reports, as the loader fills it.
        let mut pebbuf = mem[peb..peb + teb_peb::PEB_SIZE].to_vec();
        teb_peb::fill_peb(&mut pebbuf, peb as u64, ldr_va as u64, 0x5000, 0x3000);
        mem[peb..peb + teb_peb::PEB_SIZE].copy_from_slice(&pebbuf);
        k32_va
    }

    #[test]
    fn fiber_local_storage_starts_at_one_and_keeps_values() {
        use crate::win32;
        let host = MockHost::default();
        let (teb, _) = process(&host);

        let mut a = call("FlsAlloc", [0; 6], teb);
        win32::dispatch(&mut a, &host);
        let mut b = call("FlsAlloc", [0x1234, 0, 0, 0, 0, 0], teb);
        win32::dispatch(&mut b, &host);
        let (a, b) = (a.result.unwrap(), b.result.unwrap());
        assert!(a >= 1 && b >= 1 && a != b, "index zero is never handed out");

        let mut set = call("FlsSetValue", [a, 0xABCD, 0, 0, 0, 0], teb);
        win32::dispatch(&mut set, &host);
        assert_eq!(set.result, Some(1));
        let mut get = call("FlsGetValue", [a, 0, 0, 0, 0, 0], teb);
        win32::dispatch(&mut get, &host);
        assert_eq!(get.result, Some(0xABCD));
        let mut fresh = call("FlsGetValue", [b, 0, 0, 0, 0, 0], teb);
        win32::dispatch(&mut fresh, &host);
        assert_eq!(fresh.result, Some(0));

        let mut free = call("FlsFree", [a, 0, 0, 0, 0, 0], teb);
        win32::dispatch(&mut free, &host);
        assert_eq!(free.result, Some(1));
        let mut gone = call("FlsGetValue", [a, 0, 0, 0, 0, 0], teb);
        win32::dispatch(&mut gone, &host);
        assert_eq!(gone.result, Some(0));
        let mut err = call("GetLastError", [0; 6], teb);
        win32::dispatch(&mut err, &host);
        assert_eq!(err.result, Some(87), "a freed index is not a valid one");
        let mut again = call("FlsAlloc", [0; 6], teb);
        win32::dispatch(&mut again, &host);
        assert_eq!(again.result, Some(a), "and it is reused");
    }

    #[test]
    fn the_version_check_compares_the_way_rtl_does() {
        use crate::win32;
        let host = MockHost::default();
        let (teb, _) = process(&host);
        with_modules(&host);

        // VerSetConditionMask(0, VER_MAJORVERSION, VER_GREATER_EQUAL) puts the
        // condition three bits up.
        let mut mask = call("VerSetConditionMask", [0, 0x2, 3, 0, 0, 0], teb);
        win32::dispatch(&mut mask, &host);
        assert_eq!(mask.result, Some(3 << 3));
        let mut mask = call("VerSetConditionMask", [3 << 3, 0x1, 3, 0, 0, 0], teb);
        win32::dispatch(&mut mask, &host);
        let mask = mask.result.unwrap();
        assert_eq!(mask, (3 << 3) | 3);

        // RTL_OSVERSIONINFOEXW asking for at least 6.0: satisfied by 10.0.
        let info = 0x7000usize;
        {
            let mut mem = host.mem.borrow_mut();
            mem[info..info + 4].copy_from_slice(&284u32.to_le_bytes());
            mem[info + 4..info + 8].copy_from_slice(&6u32.to_le_bytes());
            mem[info + 8..info + 12].copy_from_slice(&0u32.to_le_bytes());
        }
        let mut ok = call("VerifyVersionInfoW", [info, 0x3, mask, 0, 0, 0], teb);
        win32::dispatch(&mut ok, &host);
        assert_eq!(ok.result, Some(1));
        // At least 11.0 is not.
        host.mem.borrow_mut()[info + 4..info + 8].copy_from_slice(&11u32.to_le_bytes());
        let mut old = call("VerifyVersionInfoW", [info, 0x3, mask, 0, 0, 0], teb);
        win32::dispatch(&mut old, &host);
        assert_eq!(old.result, Some(0));
        let mut err = call("GetLastError", [0; 6], teb);
        win32::dispatch(&mut err, &host);
        assert_eq!(err.result, Some(1150), "ERROR_OLD_WIN_VERSION");
    }

    #[test]
    fn libraries_the_process_has_are_found_and_others_are_not_loaded() {
        use crate::win32;
        let host = MockHost::default();
        let (teb, _) = process(&host);
        let k32 = with_modules(&host);
        put_wide(&host, 0x10000, "api-ms-win-core-file-l1-1-0.dll\0");
        put_wide(&host, 0x10200, "nope.dll\0");
        put_wide(&host, 0x10400, "KERNEL32.DLL\0");

        // An api-set name folds into kernel32, which the process has.
        let mut lib = call("LoadLibraryExW", [0x10000, 0, 0x800, 0, 0, 0], teb);
        win32::dispatch(&mut lib, &host);
        assert_eq!(lib.result, Some(k32));
        let mut again = call("LoadLibraryExW", [0x10400, 0, 0, 0, 0, 0], teb);
        win32::dispatch(&mut again, &host);
        assert_eq!(again.result, Some(k32));
        // A file the process does not have is not loaded from here.
        let mut missing = call("LoadLibraryExW", [0x10200, 0, 0, 0, 0, 0], teb);
        win32::dispatch(&mut missing, &host);
        assert_eq!(missing.result, Some(0));
        let mut err = call("GetLastError", [0; 6], teb);
        win32::dispatch(&mut err, &host);
        assert_eq!(err.result, Some(126), "ERROR_MOD_NOT_FOUND");

        // GetModuleHandleExW: NULL is the program; an address inside a module
        // names that module; a null out-pointer is refused.
        let mut exe = call("GetModuleHandleExW", [0, 0, 0x10800, 0, 0, 0], teb);
        win32::dispatch(&mut exe, &host);
        assert_eq!(exe.result, Some(1));
        let word =
            |at: usize| u64::from_le_bytes(host.mem.borrow()[at..at + 8].try_into().unwrap());
        assert_eq!(word(0x10800), 0x40000);
        let mut by_addr = call(
            "GetModuleHandleExW",
            [0x4, k32 + 0x1234, 0x10800, 0, 0, 0],
            teb,
        );
        win32::dispatch(&mut by_addr, &host);
        assert_eq!(by_addr.result, Some(1));
        assert_eq!(word(0x10800), k32 as u64);
        let mut bad = call("GetModuleHandleExW", [0, 0, 0, 0, 0, 0], teb);
        win32::dispatch(&mut bad, &host);
        assert_eq!(bad.result, Some(0));

        let mut free = call("FreeLibrary", [k32, 0, 0, 0, 0, 0], teb);
        win32::dispatch(&mut free, &host);
        assert_eq!(free.result, Some(1));
        let mut null = call("FreeLibrary", [0; 6], teb);
        win32::dispatch(&mut null, &host);
        assert_eq!(null.result, Some(0));
    }

    #[test]
    fn an_srw_lock_is_taken_and_released_and_a_condvar_wait_returns() {
        use crate::win32;
        let host = MockHost::default();
        let (teb, _) = process(&host);
        let (lock, cond) = (0x7000usize, 0x7100usize);

        let mut init = call("InitializeSRWLock", [lock, 0, 0, 0, 0, 0], teb);
        win32::dispatch(&mut init, &host);
        let word =
            |at: usize| u64::from_le_bytes(host.mem.borrow()[at..at + 8].try_into().unwrap());
        let mut acq = call("AcquireSRWLockExclusive", [lock, 0, 0, 0, 0, 0], teb);
        win32::dispatch(&mut acq, &host);
        assert_eq!(word(lock), 1, "held exclusive");
        let mut rel = call("ReleaseSRWLockExclusive", [lock, 0, 0, 0, 0, 0], teb);
        win32::dispatch(&mut rel, &host);
        assert_eq!(word(lock), 0, "free again");
        // A try on a free lock takes it and reports success.
        let mut tryacq = call("TryAcquireSRWLockExclusive", [lock, 0, 0, 0, 0, 0], teb);
        win32::dispatch(&mut tryacq, &host);
        assert_eq!(tryacq.result, Some(1));

        // Sleeping on a condition variable releases the lock and returns woken,
        // so a caller's recheck loop makes progress in this one thread.
        let mut sleep = call("SleepConditionVariableSRW", [cond, lock, 0, 0, 0, 0], teb);
        win32::dispatch(&mut sleep, &host);
        assert_eq!(sleep.result, Some(1));
        assert_eq!(word(lock), 0, "the lock was released");
    }

    #[test]
    fn an_ansi_environment_variable_comes_out_of_the_block() {
        use crate::win32;
        let host = MockHost::default();
        let (teb, _) = process(&host);
        // The mock's environment is A=1, B=two.
        put_wide(&host, 0x7000, "B\0");
        let mut got = call(
            "GetEnvironmentVariableA",
            [0x7000, 0x7100, 64, 0, 0, 0],
            teb,
        );
        win32::dispatch(&mut got, &host);
        assert_eq!(got.result, Some(3));
        assert_eq!(&host.mem.borrow()[0x7100..0x7104], b"two\0");
        // Names are matched without regard to case.
        put_wide(&host, 0x7000, "a\0");
        let mut lower = call(
            "GetEnvironmentVariableA",
            [0x7000, 0x7100, 64, 0, 0, 0],
            teb,
        );
        win32::dispatch(&mut lower, &host);
        assert_eq!(lower.result, Some(1));
        // A variable that is not set is reported as not found.
        put_wide(&host, 0x7000, "NOPE\0");
        let mut missing = call(
            "GetEnvironmentVariableA",
            [0x7000, 0x7100, 64, 0, 0, 0],
            teb,
        );
        win32::dispatch(&mut missing, &host);
        assert_eq!(missing.result, Some(0));
        let mut err = call("GetLastError", [0; 6], teb);
        win32::dispatch(&mut err, &host);
        assert_eq!(err.result, Some(203), "ERROR_ENVVAR_NOT_FOUND");
    }

    #[test]
    fn getpath_helpers_parse_and_describe_windows_paths() {
        use crate::win32;
        let host = MockHost {
            describes: Some(node(NodeKind::File, 0)),
            has_paths: true,
            ..MockHost::default()
        };
        let (teb, _) = process(&host);

        // PathCchSkipRoot on Z:\python\lib points just past the drive root.
        put_wide(&host, 0x7000, "Z:\\python\\lib\0");
        let mut skip = call("PathCchSkipRoot", [0x7000, 0x7200, 0, 0, 0, 0], teb);
        win32::dispatch(&mut skip, &host);
        assert_eq!(skip.result, Some(0), "S_OK");
        let past = u64::from_le_bytes(host.mem.borrow()[0x7200..0x7208].try_into().unwrap());
        assert_eq!(past, 0x7000 + 3 * 2, "one past the drive root");

        // PathCchCombineEx joins and folds "..".
        put_wide(&host, 0x7300, "Z:\\python\0");
        put_wide(&host, 0x7400, "lib\\..\\DLLs\0");
        let mut comb = call("PathCchCombineEx", [0x7500, 64, 0x7300, 0x7400, 0, 0], teb);
        win32::dispatch(&mut comb, &host);
        assert_eq!(comb.result, Some(0));
        assert_eq!(wide_at(&host, 0x7500), "Z:\\python\\DLLs");

        // GetFileAttributesW describes a name; a normal file is 0x80.
        put_wide(&host, 0x7600, "Z:\\python\\python.exe\0");
        let mut attr = call("GetFileAttributesW", [0x7600, 0, 0, 0, 0, 0], teb);
        win32::dispatch(&mut attr, &host);
        assert_eq!(attr.result, Some(0x80));

        // GetSystemInfo fills an AMD64, single-processor block.
        let mut si = call("GetSystemInfo", [0x7700, 0, 0, 0, 0, 0], teb);
        win32::dispatch(&mut si, &host);
        let mem = host.mem.borrow();
        assert_eq!(
            u16::from_le_bytes(mem[0x7700..0x7702].try_into().unwrap()),
            9,
            "AMD64"
        );
        assert_eq!(
            u32::from_le_bytes(mem[0x7704..0x7708].try_into().unwrap()),
            0x1000,
            "page size"
        );
        assert_eq!(
            u32::from_le_bytes(mem[0x7720..0x7724].try_into().unwrap()),
            1,
            "one processor"
        );
        drop(mem);

        // A registry key nothing provides is not found, so a caller falls back.
        let mut reg = call("RegOpenKeyExW", [0x8000_0002, 0x7000, 0, 0, 0x7800, 0], teb);
        win32::dispatch(&mut reg, &host);
        assert_eq!(reg.result, Some(2), "ERROR_FILE_NOT_FOUND");
        assert_eq!(
            u64::from_le_bytes(host.mem.borrow()[0x7800..0x7808].try_into().unwrap()),
            0
        );
    }

    #[test]
    fn a_directory_search_walks_its_entries_and_ends() {
        use crate::win32;
        let host = MockHost {
            describes: Some(node(NodeKind::Directory, 0)),
            has_paths: true,
            opens_at: Ok(7),
            entries: alloc::vec![
                (String::from("__init__.py"), NodeKind::File),
                (String::from("aliases.py"), NodeKind::File),
                (String::from("cp437.py"), NodeKind::File),
            ],
            ..MockHost::default()
        };
        let (teb, _) = process(&host);
        // FindFirstFileW("Z:\python\Lib\encodings\*", &data).
        put_wide(&host, 0x7000, "Z:\\python\\Lib\\encodings\\*\0");
        let mut first = call("FindFirstFileW", [0x7000, 0x7200, 0, 0, 0, 0], teb);
        win32::dispatch(&mut first, &host);
        let handle = first.result.unwrap();
        assert_ne!(handle, usize::MAX, "a search that matches returns a handle");
        // The directory it opened is the one the pattern named, host-spelled.
        assert_eq!(
            host.opened.borrow().as_ref().unwrap().1,
            "/python/Lib/encodings"
        );

        // cFileName sits at offset 0x2C in WIN32_FIND_DATAW.
        let name_of = |at: usize| wide_at(&host, at + 0x2C);
        assert_eq!(name_of(0x7200), "__init__.py");
        // FILE_ATTRIBUTE_NORMAL on a file.
        assert_eq!(
            u32::from_le_bytes(host.mem.borrow()[0x7200..0x7204].try_into().unwrap()),
            0x80
        );

        let mut next = call("FindNextFileW", [handle, 0x7200, 0, 0, 0, 0], teb);
        win32::dispatch(&mut next, &host);
        assert_eq!(next.result, Some(1));
        assert_eq!(name_of(0x7200), "aliases.py");
        let mut next = call("FindNextFileW", [handle, 0x7200, 0, 0, 0, 0], teb);
        win32::dispatch(&mut next, &host);
        assert_eq!(name_of(0x7200), "cp437.py");
        // The fourth advance is past the end.
        let mut done = call("FindNextFileW", [handle, 0x7200, 0, 0, 0, 0], teb);
        win32::dispatch(&mut done, &host);
        assert_eq!(done.result, Some(0));
        let mut err = call("GetLastError", [0; 6], teb);
        win32::dispatch(&mut err, &host);
        assert_eq!(err.result, Some(18), "ERROR_NO_MORE_FILES");

        let mut close = call("FindClose", [handle, 0, 0, 0, 0, 0], teb);
        win32::dispatch(&mut close, &host);
        assert_eq!(close.result, Some(1));
    }

    #[test]
    fn a_search_for_one_name_matches_only_it() {
        use crate::win32;
        let host = MockHost {
            describes: Some(node(NodeKind::Directory, 0)),
            has_paths: true,
            opens_at: Ok(7),
            entries: alloc::vec![
                (String::from("python.exe"), NodeKind::File),
                (String::from("python313.dll"), NodeKind::File),
            ],
            ..MockHost::default()
        };
        let (teb, _) = process(&host);
        put_wide(&host, 0x7000, "Z:\\python\\python.exe\0");
        let mut first = call("FindFirstFileW", [0x7000, 0x7200, 0, 0, 0, 0], teb);
        win32::dispatch(&mut first, &host);
        assert_ne!(first.result, Some(usize::MAX));
        assert_eq!(wide_at(&host, 0x7200 + 0x2C), "python.exe");
        // Nothing after the single match.
        let mut next = call(
            "FindNextFileW",
            [first.result.unwrap(), 0x7200, 0, 0, 0, 0],
            teb,
        );
        win32::dispatch(&mut next, &host);
        assert_eq!(next.result, Some(0));

        // A name nothing matches is "file not found".
        put_wide(&host, 0x7000, "Z:\\python\\missing.txt\0");
        let mut none = call("FindFirstFileW", [0x7000, 0x7200, 0, 0, 0, 0], teb);
        win32::dispatch(&mut none, &host);
        assert_eq!(none.result, Some(usize::MAX));
    }
}
