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
        /// The number a spawn hands back, or nothing for a host with no
        /// process creation at all.
        spawns: Option<u32>,
        /// Where a started thread's own block is, as the layer laid it out.
        started_at: Option<usize>,
        /// The stack the arguments past the sixth are read from.
        sp: usize,
        /// The block a started process was handed, as the layer laid it out.
        handed: Option<usize>,
    }
    impl Win32Trap {
        fn new(call: crate::win32::Win32Call, args: [usize; 6], teb: usize) -> Self {
            Self {
                nr: call.nr() as usize,
                args,
                teb,
                result: None,
                spawns: None,
                started_at: None,
                sp: 0,
                handed: None,
            }
        }

        /// A trap whose arguments past the sixth are on a stack the host can
        /// read, which is where the caller of a longer call leaves them.
        fn with_stack(
            call: crate::win32::Win32Call,
            args: [usize; 6],
            teb: usize,
            later: &[usize],
            pid: u32,
            host: &MockHost,
        ) -> Self {
            let sp = 0xB000usize;
            {
                let mut mem = host.mem.borrow_mut();
                if mem.len() < sp + 0x48 + later.len() * 8 {
                    mem.resize(sp + 0x48 + later.len() * 8, 0);
                }
                for (i, value) in later.iter().enumerate() {
                    let at = sp + 0x48 + i * 8;
                    mem[at..at + 8].copy_from_slice(&(*value as u64).to_le_bytes());
                }
            }
            Self {
                sp,
                spawns: Some(pid),
                ..Self::new(call, args, teb)
            }
        }

        /// A trap whose spawn answers with `pid`, as a host that hands the
        /// same number out again once it is free would.
        fn spawning(call: crate::win32::Win32Call, args: [usize; 6], teb: usize, pid: u32) -> Self {
            Self {
                spawns: Some(pid),
                ..Self::new(call, args, teb)
            }
        }
    }
    impl TrapEnv for Win32Trap {
        fn nr(&self) -> usize {
            self.nr
        }
        fn stack_pointer(&self) -> usize {
            self.sp
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
        fn spawn(&mut self, _entry: usize, arg: usize) -> Result<u32, i32> {
            self.handed = Some(arg);
            self.spawns.ok_or(38)
        }
        fn spawn_thread(
            &mut self,
            _entry: usize,
            _stack: usize,
            _arg: usize,
            tls: usize,
        ) -> Result<u32, i32> {
            self.started_at = Some(tls);
            self.spawns.ok_or(38)
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
        /// The monotonic clock, which a test moves by hand.
        now: RefCell<u64>,
        /// The sockets this host has handed out.
        sockets: RefCell<Vec<MockSocket>>,
        /// The last permission change asked for.
        moded: RefCell<Option<(String, u32)>>,
        /// The descriptor whose times were set, and to what.
        stamped: RefCell<Option<(i32, Option<u64>, Option<u64>)>>,
        /// The name that was unlinked, if one was.
        unlinked: RefCell<Option<String>>,
        /// What the filesystem says it has room for, if it says.
        space: Option<ax_abi_port::Space>,
        /// What this process ended with, if it did.
        ended: RefCell<Option<i32>>,
        /// Who was signalled, and with what.
        killed: RefCell<Vec<(u32, u32)>>,
        /// Whether there is a process to signal at all.
        kills: core::cell::Cell<bool>,
        /// Children the test has declared finished, and with what code.
        exits: RefCell<alloc::collections::BTreeMap<u32, i32>>,
        /// Whether this host makes sections: an open hands out the next
        /// descriptor, and mapping one lands it on a page of its own so two
        /// sections are two pages, the way two files would be.
        sections: core::cell::Cell<bool>,
        /// The descriptors handed out for sections so far.
        section_fds: core::cell::Cell<i32>,
        /// How long each of those sections is, which starts at nothing and is
        /// what truncating it sets - the way a fresh file behaves.
        section_sizes: RefCell<alloc::collections::BTreeMap<i32, u64>>,
        /// How long the last park was asked to last, or nothing for one with
        /// no deadline.
        parked: RefCell<Option<Option<u64>>>,
        /// The process and descriptor the last steal named.
        stolen: RefCell<Option<(u32, i32)>>,
    }

    /// Where the first section a mock host makes is mapped: past the heap
    /// arena the test process lays out, with a page for each.
    const SECTION_BASE: usize = 0x18000;
    /// The first descriptor a mock section is given.
    const SECTION_FD: i32 = 40;

    impl MockHost {
        /// The socket a descriptor names, for a test to set up or inspect.
        fn socket(&self, fd: i32) -> Result<core::cell::RefMut<'_, MockSocket>, i32> {
            let index = (fd - 3) as usize;
            let table = self.sockets.borrow_mut();
            if index >= table.len() || table[index].closed {
                return Err(88); // ENOTSOCK
            }
            Ok(core::cell::RefMut::map(table, |table| &mut table[index]))
        }
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
                now: RefCell::default(),
                sockets: RefCell::default(),
                moded: RefCell::default(),
                stamped: RefCell::default(),
                unlinked: RefCell::default(),
                space: None,
                ended: RefCell::default(),
                killed: RefCell::default(),
                kills: core::cell::Cell::new(true),
                exits: RefCell::default(),
                sections: core::cell::Cell::new(false),
                section_fds: core::cell::Cell::new(SECTION_FD),
                section_sizes: RefCell::default(),
                parked: RefCell::default(),
                stolen: RefCell::default(),
            }
        }
    }

    // The host's synchronisation steps over the mock's flat memory. Nothing
    // else runs in a test, so a park is a park nobody will end: it reports
    // the deadline, which is what a real host reports when no wake arrives.
    /// A socket table the tests can inspect: enough of one for the Winsock
    /// layer to be exercised end to end without a network.
    #[derive(Default, Clone)]
    struct MockSocket {
        kind: Option<ax_abi_port::SocketKind>,
        v6: bool,
        bound: Option<ax_abi_port::Address>,
        peer: Option<ax_abi_port::Address>,
        listening: bool,
        blocking: bool,
        sent: Vec<(usize, usize, Option<ax_abi_port::Address>)>,
        queued: Vec<u8>,
        shutdown: Option<ax_abi_port::Shutdown>,
        options: Vec<(ax_abi_port::SocketOption, u32)>,
        closed: bool,
    }

    impl ax_abi_port::Sockets for MockHost {
        fn open(
            &self,
            domain: ax_abi_port::Domain,
            kind: ax_abi_port::SocketKind,
        ) -> Result<i32, i32> {
            let mut table = self.sockets.borrow_mut();
            table.push(MockSocket {
                kind: Some(kind),
                v6: domain == ax_abi_port::Domain::Inet6,
                blocking: true,
                ..MockSocket::default()
            });
            // Descriptor 0 is stdin elsewhere in these tests, so sockets start
            // above the standard three.
            Ok(table.len() as i32 + 2)
        }
        fn bind(&self, fd: i32, at: &ax_abi_port::Address) -> Result<(), i32> {
            self.socket(fd)?.bound = Some(*at);
            Ok(())
        }
        fn connect(&self, fd: i32, to: &ax_abi_port::Address) -> Result<(), i32> {
            self.socket(fd)?.peer = Some(*to);
            Ok(())
        }
        fn listen(&self, fd: i32, _backlog: u32) -> Result<(), i32> {
            self.socket(fd)?.listening = true;
            Ok(())
        }
        fn accept(&self, fd: i32) -> Result<(i32, Option<ax_abi_port::Address>), i32> {
            if !self.socket(fd)?.listening {
                return Err(107); // ENOTCONN
            }
            let peer = ax_abi_port::Address::V4([198, 51, 100, 7], 4242);
            let mut table = self.sockets.borrow_mut();
            table.push(MockSocket {
                peer: Some(peer),
                blocking: true,
                ..MockSocket::default()
            });
            Ok((table.len() as i32 + 2, Some(peer)))
        }
        fn send(
            &self,
            fd: i32,
            uaddr: usize,
            len: usize,
            to: Option<&ax_abi_port::Address>,
        ) -> ax_abi_port::SysResult {
            self.socket(fd)?.sent.push((uaddr, len, to.copied()));
            Ok(len as isize)
        }
        fn recv(
            &self,
            fd: i32,
            uaddr: usize,
            len: usize,
            peek: bool,
        ) -> Result<(usize, Option<ax_abi_port::Address>), i32> {
            let queued = self.socket(fd)?.queued.clone();
            // An empty socket that has not been shut down would block, which
            // is what a host tells a non-blocking read.
            if queued.is_empty() && self.socket(fd)?.shutdown.is_none() {
                return Err(ax_abi_port::EAGAIN);
            }
            let read = queued.len().min(len);
            {
                let mut mem = self.mem.borrow_mut();
                if mem.len() < uaddr + read {
                    mem.resize(uaddr + read, 0);
                }
                mem[uaddr..uaddr + read].copy_from_slice(&queued[..read]);
            }
            if !peek {
                self.socket(fd)?.queued.drain(..read);
            }
            Ok((read, Some(ax_abi_port::Address::V4([203, 0, 113, 9], 1234))))
        }
        fn shutdown(&self, fd: i32, how: ax_abi_port::Shutdown) -> Result<(), i32> {
            self.socket(fd)?.shutdown = Some(how);
            Ok(())
        }
        fn local(&self, fd: i32) -> Result<ax_abi_port::Address, i32> {
            self.socket(fd)?.bound.ok_or(107)
        }
        fn peer(&self, fd: i32) -> Result<ax_abi_port::Address, i32> {
            self.socket(fd)?.peer.ok_or(107)
        }
        fn set_blocking(&self, fd: i32, blocking: bool) -> Result<(), i32> {
            self.socket(fd)?.blocking = blocking;
            Ok(())
        }
        fn pending(&self, fd: i32) -> Result<usize, i32> {
            Ok(self.socket(fd)?.queued.len())
        }
        fn set_option(
            &self,
            fd: i32,
            option: ax_abi_port::SocketOption,
            value: u32,
        ) -> Result<(), i32> {
            self.socket(fd)?.options.push((option, value));
            Ok(())
        }
        fn option(&self, fd: i32, option: ax_abi_port::SocketOption) -> Result<u32, i32> {
            let socket = self.socket(fd)?;
            Ok(match option {
                ax_abi_port::SocketOption::Kind => match socket.kind {
                    Some(ax_abi_port::SocketKind::Datagram) => 2,
                    _ => 1,
                },
                other => socket
                    .options
                    .iter()
                    .rev()
                    .find(|(seen, _)| *seen == other)
                    .map_or(0, |(_, value)| *value),
            })
        }
    }

    impl MockHost {
        /// Readiness the way the host reports it: a socket with something
        /// queued reads, one that is connected writes.
        fn readiness(&self, fd: i32) -> Option<ax_abi_port::Ready> {
            let socket = self.socket(fd).ok()?;
            Some(ax_abi_port::Ready {
                read: !socket.queued.is_empty(),
                write: socket.peer.is_some(),
                error: socket.shutdown.is_some(),
            })
        }
    }

    impl ax_abi_port::Tasks for MockHost {
        fn getpid(&self) -> ax_abi_port::SysResult {
            Ok(1)
        }
        fn getppid(&self) -> ax_abi_port::SysResult {
            Ok(0)
        }
        fn gettid(&self) -> u32 {
            1
        }
        fn set_tid_address(&self, _at: usize) -> ax_abi_port::SysResult {
            Ok(0)
        }
        fn sched_yield(&self) -> ax_abi_port::SysResult {
            Ok(0)
        }
        fn exit(&self, _code: i32) -> ax_abi_port::SysResult {
            Ok(0)
        }
        fn exit_group(&self, code: i32) -> ax_abi_port::SysResult {
            *self.ended.borrow_mut() = Some(code);
            Ok(0)
        }
        fn wait(&self, pid: u32, status_out: usize, _nohang: bool) -> Result<u32, i32> {
            // A child the test has said is finished reports the status the
            // host would lay out; anything else has not ended yet.
            let Some(code) = self.exits.borrow_mut().remove(&pid) else {
                return Ok(0);
            };
            let mut mem = self.mem.borrow_mut();
            if mem.len() < status_out + 4 {
                mem.resize(status_out + 4, 0);
            }
            mem[status_out..status_out + 4].copy_from_slice(&((code as u32) << 8).to_le_bytes());
            Ok(pid)
        }
    }

    impl ax_abi_port::Signals for MockHost {
        fn kill(&self, target: ax_abi_port::SignalTarget, signo: u32) -> ax_abi_port::SysResult {
            match target {
                ax_abi_port::SignalTarget::Process(pid) => {
                    if !self.kills.get() {
                        return Err(ax_abi_port::ESRCH);
                    }
                    self.killed.borrow_mut().push((pid, signo));
                    Ok(0)
                }
                _ => Err(ax_abi_port::EINVAL),
            }
        }
        fn tgkill(&self, _tgid: u32, _tid: u32, _signo: u32) -> ax_abi_port::SysResult {
            Err(ax_abi_port::ENOSYS)
        }
        fn tkill(&self, _tid: u32, _signo: u32) -> ax_abi_port::SysResult {
            Err(ax_abi_port::ENOSYS)
        }
        fn sigprocmask(&self, _how: i32, _new: Option<u64>) -> Result<u64, i32> {
            Err(ax_abi_port::ENOSYS)
        }
    }

    impl ax_abi_port::System for MockHost {
        fn uname(&self, put: &mut dyn FnMut(ax_abi_port::UtsField, &str)) {
            put(ax_abi_port::UtsField::SysName, "Starry");
            put(ax_abi_port::UtsField::NodeName, "starry-host");
        }
    }

    impl ax_abi_port::Clock for MockHost {
        fn monotonic_ns(&self) -> u64 {
            *self.now.borrow()
        }
        fn wall_ns(&self) -> u64 {
            *self.now.borrow()
        }
        fn sleep_ns(&self, ns: u64) -> ax_abi_port::Slept {
            *self.now.borrow_mut() += ns;
            ax_abi_port::Slept::Full
        }
    }

    impl ax_abi_port::Wait for MockHost {
        fn wait(
            &self,
            _at: usize,
            _expected: u32,
            timeout_ns: Option<u64>,
            _shared: bool,
        ) -> Result<bool, i32> {
            *self.parked.borrow_mut() = Some(timeout_ns);
            // Nothing here wakes a parked thread, so a park with a deadline
            // is exactly that much time going by.
            if let Some(ns) = timeout_ns {
                *self.now.borrow_mut() += ns;
            }
            Ok(false)
        }
        fn wake(&self, _at: usize, _count: u32, _shared: bool) -> Result<u32, i32> {
            Ok(0)
        }
        fn swap(&self, at: usize, value: u32) -> Result<u32, i32> {
            let mut mem = self.mem.borrow_mut();
            if mem.len() < at + 4 {
                mem.resize(at + 4, 0);
            }
            let old = u32::from_le_bytes(mem[at..at + 4].try_into().unwrap());
            mem[at..at + 4].copy_from_slice(&value.to_le_bytes());
            Ok(old)
        }
        fn fetch_add(&self, at: usize, value: u32) -> Result<u32, i32> {
            let mut mem = self.mem.borrow_mut();
            if mem.len() < at + 4 {
                mem.resize(at + 4, 0);
            }
            let old = u32::from_le_bytes(mem[at..at + 4].try_into().unwrap());
            mem[at..at + 4].copy_from_slice(&old.wrapping_add(value).to_le_bytes());
            Ok(old)
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
        fn poll(
            &self,
            interest: &mut [(i32, ax_abi_port::Ready)],
            timeout_ns: Option<u64>,
        ) -> Result<usize, i32> {
            let mut count = 0;
            for (fd, ready) in interest.iter_mut() {
                let wanted = *ready;
                *ready = ax_abi_port::Ready::default();
                let Some(is) = self.readiness(*fd) else {
                    ready.error = true;
                    count += 1;
                    continue;
                };
                let asked = (wanted.read && is.read)
                    || (wanted.write && is.write)
                    || (wanted.error && is.error);
                if asked {
                    *ready = is;
                    count += 1;
                }
            }
            // Nothing became ready, so the wait ran to its deadline and that
            // much time has gone by.
            if count == 0
                && let Some(ns) = timeout_ns
            {
                *self.now.borrow_mut() += ns;
            }
            Ok(count)
        }

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
        fn steal(&self, pid: u32, fd: i32) -> ax_abi_port::SysResult {
            *self.stolen.borrow_mut() = Some((pid, fd));
            Ok(99)
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
            if self.sections.get() {
                self.section_sizes.borrow_mut().insert(fd, len);
            }
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
            if let ax_abi_port::MapSource::File { fd, .. } = req.source
                && self.sections.get()
                && (SECTION_FD..self.section_fds.get()).contains(&fd)
            {
                return Ok((SECTION_BASE + (fd - SECTION_FD) as usize * 0x1000) as isize);
            }
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
            if self.sections.get() {
                let fd = self.section_fds.get();
                self.section_fds.set(fd + 1);
                return Ok(fd as isize);
            }
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
        fn attributes_of(&self, fd: i32) -> Result<Attributes, i32> {
            if self.sections.get() && (SECTION_FD..self.section_fds.get()).contains(&fd) {
                return Ok(Attributes {
                    size: self.section_sizes.borrow().get(&fd).copied().unwrap_or(0),
                    ..Attributes::default()
                });
            }
            self.describes.clone().ok_or(ax_abi_port::EBADF)
        }
        fn space(&self, _at: At, _path: &str) -> Result<ax_abi_port::Space, i32> {
            self.space.ok_or(ax_abi_port::ENOSYS)
        }
        fn unlink(&self, _at: At, path: &str) -> Result<(), i32> {
            *self.unlinked.borrow_mut() = Some(String::from(path));
            Ok(())
        }
        fn set_mode(&self, _at: At, path: &str, mode: u32, _follow: bool) -> Result<(), i32> {
            *self.moded.borrow_mut() = Some((String::from(path), mode));
            Ok(())
        }
        fn set_mode_of(&self, fd: i32, mode: u32) -> Result<(), i32> {
            *self.moded.borrow_mut() = Some((alloc::format!("fd{fd}"), mode));
            Ok(())
        }
        fn set_times_of(
            &self,
            fd: i32,
            accessed: Option<u64>,
            modified: Option<u64>,
        ) -> Result<(), i32> {
            *self.stamped.borrow_mut() = Some((fd, accessed, modified));
            Ok(())
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
        fn wait(&self) -> Option<&dyn ax_abi_port::Wait> {
            Some(self)
        }
        fn signals(&self) -> Option<&dyn ax_abi_port::Signals> {
            Some(self)
        }
        fn clock(&self) -> Option<&dyn ax_abi_port::Clock> {
            Some(self)
        }
        fn sockets(&self) -> Option<&dyn ax_abi_port::Sockets> {
            Some(self)
        }
        fn system(&self) -> Option<&dyn ax_abi_port::System> {
            Some(self)
        }
        fn tasks(&self) -> Option<&dyn ax_abi_port::Tasks> {
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
        // The heap sits past everything else: a thread's control block alone
        // is larger than the rest of this layout.
        let (teb, peb, arena, params) = (0x100usize, 0x2000usize, 0x10000usize, 0x5000usize);
        let mut mem = host.mem.borrow_mut();
        mem.resize(0x20000, 0);
        mem[teb + TEB_PEB..teb + TEB_PEB + 8].copy_from_slice(&(peb as u64).to_le_bytes());
        mem[peb + PEB_PROCESS_HEAP..peb + PEB_PROCESS_HEAP + 8]
            .copy_from_slice(&(arena as u64).to_le_bytes());
        mem[arena..arena + heap::HEADER].copy_from_slice(&heap::arena(arena as u64, 0x6000));
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

    /// The descriptor a socket handle names, as the layer computes it.
    fn socket_fd(handle: usize) -> i32 {
        (handle / 4 - 1) as i32
    }

    fn put_bytes(host: &MockHost, at: usize, bytes: &[u8]) {
        let mut mem = host.mem.borrow_mut();
        if mem.len() < at + bytes.len() {
            mem.resize(at + bytes.len(), 0);
        }
        mem[at..at + bytes.len()].copy_from_slice(bytes);
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

        // Past the first arena's end the heap grows: another arena is mapped
        // and the block comes from it rather than being refused.
        let mut huge = call("HeapAlloc", [arena, 0, 0x2000, 0, 0, 0], teb);
        win32::dispatch(&mut huge, &host);
        assert!(huge.result.is_some_and(|block| block != 0));
    }

    #[test]
    fn a_block_freed_twice_is_not_handed_to_two_callers() {
        use crate::win32;
        let host = MockHost::default();
        let (teb, arena) = process(&host);

        let mut made = call("HeapAlloc", [arena, 0, 32, 0, 0, 0], teb);
        win32::dispatch(&mut made, &host);
        let block = made.result.expect("a block");

        let mut free = call("HeapFree", [arena, 0, block, 0, 0, 0], teb);
        win32::dispatch(&mut free, &host);
        assert_eq!(free.result, Some(1));
        // Freeing it again is refused, and - what matters - does not put it
        // on the free list a second time.
        let mut again = call("HeapFree", [arena, 0, block, 0, 0, 0], teb);
        win32::dispatch(&mut again, &host);
        assert_eq!(again.result, Some(0));

        let mut one = call("HeapAlloc", [arena, 0, 32, 0, 0, 0], teb);
        win32::dispatch(&mut one, &host);
        let mut two = call("HeapAlloc", [arena, 0, 32, 0, 0, 0], teb);
        win32::dispatch(&mut two, &host);
        assert_ne!(
            one.result, two.result,
            "two allocations are two blocks, whatever was freed twice"
        );
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
        assert_eq!(word(8), 0, "the lock word starts free");

        for _ in 0..2 {
            let mut enter = call("EnterCriticalSection", [cs, 0, 0, 0, 0, 0], teb);
            win32::dispatch(&mut enter, &host);
        }
        assert_eq!(word(12), 2, "RecursionCount");
        assert_eq!(word(8), 1, "held, and a recursive enter does not retake it");

        let mut leave = call("LeaveCriticalSection", [cs, 0, 0, 0, 0, 0], teb);
        win32::dispatch(&mut leave, &host);
        assert_eq!(word(12), 1);
        let mut leave = call("LeaveCriticalSection", [cs, 0, 0, 0, 0, 0], teb);
        win32::dispatch(&mut leave, &host);
        assert_eq!(word(12), 0);
        assert_eq!(word(8), 0, "free again");
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
            mem[0x10200..0x10200 + 16].copy_from_slice(b"NoSuchFunctionW\0");
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
    fn the_ansi_version_check_reads_the_ansi_layout() {
        use crate::win32;
        const VER_MAJORVERSION: usize = 0x2;
        const VER_SERVICEPACKMAJOR: usize = 0x20;
        const VER_GREATER_EQUAL: u64 = 3;
        const VER_EQUAL: u64 = 1;
        let host = MockHost::default();
        let (teb, _) = process(&host);
        // The version the loader reports lives in the PEB.
        with_modules(&host);

        // OSVERSIONINFOEXA: szCSDVersion is 128 bytes rather than 128
        // characters, so the service pack sits at 148, not 276.
        let info = 0x7000usize;
        let put32 = |at: usize, value: u32| {
            let mut mem = host.mem.borrow_mut();
            mem[at..at + 4].copy_from_slice(&value.to_le_bytes());
        };
        let put16 = |at: usize, value: u16| {
            let mut mem = host.mem.borrow_mut();
            mem[at..at + 2].copy_from_slice(&value.to_le_bytes());
        };
        put32(info, 156);
        put32(info + 4, 10);
        put16(info + 148, 0);
        // What a reader of the wide layout would pick up instead.
        put16(info + 276, 5);

        let mask = (VER_GREATER_EQUAL << (3 * 1)) | (VER_EQUAL << (3 * 5));
        let kinds = VER_MAJORVERSION | VER_SERVICEPACKMAJOR;
        let mut asked = call(
            "VerifyVersionInfoA",
            [info, kinds, mask as usize, 0, 0, 0],
            teb,
        );
        win32::dispatch(&mut asked, &host);
        assert_eq!(asked.result, Some(1), "10.0 with no service pack matches");

        // And a version this is not still says no.
        put32(info + 4, 11);
        let mut newer = call(
            "VerifyVersionInfoA",
            [info, kinds, mask as usize, 0, 0, 0],
            teb,
        );
        win32::dispatch(&mut newer, &host);
        assert_eq!(newer.result, Some(0), "11 is not 10 or better");
    }

    #[test]
    fn the_reserved_device_names_open_the_devices_they_stand_for() {
        use crate::win32;
        let host = MockHost {
            opens_at: Ok(5),
            has_paths: true,
            ..MockHost::default()
        };
        let (teb, _) = process(&host);
        let open = |host: &MockHost, name: &str| {
            put_wide(host, 0x7000, &alloc::format!("{name}\0"));
            let mut open = call("CreateFileW", [0x7000, 0x8000_0000, 1, 0, 3, 0x80], teb);
            win32::dispatch(&mut open, host);
            host.opened.borrow().clone().expect("opened").1
        };
        // The name resolves wherever it is spelled, in any case, with an
        // extension or a colon after it, and through the device path.
        for name in [
            "nul",
            "NUL",
            "Z:\\app\\nul",
            "nul.txt",
            "NUL:",
            "\\\\.\\NUL",
        ] {
            assert_eq!(open(&host, name), "/dev/null", "{name}");
        }
        assert_eq!(open(&host, "con"), "/dev/console");
        // A name that only starts the same way is a file, and the prefix that
        // turns device names off leaves one alone.
        assert_eq!(open(&host, "nullify.txt"), "/app/nullify.txt");
        assert_eq!(open(&host, "\\\\?\\Z:\\app\\nul"), "/app/nul");
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
        use crate::{teb_peb, thunk, win32};
        let (ldr_va, k32_va, exe_va) = (0x6000usize, 0x8000usize, 0x40000usize);
        let sock_va = 0xA000usize;
        let image = thunk::system_header(k32_va as u64, 0);
        // The library the Winsock extensions belong to is synthesized like
        // any other, so a pointer handed out for one lands in it.
        let sock_lib = win32::LIBRARIES
            .iter()
            .position(|library| library.name == "MSWSOCK.dll")
            .expect("the extension library");
        let sock_image = thunk::system_header(sock_va as u64, sock_lib);
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
                teb_peb::LdrModule {
                    base: sock_va as u64,
                    entry: 0,
                    size: thunk::system_size(sock_lib) as u64,
                    path: "Z:\\windows\\system32\\mswsock.dll",
                    name: "mswsock.dll",
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
        mem[sock_va..sock_va + sock_image.len()].copy_from_slice(&sock_image);
        let peb = 0x2000;
        mem[peb + teb_peb::PEB_LDR..peb + teb_peb::PEB_LDR + 8]
            .copy_from_slice(&(ldr_va as u64).to_le_bytes());
        mem[peb + teb_peb::PEB_IMAGE_BASE..peb + teb_peb::PEB_IMAGE_BASE + 8]
            .copy_from_slice(&(exe_va as u64).to_le_bytes());
        // The version the PEB reports, as the loader fills it. A heap the
        // caller already laid out stays where it is.
        let mut pebbuf = mem[peb..peb + teb_peb::PEB_SIZE].to_vec();
        let heap = u64::from_le_bytes(
            pebbuf[teb_peb::PEB_PROCESS_HEAP..teb_peb::PEB_PROCESS_HEAP + 8]
                .try_into()
                .unwrap(),
        );
        let heap = if heap == 0 { 0x3000 } else { heap };
        teb_peb::fill_peb(&mut pebbuf, peb as u64, ldr_va as u64, 0x5000, heap);
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

        let mut rel = call("ReleaseSRWLockExclusive", [lock, 0, 0, 0, 0, 0], teb);
        win32::dispatch(&mut rel, &host);

        // Sleeping on a condition variable drops the lock while it waits and
        // has it again when it returns, whether it was woken or timed out.
        // Nothing wakes it here, so it reports the deadline.
        let mut sleep = call("SleepConditionVariableSRW", [cond, lock, 0, 0, 0, 0], teb);
        win32::dispatch(&mut sleep, &host);
        assert_eq!(sleep.result, Some(0), "timed out");
        assert_eq!(word(lock), 1, "the lock is held again on the way out");
    }

    /// The handle a create call answered with.
    fn created(host: &MockHost, teb: usize, name: &str, args: [usize; 6]) -> usize {
        use crate::win32;
        let mut made = call(name, args, teb);
        win32::dispatch(&mut made, host);
        made.result.expect("the object was created")
    }

    /// What waiting on `handle` for `ms` reports.
    fn waited(host: &MockHost, teb: usize, handle: usize, ms: usize) -> usize {
        use crate::win32;
        let mut wait = call("WaitForSingleObject", [handle, ms, 0, 0, 0, 0], teb);
        win32::dispatch(&mut wait, host);
        wait.result.expect("the wait answered")
    }

    const WAIT_OBJECT_0: usize = 0;
    const WAIT_TIMEOUT: usize = 0x102;

    #[test]
    fn an_auto_reset_event_hands_its_signal_to_one_waiter() {
        use crate::win32;
        let host = MockHost::default();
        let (teb, _) = process(&host);
        // Auto reset, signalled to begin with.
        let event = created(&host, teb, "CreateEventW", [0, 0, 1, 0, 0, 0]);
        assert_ne!(event, 0);
        assert_eq!(
            waited(&host, teb, event, 0),
            WAIT_OBJECT_0,
            "takes the signal"
        );
        assert_eq!(
            waited(&host, teb, event, 0),
            WAIT_TIMEOUT,
            "and the signal went with it"
        );
        let mut set = call("SetEvent", [event, 0, 0, 0, 0, 0], teb);
        win32::dispatch(&mut set, &host);
        assert_eq!(waited(&host, teb, event, 0), WAIT_OBJECT_0);
    }

    #[test]
    fn a_manual_reset_event_stays_signalled_until_it_is_reset() {
        use crate::win32;
        let host = MockHost::default();
        let (teb, _) = process(&host);
        let event = created(&host, teb, "CreateEventW", [0, 1, 0, 0, 0, 0]);
        assert_eq!(
            waited(&host, teb, event, 0),
            WAIT_TIMEOUT,
            "not signalled yet"
        );
        let mut set = call("SetEvent", [event, 0, 0, 0, 0, 0], teb);
        win32::dispatch(&mut set, &host);
        assert_eq!(waited(&host, teb, event, 0), WAIT_OBJECT_0);
        assert_eq!(
            waited(&host, teb, event, 0),
            WAIT_OBJECT_0,
            "a manual reset event releases everyone"
        );
        let mut reset = call("ResetEvent", [event, 0, 0, 0, 0, 0], teb);
        win32::dispatch(&mut reset, &host);
        assert_eq!(waited(&host, teb, event, 0), WAIT_TIMEOUT);
    }

    /// A host that can make sections, which is what a semaphore lives in.
    fn section_host() -> MockHost {
        let host = MockHost {
            has_paths: true,
            ..MockHost::default()
        };
        host.sections.set(true);
        host
    }

    #[test]
    fn a_wait_on_several_objects_looks_again_when_one_can_be_signalled_elsewhere() {
        use crate::win32;
        let host = section_host();
        let (teb, _) = process(&host);
        let event = created(&host, teb, "CreateEventW", [0, 0, 0, 0, 0, 0]);
        let semaphore = created(&host, teb, "CreateSemaphoreW", [0, 0, 1, 0, 0, 0]);
        let set = 0x7400usize;
        let park_for = |handles: &[usize]| {
            {
                let mut mem = host.mem.borrow_mut();
                for (i, handle) in handles.iter().enumerate() {
                    let at = set + i * 8;
                    mem[at..at + 8].copy_from_slice(&(*handle as u64).to_le_bytes());
                }
            }
            *host.parked.borrow_mut() = None;
            let mut wait = call(
                "WaitForMultipleObjects",
                [handles.len(), set, 0, 5_000, 0, 0],
                teb,
            );
            win32::dispatch(&mut wait, &host);
            (*host.parked.borrow()).expect("the wait parked")
        };
        // Nothing but this process can signal an event, so a wait on one
        // sleeps for as long as it was given.
        assert_eq!(
            park_for(&[event]),
            Some(5_000_000_000),
            "a private object is slept on"
        );
        // A semaphore lives in a section another process can release, and
        // that release does not touch this process's signal count - so the
        // wait has to come back and look rather than sleep through it.
        assert_eq!(
            park_for(&[event, semaphore]),
            Some(10_000_000),
            "a set holding a shared object is swept"
        );
    }

    #[test]
    fn a_swept_wait_still_waits_the_whole_time_it_was_given() {
        use crate::win32;
        let host = section_host();
        let (teb, _) = process(&host);
        let semaphore = created(&host, teb, "CreateSemaphoreW", [0, 0, 1, 0, 0, 0]);
        let set = 0x7480usize;
        {
            let mut mem = host.mem.borrow_mut();
            mem[set..set + 8].copy_from_slice(&(semaphore as u64).to_le_bytes());
        }
        let started = *host.now.borrow();
        let mut wait = call("WaitForMultipleObjects", [1, set, 0, 500, 0, 0], teb);
        win32::dispatch(&mut wait, &host);
        assert_eq!(wait.result, Some(WAIT_TIMEOUT));
        // The sweep cuts each park short on purpose; ending the wait at the
        // first one that came back empty would report a deadline that is
        // nowhere near - which is a wait of ten milliseconds where half a
        // second was asked for.
        assert!(
            *host.now.borrow() - started >= 500 * 1_000_000,
            "it waited the time it was given, not one sweep"
        );
    }

    #[test]
    fn a_semaphore_is_a_section_a_process_that_only_holds_the_descriptor_can_use() {
        use crate::win32;
        let host = section_host();
        let (teb, peb) = process(&host);
        let semaphore = created(&host, teb, "CreateSemaphoreW", [0, 1, 1, 0, 0, 0]);
        // The handle is a descriptor, which is the whole point: that is what
        // crosses to a child, where a block of this process's heap could not.
        assert_eq!(
            crate::handle::Handle(semaphore as u32).slot(),
            Some(SECTION_FD as usize),
            "the handle names the section's descriptor"
        );
        // A process that never created it has no view of the section. Losing
        // the views is what that looks like from here, and the next wait has
        // to map it again and find the same count.
        let clear = |at: usize| {
            let mut mem = host.mem.borrow_mut();
            mem[at..at + 8].copy_from_slice(&0u64.to_le_bytes());
        };
        clear(peb + win32::PEB_MAPPINGS);
        assert_eq!(waited(&host, teb, semaphore, 0), WAIT_OBJECT_0);
        clear(peb + win32::PEB_MAPPINGS);
        assert_eq!(
            waited(&host, teb, semaphore, 0),
            WAIT_TIMEOUT,
            "the count one process spent is the count the other sees"
        );
    }

    #[test]
    fn a_semaphore_released_past_its_maximum_is_refused() {
        use crate::win32;
        let host = section_host();
        let (teb, _) = process(&host);
        let semaphore = created(&host, teb, "CreateSemaphoreW", [0, 1, 1, 0, 0, 0]);
        let mut release = call("ReleaseSemaphore", [semaphore, 1, 0, 0, 0, 0], teb);
        win32::dispatch(&mut release, &host);
        assert_eq!(release.result, Some(0), "past the ceiling nothing is added");
        assert_eq!(
            last_error(&host, teb),
            298,
            "ERROR_TOO_MANY_POSTS is how a lock released twice is reported"
        );
        // The count stayed where it was, so the one unit it holds is still
        // there to be taken exactly once.
        assert_eq!(waited(&host, teb, semaphore, 0), WAIT_OBJECT_0);
        assert_eq!(waited(&host, teb, semaphore, 0), WAIT_TIMEOUT);
    }

    #[test]
    fn a_handle_duplicated_into_another_process_keeps_the_value_it_had() {
        use crate::win32;
        const PROCESS_TAG: usize = 0x2000_0000;
        let host = section_host();
        let (teb, _) = process(&host);
        let semaphore = created(&host, teb, "CreateSemaphoreW", [0, 1, 1, 0, 0, 0]);
        let out = 0x7300usize;
        // Into a child: the child inherited the descriptor, so the number the
        // parent sends it is the number it already holds.
        let mut across = Win32Trap::with_stack(
            crate::win32::Win32Call::named("DuplicateHandle").unwrap(),
            [
                crate::handle::Handle::CURRENT_PROCESS.0 as usize,
                semaphore,
                PROCESS_TAG | 4242,
                out,
                0,
                0,
            ],
            teb,
            &[2],
            0,
            &host,
        );
        win32::dispatch(&mut across, &host);
        assert_eq!(across.result, Some(1));
        let handed = {
            let mem = host.mem.borrow();
            u64::from_le_bytes(mem[out..out + 8].try_into().unwrap()) as usize
        };
        assert_eq!(
            handed, semaphore,
            "a handle crossing to another process is the one it already has"
        );
        // Into this process it is a copy, which is a number of its own.
        let mut here = Win32Trap::with_stack(
            crate::win32::Win32Call::named("DuplicateHandle").unwrap(),
            [
                crate::handle::Handle::CURRENT_PROCESS.0 as usize,
                semaphore,
                crate::handle::Handle::CURRENT_PROCESS.0 as usize,
                out,
                0,
                0,
            ],
            teb,
            &[2],
            0,
            &host,
        );
        win32::dispatch(&mut here, &host);
        let copy = {
            let mem = host.mem.borrow();
            u64::from_le_bytes(mem[out..out + 8].try_into().unwrap()) as usize
        };
        assert_ne!(copy, semaphore, "a copy of one's own is a new number");
    }

    #[test]
    fn a_handle_read_out_of_another_process_is_fetched_from_it() {
        use crate::win32;
        const PROCESS_TAG: usize = 0x2000_0000;
        let host = MockHost::default();
        let (teb, _) = process(&host);
        let out = 0x7900usize;
        let parent = PROCESS_TAG | 4242;
        let handle = crate::handle::Handle::from_slot(7).0 as usize;
        let mut across = Win32Trap::with_stack(
            crate::win32::Win32Call::named("DuplicateHandle").unwrap(),
            [
                parent,
                handle,
                crate::handle::Handle::CURRENT_PROCESS.0 as usize,
                out,
                0,
                0,
            ],
            teb,
            // DUPLICATE_CLOSE_SOURCE | DUPLICATE_SAME_ACCESS, which is what a
            // spawned child asks for when it takes the pipe its parent left.
            &[3],
            0,
            &host,
        );
        win32::dispatch(&mut across, &host);
        assert_eq!(across.result, Some(1));
        // The number belongs to the other process's table, so it is fetched
        // from there rather than copied here.
        assert_eq!(*host.stolen.borrow(), Some((4242, 7)));
        let handed = {
            let mem = host.mem.borrow();
            u64::from_le_bytes(mem[out..out + 8].try_into().unwrap()) as usize
        };
        assert_eq!(handed, crate::handle::Handle::from_slot(99).0 as usize);
        // And nothing of this process's was closed: the source named a
        // descriptor of the other one's.
        assert_eq!(*host.closed.borrow(), None);
    }

    #[test]
    fn a_section_is_mapped_shared_from_the_descriptor_that_names_it() {
        use crate::win32;
        let host = section_host();
        let (teb, _) = process(&host);
        let section = created(
            &host,
            teb,
            "CreateFileMappingW",
            [usize::MAX, 0, 0x04, 0, 0x1000, 0],
        );
        assert_eq!(
            *host.truncated.borrow(),
            Some((SECTION_FD, 0x1000)),
            "the section is as long as it was asked for"
        );
        const FILE_MAP_ALL_ACCESS: usize = 0x000F_001F;
        let mut view = call(
            "MapViewOfFile",
            [section, FILE_MAP_ALL_ACCESS, 0, 0, 0, 0],
            teb,
        );
        win32::dispatch(&mut view, &host);
        let at = view.result.expect("the view was placed");
        assert_ne!(at, 0);
        // Shared and from the section's own descriptor: a private mapping
        // would be a copy, and a copy is not what two processes share.
        let asked = host.mapped.borrow().expect("the host was asked to map");
        assert!(asked.shared, "a view of a section is shared");
        assert_eq!(
            asked.source,
            ax_abi_port::MapSource::File {
                fd: SECTION_FD,
                offset: 0
            }
        );
        assert_eq!(asked.len, 0x1000, "a length of zero means all of it");
        let mut unmap = call("UnmapViewOfFile", [at, 0, 0, 0, 0, 0], teb);
        win32::dispatch(&mut unmap, &host);
        assert_eq!(unmap.result, Some(1));
        let mut twice = call("UnmapViewOfFile", [at, 0, 0, 0, 0, 0], teb);
        win32::dispatch(&mut twice, &host);
        assert_eq!(twice.result, Some(0), "a view goes only once");
    }

    #[test]
    fn a_semaphore_hands_out_its_count_and_release_reports_the_previous_one() {
        use crate::win32;
        let host = section_host();
        let (teb, _) = process(&host);
        let previous_out = 0x7200usize;
        let semaphore = created(&host, teb, "CreateSemaphoreW", [0, 2, 2, 0, 0, 0]);
        assert_eq!(waited(&host, teb, semaphore, 0), WAIT_OBJECT_0);
        assert_eq!(waited(&host, teb, semaphore, 0), WAIT_OBJECT_0);
        assert_eq!(
            waited(&host, teb, semaphore, 0),
            WAIT_TIMEOUT,
            "the count is spent"
        );
        let mut release = call(
            "ReleaseSemaphore",
            [semaphore, 2, previous_out, 0, 0, 0],
            teb,
        );
        win32::dispatch(&mut release, &host);
        let previous = {
            let mem = host.mem.borrow();
            u32::from_le_bytes(mem[previous_out..previous_out + 4].try_into().unwrap())
        };
        assert_eq!(previous, 0, "it was spent when the count went back up");
        assert_eq!(waited(&host, teb, semaphore, 0), WAIT_OBJECT_0);
    }

    #[test]
    fn a_mutex_is_recursive_to_its_owner_and_freed_on_the_last_release() {
        use crate::win32;
        let host = MockHost::default();
        let (teb, _) = process(&host);
        // Created owned, so the creating thread already holds it once.
        let mutex = created(&host, teb, "CreateMutexW", [0, 1, 0, 0, 0, 0]);
        assert_eq!(
            waited(&host, teb, mutex, 0),
            WAIT_OBJECT_0,
            "the owner takes it again rather than waiting on itself"
        );
        let mut release = call("ReleaseMutex", [mutex, 0, 0, 0, 0, 0], teb);
        win32::dispatch(&mut release, &host);
        let mut release = call("ReleaseMutex", [mutex, 0, 0, 0, 0, 0], teb);
        win32::dispatch(&mut release, &host);
        // Free now, so it can be taken from scratch.
        assert_eq!(waited(&host, teb, mutex, 0), WAIT_OBJECT_0);
    }

    #[test]
    fn waiting_on_several_objects_answers_with_the_one_that_is_ready() {
        use crate::win32;
        let host = MockHost::default();
        let (teb, _) = process(&host);
        let quiet = created(&host, teb, "CreateEventW", [0, 1, 0, 0, 0, 0]);
        let ready = created(&host, teb, "CreateEventW", [0, 1, 1, 0, 0, 0]);
        let handles = 0x7300usize;
        {
            let mut mem = host.mem.borrow_mut();
            mem[handles..handles + 8].copy_from_slice(&(quiet as u64).to_le_bytes());
            mem[handles + 8..handles + 16].copy_from_slice(&(ready as u64).to_le_bytes());
        }
        let mut any = call("WaitForMultipleObjects", [2, handles, 0, 0, 0, 0], teb);
        win32::dispatch(&mut any, &host);
        assert_eq!(any.result, Some(1), "the second one is the ready one");
        // Waiting for all of them cannot finish while one is quiet.
        let mut all = call("WaitForMultipleObjects", [2, handles, 1, 0, 0, 0], teb);
        win32::dispatch(&mut all, &host);
        assert_eq!(all.result, Some(WAIT_TIMEOUT));
    }

    #[test]
    fn a_timer_is_unsignalled_until_the_moment_it_was_set_for() {
        use crate::win32;
        let host = MockHost::default();
        let (teb, _) = process(&host);
        let timer = created(&host, teb, "CreateWaitableTimerExW", [0, 0, 0, 0, 0, 0]);
        assert_ne!(timer, 0);
        // Unarmed, it is never signalled.
        assert_eq!(waited(&host, teb, timer, 0), WAIT_TIMEOUT);
        // A negative due time is relative, in hundreds of nanoseconds. The
        // mock has no clock, so anything in the past is already due and
        // anything in the future never arrives.
        let due = 0x7000usize;
        {
            let mut mem = host.mem.borrow_mut();
            mem[due..due + 8].copy_from_slice(&(-10_000_000i64).to_le_bytes());
        }
        let mut set = call("SetWaitableTimerEx", [timer, due, 0, 0, 0, 0], teb);
        win32::dispatch(&mut set, &host);
        assert_eq!(set.result, Some(1));
        assert_eq!(
            waited(&host, teb, timer, 0),
            WAIT_TIMEOUT,
            "a second away is not due yet"
        );
        // Move the clock past the moment it was set for.
        *host.now.borrow_mut() += 1_000_000_000;
        assert_eq!(waited(&host, teb, timer, 0), WAIT_OBJECT_0, "due now");
        assert_eq!(
            waited(&host, teb, timer, 0),
            WAIT_OBJECT_0,
            "and it stays signalled until it is set again"
        );
        // Cancelling leaves it unarmed and unsignalled.
        let mut cancel = call("CancelWaitableTimer", [timer, 0, 0, 0, 0, 0], teb);
        win32::dispatch(&mut cancel, &host);
        assert_eq!(waited(&host, teb, timer, 0), WAIT_TIMEOUT);
    }

    /// The handle a socket call answered with, and the descriptor behind it.
    fn opened(host: &MockHost, teb: usize, family: usize, kind: usize) -> usize {
        use crate::win32;
        let mut made = call("socket", [family, kind, 0, 0, 0, 0], teb);
        win32::dispatch(&mut made, host);
        made.result.expect("socket answered")
    }

    /// A completion port, and a socket that reports to it under `key`.
    fn ported(host: &MockHost, teb: usize, key: usize) -> (usize, usize) {
        use crate::win32;
        const INVALID_HANDLE: usize = usize::MAX;
        let mut made = call(
            "CreateIoCompletionPort",
            [INVALID_HANDLE, 0, 0, 0, 0, 0],
            teb,
        );
        win32::dispatch(&mut made, host);
        let port = made.result.expect("a port");
        assert_ne!(port, 0);
        let socket = opened(host, teb, 2, 1);
        let mut joined = call("CreateIoCompletionPort", [socket, port, key, 0, 0, 0], teb);
        win32::dispatch(&mut joined, host);
        assert_eq!(joined.result, Some(port), "the socket joined the port");
        (port, socket)
    }

    /// Lay a WSABUF naming `len` bytes at `buffer` down at `at`.
    fn put_wsabuf(host: &MockHost, at: usize, buffer: usize, len: usize) {
        let mut mem = host.mem.borrow_mut();
        mem[at..at + 4].copy_from_slice(&(len as u32).to_le_bytes());
        mem[at + 8..at + 16].copy_from_slice(&(buffer as u64).to_le_bytes());
    }

    #[test]
    fn an_overlapped_read_that_must_wait_completes_through_its_port() {
        use crate::win32;
        const SOCKET_ERROR: usize = -1i32 as u32 as usize;
        const ERROR_IO_PENDING: u32 = 997;
        const WAIT_TIMEOUT: u32 = 258;
        let host = MockHost::default();
        let (teb, _) = process(&host);
        let (port, socket) = ported(&host, teb, 0x1234);
        let (buffers, buffer, overlapped) = (0x7000usize, 0x7100usize, 0x7200usize);
        put_wsabuf(&host, buffers, buffer, 8);

        // Nothing has arrived, so the read is under way rather than done.
        let mut started = Win32Trap::with_stack(
            crate::win32::Win32Call::named("WSARecv").unwrap(),
            [socket, buffers, 1, 0, 0x7300, overlapped],
            teb,
            &[],
            0,
            &host,
        );
        win32::dispatch(&mut started, &host);
        assert_eq!(started.result, Some(SOCKET_ERROR));
        assert_eq!(last_error(&host, teb), ERROR_IO_PENDING);
        assert_eq!(
            read_u64(&host, overlapped),
            0x103,
            "STATUS_PENDING, until it is not"
        );

        // A wait with nothing to report gives up at its deadline.
        let (bytes, key, out) = (0x7400usize, 0x7408usize, 0x7410usize);
        let mut empty = Win32Trap::with_stack(
            crate::win32::Win32Call::named("GetQueuedCompletionStatus").unwrap(),
            [port, bytes, key, out, 10, 0],
            teb,
            &[],
            0,
            &host,
        );
        win32::dispatch(&mut empty, &host);
        assert_eq!(empty.result, Some(0));
        assert_eq!(last_error(&host, teb), WAIT_TIMEOUT);
        assert_eq!(
            read_u64(&host, out),
            0,
            "a wait that hands nothing back leaves no operation behind"
        );

        // What arrives is what the read was waiting for.
        host.sockets.borrow_mut()[0]
            .queued
            .extend_from_slice(b"hello");
        let mut got = Win32Trap::with_stack(
            crate::win32::Win32Call::named("GetQueuedCompletionStatus").unwrap(),
            [port, bytes, key, out, 1000, 0],
            teb,
            &[],
            0,
            &host,
        );
        win32::dispatch(&mut got, &host);
        assert_eq!(got.result, Some(1), "a completion");
        assert_eq!(read_u32(&host, bytes), 5);
        assert_eq!(read_u64(&host, key), 0x1234, "the key it registered under");
        assert_eq!(read_u64(&host, out), overlapped as u64);
        assert_eq!(read_u64(&host, overlapped), 0, "and it succeeded");
        assert_eq!(read_u64(&host, overlapped + 8), 5, "with the count");
        {
            let mem = host.mem.borrow();
            assert_eq!(&mem[buffer..buffer + 5], b"hello");
        }
    }

    #[test]
    fn the_version_is_reported_in_both_shapes_of_the_block() {
        use crate::win32;
        let host = MockHost::default();
        let (teb, _) = process(&host);
        with_modules(&host);
        let at = 0x7000usize;
        let read32 = |host: &MockHost, off: usize| read_u32(host, at + off);

        // The plain OSVERSIONINFOW: the caller says which shape by its size.
        put_bytes(&host, at, &276u32.to_le_bytes());
        let mut plain = call("GetVersionExW", [at, 0, 0, 0, 0, 0], teb);
        win32::dispatch(&mut plain, &host);
        assert_eq!(plain.result, Some(1));
        assert_eq!((read32(&host, 4), read32(&host, 8)), (10, 0), "10.0");
        assert_eq!(read32(&host, 12), 19041, "the build");
        assert_eq!(read32(&host, 16), 2, "VER_PLATFORM_WIN32_NT");
        assert_eq!(read32(&host, 20), 0, "no service pack text");

        // The extended one carries the service pack, suite and product too.
        put_bytes(&host, at, &284u32.to_le_bytes());
        let mut extended = call("GetVersionExW", [at, 0, 0, 0, 0, 0], teb);
        win32::dispatch(&mut extended, &host);
        assert_eq!(extended.result, Some(1));
        {
            let mem = host.mem.borrow();
            let sp = u16::from_le_bytes(mem[at + 276..at + 278].try_into().unwrap());
            let suite = u16::from_le_bytes(mem[at + 280..at + 282].try_into().unwrap());
            assert_eq!(sp, 0);
            assert_eq!(suite, 0x100, "VER_SUITE_SINGLEUSERTS");
            assert_eq!(mem[at + 282], 1, "VER_NT_WORKSTATION");
        }

        // A size that is neither shape is refused.
        put_bytes(&host, at, &8u32.to_le_bytes());
        let mut odd = call("GetVersionExW", [at, 0, 0, 0, 0, 0], teb);
        win32::dispatch(&mut odd, &host);
        assert_eq!(odd.result, Some(0));

        // The old form packs the same numbers into one word.
        let mut packed = call("GetVersion", [0; 6], teb);
        win32::dispatch(&mut packed, &host);
        assert_eq!(packed.result, Some(10 | (0 << 8) | (19041 << 16)));
    }

    #[test]
    fn the_room_a_filesystem_has_is_reported_in_bytes() {
        use crate::win32;
        let host = MockHost {
            has_paths: true,
            space: Some(ax_abi_port::Space {
                total: 4096 * 1000,
                free: 4096 * 400,
                available: 4096 * 300,
            }),
            ..MockHost::default()
        };
        let (teb, _) = process(&host);
        put_wide(&host, 0x7000, "Z:\\app\0");
        let (caller, total, free) = (0x7100usize, 0x7108usize, 0x7110usize);
        let mut asked = call(
            "GetDiskFreeSpaceExW",
            [0x7000, caller, total, free, 0, 0],
            teb,
        );
        win32::dispatch(&mut asked, &host);
        assert_eq!(asked.result, Some(1));
        assert_eq!(read_u64(&host, caller), 4096 * 300, "what is left to use");
        assert_eq!(read_u64(&host, total), 4096 * 1000);
        assert_eq!(read_u64(&host, free), 4096 * 400);

        // A filesystem that cannot say fails rather than reporting nothing.
        let host = MockHost {
            has_paths: true,
            ..MockHost::default()
        };
        let (teb, _) = process(&host);
        put_wide(&host, 0x7000, "Z:\\app\0");
        let mut refused = call(
            "GetDiskFreeSpaceExW",
            [0x7000, caller, total, free, 0, 0],
            teb,
        );
        win32::dispatch(&mut refused, &host);
        assert_eq!(refused.result, Some(0));
    }

    #[test]
    fn a_file_opened_to_be_deleted_on_close_is_unlinked_when_it_is() {
        use crate::win32;
        const FILE_FLAG_DELETE_ON_CLOSE: usize = 0x0400_0000;
        let host = MockHost {
            opens_at: Ok(5),
            has_paths: true,
            ..MockHost::default()
        };
        let (teb, _) = process(&host);
        put_wide(&host, 0x7000, "Z:\\tmp\\scratch\0");

        // CREATE_ALWAYS with the flag that says the name goes with the handle.
        let mut opened = call(
            "CreateFileW",
            [0x7000, 0xC000_0000, 0, 0, 2, FILE_FLAG_DELETE_ON_CLOSE],
            teb,
        );
        win32::dispatch(&mut opened, &host);
        let handle = opened.result.expect("a file");
        assert!(host.unlinked.borrow().is_none(), "not while it is open");

        let mut closed = call("CloseHandle", [handle, 0, 0, 0, 0, 0], teb);
        win32::dispatch(&mut closed, &host);
        assert_eq!(closed.result, Some(1));
        assert_eq!(
            host.unlinked.borrow().as_deref(),
            Some("/tmp/scratch"),
            "closing it takes the name with it"
        );

        // A file opened without the flag is left where it is.
        let mut plain = call("CreateFileW", [0x7000, 0xC000_0000, 0, 0, 2, 0], teb);
        win32::dispatch(&mut plain, &host);
        let plain = plain.result.expect("a file");
        *host.unlinked.borrow_mut() = None;
        let mut closed = call("CloseHandle", [plain, 0, 0, 0, 0, 0], teb);
        win32::dispatch(&mut closed, &host);
        assert!(host.unlinked.borrow().is_none());
    }

    #[test]
    fn a_bstr_carries_its_length_in_front_of_it() {
        use crate::win32;
        let host = MockHost::default();
        let (teb, _) = process(&host);
        let from = 0x7000usize;
        put_wide(&host, from, "hi");

        let mut made = call("SysAllocStringLen", [from, 2, 0, 0, 0, 0], teb);
        win32::dispatch(&mut made, &host);
        let bstr = made.result.expect("a string");
        assert_ne!(bstr, 0);
        {
            let mem = host.mem.borrow();
            let bytes = u32::from_le_bytes(mem[bstr - 4..bstr].try_into().unwrap());
            assert_eq!(bytes, 4, "two characters, in bytes");
            assert_eq!(&mem[bstr..bstr + 4], b"h\0i\0");
            assert_eq!(&mem[bstr + 4..bstr + 6], b"\0\0", "and a terminator");
        }
        let mut len = call("SysStringLen", [bstr, 0, 0, 0, 0, 0], teb);
        win32::dispatch(&mut len, &host);
        assert_eq!(len.result, Some(2));

        // A string of nothing is as long as it was asked for, and reads as
        // zeroes rather than as whatever the heap held.
        let mut empty = call("SysAllocStringLen", [0, 3, 0, 0, 0, 0], teb);
        win32::dispatch(&mut empty, &host);
        let empty = empty.result.expect("a string");
        {
            let mem = host.mem.borrow();
            assert_eq!(&mem[empty..empty + 6], &[0u8; 6]);
        }
        let mut len = call("SysStringLen", [empty, 0, 0, 0, 0, 0], teb);
        win32::dispatch(&mut len, &host);
        assert_eq!(len.result, Some(3));

        // Freeing one gives its block back, and a null string is nothing to
        // free rather than a fault.
        let mut freed = call("SysFreeString", [bstr, 0, 0, 0, 0, 0], teb);
        win32::dispatch(&mut freed, &host);
        assert_eq!(freed.result, Some(0));
        let mut nothing = call("SysFreeString", [0, 0, 0, 0, 0, 0], teb);
        win32::dispatch(&mut nothing, &host);
        assert_eq!(nothing.result, Some(0));
        let mut len = call("SysStringLen", [0, 0, 0, 0, 0, 0], teb);
        win32::dispatch(&mut len, &host);
        assert_eq!(len.result, Some(0), "a null string is empty");
    }

    #[test]
    fn a_named_pipe_is_a_socket_bound_to_the_name_the_path_carries() {
        use crate::win32;
        const ERROR_PIPE_CONNECTED: u32 = 535;
        const INVALID_HANDLE: usize = usize::MAX;
        let host = MockHost::default();
        let (teb, _) = process(&host);
        let path = 0x7000usize;
        put_wide(&host, path, "\\\\.\\pipe\\pyc-42-0\0");

        // CreateNamedPipeW(name, openMode, pipeMode, instances, out, in,
        // timeout, security).
        let mut made = Win32Trap::with_stack(
            crate::win32::Win32Call::named("CreateNamedPipeW").unwrap(),
            [path, 3, 6, 1, 0x1000, 0x1000],
            teb,
            &[0, 0],
            0,
            &host,
        );
        win32::dispatch(&mut made, &host);
        let server = made.result.expect("a pipe");
        assert_ne!(server, INVALID_HANDLE, "the pipe was made");

        // The client end is opened by the same name, which is not a path.
        let mut opened = call("CreateFileW", [path, 0xC000_0000, 0, 0, 3, 0], teb);
        win32::dispatch(&mut opened, &host);
        let client = opened.result.expect("a client end");
        assert_ne!(client, INVALID_HANDLE);
        assert!(
            host.opened.borrow().is_none(),
            "a pipe name is never looked up in the file system"
        );

        // Both ends are on the name the path carried, in the machine's own
        // namespace.
        let name = ax_abi_port::Address::local(b"pyc-42-0").unwrap();
        {
            let sockets = host.sockets.borrow();
            assert_eq!(sockets[0].bound, Some(name), "the pipe took its name");
            assert!(sockets[0].listening, "and waits for a client");
            assert_eq!(sockets[1].peer, Some(name), "the client asked for it");
            assert_eq!(
                sockets[0].kind,
                Some(ax_abi_port::SocketKind::SeqPacket),
                "a message-mode pipe keeps message boundaries"
            );
        }

        // Connecting reports the client that was already there the way
        // Windows does: as ERROR_PIPE_CONNECTED.
        let mut connected = call("ConnectNamedPipe", [server, 0, 0, 0, 0, 0], teb);
        win32::dispatch(&mut connected, &host);
        assert_eq!(connected.result, Some(0));
        assert_eq!(last_error(&host, teb), ERROR_PIPE_CONNECTED);

        // Message mode is the mode it is already in; a byte stream is not.
        let mode = 0x7200usize;
        put_bytes(&host, mode, &2u32.to_le_bytes());
        let mut message = call("SetNamedPipeHandleState", [client, mode, 0, 0, 0, 0], teb);
        win32::dispatch(&mut message, &host);
        assert_eq!(message.result, Some(1));
        put_bytes(&host, mode, &0u32.to_le_bytes());
        let mut stream = call("SetNamedPipeHandleState", [client, mode, 0, 0, 0, 0], teb);
        win32::dispatch(&mut stream, &host);
        assert_eq!(stream.result, Some(0), "a byte-mode pipe is not on offer");
    }

    #[test]
    fn what_is_waiting_in_a_pipe_is_reported_without_taking_it() {
        use crate::win32;
        let host = MockHost::default();
        let (teb, _) = process(&host);
        let path = 0x7000usize;
        put_wide(&host, path, "\\\\.\\pipe\\peek\0");
        let mut opened = call("CreateFileW", [path, 0xC000_0000, 0, 0, 3, 0], teb);
        win32::dispatch(&mut opened, &host);
        let client = opened.result.expect("a client end");
        host.sockets.borrow_mut()[0]
            .queued
            .extend_from_slice(b"a message");

        let (buffer, read, available, left) = (0x7100usize, 0x7200usize, 0x7208, 0x7210);
        let mut peeked = Win32Trap::with_stack(
            crate::win32::Win32Call::named("PeekNamedPipe").unwrap(),
            [client, buffer, 16, read, available, left],
            teb,
            &[],
            0,
            &host,
        );
        win32::dispatch(&mut peeked, &host);
        assert_eq!(peeked.result, Some(1));
        assert_eq!(read_u32(&host, read), 9);
        assert_eq!(read_u32(&host, available), 9);
        {
            let mem = host.mem.borrow();
            assert_eq!(&mem[buffer..buffer + 9], b"a message");
        }
        // Peeking leaves it where it was.
        assert_eq!(host.sockets.borrow()[0].queued.len(), 9);
    }

    #[test]
    fn a_closed_socket_no_longer_reports_to_its_port() {
        use crate::win32;
        const ERROR_IO_PENDING: u32 = 997;
        let host = MockHost::default();
        let (teb, _) = process(&host);
        let (_port, socket) = ported(&host, teb, 5);
        let (buffers, overlapped) = (0x7000usize, 0x7200usize);
        put_wsabuf(&host, buffers, 0x7100, 8);

        let mut closed = call("closesocket", [socket, 0, 0, 0, 0, 0], teb);
        win32::dispatch(&mut closed, &host);
        assert_eq!(closed.result, Some(0));

        // The number is the host's again, so a read on it belongs to no
        // port: it is answered here and now, never queued to the port the
        // socket that had the number used to report to.
        let mut started = Win32Trap::with_stack(
            crate::win32::Win32Call::named("WSARecv").unwrap(),
            [socket, buffers, 1, 0, 0x7300, overlapped],
            teb,
            &[],
            0,
            &host,
        );
        win32::dispatch(&mut started, &host);
        assert_ne!(
            last_error(&host, teb),
            ERROR_IO_PENDING,
            "nothing is outstanding on a port the socket left"
        );
        let (bytes, key, out) = (0x7400usize, 0x7408usize, 0x7410usize);
        let mut got = Win32Trap::with_stack(
            crate::win32::Win32Call::named("GetQueuedCompletionStatus").unwrap(),
            [_port, bytes, key, out, 0, 0],
            teb,
            &[],
            0,
            &host,
        );
        win32::dispatch(&mut got, &host);
        assert_eq!(got.result, Some(0), "and the port has nothing to report");
    }

    #[test]
    fn a_posted_completion_comes_back_out_of_the_port() {
        use crate::win32;
        let host = MockHost::default();
        let (teb, _) = process(&host);
        let (port, _) = ported(&host, teb, 7);
        let mut posted = Win32Trap::with_stack(
            crate::win32::Win32Call::named("PostQueuedCompletionStatus").unwrap(),
            [port, 42, 99, 0x9000, 0, 0],
            teb,
            &[],
            0,
            &host,
        );
        win32::dispatch(&mut posted, &host);
        assert_eq!(posted.result, Some(1));

        let (bytes, key, out) = (0x7400usize, 0x7408usize, 0x7410usize);
        let mut got = Win32Trap::with_stack(
            crate::win32::Win32Call::named("GetQueuedCompletionStatus").unwrap(),
            [port, bytes, key, out, 0, 0],
            teb,
            &[],
            0,
            &host,
        );
        win32::dispatch(&mut got, &host);
        assert_eq!(got.result, Some(1));
        assert_eq!(read_u32(&host, bytes), 42);
        assert_eq!(read_u64(&host, key), 99);
        assert_eq!(
            read_u64(&host, out),
            0x9000,
            "the overlapped it was posted with"
        );
    }

    #[test]
    fn a_cancelled_operation_is_reported_as_cancelled() {
        use crate::win32;
        const ERROR_OPERATION_ABORTED: u32 = 995;
        let host = MockHost::default();
        let (teb, _) = process(&host);
        let (port, socket) = ported(&host, teb, 0);
        let (buffers, overlapped) = (0x7000usize, 0x7200usize);
        put_wsabuf(&host, buffers, 0x7100, 8);
        let mut started = Win32Trap::with_stack(
            crate::win32::Win32Call::named("WSARecv").unwrap(),
            [socket, buffers, 1, 0, 0x7300, overlapped],
            teb,
            &[],
            0,
            &host,
        );
        win32::dispatch(&mut started, &host);

        let mut cancelled = call("CancelIoEx", [socket, overlapped, 0, 0, 0, 0], teb);
        win32::dispatch(&mut cancelled, &host);
        assert_eq!(cancelled.result, Some(1));

        let (bytes, key, out) = (0x7400usize, 0x7408usize, 0x7410usize);
        let mut got = Win32Trap::with_stack(
            crate::win32::Win32Call::named("GetQueuedCompletionStatus").unwrap(),
            [port, bytes, key, out, 0, 0],
            teb,
            &[],
            0,
            &host,
        );
        win32::dispatch(&mut got, &host);
        assert_eq!(got.result, Some(0), "a cancelled operation is a failure");
        assert_eq!(last_error(&host, teb), ERROR_OPERATION_ABORTED);
        assert_eq!(
            read_u64(&host, out),
            overlapped as u64,
            "and it says which one"
        );
    }

    #[test]
    fn the_winsock_extensions_are_handed_out_as_entry_points() {
        use crate::win32::{self, LIBRARIES};
        // SIO_GET_EXTENSION_FUNCTION_POINTER is _WSAIORW(IOC_WS2, 6):
        // IOC_INOUT, then the Winsock 2 vendor space, then the number six.
        const GET_EXTENSION: usize = 0xC000_0000 | 0x0800_0000 | 6;
        let host = MockHost::default();
        let (teb, _) = process(&host);
        with_modules(&host);
        let socket = opened(&host, teb, 2, 1);
        // WSAID_CONNECTEX.
        let guid: [u8; 16] = [
            0xb9, 0x07, 0xa2, 0x25, 0xf3, 0xdd, 0x60, 0x46, 0x8e, 0xe9, 0x76, 0xe5, 0x8c, 0x74,
            0x06, 0x3e,
        ];
        let (input, output, returned) = (0x7000usize, 0x7100usize, 0x7108usize);
        put_bytes(&host, input, &guid);
        let mut asked = Win32Trap::with_stack(
            crate::win32::Win32Call::named("WSAIoctl").unwrap(),
            [socket, GET_EXTENSION, input, 16, output, 8],
            teb,
            &[returned],
            0,
            &host,
        );
        win32::dispatch(&mut asked, &host);
        assert_eq!(asked.result, Some(0), "the pointer was handed out");
        assert_eq!(read_u32(&host, returned), 8);
        let at = read_u64(&host, output) as usize;
        assert_ne!(at, 0, "and it points somewhere");

        // Somewhere being mswsock: the address is a stub of that module.
        let mut named = call("GetModuleHandleW", [0x7200, 0, 0, 0, 0, 0], teb);
        put_wide(&host, 0x7200, "mswsock.dll\0");
        win32::dispatch(&mut named, &host);
        let base = named.result.expect("mswsock is a module");
        let size = crate::thunk::system_size(
            LIBRARIES
                .iter()
                .position(|library| library.name == "MSWSOCK.dll")
                .unwrap(),
        );
        assert!(at > base && at < base + size, "{at:#x} is in mswsock");
    }

    fn read_u32(host: &MockHost, at: usize) -> u32 {
        let mem = host.mem.borrow();
        u32::from_le_bytes(mem[at..at + 4].try_into().unwrap())
    }

    fn read_u64(host: &MockHost, at: usize) -> u64 {
        let mem = host.mem.borrow();
        u64::from_le_bytes(mem[at..at + 8].try_into().unwrap())
    }

    fn last_error(host: &MockHost, teb: usize) -> u32 {
        read_u32(host, teb + crate::teb_peb::TEB_LAST_ERROR)
    }

    /// Lay a Winsock SOCKADDR_IN down at `at`.
    fn put_sockaddr_in(host: &MockHost, at: usize, ip: [u8; 4], port: u16) {
        let mut block = [0u8; 16];
        block[0..2].copy_from_slice(&2u16.to_le_bytes());
        block[2..4].copy_from_slice(&port.to_be_bytes());
        block[4..8].copy_from_slice(&ip);
        put_bytes(host, at, &block);
    }

    #[test]
    fn a_socket_is_opened_for_the_families_and_kinds_winsock_names() {
        use crate::win32;
        let host = MockHost::default();
        let (teb, _) = process(&host);
        // AF_INET/SOCK_STREAM, AF_INET6/SOCK_DGRAM.
        assert_ne!(opened(&host, teb, 2, 1), usize::MAX);
        assert_ne!(opened(&host, teb, 23, 2), usize::MAX);
        assert_eq!(host.sockets.borrow().len(), 2);
        assert!(host.sockets.borrow()[1].v6, "AF_INET6 is 23 on Windows");

        // A family this layer does not carry, and a kind it does not carry.
        let mut family = call("socket", [17, 1, 0, 0, 0, 0], teb);
        win32::dispatch(&mut family, &host);
        assert_eq!(family.result, Some(usize::MAX), "INVALID_SOCKET");
        let mut kind = call("socket", [2, 3, 0, 0, 0, 0], teb);
        win32::dispatch(&mut kind, &host);
        assert_eq!(kind.result, Some(usize::MAX));
    }

    #[test]
    fn binding_and_connecting_read_the_address_winsock_lays_down() {
        use crate::win32;
        let host = MockHost::default();
        let (teb, _) = process(&host);
        let socket = opened(&host, teb, 2, 1);
        let at = 0x7000usize;
        put_sockaddr_in(&host, at, [192, 0, 2, 10], 8080);

        let mut bound = call("bind", [socket, at, 16, 0, 0, 0], teb);
        win32::dispatch(&mut bound, &host);
        assert_eq!(bound.result, Some(0));
        assert_eq!(
            host.sockets.borrow()[0].bound,
            Some(ax_abi_port::Address::V4([192, 0, 2, 10], 8080)),
            "the port comes off the wire in network order"
        );

        put_sockaddr_in(&host, at, [198, 51, 100, 20], 53);
        let mut connected = call("connect", [socket, at, 16, 0, 0, 0], teb);
        win32::dispatch(&mut connected, &host);
        assert_eq!(connected.result, Some(0));
        assert_eq!(
            host.sockets.borrow()[0].peer,
            Some(ax_abi_port::Address::V4([198, 51, 100, 20], 53))
        );

        // An address shorter than the structure it claims to be is refused.
        let mut short = call("bind", [socket, at, 8, 0, 0, 0], teb);
        win32::dispatch(&mut short, &host);
        assert_eq!(short.result, Some(-1i32 as u32 as usize), "SOCKET_ERROR");
    }

    #[test]
    fn an_accepted_connection_reports_where_it_came_from() {
        use crate::win32;
        let host = MockHost::default();
        let (teb, _) = process(&host);
        let socket = opened(&host, teb, 2, 1);

        // Accepting before listening is refused, as the host reports it.
        let mut early = call("accept", [socket, 0, 0, 0, 0, 0], teb);
        win32::dispatch(&mut early, &host);
        assert_eq!(early.result, Some(usize::MAX));

        let mut listening = call("listen", [socket, 8, 0, 0, 0, 0], teb);
        win32::dispatch(&mut listening, &host);
        assert_eq!(listening.result, Some(0));
        assert!(host.sockets.borrow()[0].listening);

        let (at, len_at) = (0x7000usize, 0x7100usize);
        put_bytes(&host, len_at, &16u32.to_le_bytes());
        let mut taken = call("accept", [socket, at, len_at, 0, 0, 0], teb);
        win32::dispatch(&mut taken, &host);
        assert_ne!(taken.result, Some(usize::MAX));
        let mem = host.mem.borrow();
        assert_eq!(&mem[at..at + 2], &2u16.to_le_bytes(), "AF_INET");
        assert_eq!(&mem[at + 2..at + 4], &4242u16.to_be_bytes());
        assert_eq!(&mem[at + 4..at + 8], &[198, 51, 100, 7]);
        assert_eq!(
            u32::from_le_bytes(mem[len_at..len_at + 4].try_into().unwrap()),
            16,
            "and the length it took"
        );
    }

    #[test]
    fn sending_and_receiving_carry_the_address_when_the_call_has_one() {
        use crate::win32;
        let host = MockHost::default();
        let (teb, _) = process(&host);
        let socket = opened(&host, teb, 2, 2);
        let (buf, to) = (0x7000usize, 0x7100usize);
        put_bytes(&host, buf, b"hello");
        put_sockaddr_in(&host, to, [203, 0, 113, 9], 1234);

        let mut sent = call("send", [socket, buf, 5, 0, 0, 0], teb);
        win32::dispatch(&mut sent, &host);
        assert_eq!(sent.result, Some(5));
        assert_eq!(host.sockets.borrow()[0].sent[0], (buf, 5, None));

        let mut sent_to = call("sendto", [socket, buf, 5, 0, to, 16], teb);
        win32::dispatch(&mut sent_to, &host);
        assert_eq!(sent_to.result, Some(5));
        assert_eq!(
            host.sockets.borrow()[0].sent[1].2,
            Some(ax_abi_port::Address::V4([203, 0, 113, 9], 1234))
        );

        host.socket(socket_fd(socket)).unwrap().queued = b"world".to_vec();
        let (into, from, from_len) = (0x7200usize, 0x7300usize, 0x7400usize);
        put_bytes(&host, from_len, &16u32.to_le_bytes());
        // MSG_PEEK leaves what it read where it was.
        let mut peeked = call("recv", [socket, into, 16, 2, 0, 0], teb);
        win32::dispatch(&mut peeked, &host);
        assert_eq!(peeked.result, Some(5));
        assert_eq!(host.sockets.borrow()[0].queued, b"world".to_vec());
        assert_eq!(&host.mem.borrow()[into..into + 5], b"world");

        let mut from_recv = call("recvfrom", [socket, into, 16, 0, from, from_len], teb);
        win32::dispatch(&mut from_recv, &host);
        assert_eq!(from_recv.result, Some(5));
        assert!(
            host.sockets.borrow()[0].queued.is_empty(),
            "and a plain read takes it"
        );
        let mem = host.mem.borrow();
        assert_eq!(&mem[from + 4..from + 8], &[203, 0, 113, 9]);
    }

    #[test]
    fn each_direction_of_a_shutdown_is_carried_through() {
        use crate::win32;
        let host = MockHost::default();
        let (teb, _) = process(&host);
        let socket = opened(&host, teb, 2, 1);
        for (how, expected) in [
            (0usize, ax_abi_port::Shutdown::Read),
            (1, ax_abi_port::Shutdown::Write),
            (2, ax_abi_port::Shutdown::Both),
        ] {
            let mut done = call("shutdown", [socket, how, 0, 0, 0, 0], teb);
            win32::dispatch(&mut done, &host);
            assert_eq!(done.result, Some(0));
            assert_eq!(host.sockets.borrow()[0].shutdown, Some(expected));
        }
        let mut wrong = call("shutdown", [socket, 9, 0, 0, 0, 0], teb);
        win32::dispatch(&mut wrong, &host);
        assert_eq!(wrong.result, Some(-1i32 as u32 as usize));
    }

    #[test]
    fn the_two_socket_ioctls_reach_the_host() {
        use crate::win32;
        let host = MockHost::default();
        let (teb, _) = process(&host);
        let socket = opened(&host, teb, 2, 1);
        let arg = 0x7000usize;

        // FIONBIO with a non-zero argument stops calls from waiting.
        put_bytes(&host, arg, &1u32.to_le_bytes());
        let mut nonblocking = call("ioctlsocket", [socket, 0x8004_667E, arg, 0, 0, 0], teb);
        win32::dispatch(&mut nonblocking, &host);
        assert_eq!(nonblocking.result, Some(0));
        assert!(!host.sockets.borrow()[0].blocking);

        put_bytes(&host, arg, &0u32.to_le_bytes());
        let mut blocking = call("ioctlsocket", [socket, 0x8004_667E, arg, 0, 0, 0], teb);
        win32::dispatch(&mut blocking, &host);
        assert!(host.sockets.borrow()[0].blocking);

        // FIONREAD reports what is waiting.
        host.socket(socket_fd(socket)).unwrap().queued = b"abcd".to_vec();
        let mut ready = call("ioctlsocket", [socket, 0x4004_667F, arg, 0, 0, 0], teb);
        win32::dispatch(&mut ready, &host);
        assert_eq!(ready.result, Some(0));
        let waiting = {
            let mem = host.mem.borrow();
            u32::from_le_bytes(mem[arg..arg + 4].try_into().unwrap())
        };
        assert_eq!(waiting, 4);

        let mut unknown = call("ioctlsocket", [socket, 0x1234, arg, 0, 0, 0], teb);
        win32::dispatch(&mut unknown, &host);
        assert_eq!(unknown.result, Some(-1i32 as u32 as usize));
    }

    #[test]
    fn the_options_winsock_numbers_reach_the_ones_the_host_names() {
        use ax_abi_port::SocketOption as O;

        use crate::win32;
        let host = MockHost::default();
        let (teb, _) = process(&host);
        let stream = opened(&host, teb, 2, 1);
        let (value, len) = (0x7000usize, 0x7100usize);
        put_bytes(&host, value, &1u32.to_le_bytes());

        // (level, name) pairs Winsock uses, and the settings they mean.
        for (level, name, option) in [
            (0xFFFFusize, 0x0004usize, O::ReuseAddress),
            (0xFFFF, 0x0008, O::KeepAlive),
            (0xFFFF, 0x0020, O::Broadcast),
            (6, 0x0001, O::NoDelay),
        ] {
            let mut set = call("setsockopt", [stream, level, name, value, 4, 0], teb);
            win32::dispatch(&mut set, &host);
            assert_eq!(set.result, Some(0));
            assert!(
                host.sockets.borrow()[0]
                    .options
                    .iter()
                    .any(|(seen, on)| *seen == option && *on == 1),
                "{option:?} was set"
            );
        }

        // SO_TYPE is a report, and comes from what the socket is.
        put_bytes(&host, len, &4u32.to_le_bytes());
        let mut kind = call("getsockopt", [stream, 0xFFFF, 0x1008, value, len, 0], teb);
        win32::dispatch(&mut kind, &host);
        assert_eq!(kind.result, Some(0));
        let read = {
            let mem = host.mem.borrow();
            u32::from_le_bytes(mem[value..value + 4].try_into().unwrap())
        };
        assert_eq!(read, 1, "SOCK_STREAM");

        // A pending error reads back in Winsock's numbering, since that is
        // what the caller turns into an exception.
        host.socket(socket_fd(stream))
            .unwrap()
            .options
            .push((O::Error, 111));
        let mut failure = call("getsockopt", [stream, 0xFFFF, 0x1007, value, len, 0], teb);
        win32::dispatch(&mut failure, &host);
        let reported = {
            let mem = host.mem.borrow();
            u32::from_le_bytes(mem[value..value + 4].try_into().unwrap())
        };
        assert_eq!(reported, 10061, "ECONNREFUSED as WSAECONNREFUSED");

        // An option this layer does not model is accepted, and reads as zero,
        // rather than failing a caller that only stated a preference.
        let mut spare = call("setsockopt", [stream, 0xFFFF, 0x4242, value, 4, 0], teb);
        win32::dispatch(&mut spare, &host);
        assert_eq!(spare.result, Some(0));
        let mut read_spare = call("getsockopt", [stream, 0xFFFF, 0x4242, value, len, 0], teb);
        win32::dispatch(&mut read_spare, &host);
        assert_eq!(read_spare.result, Some(0));
        let zero = {
            let mem = host.mem.borrow();
            u32::from_le_bytes(mem[value..value + 4].try_into().unwrap())
        };
        assert_eq!(zero, 0);
    }

    #[test]
    fn the_names_of_a_socket_come_back_in_winsock_shape() {
        use crate::win32;
        let host = MockHost::default();
        let (teb, _) = process(&host);
        let socket = opened(&host, teb, 2, 1);
        let at = 0x7000usize;
        put_sockaddr_in(&host, at, [192, 0, 2, 10], 8080);
        let mut bound = call("bind", [socket, at, 16, 0, 0, 0], teb);
        win32::dispatch(&mut bound, &host);

        let (out, len_at) = (0x7200usize, 0x7300usize);
        put_bytes(&host, len_at, &16u32.to_le_bytes());
        let mut local = call("getsockname", [socket, out, len_at, 0, 0, 0], teb);
        win32::dispatch(&mut local, &host);
        assert_eq!(local.result, Some(0));
        assert_eq!(&host.mem.borrow()[out + 4..out + 8], &[192, 0, 2, 10]);

        // A socket with no peer says so rather than inventing one.
        let mut peer = call("getpeername", [socket, out, len_at, 0, 0, 0], teb);
        win32::dispatch(&mut peer, &host);
        assert_eq!(peer.result, Some(-1i32 as u32 as usize));

        // A buffer too small for the address is a fault, not a truncation.
        put_bytes(&host, len_at, &4u32.to_le_bytes());
        let mut cramped = call("getsockname", [socket, out, len_at, 0, 0, 0], teb);
        win32::dispatch(&mut cramped, &host);
        assert_eq!(cramped.result, Some(-1i32 as u32 as usize));
    }

    #[test]
    fn starting_and_ending_winsock_answers_the_way_a_caller_expects() {
        use crate::win32;
        let host = MockHost::default();
        let (teb, _) = process(&host);
        let data = 0x7000usize;
        let mut started = call("WSAStartup", [0x0202, data, 0, 0, 0, 0], teb);
        win32::dispatch(&mut started, &host);
        assert_eq!(started.result, Some(0));
        let mem = host.mem.borrow();
        assert_eq!(
            u16::from_le_bytes(mem[data..data + 2].try_into().unwrap()),
            0x0202,
            "the version it was asked for"
        );
        drop(mem);

        let mut ended = call("WSACleanup", [0; 6], teb);
        win32::dispatch(&mut ended, &host);
        assert_eq!(ended.result, Some(0));

        // The last error is the thread's, under Winsock's name for it.
        let mut set = call("WSASetLastError", [10061, 0, 0, 0, 0, 0], teb);
        win32::dispatch(&mut set, &host);
        let mut got = call("WSAGetLastError", [0; 6], teb);
        win32::dispatch(&mut got, &host);
        assert_eq!(got.result, Some(10061), "WSAECONNREFUSED");
    }

    #[test]
    fn byte_order_calls_swap_the_width_they_name() {
        use crate::win32;
        let host = MockHost::default();
        let (teb, _) = process(&host);
        for (name, input, expected) in [
            ("htons", 0x1234usize, 0x3412usize),
            ("ntohs", 0x3412, 0x1234),
            ("htonl", 0x1234_5678, 0x7856_3412),
            ("ntohl", 0x7856_3412, 0x1234_5678),
        ] {
            let mut swapped = call(name, [input, 0, 0, 0, 0, 0], teb);
            win32::dispatch(&mut swapped, &host);
            assert_eq!(swapped.result, Some(expected), "{name}");
        }
    }

    /// Lay a Winsock fd_set down: a count, then the sockets.
    fn put_fd_set(host: &MockHost, at: usize, handles: &[usize]) {
        let mut block = alloc::vec![0u8; 8 + handles.len() * 8];
        block[0..4].copy_from_slice(&(handles.len() as u32).to_le_bytes());
        for (i, handle) in handles.iter().enumerate() {
            block[8 + i * 8..16 + i * 8].copy_from_slice(&(*handle as u64).to_le_bytes());
        }
        put_bytes(host, at, &block);
    }

    /// The sockets a set holds after a call wrote it back.
    fn read_fd_set(host: &MockHost, at: usize) -> Vec<usize> {
        let mem = host.mem.borrow();
        let count = u32::from_le_bytes(mem[at..at + 4].try_into().unwrap()) as usize;
        (0..count)
            .map(|i| {
                u64::from_le_bytes(mem[at + 8 + i * 8..at + 16 + i * 8].try_into().unwrap())
                    as usize
            })
            .collect()
    }

    #[test]
    fn select_keeps_only_the_sockets_that_are_ready_for_what_was_asked() {
        use crate::win32;
        let host = MockHost::default();
        let (teb, _) = process(&host);
        let quiet = opened(&host, teb, 2, 1);
        let ready = opened(&host, teb, 2, 1);
        // The second socket has something to read and somewhere to write to.
        {
            let mut socket = host.socket(socket_fd(ready)).unwrap();
            socket.queued = b"data".to_vec();
            socket.peer = Some(ax_abi_port::Address::V4([127, 0, 0, 1], 9));
        }
        let (read_at, write_at, timeout_at) = (0x7000usize, 0x7100usize, 0x7200usize);
        put_fd_set(&host, read_at, &[quiet, ready]);
        put_fd_set(&host, write_at, &[ready]);
        // A timeval of zero asks what is ready now; Windows keeps both fields
        // 32-bit even on x64.
        put_bytes(&host, timeout_at, &[0u8; 8]);

        let mut chosen = call("select", [0, read_at, write_at, 0, timeout_at, 0], teb);
        win32::dispatch(&mut chosen, &host);
        assert_eq!(chosen.result, Some(2), "one readable and one writable");
        assert_eq!(read_fd_set(&host, read_at), alloc::vec![ready]);
        assert_eq!(read_fd_set(&host, write_at), alloc::vec![ready]);
    }

    #[test]
    fn select_with_nothing_ready_empties_the_sets() {
        use crate::win32;
        let host = MockHost::default();
        let (teb, _) = process(&host);
        let quiet = opened(&host, teb, 2, 1);
        let (read_at, timeout_at) = (0x7000usize, 0x7200usize);
        put_fd_set(&host, read_at, &[quiet]);
        put_bytes(&host, timeout_at, &[0u8; 8]);

        let mut none = call("select", [0, read_at, 0, 0, timeout_at, 0], teb);
        win32::dispatch(&mut none, &host);
        assert_eq!(none.result, Some(0), "a timeout is not a failure");
        assert!(read_fd_set(&host, read_at).is_empty());
    }

    #[test]
    fn the_read_only_attribute_moves_the_write_permission_bits() {
        use crate::win32;
        const READONLY: usize = 0x1;
        let host = MockHost {
            describes: Some(Attributes {
                kind: NodeKind::File,
                mode: 0o644,
                ..Attributes::default()
            }),
            has_paths: true,
            ..MockHost::default()
        };
        let (teb, _) = process(&host);
        let name = 0x7000usize;
        put_wide(&host, name, "Z:\\file.txt\0");

        // Setting it clears every write bit.
        let mut lock = call("SetFileAttributesW", [name, READONLY, 0, 0, 0, 0], teb);
        win32::dispatch(&mut lock, &host);
        assert_eq!(lock.result, Some(1));
        assert_eq!(host.moded.borrow().as_ref().unwrap().1, 0o444);

        // Clearing it adds write where read already is, less what the
        // process withholds - the mock keeps no umask, so all of it lands.
        let mut unlock = call("SetFileAttributesW", [name, 0, 0, 0, 0, 0], teb);
        win32::dispatch(&mut unlock, &host);
        assert_eq!(unlock.result, Some(1));
        assert_eq!(host.moded.borrow().as_ref().unwrap().1, 0o666);
    }

    #[test]
    fn a_handle_sets_what_its_file_permits_and_when_it_was_touched() {
        use crate::win32;
        const TICKS_1601_TO_1970: u64 = 116_444_736_000_000_000;
        let host = MockHost {
            describes: Some(Attributes {
                kind: NodeKind::File,
                mode: 0o444,
                ..Attributes::default()
            }),
            has_paths: true,
            ..MockHost::default()
        };
        let (teb, _) = process(&host);
        let (info, handle) = (0x7000usize, Handle::from_slot(5).0 as usize);
        let put = |at: usize, value: u64| {
            let mut mem = host.mem.borrow_mut();
            mem[at..at + 8].copy_from_slice(&value.to_le_bytes());
        };
        // FILE_BASIC_INFO: creation, access, write, change, then attributes.
        // A second past the epoch, and the readonly bit cleared.
        let second = TICKS_1601_TO_1970 + 10_000_000;
        put(info, 0);
        put(info + 8, second);
        put(info + 16, u64::MAX);
        put(info + 24, 0);
        put(info + 32, 0x80); // FILE_ATTRIBUTE_NORMAL
        let mut set = call(
            "SetFileInformationByHandle",
            [handle, 0, info, 40, 0, 0],
            teb,
        );
        win32::dispatch(&mut set, &host);
        assert_eq!(set.result, Some(1));
        assert_eq!(
            *host.stamped.borrow(),
            Some((5, Some(1_000_000_000), None)),
            "the access time was set and the write time left alone"
        );
        assert_eq!(
            host.moded.borrow().as_ref().unwrap(),
            &(String::from("fd5"), 0o666),
            "clearing readonly puts back the write bits where read is, less              what the \
             process withholds - the mock withholds none"
        );

        // A class this filesystem has nothing to change for says so.
        let mut odd = call(
            "SetFileInformationByHandle",
            [handle, 3, info, 40, 0, 0],
            teb,
        );
        win32::dispatch(&mut odd, &host);
        assert_eq!(odd.result, Some(0));
    }

    #[test]
    fn a_handle_stamps_its_file_with_the_times_it_is_given() {
        use crate::win32;
        const TICKS_1601_TO_1970: u64 = 116_444_736_000_000_000;
        let host = MockHost {
            describes: Some(Attributes::default()),
            has_paths: true,
            ..MockHost::default()
        };
        let (teb, _) = process(&host);
        let handle = Handle::from_slot(5).0 as usize;
        let (created, accessed, written) = (0x7000usize, 0x7008usize, 0x7010usize);
        let put = |at: usize, value: u64| {
            let mut mem = host.mem.borrow_mut();
            mem[at..at + 8].copy_from_slice(&value.to_le_bytes());
        };
        put(created, TICKS_1601_TO_1970);
        put(accessed, TICKS_1601_TO_1970 + 20_000_000);
        put(written, TICKS_1601_TO_1970 + 30_000_000);
        let mut set = call(
            "SetFileTime",
            [handle, created, accessed, written, 0, 0],
            teb,
        );
        win32::dispatch(&mut set, &host);
        assert_eq!(set.result, Some(1));
        assert_eq!(
            *host.stamped.borrow(),
            Some((5, Some(2_000_000_000), Some(3_000_000_000)))
        );

        // Nothing to change is still a success, and changes nothing.
        *host.stamped.borrow_mut() = None;
        let mut none = call("SetFileTime", [handle, 0, 0, 0, 0, 0], teb);
        win32::dispatch(&mut none, &host);
        assert_eq!(none.result, Some(1));
        assert!(host.stamped.borrow().is_none());
    }

    #[test]
    fn a_directory_keeps_its_permissions_whatever_the_attribute_says() {
        use crate::win32;
        let host = MockHost {
            describes: Some(Attributes {
                kind: NodeKind::Directory,
                mode: 0o755,
                ..Attributes::default()
            }),
            has_paths: true,
            ..MockHost::default()
        };
        let (teb, _) = process(&host);
        let name = 0x7000usize;
        put_wide(&host, name, "Z:\\dir\0");
        let mut asked = call("SetFileAttributesW", [name, 1, 0, 0, 0, 0], teb);
        win32::dispatch(&mut asked, &host);
        assert_eq!(asked.result, Some(1), "accepted");
        assert!(host.moded.borrow().is_none(), "and nothing was changed");
    }

    #[test]
    fn a_child_is_started_with_its_command_line_environment_and_directory() {
        use crate::win32;
        let host = MockHost::default();
        let (teb, _) = process(&host);
        // A child starts on the trampoline kernel32 carries.
        with_modules(&host);
        let (line, dir, pi) = (0x7000usize, 0x7200usize, 0x7400usize);
        put_wide(&host, line, "Z:\\python\\python.exe -c \"print(1)\"\0");
        put_wide(&host, dir, "Z:\\tmp\0");

        // CreateProcessW(app, line, sa, sa, inherit, flags, env, dir, si, pi).
        let mut made = Win32Trap::with_stack(
            crate::win32::Win32Call::named("CreateProcessW").unwrap(),
            [0, line, 0, 0, 0, 0],
            teb,
            &[0, dir, 0, pi],
            9,
            &host,
        );
        win32::dispatch(&mut made, &host);
        assert_eq!(made.result, Some(1), "the child started");

        // PROCESS_INFORMATION carries the child's numbers.
        {
            let mem = host.mem.borrow();
            let id = |at: usize| u32::from_le_bytes(mem[at..at + 4].try_into().unwrap());
            assert_eq!((id(pi + 16), id(pi + 20)), (9, 9));
        }

        // The block the child was handed: the program, then its arguments as
        // the command line splits them, then the environment.
        let block = made.handed.expect("a block for the child");
        let read = |at: usize| {
            let mem = host.mem.borrow();
            u64::from_le_bytes(mem[at..at + 8].try_into().unwrap()) as usize
        };
        let text = |at: usize| {
            let mem = host.mem.borrow();
            let end = mem[at..].iter().position(|b| *b == 0).unwrap() + at;
            String::from_utf8(mem[at..end].to_vec()).unwrap()
        };
        assert_eq!(text(read(block + 16)), "/python/python.exe", "the program");
        let argv = read(block + 24);
        let args: Vec<String> = (0..)
            .map(|i| read(argv + i * 8))
            .take_while(|at| *at != 0)
            .map(text)
            .collect();
        assert_eq!(
            args,
            ["Z:\\python\\python.exe", "-c", "print(1)"],
            "quotes group one argument"
        );
        let envp = read(block + 32);
        let envs: Vec<String> = (0..)
            .map(|i| read(envp + i * 8))
            .take_while(|at| *at != 0)
            .map(text)
            .collect();
        assert!(
            envs.contains(&String::from("A=1")),
            "{envs:?} was inherited"
        );
        assert!(
            envs.contains(&String::from("=Z:=Z:\\tmp")),
            "{envs:?} says where the child starts"
        );
    }

    #[test]
    fn a_child_with_no_directory_named_starts_where_its_parent_is() {
        use crate::win32;
        let host = MockHost::default();
        let (teb, _) = process(&host);
        with_modules(&host);
        let (line, pi) = (0x7000usize, 0x7400usize);
        put_wide(&host, line, "Z:\\python\\python.exe\0");
        let mut made = Win32Trap::with_stack(
            crate::win32::Win32Call::named("CreateProcessW").unwrap(),
            [0, line, 0, 0, 0, 0],
            teb,
            &[0, 0, 0, pi],
            9,
            &host,
        );
        win32::dispatch(&mut made, &host);
        assert_eq!(made.result, Some(1));
        let block = made.handed.expect("a block for the child");
        let read = |at: usize| {
            let mem = host.mem.borrow();
            u64::from_le_bytes(mem[at..at + 8].try_into().unwrap()) as usize
        };
        let text = |at: usize| {
            let mem = host.mem.borrow();
            let end = mem[at..].iter().position(|b| *b == 0).unwrap() + at;
            String::from_utf8(mem[at..end].to_vec()).unwrap()
        };
        let envp = read(block + 32);
        let envs: Vec<String> = (0..)
            .map(|i| read(envp + i * 8))
            .take_while(|at| *at != 0)
            .map(text)
            .collect();
        assert!(
            envs.contains(&String::from("=Z:=Z:\\app")),
            "{envs:?} is where this process is"
        );
    }

    #[test]
    fn a_process_that_is_there_can_be_opened_and_one_that_is_not_cannot() {
        use crate::win32;
        const PROCESS_TAG: usize = 0x2000_0000;
        let host = MockHost::default();
        let (teb, _) = process(&host);

        let mut open = call("OpenProcess", [0x1F_0FFF, 0, 21, 0, 0, 0], teb);
        win32::dispatch(&mut open, &host);
        assert_eq!(open.result, Some(PROCESS_TAG | 21));
        assert_eq!(
            *host.killed.borrow(),
            [(21, 0)],
            "asked whether it is there, without signalling it"
        );

        // A number that names nothing has no handle.
        host.kills.set(false);
        let mut missing = call("OpenProcess", [0x1F_0FFF, 0, 22, 0, 0, 0], teb);
        win32::dispatch(&mut missing, &host);
        assert_eq!(missing.result, Some(0));
    }

    #[test]
    fn terminating_a_child_kills_the_child_and_not_the_caller() {
        use crate::win32;
        const PROCESS_TAG: usize = 0x2000_0000;
        const SIGKILL: u32 = 9;
        let host = MockHost::default();
        let (teb, _) = process(&host);

        let mut killed = call("TerminateProcess", [PROCESS_TAG | 12, 3, 0, 0, 0, 0], teb);
        win32::dispatch(&mut killed, &host);
        assert_eq!(killed.result, Some(1), "the child was terminated");
        assert_eq!(*host.killed.borrow(), [(12, SIGKILL)]);
        assert!(
            host.ended.borrow().is_none(),
            "and the caller is still running"
        );

        // What it exited with is what the caller said to end it with, not
        // the signal that carried that out.
        host.exits.borrow_mut().insert(12, 137);
        let code_at = 0x7300usize;
        let mut asked = call(
            "GetExitCodeProcess",
            [PROCESS_TAG | 12, code_at, 0, 0, 0, 0],
            teb,
        );
        win32::dispatch(&mut asked, &host);
        let code = {
            let mem = host.mem.borrow();
            u32::from_le_bytes(mem[code_at..code_at + 4].try_into().unwrap())
        };
        assert_eq!(code, 3);

        // The process's own handle still ends this process.
        let mut own = call(
            "TerminateProcess",
            [
                crate::handle::Handle::CURRENT_PROCESS.0 as usize,
                4,
                0,
                0,
                0,
                0,
            ],
            teb,
        );
        win32::dispatch(&mut own, &host);
        assert_eq!(*host.ended.borrow(), Some(4));
    }

    #[test]
    fn a_wait_on_a_running_child_gives_up_when_its_time_is_up() {
        use crate::win32;
        const PROCESS_TAG: usize = 0x2000_0000;
        let host = MockHost::default();
        let (teb, _) = process(&host);
        let handle = PROCESS_TAG | 11;

        // Nothing has ended, so a bounded wait comes back at its deadline
        // rather than blocking until the child does end.
        let started = *host.now.borrow();
        assert_eq!(waited(&host, teb, handle, 500), WAIT_TIMEOUT);
        assert!(
            *host.now.borrow() - started >= 500 * 1_000_000,
            "and it waited that long"
        );

        // Once the child ends the same wait finds it.
        host.exits.borrow_mut().insert(11, 3);
        assert_eq!(waited(&host, teb, handle, 500), WAIT_OBJECT_0);
    }

    #[test]
    fn a_wait_on_several_objects_does_not_call_a_running_child_signalled() {
        use crate::win32;
        const PROCESS_TAG: usize = 0x2000_0000;
        let host = MockHost::default();
        let (teb, _) = process(&host);
        let set = 0x7500usize;
        let handle = PROCESS_TAG | 31;
        {
            let mut mem = host.mem.borrow_mut();
            mem[set..set + 8].copy_from_slice(&(handle as u64).to_le_bytes());
        }
        let wait_for = |ms: usize| {
            let mut wait = call("WaitForMultipleObjects", [1, set, 0, ms, 0, 0], teb);
            win32::dispatch(&mut wait, &host);
            wait.result.expect("the wait answered")
        };
        // A process handle is not one of the objects this layer keeps, and
        // taking "not mine" for "signalled" would tell a caller its child had
        // ended while it was still running.
        assert_eq!(wait_for(200), WAIT_TIMEOUT, "the child is still running");
        host.exits.borrow_mut().insert(31, 7);
        assert_eq!(wait_for(200), WAIT_OBJECT_0, "and found once it ends");
    }

    #[test]
    fn making_a_named_pipe_leaves_the_runtime_its_thread_data() {
        use crate::win32;
        let host = MockHost::default();
        let (teb, _) = process(&host);
        let call_it = |name: &str, args: [usize; 6]| {
            let mut c = call(name, args, teb);
            win32::dispatch(&mut c, &host);
            c.result
        };
        let first = call_it("FlsAlloc", [0; 6]).expect("an index");
        let second = call_it("FlsAlloc", [0; 6]).expect("another index");
        assert_ne!(first, second);
        assert_eq!(call_it("FlsSetValue", [first, 0xDEAD, 0, 0, 0, 0]), Some(1));
        assert_eq!(
            call_it("FlsSetValue", [second, 0xBEEF, 0, 0, 0, 0]),
            Some(1)
        );

        // The pipe keeps a list of its own past the real PEB, as several other
        // things here do. Sharing a word with the FLS table would leave the
        // runtime unable to keep its per-thread data, which it answers by
        // aborting the process.
        let name: Vec<u8> = "\\\\.\\pipe\\t\0"
            .encode_utf16()
            .flat_map(u16::to_le_bytes)
            .collect();
        let name_at = 0x7800usize;
        {
            let mut mem = host.mem.borrow_mut();
            mem[name_at..name_at + name.len()].copy_from_slice(&name);
        }
        let mut made = Win32Trap::with_stack(
            crate::win32::Win32Call::named("CreateNamedPipeW").unwrap(),
            [name_at, 3, 4, 1, 8192, 8192],
            teb,
            &[0xFFFF_FFFF, 0],
            0,
            &host,
        );
        win32::dispatch(&mut made, &host);
        assert_ne!(made.result, Some(usize::MAX), "the pipe was made");

        assert_eq!(call_it("FlsGetValue", [first, 0, 0, 0, 0, 0]), Some(0xDEAD));
        assert_eq!(
            call_it("FlsGetValue", [second, 0, 0, 0, 0, 0]),
            Some(0xBEEF)
        );
        let third = call_it("FlsAlloc", [0; 6]).expect("a third index");
        assert!(
            third != first && third != second,
            "and the next index is a new one, not one already handed out"
        );
    }

    #[test]
    fn the_temporary_directory_is_what_the_environment_says_it_is() {
        use crate::win32;
        let host = MockHost::default();
        let (teb, _) = process(&host);
        let (buf, size) = (0x7600usize, 64usize);
        let temp_path = || {
            let mut ask = call("GetTempPathW", [size, buf, 0, 0, 0, 0], teb);
            win32::dispatch(&mut ask, &host);
            let len = ask.result.expect("the path was answered");
            let mem = host.mem.borrow();
            String::from_utf16_lossy(
                &mem[buf..buf + len * 2]
                    .chunks(2)
                    .map(|c| u16::from_le_bytes([c[0], c[1]]))
                    .collect::<Vec<u16>>(),
            )
        };
        // Nothing set it, so it is where this personality puts them.
        assert_eq!(temp_path(), "Z:\\tmp\\");

        // TMP is the first name Windows looks at, and a value without the
        // trailing separator still comes back with one.
        let name: Vec<u8> = "TMP\0".encode_utf16().flat_map(u16::to_le_bytes).collect();
        let value: Vec<u8> = "Z:\\scratch\0"
            .encode_utf16()
            .flat_map(u16::to_le_bytes)
            .collect();
        let (name_at, value_at) = (0x7700usize, 0x7780usize);
        {
            let mut mem = host.mem.borrow_mut();
            mem[name_at..name_at + name.len()].copy_from_slice(&name);
            mem[value_at..value_at + value.len()].copy_from_slice(&value);
        }
        let mut set = call(
            "SetEnvironmentVariableW",
            [name_at, value_at, 0, 0, 0, 0],
            teb,
        );
        win32::dispatch(&mut set, &host);
        assert_eq!(set.result, Some(1));
        assert_eq!(temp_path(), "Z:\\scratch\\");
    }

    #[test]
    fn the_error_mode_is_kept_and_handed_back_to_whoever_set_it() {
        use crate::win32;
        const SEM_FAILCRITICALERRORS: usize = 0x1;
        const SEM_NOGPFAULTERRORBOX: usize = 0x2;
        let host = MockHost::default();
        let (teb, _) = process(&host);

        let mut first = call("SetErrorMode", [SEM_FAILCRITICALERRORS, 0, 0, 0, 0, 0], teb);
        win32::dispatch(&mut first, &host);
        assert_eq!(first.result, Some(0), "nothing was set before");

        let mut second = call("SetErrorMode", [SEM_NOGPFAULTERRORBOX, 0, 0, 0, 0, 0], teb);
        win32::dispatch(&mut second, &host);
        assert_eq!(
            second.result,
            Some(SEM_FAILCRITICALERRORS),
            "the mode that was in force"
        );

        let mut read = call("GetErrorMode", [0; 6], teb);
        win32::dispatch(&mut read, &host);
        assert_eq!(read.result, Some(SEM_NOGPFAULTERRORBOX));

        // Bits the call does not define are not kept.
        let mut odd = call("SetErrorMode", [0xF000, 0, 0, 0, 0, 0], teb);
        win32::dispatch(&mut odd, &host);
        let mut read = call("GetErrorMode", [0; 6], teb);
        win32::dispatch(&mut read, &host);
        assert_eq!(read.result, Some(0x8000), "only SEM_NOOPENFILEERRORBOX");
    }

    #[test]
    fn a_handle_that_is_not_a_console_says_so() {
        use crate::win32;
        const ERROR_INVALID_HANDLE: u32 = 6;
        let host = MockHost::default();
        let (teb, _) = process(&host);
        for name in [
            "GetConsoleMode",
            "SetConsoleMode",
            "GetConsoleScreenBufferInfo",
        ] {
            let mut asked = call(name, [4, 0x7000, 0, 0, 0, 0], teb);
            win32::dispatch(&mut asked, &host);
            assert_eq!(asked.result, Some(0), "{name} did not succeed");
            let mem = host.mem.borrow();
            let error = u32::from_le_bytes(
                mem[teb + crate::teb_peb::TEB_LAST_ERROR..teb + crate::teb_peb::TEB_LAST_ERROR + 4]
                    .try_into()
                    .unwrap(),
            );
            assert_eq!(error, ERROR_INVALID_HANDLE, "{name} said why");
        }
    }

    #[test]
    fn a_thread_reads_its_stack_bounds_and_keeps_a_guarantee() {
        use crate::{
            teb_peb::{TEB_STACK_BASE, TEB_STACK_LIMIT},
            win32,
        };
        let host = MockHost::default();
        let (teb, _) = process(&host);
        let (low, high) = (0x30_0000u64, 0x40_0000u64);
        {
            let mut mem = host.mem.borrow_mut();
            mem[teb + TEB_STACK_LIMIT..teb + TEB_STACK_LIMIT + 8]
                .copy_from_slice(&low.to_le_bytes());
            mem[teb + TEB_STACK_BASE..teb + TEB_STACK_BASE + 8]
                .copy_from_slice(&high.to_le_bytes());
        }
        let (low_out, high_out) = (0x7000usize, 0x7008usize);
        let mut limits = call(
            "GetCurrentThreadStackLimits",
            [low_out, high_out, 0, 0, 0, 0],
            teb,
        );
        win32::dispatch(&mut limits, &host);
        {
            let mem = host.mem.borrow();
            let read = |at: usize| u64::from_le_bytes(mem[at..at + 8].try_into().unwrap());
            assert_eq!((read(low_out), read(high_out)), (low, high));
        }

        // The guarantee is read from the word and the previous one written
        // back, rounded to a page.
        let at = 0x7020usize;
        let ask = |host: &MockHost, bytes: u32| {
            {
                let mut mem = host.mem.borrow_mut();
                mem[at..at + 4].copy_from_slice(&bytes.to_le_bytes());
            }
            let mut asked = call("SetThreadStackGuarantee", [at, 0, 0, 0, 0, 0], teb);
            win32::dispatch(&mut asked, host);
            assert_eq!(asked.result, Some(1));
            let mem = host.mem.borrow();
            u32::from_le_bytes(mem[at..at + 4].try_into().unwrap())
        };
        assert_eq!(ask(&host, 0x1200), 0, "nothing was guaranteed before");
        assert_eq!(ask(&host, 0), 0x2000, "rounded up to whole pages");
        assert_eq!(ask(&host, 0x800), 0x2000, "a smaller ask keeps the larger");
    }

    #[test]
    fn what_a_child_exited_with_is_forgotten_once_its_handle_is_closed() {
        use crate::win32;
        const STILL_ACTIVE: u32 = 259;
        const PROCESS_TAG: usize = 0x2000_0000;
        let host = MockHost::default();
        let (teb, _) = process(&host);
        let (handle, code_at) = (PROCESS_TAG | 7, 0x7300usize);

        // The child ends, and the caller collects what it ended with.
        host.exits.borrow_mut().insert(7, 7);
        let read_code = |teb: usize| {
            let mut asked = call("GetExitCodeProcess", [handle, code_at, 0, 0, 0, 0], teb);
            win32::dispatch(&mut asked, &host);
            let mem = host.mem.borrow();
            u32::from_le_bytes(mem[code_at..code_at + 4].try_into().unwrap())
        };
        assert_eq!(read_code(teb), 7);
        // Asking again answers the same while the handle is open.
        assert_eq!(read_code(teb), 7);

        let mut closed = call("CloseHandle", [handle, 0, 0, 0, 0, 0], teb);
        win32::dispatch(&mut closed, &host);
        assert_eq!(closed.result, Some(1));

        // The number is free now, and a process that takes it next is not the
        // one that exited; answering with the old code would report a running
        // child as finished the moment it started.
        assert_eq!(
            read_code(teb),
            STILL_ACTIVE,
            "a closed handle leaves no answer behind"
        );
    }

    #[test]
    fn an_encoded_pointer_survives_an_object_being_signalled() {
        use crate::win32;
        let host = MockHost::default();
        let (teb, _) = process(&host);

        let pointer = 0x1_4000_1234usize;
        let mut encoded = call("EncodePointer", [pointer, 0, 0, 0, 0, 0], teb);
        win32::dispatch(&mut encoded, &host);
        let encoded = encoded.result.expect("an encoded pointer");

        // Signalling bumps the counter a many-object wait parks on. The
        // pointer cookie must not be kept in that same word.
        let mut made = call("CreateSemaphoreW", [0, 0, 4, 0, 0, 0], teb);
        win32::dispatch(&mut made, &host);
        let semaphore = made.result.expect("a semaphore");
        let mut up = call("ReleaseSemaphore", [semaphore, 1, 0, 0, 0, 0], teb);
        win32::dispatch(&mut up, &host);

        let mut back = call("DecodePointer", [encoded, 0, 0, 0, 0, 0], teb);
        win32::dispatch(&mut back, &host);
        assert_eq!(back.result, Some(pointer), "decoding undoes encoding");
    }

    #[test]
    fn signalling_an_event_wakes_a_wait_on_several_objects() {
        use crate::{teb_peb::TEB_PEB, win32};
        let host = MockHost::default();
        let (teb, _) = process(&host);
        let peb = {
            let mem = host.mem.borrow();
            u64::from_le_bytes(mem[teb + TEB_PEB..teb + TEB_PEB + 8].try_into().unwrap()) as usize
        };
        let counter = |host: &MockHost| {
            let mem = host.mem.borrow();
            let at = peb + win32::PEB_SIGNAL_SEQ;
            u32::from_le_bytes(mem[at..at + 4].try_into().unwrap())
        };

        let mut made = call("CreateEventW", [0, 1, 0, 0, 0, 0], teb);
        win32::dispatch(&mut made, &host);
        let event = made.result.expect("an event");

        // A thread waiting on several objects parks on the process-wide
        // counter, so setting one of them has to bump it.
        let before = counter(&host);
        let mut set = call("SetEvent", [event, 0, 0, 0, 0, 0], teb);
        win32::dispatch(&mut set, &host);
        assert_ne!(counter(&host), before, "a set event is a signal");
        assert_eq!(
            waited(&host, teb, event, 0),
            WAIT_OBJECT_0,
            "and the event itself is signalled"
        );
    }

    #[test]
    fn a_thread_handle_is_waited_on_until_the_thread_ends() {
        use crate::win32;
        const STILL_ACTIVE: usize = 259;
        let host = MockHost::default();
        let (teb, _) = process(&host);
        // A new thread starts on the trampoline kernel32 carries.
        with_modules(&host);

        // The trap double hands back a thread id, as a host that can start
        // one does.
        let mut made = Win32Trap::spawning(
            crate::win32::Win32Call::named("CreateThread").unwrap(),
            [0, 0, 0x140000, 0, 0, 0],
            teb,
            9,
        );
        win32::dispatch(&mut made, &host);
        let handle = made.result.expect("a thread handle");
        assert_ne!(handle, 0);

        // While it runs, a join times out and its code says so.
        assert_eq!(waited(&host, teb, handle, 0), WAIT_TIMEOUT);
        let code_at = 0x7300usize;
        let mut running = call("GetExitCodeThread", [handle, code_at, 0, 0, 0, 0], teb);
        win32::dispatch(&mut running, &host);
        let code = {
            let mem = host.mem.borrow();
            u32::from_le_bytes(mem[code_at..code_at + 4].try_into().unwrap()) as usize
        };
        assert_eq!(code, STILL_ACTIVE);

        // The thread ends on its own block, which is what a join waits for.
        let started = made.started_at.expect("a block for the new thread");
        let mut ended = call("ExitThread", [3, 0, 0, 0, 0, 0], started);
        win32::dispatch(&mut ended, &host);
        assert_eq!(waited(&host, teb, handle, 0), WAIT_OBJECT_0, "joined");
        assert_eq!(
            waited(&host, teb, handle, 0),
            WAIT_OBJECT_0,
            "and it stays joinable"
        );
        let mut finished = call("GetExitCodeThread", [handle, code_at, 0, 0, 0, 0], teb);
        win32::dispatch(&mut finished, &host);
        let code = {
            let mem = host.mem.borrow();
            u32::from_le_bytes(mem[code_at..code_at + 4].try_into().unwrap())
        };
        assert_eq!(code, 3, "what the thread ended with");
    }

    #[test]
    fn a_set_says_whether_it_holds_a_socket() {
        use crate::win32;
        let host = MockHost::default();
        let (teb, _) = process(&host);
        let (inside, outside) = (opened(&host, teb, 2, 1), opened(&host, teb, 2, 1));
        let at = 0x7000usize;
        put_fd_set(&host, at, &[inside]);

        let mut held = call("__WSAFDIsSet", [inside, at, 0, 0, 0, 0], teb);
        win32::dispatch(&mut held, &host);
        assert_eq!(held.result, Some(1));
        let mut absent = call("__WSAFDIsSet", [outside, at, 0, 0, 0, 0], teb);
        win32::dispatch(&mut absent, &host);
        assert_eq!(absent.result, Some(0));
    }

    #[test]
    fn the_machine_name_is_reported_and_its_length_asked_for_first() {
        use crate::win32;
        let host = MockHost::default();
        let (teb, _) = process(&host);
        let (buffer, size_at) = (0x7000usize, 0x7100usize);

        // A buffer too small says how much is needed, as the second call
        // a caller makes depends on.
        put_bytes(&host, size_at, &1u32.to_le_bytes());
        let mut short = call("GetComputerNameExW", [0, buffer, size_at, 0, 0, 0], teb);
        win32::dispatch(&mut short, &host);
        assert_eq!(short.result, Some(0), "FALSE");
        let needed = {
            let mem = host.mem.borrow();
            u32::from_le_bytes(mem[size_at..size_at + 4].try_into().unwrap())
        };
        assert!(needed > 1, "the room the name needs, with its terminator");

        put_bytes(&host, size_at, &needed.to_le_bytes());
        let mut named = call("GetComputerNameExW", [0, buffer, size_at, 0, 0, 0], teb);
        win32::dispatch(&mut named, &host);
        assert_eq!(named.result, Some(1), "TRUE");
        let wrote = {
            let mem = host.mem.borrow();
            u32::from_le_bytes(mem[size_at..size_at + 4].try_into().unwrap())
        };
        assert_eq!(wrote, needed - 1, "and the count excludes the terminator");
        assert_eq!(wide_at(&host, buffer), "starry-host");

        // The same name comes back through the sockets spelling of it.
        let (name_at, len_at) = (0x7200usize, 32usize);
        let mut sockets_name = call("gethostname", [name_at, len_at, 0, 0, 0, 0], teb);
        win32::dispatch(&mut sockets_name, &host);
        assert_eq!(sockets_name.result, Some(0));
        let text = {
            let mem = host.mem.borrow();
            let end = mem[name_at..].iter().position(|b| *b == 0).unwrap();
            String::from_utf8(mem[name_at..name_at + end].to_vec()).unwrap()
        };
        assert_eq!(text, "starry-host");
    }

    #[test]
    fn select_refuses_a_handle_that_is_not_a_socket() {
        use crate::win32;
        let host = MockHost::default();
        let (teb, _) = process(&host);
        let (read_at, timeout_at) = (0x7000usize, 0x7200usize);
        put_fd_set(&host, read_at, &[0]);
        put_bytes(&host, timeout_at, &[0u8; 8]);
        let mut bad = call("select", [0, read_at, 0, 0, timeout_at, 0], teb);
        win32::dispatch(&mut bad, &host);
        assert_eq!(bad.result, Some(-1i32 as u32 as usize), "SOCKET_ERROR");
    }

    #[test]
    fn an_address_goes_to_text_and_back() {
        use crate::win32;
        let host = MockHost::default();
        let (teb, _) = process(&host);
        let (text_at, bytes_at, out_at) = (0x7000usize, 0x7100usize, 0x7200usize);
        put_bytes(&host, text_at, b"192.0.2.10\0");

        let mut to_bytes = call("inet_pton", [2, text_at, bytes_at, 0, 0, 0], teb);
        win32::dispatch(&mut to_bytes, &host);
        assert_eq!(to_bytes.result, Some(1), "a well-formed address parses");
        assert_eq!(&host.mem.borrow()[bytes_at..bytes_at + 4], &[192, 0, 2, 10]);

        let mut to_text = call("inet_ntop", [2, bytes_at, out_at, 64, 0, 0], teb);
        win32::dispatch(&mut to_text, &host);
        assert_eq!(to_text.result, Some(out_at));
        let printed = {
            let mem = host.mem.borrow();
            let end = mem[out_at..].iter().position(|b| *b == 0).unwrap();
            String::from_utf8(mem[out_at..out_at + end].to_vec()).unwrap()
        };
        assert_eq!(printed, "192.0.2.10");

        // Text that is not an address of that family is answered with zero,
        // which is the question answered rather than an error.
        put_bytes(&host, text_at, b"not-an-address\0");
        let mut refused = call("inet_pton", [2, text_at, bytes_at, 0, 0, 0], teb);
        win32::dispatch(&mut refused, &host);
        assert_eq!(refused.result, Some(0));

        // The older pair answers the same way, with the address as a word and
        // the text in a buffer of the calling thread's.
        put_bytes(&host, text_at, b"192.0.2.10\0");
        let mut packed = call("inet_addr", [text_at, 0, 0, 0, 0, 0], teb);
        win32::dispatch(&mut packed, &host);
        assert_eq!(
            packed.result,
            Some(u32::from_le_bytes([192, 0, 2, 10]) as usize)
        );
        let mut printed = call("inet_ntoa", [packed.result.unwrap(), 0, 0, 0, 0, 0], teb);
        win32::dispatch(&mut printed, &host);
        let at = printed.result.unwrap();
        assert_eq!(
            at,
            teb + crate::teb_peb::TEB_ADDRESS_TEXT,
            "the thread's own"
        );
        let text = {
            let mem = host.mem.borrow();
            let end = mem[at..].iter().position(|b| *b == 0).unwrap();
            String::from_utf8(mem[at..at + end].to_vec()).unwrap()
        };
        assert_eq!(text, "192.0.2.10");

        put_bytes(&host, text_at, b"999.1.1.1\0");
        let mut none = call("inet_addr", [text_at, 0, 0, 0, 0, 0], teb);
        win32::dispatch(&mut none, &host);
        assert_eq!(none.result, Some(0xFFFF_FFFF), "INADDR_NONE");
    }

    #[test]
    fn a_numeric_lookup_answers_with_that_address() {
        use crate::win32;
        let host = MockHost::default();
        let (teb, _) = process(&host);
        let (node, service, result) = (0x7000usize, 0x7040usize, 0x7080usize);
        put_bytes(&host, node, b"127.0.0.1\0");
        put_bytes(&host, service, b"80\0");

        let mut looked = call("getaddrinfo", [node, service, 0, result, 0, 0], teb);
        win32::dispatch(&mut looked, &host);
        assert_eq!(looked.result, Some(0));
        let entry = {
            let mem = host.mem.borrow();
            u64::from_le_bytes(mem[result..result + 8].try_into().unwrap()) as usize
        };
        assert_ne!(entry, 0);
        let word = |at: usize| {
            let mem = host.mem.borrow();
            u32::from_le_bytes(mem[at..at + 4].try_into().unwrap())
        };
        assert_eq!(word(entry + 4), 2, "AF_INET");
        assert_eq!(word(entry + 8), 1, "SOCK_STREAM by default");
        let address = {
            let mem = host.mem.borrow();
            u64::from_le_bytes(mem[entry + 32..entry + 40].try_into().unwrap()) as usize
        };
        let sockaddr = host.mem.borrow()[address..address + 8].to_vec();
        assert_eq!(&sockaddr[0..2], &2u16.to_le_bytes(), "AF_INET");
        assert_eq!(&sockaddr[2..4], &80u16.to_be_bytes(), "the port, as sent");
        assert_eq!(&sockaddr[4..8], &[127, 0, 0, 1]);

        // A name that would need a resolver is reported as not found rather
        // than answered with a guess.
        put_bytes(&host, node, b"example.invalid\0");
        let mut absent = call("getaddrinfo", [node, service, 0, result, 0, 0], teb);
        win32::dispatch(&mut absent, &host);
        assert_eq!(absent.result, Some(11001), "WSAHOST_NOT_FOUND");
    }

    #[test]
    fn a_well_known_service_has_its_assigned_port() {
        use crate::win32;
        let host = MockHost::default();
        let (teb, _) = process(&host);
        let (name, proto) = (0x7000usize, 0x7040usize);
        put_bytes(&host, name, b"http\0");
        put_bytes(&host, proto, b"tcp\0");
        let mut found = call("getservbyname", [name, proto, 0, 0, 0, 0], teb);
        win32::dispatch(&mut found, &host);
        let entry = found.result.expect("an entry");
        assert_ne!(entry, 0);
        // The 64-bit servent puts the protocol before the port, which is a
        // short in network order; reading them the other way round is the
        // mistake this pins down.
        let mem = host.mem.borrow();
        let port = u16::from_be_bytes(mem[entry + 24..entry + 26].try_into().unwrap());
        assert_eq!(port, 80);
        let proto_at = u64::from_le_bytes(mem[entry + 16..entry + 24].try_into().unwrap()) as usize;
        let end = mem[proto_at..].iter().position(|b| *b == 0).unwrap();
        assert_eq!(&mem[proto_at..proto_at + end], b"tcp");
        drop(mem);

        put_bytes(&host, name, b"nosuchservice\0");
        let mut missing = call("getservbyname", [name, proto, 0, 0, 0, 0], teb);
        win32::dispatch(&mut missing, &host);
        assert_eq!(missing.result, Some(0));
    }

    #[test]
    fn closing_a_synchronisation_handle_gives_its_block_back() {
        use crate::win32;
        let host = MockHost::default();
        let (teb, _) = process(&host);
        let event = created(&host, teb, "CreateEventW", [0, 1, 1, 0, 0, 0]);
        let mut close = call("CloseHandle", [event, 0, 0, 0, 0, 0], teb);
        win32::dispatch(&mut close, &host);
        assert_eq!(close.result, Some(1));
        // The block no longer names an object, so a stale handle cannot wait
        // on memory that has been handed out again.
        let magic = {
            let mem = host.mem.borrow();
            u64::from_le_bytes(mem[event..event + 8].try_into().unwrap())
        };
        assert_eq!(magic, 0);
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
        // A whole-directory search lists "." and ".." first, as directories.
        assert_eq!(name_of(0x7200), ".");
        assert_eq!(
            u32::from_le_bytes(host.mem.borrow()[0x7200..0x7204].try_into().unwrap()),
            0x10
        );
        for name in ["..", "__init__.py"] {
            let mut next = call("FindNextFileW", [handle, 0x7200, 0, 0, 0, 0], teb);
            win32::dispatch(&mut next, &host);
            assert_eq!(next.result, Some(1));
            assert_eq!(name_of(0x7200), name);
        }
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
        // The next advance is past the end.
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
