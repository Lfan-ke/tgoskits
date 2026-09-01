//! Files, as kernel32 offers them: Win32 names and conventions over the NT
//! layer's opening, transferring and describing.
//!
//! Each function is the one in Wine's `dlls/kernelbase/file.c` with the NT
//! call it makes replaced by the same work done through the ports. A name
//! arrives as Windows spells it - a drive, backslashes, maybe relative to the
//! process's current directory - and is turned into the single-rooted path the
//! host resolves, the way `RtlDosPathNameToNtPathName_U` and then the NT layer
//! would between them.

use alloc::{string::String, vec::Vec};

use ax_abi_port::{At, NodeKind, SeekFrom};

use super::{
    Call, Dispatch, ERROR_CALL_NOT_IMPLEMENTED, ERROR_INSUFFICIENT_BUFFER, ERROR_INVALID_PARAMETER,
    FALSE, INVALID_HANDLE_VALUE, TRUE,
};
use crate::{
    handle::Handle,
    nt::{self, Ntstatus},
    teb_peb::{MAX_PATH, PARAMS_CURRENT_DIRECTORY},
};

const ERROR_PATH_NOT_FOUND: u32 = 3;
const ERROR_NEGATIVE_SEEK: u32 = 131;
const ERROR_DIRECTORY: u32 = 267;

// CreateFileW's dispositions (`winbase.h`), and the NT disposition each is.
const CREATE_NEW: usize = 1;
const TRUNCATE_EXISTING: usize = 5;
const NT_DISPOSITION: [usize; 5] = [
    2, // CREATE_NEW        -> FILE_CREATE
    5, // CREATE_ALWAYS     -> FILE_OVERWRITE_IF
    1, // OPEN_EXISTING     -> FILE_OPEN
    3, // OPEN_ALWAYS       -> FILE_OPEN_IF
    4, // TRUNCATE_EXISTING -> FILE_OVERWRITE
];
const SYNCHRONIZE: usize = 0x0010_0000;
const FILE_READ_ATTRIBUTES: usize = 0x80;
const FILE_FLAG_BACKUP_SEMANTICS: usize = 0x0200_0000;
const FILE_FLAG_OPEN_REPARSE_POINT: usize = 0x0020_0000;
const FILE_NON_DIRECTORY_FILE: usize = 0x40;
const FILE_OPEN_REPARSE_POINT: usize = 0x0020_0000;
const OBJ_INHERIT: u32 = 0x2;

const FILE_TYPE_UNKNOWN: usize = 0;
const FILE_TYPE_DISK: usize = 1;
const FILE_TYPE_CHAR: usize = 2;
const FILE_TYPE_PIPE: usize = 3;

const FILE_BEGIN: usize = 0;
const FILE_CURRENT: usize = 1;
const FILE_END: usize = 2;

const STD_INPUT_HANDLE: usize = -10i32 as u32 as usize;
const STD_OUTPUT_HANDLE: usize = -11i32 as u32 as usize;
const STD_ERROR_HANDLE: usize = -12i32 as u32 as usize;

/// The process's current directory as Windows spells it, `Z:\\app\\`.
fn current_directory(c: &Call<'_>) -> Option<String> {
    let params = c.params()?;
    let (len, buf) = c.unicode(params + PARAMS_CURRENT_DIRECTORY)?;
    let units = c.read_wide_n(buf, len / 2)?;
    String::from_utf16(&units).ok()
}

/// A Windows name made absolute and normalized, still spelled the Windows
/// way: `Z:\\app\\..\\x` becomes `Z:\\x`. Relative names go against the current
/// directory; `\\\\?\\` is dropped; a device name has no place here.
fn full_windows_path(c: &Call<'_>, name: &str) -> Option<String> {
    let name = name.strip_prefix("\\\\?\\").unwrap_or(name);
    if name.starts_with("\\\\") {
        return None;
    }
    let bytes = name.as_bytes();
    let (drive, rest) = match bytes {
        [d, b':', ..] if d.is_ascii_alphabetic() => {
            (Some(d.to_ascii_uppercase() as char), &name[2..])
        }
        _ => (None, name),
    };
    let (drive, joined) = if rest.starts_with('\\') || rest.starts_with('/') {
        (drive.unwrap_or('Z'), String::from(rest))
    } else {
        let cwd = current_directory(c)?;
        let cwd_drive = cwd.chars().next().unwrap_or('Z');
        let mut joined = String::from(&cwd[2..]);
        if !joined.ends_with('\\') {
            joined.push('\\');
        }
        joined.push_str(rest);
        (drive.unwrap_or(cwd_drive), joined)
    };
    let mut parts: Vec<&str> = Vec::new();
    for part in joined.split(['\\', '/']) {
        match part {
            "" | "." => {}
            ".." => {
                parts.pop();
            }
            p => parts.push(p),
        }
    }
    let mut out = String::new();
    out.push(drive);
    out.push(':');
    for part in &parts {
        out.push('\\');
        out.push_str(part);
    }
    if parts.is_empty() {
        out.push('\\');
    }
    Some(out)
}

/// The host path a Windows name means: the full path with its drive dropped,
/// since one tree is all there is, and separators the host resolves.
fn host_path(c: &Call<'_>, name: &str) -> Option<String> {
    let full = full_windows_path(c, name)?;
    let path: String = full[2..]
        .chars()
        .map(|ch| if ch == '\\' { '/' } else { ch })
        .collect();
    Some(if path.is_empty() {
        String::from("/")
    } else {
        path
    })
}

fn name_at(c: &Call<'_>, at: usize) -> Option<String> {
    if at == 0 {
        return None;
    }
    String::from_utf16(&c.read_wstr(at)?).ok()
}

/// The descriptor a handle names, with the three standard pseudo-handles
/// resolved to the streams they stand for, as `GetStdHandle` would.
fn descriptor(handle: usize) -> Result<i32, Ntstatus> {
    let handle = match handle {
        STD_INPUT_HANDLE => Handle::from_slot(0).0 as usize,
        STD_OUTPUT_HANDLE => Handle::from_slot(1).0 as usize,
        STD_ERROR_HANDLE => Handle::from_slot(2).0 as usize,
        other => other,
    };
    nt::descriptor(handle)
}

/// CreateFileW(lpFileName, dwDesiredAccess, dwShareMode, lpSecurityAttributes,
/// dwCreationDisposition, dwFlagsAndAttributes, hTemplateFile).
pub fn create_file(c: &mut Call<'_>) -> Dispatch {
    let (name, access, sa, creation, attributes) =
        (c.arg(0), c.arg(1), c.arg(3), c.arg(4), c.arg(5));
    let Some(name) = name_at(c, name).filter(|n| !n.is_empty()) else {
        return c.fail(ERROR_PATH_NOT_FOUND, INVALID_HANDLE_VALUE);
    };
    if !(CREATE_NEW..=TRUNCATE_EXISTING).contains(&creation) {
        return c.fail(ERROR_INVALID_PARAMETER, INVALID_HANDLE_VALUE);
    }
    let Some(path) = host_path(c, &name) else {
        return c.fail(ERROR_PATH_NOT_FOUND, INVALID_HANDLE_VALUE);
    };
    let Some(paths) = c.host.paths() else {
        return c.fail(ERROR_CALL_NOT_IMPLEMENTED, INVALID_HANDLE_VALUE);
    };
    // get_nt_file_options: a plain open wants a file, not a directory, unless
    // backup semantics say either will do.
    let mut options = 0;
    if attributes & FILE_FLAG_BACKUP_SEMANTICS == 0 {
        options |= FILE_NON_DIRECTORY_FILE;
    }
    if attributes & FILE_FLAG_OPEN_REPARSE_POINT != 0 {
        options |= FILE_OPEN_REPARSE_POINT;
    }
    // SECURITY_ATTRIBUTES.bInheritHandle sits after the length and the
    // descriptor pointer.
    let inherit = sa != 0 && c.read_u32(sa + 16).is_some_and(|b| b != 0);
    let (how, _) = match nt::open_request(
        access | SYNCHRONIZE | FILE_READ_ATTRIBUTES,
        NT_DISPOSITION[creation - CREATE_NEW],
        options,
        if inherit { OBJ_INHERIT } else { 0 },
    ) {
        Ok(request) => request,
        Err(status) => return c.fail_status(status, INVALID_HANDLE_VALUE),
    };
    match paths.open(At::Cwd, &path, &how) {
        Ok(fd) => {
            let Ok(slot) = usize::try_from(fd) else {
                return c.fail_status(Ntstatus::UNSUCCESSFUL, INVALID_HANDLE_VALUE);
            };
            // Whether an existing file was found behind CREATE_ALWAYS or
            // OPEN_ALWAYS is not reported by the host, so the last error is
            // cleared rather than guessed at.
            c.set_last_error(0);
            let handle = Handle::from_slot(slot).0 as usize;
            c.finish(handle)
        }
        Err(errno) => c.fail_status(nt::status_from_errno(errno), INVALID_HANDLE_VALUE),
    }
}

/// ReadFile(hFile, lpBuffer, nNumberOfBytesToRead, lpNumberOfBytesRead,
/// lpOverlapped). The end of a file is not a failure here: the count is zero
/// and the call succeeds, as Wine treats STATUS_END_OF_FILE without an
/// OVERLAPPED.
pub fn read_file(c: &mut Call<'_>) -> Dispatch {
    let (handle, buffer, length, read, overlapped) =
        (c.arg(0), c.arg(1), c.arg(2), c.arg(3), c.arg(4));
    if read != 0 && !c.write_u32(read, 0) {
        return c.fail_status(Ntstatus::ACCESS_VIOLATION, FALSE);
    }
    if overlapped != 0 {
        return c.fail_status(Ntstatus::NOT_IMPLEMENTED, FALSE);
    }
    let handle = match descriptor(handle) {
        Ok(fd) => Handle::from_slot(fd as usize).0 as usize,
        Err(status) => return c.fail_status(status, FALSE),
    };
    let (status, information) =
        nt::transfer(c.host, false, handle, buffer, length, None).unwrap_or_else(|s| (s, 0));
    if status != Ntstatus::SUCCESS && status != Ntstatus::END_OF_FILE {
        return c.fail_status(status, FALSE);
    }
    if read != 0 && !c.write_u32(read, information as u32) {
        return c.fail_status(Ntstatus::ACCESS_VIOLATION, FALSE);
    }
    c.finish(TRUE)
}

/// GetFileType(hFile): what kind of thing the handle is, as its device type
/// says on Windows and its node kind says here.
pub fn get_file_type(c: &mut Call<'_>) -> Dispatch {
    let (Ok(fd), Some(paths)) = (descriptor(c.arg(0)), c.host.paths()) else {
        return c.fail_status(Ntstatus::INVALID_HANDLE, FILE_TYPE_UNKNOWN);
    };
    match paths.attributes_of(fd) {
        Ok(attr) => {
            c.set_last_error(0);
            c.finish(match attr.kind {
                NodeKind::CharDevice => FILE_TYPE_CHAR,
                NodeKind::Fifo | NodeKind::Socket => FILE_TYPE_PIPE,
                _ => FILE_TYPE_DISK,
            })
        }
        Err(errno) => c.fail_status(nt::status_from_errno(errno), FILE_TYPE_UNKNOWN),
    }
}

/// SetFilePointerEx(hFile, liDistanceToMove, lpNewFilePointer, dwMoveMethod).
pub fn set_file_pointer_ex(c: &mut Call<'_>) -> Dispatch {
    let (handle, distance, newpos, method) = (c.arg(0), c.arg(1) as i64, c.arg(2), c.arg(3));
    let (Ok(fd), Some(files)) = (descriptor(handle), c.host.files()) else {
        return c.fail_status(Ntstatus::INVALID_HANDLE, FALSE);
    };
    let from = match method {
        FILE_BEGIN if distance < 0 => return c.fail(ERROR_NEGATIVE_SEEK, FALSE),
        FILE_BEGIN => SeekFrom::Start(distance as u64),
        FILE_CURRENT => SeekFrom::Current(distance),
        FILE_END => SeekFrom::End(distance),
        _ => return c.fail(ERROR_INVALID_PARAMETER, FALSE),
    };
    match files.seek(fd, from) {
        Ok(pos) if pos >= 0 => {
            if newpos != 0 && !c.write_u64(newpos, pos as u64) {
                return c.fail_status(Ntstatus::ACCESS_VIOLATION, FALSE);
            }
            c.finish(TRUE)
        }
        Ok(_) => c.fail(ERROR_NEGATIVE_SEEK, FALSE),
        // A seek before the start is the one EINVAL a positioned handle gives.
        Err(errno) if errno == ax_abi_port::EINVAL && distance < 0 => {
            c.fail(ERROR_NEGATIVE_SEEK, FALSE)
        }
        Err(errno) => c.fail_status(nt::status_from_errno(errno), FALSE),
    }
}

/// GetFileSizeEx(hFile, lpFileSize).
pub fn get_file_size_ex(c: &mut Call<'_>) -> Dispatch {
    let (handle, out) = (c.arg(0), c.arg(1));
    let (Ok(fd), Some(paths)) = (descriptor(handle), c.host.paths()) else {
        return c.fail_status(Ntstatus::INVALID_HANDLE, FALSE);
    };
    match paths.attributes_of(fd) {
        Ok(attr) if c.write_u64(out, attr.size) => c.finish(TRUE),
        Ok(_) => c.fail_status(Ntstatus::ACCESS_VIOLATION, FALSE),
        Err(errno) => c.fail_status(nt::status_from_errno(errno), FALSE),
    }
}

/// FlushFileBuffers(hFile).
pub fn flush_file_buffers(c: &mut Call<'_>) -> Dispatch {
    let (Ok(fd), Some(files)) = (descriptor(c.arg(0)), c.host.files()) else {
        return c.fail_status(Ntstatus::INVALID_HANDLE, FALSE);
    };
    match files.fsync(fd, false) {
        Ok(_) => c.finish(TRUE),
        Err(errno) => c.fail_status(nt::status_from_errno(errno), FALSE),
    }
}

/// SetEndOfFile(hFile): the file ends where its pointer is.
pub fn set_end_of_file(c: &mut Call<'_>) -> Dispatch {
    let (Ok(fd), Some(files)) = (descriptor(c.arg(0)), c.host.files()) else {
        return c.fail_status(Ntstatus::INVALID_HANDLE, FALSE);
    };
    let at = match files.seek(fd, SeekFrom::Current(0)) {
        Ok(at) => at as u64,
        Err(errno) => return c.fail_status(nt::status_from_errno(errno), FALSE),
    };
    match files.ftruncate(fd, at) {
        Ok(_) => c.finish(TRUE),
        Err(errno) => c.fail_status(nt::status_from_errno(errno), FALSE),
    }
}

/// A FILETIME, split as the Win32 structures carry it.
fn file_time(ns: u64) -> [u8; 8] {
    nt::nt_time(ns).to_le_bytes()
}

/// GetFileAttributesExW(lpFileName, fInfoLevelId, lpFileInformation):
/// WIN32_FILE_ATTRIBUTE_DATA, at the one level there is.
pub fn get_file_attributes_ex(c: &mut Call<'_>) -> Dispatch {
    let (name, level, out) = (c.arg(0), c.arg(1), c.arg(2));
    if level != 0 {
        return c.fail(ERROR_INVALID_PARAMETER, FALSE);
    }
    let Some(path) = name_at(c, name).and_then(|n| host_path(c, &n)) else {
        return c.fail(ERROR_PATH_NOT_FOUND, FALSE);
    };
    let Some(paths) = c.host.paths() else {
        return c.fail(ERROR_CALL_NOT_IMPLEMENTED, FALSE);
    };
    let attr = match paths.attributes(At::Cwd, &path, true) {
        Ok(attr) => attr,
        Err(errno) => return c.fail_status(nt::status_from_errno(errno), FALSE),
    };
    let mut data = [0u8; 36];
    data[..4].copy_from_slice(&nt::file_attributes(&attr).to_le_bytes());
    // Creation time has no counterpart in what the host reports; the
    // status-change time stands in, as the NT layer answers too.
    data[4..12].copy_from_slice(&file_time(attr.changed_ns));
    data[12..20].copy_from_slice(&file_time(attr.accessed_ns));
    data[20..28].copy_from_slice(&file_time(attr.modified_ns));
    data[28..32].copy_from_slice(&((attr.size >> 32) as u32).to_le_bytes());
    data[32..36].copy_from_slice(&(attr.size as u32).to_le_bytes());
    if !c.write(out, &data) {
        return c.fail_status(Ntstatus::ACCESS_VIOLATION, FALSE);
    }
    c.finish(TRUE)
}

/// GetFileInformationByHandle(hFile, lpFileInformation):
/// BY_HANDLE_FILE_INFORMATION.
pub fn get_file_information_by_handle(c: &mut Call<'_>) -> Dispatch {
    let (handle, out) = (c.arg(0), c.arg(1));
    let (Ok(fd), Some(paths)) = (descriptor(handle), c.host.paths()) else {
        return c.fail_status(Ntstatus::INVALID_HANDLE, FALSE);
    };
    let attr = match paths.attributes_of(fd) {
        Ok(attr) => attr,
        Err(errno) => return c.fail_status(nt::status_from_errno(errno), FALSE),
    };
    let mut data = [0u8; 52];
    data[..4].copy_from_slice(&nt::file_attributes(&attr).to_le_bytes());
    data[4..12].copy_from_slice(&file_time(attr.changed_ns));
    data[12..20].copy_from_slice(&file_time(attr.accessed_ns));
    data[20..28].copy_from_slice(&file_time(attr.modified_ns));
    data[28..32].copy_from_slice(&(attr.device as u32).to_le_bytes()); // dwVolumeSerialNumber
    data[32..36].copy_from_slice(&((attr.size >> 32) as u32).to_le_bytes());
    data[36..40].copy_from_slice(&(attr.size as u32).to_le_bytes());
    data[40..44].copy_from_slice(&(attr.links as u32).to_le_bytes());
    data[44..48].copy_from_slice(&((attr.inode >> 32) as u32).to_le_bytes());
    data[48..52].copy_from_slice(&(attr.inode as u32).to_le_bytes());
    if !c.write(out, &data) {
        return c.fail_status(Ntstatus::ACCESS_VIOLATION, FALSE);
    }
    c.finish(TRUE)
}

/// DuplicateHandle(hSourceProcessHandle, hSourceHandle, hTargetProcessHandle,
/// lpTargetHandle, dwDesiredAccess, bInheritHandle, dwOptions): within this
/// process, another handle on the same file.
pub fn duplicate_handle(c: &mut Call<'_>) -> Dispatch {
    let (source, target_out) = (c.arg(1), c.arg(3));
    let (Ok(fd), Some(files)) = (descriptor(source), c.host.files()) else {
        return c.fail_status(Ntstatus::INVALID_HANDLE, FALSE);
    };
    match files.dup(fd) {
        Ok(new) if new >= 0 => {
            let handle = Handle::from_slot(new as usize).0 as u64;
            if target_out != 0 && !c.write_u64(target_out, handle) {
                return c.fail_status(Ntstatus::ACCESS_VIOLATION, FALSE);
            }
            c.finish(TRUE)
        }
        Ok(_) => c.fail_status(Ntstatus::UNSUCCESSFUL, FALSE),
        Err(errno) => c.fail_status(nt::status_from_errno(errno), FALSE),
    }
}

/// Write `text` as UTF-16 into a buffer of `size` units, or say how many it
/// needs - terminator included when it did not fit, excluded when it did, as
/// the path functions report.
fn answer_text(c: &mut Call<'_>, text: &str, buf: usize, size: usize) -> Dispatch {
    let units: Vec<u16> = text.encode_utf16().collect();
    if size <= units.len() {
        return c.finish(units.len() + 1);
    }
    let mut bytes: Vec<u8> = units.iter().flat_map(|u| u.to_le_bytes()).collect();
    bytes.extend_from_slice(&[0, 0]);
    if !c.write(buf, &bytes) {
        return c.fail_status(Ntstatus::ACCESS_VIOLATION, 0);
    }
    c.finish(units.len())
}

/// GetFullPathNameW(lpFileName, nBufferLength, lpBuffer, lpFilePart).
pub fn get_full_path_name(c: &mut Call<'_>) -> Dispatch {
    let (name, size, buf, file_part) = (c.arg(0), c.arg(1), c.arg(2), c.arg(3));
    let Some(full) = name_at(c, name).and_then(|n| full_windows_path(c, &n)) else {
        return c.fail(ERROR_INVALID_PARAMETER, 0);
    };
    let units = full.encode_utf16().count();
    let result = answer_text(c, &full, buf, size);
    if file_part != 0 && size > units {
        // The last component, or nothing for a name that ends in a separator.
        let at = match full.rfind('\\') {
            Some(i) if i + 1 < full.len() => buf + full[..i + 1].encode_utf16().count() * 2,
            _ => 0,
        };
        c.write_u64(file_part, at as u64);
    }
    result
}

/// GetTempPathW(nBufferLength, lpBuffer): where temporary files go, with its
/// trailing separator.
pub fn get_temp_path(c: &mut Call<'_>) -> Dispatch {
    let (size, buf) = (c.arg(0), c.arg(1));
    answer_text(c, "Z:\\tmp\\", buf, size)
}

/// SetCurrentDirectoryW(lpPathName): a directory that exists becomes the one
/// relative names go against, recorded in the parameters block where every
/// reader of it looks.
pub fn set_current_directory(c: &mut Call<'_>) -> Dispatch {
    let Some(name) = name_at(c, c.arg(0)) else {
        return c.fail(ERROR_INVALID_PARAMETER, FALSE);
    };
    let (Some(full), Some(path)) = (full_windows_path(c, &name), host_path(c, &name)) else {
        return c.fail(ERROR_PATH_NOT_FOUND, FALSE);
    };
    let Some(paths) = c.host.paths() else {
        return c.fail(ERROR_CALL_NOT_IMPLEMENTED, FALSE);
    };
    match paths.attributes(At::Cwd, &path, true) {
        Ok(attr) if attr.kind == NodeKind::Directory => {}
        Ok(_) => return c.fail(ERROR_DIRECTORY, FALSE),
        Err(errno) => return c.fail_status(nt::status_from_errno(errno), FALSE),
    }
    let Some(params) = c.params() else {
        return c.fail(ERROR_CALL_NOT_IMPLEMENTED, FALSE);
    };
    let mut text = full;
    if !text.ends_with('\\') {
        text.push('\\');
    }
    let units: Vec<u16> = text.encode_utf16().collect();
    let field = params + PARAMS_CURRENT_DIRECTORY;
    let room = u16::from_le_bytes(c.read::<2>(field + 2).unwrap_or([0, 0])) as usize;
    if (units.len() + 1) * 2 > room.max(MAX_PATH * 2) {
        return c.fail(ERROR_INSUFFICIENT_BUFFER, FALSE);
    }
    let Some((_, buf)) = c.unicode(field) else {
        return c.fail(ERROR_CALL_NOT_IMPLEMENTED, FALSE);
    };
    let mut bytes: Vec<u8> = units.iter().flat_map(|u| u.to_le_bytes()).collect();
    bytes.extend_from_slice(&[0, 0]);
    if !c.write(buf, &bytes) || !c.write(field, &((units.len() * 2) as u16).to_le_bytes()) {
        return c.fail_status(Ntstatus::ACCESS_VIOLATION, FALSE);
    }
    c.finish(TRUE)
}
