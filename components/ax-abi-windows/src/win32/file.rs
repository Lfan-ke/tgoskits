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
    // CreateFileW's dwDesiredAccess / dwCreationDisposition /
    // dwFlagsAndAttributes are 32-bit DWORDs; the x64 stack slots carrying
    // them may leave the upper 32 bits dirty, so truncate before use (a
    // dirty disposition like 0x1_0000_0003 must read as OPEN_EXISTING).
    let (name, access, sa, creation, attributes) = (
        c.arg(0),
        c.arg(1) as u32 as usize,
        c.arg(3),
        c.arg(4) as u32 as usize,
        c.arg(5) as u32 as usize,
    );
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

const E_INVALIDARG: usize = 0x8007_0057;
const S_OK: usize = 0;
const INVALID_FILE_ATTRIBUTES: usize = usize::MAX;

/// Write a UTF-16 string with its terminator at `at`.
fn write_wide(c: &Call<'_>, at: usize, text: &str) -> bool {
    let mut bytes: Vec<u8> = text.encode_utf16().flat_map(u16::to_le_bytes).collect();
    bytes.extend_from_slice(&[0, 0]);
    c.write(at, &bytes)
}

/// Where the root of a Windows path ends, as a character offset, following
/// `get_root_end` in Wine's `kernelbase/path.c`. `None` for a path with no
/// root this recognizes.
fn root_end(units: &[u16]) -> Option<usize> {
    let at = |i: usize| units.get(i).copied().unwrap_or(0);
    let is_drive = at(0) < 0x80 && (at(0) as u8).is_ascii_alphabetic() && at(1) == u16::from(b':');
    if at(0) == u16::from(b'\\') && at(1) == u16::from(b'\\') {
        Some(1)
    } else if at(0) == u16::from(b'\\') {
        Some(0)
    } else if is_drive {
        Some(if at(2) == u16::from(b'\\') { 2 } else { 1 })
    } else {
        None
    }
}

/// PathCchSkipRoot(path, root_end): write, through `root_end`, a pointer just
/// past the path's root. `\\` shares are not produced here, so the drive and
/// rooted cases are what this serves.
pub fn path_cch_skip_root(c: &mut Call<'_>) -> Dispatch {
    let (path, out) = (c.arg(0), c.arg(1));
    let Some(units) = c.read_wstr(path) else {
        return c.finish(E_INVALIDARG);
    };
    if units.is_empty() || out == 0 {
        return c.finish(E_INVALIDARG);
    }
    match root_end(&units) {
        // One past the root: get_root_end then the `++` Wine applies.
        Some(end) if c.write_u64(out, (path + (end + 1) * 2) as u64) => c.finish(S_OK),
        Some(_) => c.fail_status(Ntstatus::ACCESS_VIOLATION, E_INVALIDARG),
        None => c.finish(E_INVALIDARG),
    }
}

/// PathCchCombineEx(out, size, path1, path2, flags): path2 against path1, or
/// path2 alone when it is absolute, canonicalized lexically. `size` is in
/// characters.
pub fn path_cch_combine_ex(c: &mut Call<'_>) -> Dispatch {
    let (out, size, p1, p2) = (c.arg(0), c.arg(1), c.arg(2), c.arg(3));
    if out == 0 || size == 0 {
        return c.finish(E_INVALIDARG);
    }
    let s1 = name_at(c, p1).unwrap_or_default();
    let s2 = name_at(c, p2).unwrap_or_default();
    let s2_absolute = root_end(&s2.encode_utf16().collect::<Vec<_>>()).is_some();
    let combined = if s2.is_empty() {
        s1
    } else if s2_absolute || s1.is_empty() {
        s2
    } else {
        let sep = if s1.ends_with('\\') { "" } else { "\\" };
        alloc::format!("{s1}{sep}{s2}")
    };
    // Lexical .. and . folding, keeping the drive.
    let combined = canonicalize(&combined);
    if combined.encode_utf16().count() + 1 > size {
        return c.finish(0x8007_007A); // HRESULT_FROM_WIN32(ERROR_INSUFFICIENT_BUFFER)
    }
    if !write_wide(c, out, &combined) {
        return c.fail_status(Ntstatus::ACCESS_VIOLATION, E_INVALIDARG);
    }
    c.finish(S_OK)
}

/// Fold `.` and `..` out of a Windows path lexically, keeping any drive.
fn canonicalize(path: &str) -> String {
    let (drive, rest) = match path.as_bytes() {
        [d, b':', ..] if d.is_ascii_alphabetic() => (&path[..2], &path[2..]),
        _ => ("", path),
    };
    let rooted = rest.starts_with('\\') || rest.starts_with('/');
    let mut parts: Vec<&str> = Vec::new();
    for part in rest.split(['\\', '/']) {
        match part {
            "" | "." => {}
            ".." => {
                parts.pop();
            }
            p => parts.push(p),
        }
    }
    let mut out = String::from(drive);
    if rooted {
        out.push('\\');
    }
    out.push_str(&parts.join("\\"));
    out
}

/// GetFileAttributesW(lpFileName): the attribute word, or INVALID with the
/// error the host's refusal means.
pub fn get_file_attributes_w(c: &mut Call<'_>) -> Dispatch {
    const ERROR_PATH_NOT_FOUND: u32 = 3;
    let Some(path) = name_at(c, c.arg(0)).and_then(|n| host_path(c, &n)) else {
        return c.fail(ERROR_PATH_NOT_FOUND, INVALID_FILE_ATTRIBUTES);
    };
    let Some(paths) = c.host.paths() else {
        return c.fail(super::ERROR_CALL_NOT_IMPLEMENTED, INVALID_FILE_ATTRIBUTES);
    };
    match paths.attributes(At::Cwd, &path, true) {
        Ok(attr) => {
            c.set_last_error(0);
            c.finish(nt::file_attributes(&attr) as usize)
        }
        Err(errno) => c.fail_status(nt::status_from_errno(errno), INVALID_FILE_ATTRIBUTES),
    }
}

/// GetFileInformationByHandleEx(hFile, class, info, size): the classes a
/// runtime reads about an open file - basic, standard and attribute-tag - out
/// of what the host describes. A class this does not answer says so, as Wine's
/// unimplemented ones do, rather than leave the caller a filled-looking buffer.
pub fn get_file_information_by_handle_ex(c: &mut Call<'_>) -> Dispatch {
    const FILE_BASIC_INFO: usize = 0;
    const FILE_STANDARD_INFO: usize = 1;
    const FILE_ATTRIBUTE_TAG_INFO: usize = 9;
    const FILE_ID_INFO: usize = 18;
    let (handle, class, info) = (c.arg(0), c.arg(1), c.arg(2));
    let (Ok(fd), Some(paths)) = (descriptor(handle), c.host.paths()) else {
        return c.fail_status(Ntstatus::INVALID_HANDLE, FALSE);
    };
    let attr = match paths.attributes_of(fd) {
        Ok(attr) => attr,
        Err(errno) => return c.fail_status(nt::status_from_errno(errno), FALSE),
    };
    let attributes = nt::file_attributes(&attr);
    let ok = match class {
        FILE_BASIC_INFO => {
            // FILE_BASIC_INFO: four times, then the attribute word.
            let mut buf = [0u8; 40];
            buf[..8].copy_from_slice(&file_time(attr.changed_ns));
            buf[8..16].copy_from_slice(&file_time(attr.accessed_ns));
            buf[16..24].copy_from_slice(&file_time(attr.modified_ns));
            buf[24..32].copy_from_slice(&file_time(attr.changed_ns));
            buf[32..36].copy_from_slice(&attributes.to_le_bytes());
            c.write(info, &buf)
        }
        FILE_STANDARD_INFO => {
            // AllocationSize, EndOfFile, NumberOfLinks, DeletePending, Directory.
            let mut buf = [0u8; 24];
            buf[..8].copy_from_slice(&attr.size.to_le_bytes());
            buf[8..16].copy_from_slice(&attr.size.to_le_bytes());
            buf[16..20].copy_from_slice(&(attr.links as u32).to_le_bytes());
            buf[21] = u8::from(attr.kind == NodeKind::Directory);
            c.write(info, &buf)
        }
        FILE_ATTRIBUTE_TAG_INFO => {
            let mut buf = [0u8; 8];
            buf[..4].copy_from_slice(&attributes.to_le_bytes());
            c.write(info, &buf)
        }
        // FILE_ID_INFO: the volume serial and a 128-bit file id, which os.stat
        // uses to tell files apart. The device and inode the host reports fill
        // both; the id's high half is zero, as a 64-bit inode leaves it.
        FILE_ID_INFO => {
            let mut buf = [0u8; 24];
            buf[..8].copy_from_slice(&attr.device.to_le_bytes());
            buf[8..16].copy_from_slice(&attr.inode.to_le_bytes());
            c.write(info, &buf)
        }
        _ => {
            c.host.platform().trace(&alloc::format!(
                "GetFileInformationByHandleEx class {class} is not implemented"
            ));
            return c.fail(super::ERROR_CALL_NOT_IMPLEMENTED, FALSE);
        }
    };
    if ok {
        c.finish(TRUE)
    } else {
        c.fail_status(Ntstatus::ACCESS_VIOLATION, FALSE)
    }
}

// A directory search's state lives in the process heap: FindFirstFileW takes a
// snapshot of the matching entries there and returns its address as the find
// handle, FindNextFileW advances a cursor in it, and FindClose frees it. The
// block is a small header then one fixed-width record per entry.
const FIND_MAGIC: u64 = 0x444E_4946_5241_5852; // "RXARFIND"
const FIND_COUNT: usize = 8;
const FIND_CURSOR: usize = 12;
const FIND_HEADER: usize = 16;
/// Per-entry: the attribute word, the name length in units, then the name.
const FIND_NAME: usize = 260;
const FIND_RECORD: usize = 8 + FIND_NAME * 2;
const ERROR_FILE_NOT_FOUND: u32 = 2;
const ERROR_NO_MORE_FILES: u32 = 18;

/// Fill one WIN32_FIND_DATAW at `out` from a record at `rec` in the snapshot.
fn write_find_data(c: &Call<'_>, out: usize, rec: usize) -> bool {
    let Some(attr) = c.read_u32(rec) else {
        return false;
    };
    let Some(len) = c.read::<2>(rec + 4).map(u16::from_le_bytes) else {
        return false;
    };
    let mut data = [0u8; 592];
    data[..4].copy_from_slice(&attr.to_le_bytes());
    // cFileName is at offset 0x2C; copy the stored name and its terminator.
    let name_bytes = (usize::from(len) + 1) * 2;
    let mut name = alloc::vec![0u8; name_bytes.min(FIND_NAME * 2)];
    if c.host.platform().read_user(rec + 8, &mut name).is_err() {
        return false;
    }
    data[0x2C..0x2C + name.len()].copy_from_slice(&name);
    c.write(out, &data)
}

/// FindFirstFileW(lpFileName, lpFindFileData): open the directory the pattern
/// names, snapshot its entries into the process heap, and report the first.
/// The only patterns a runtime uses are a whole-directory `*` and a specific
/// name; both are served, and a directory with no match is reported as empty.
pub fn find_first_file(c: &mut Call<'_>) -> Dispatch {
    let (pattern, out) = (c.arg(0), c.arg(1));
    let Some(spec) = name_at(c, pattern) else {
        return c.fail(ERROR_FILE_NOT_FOUND, INVALID_HANDLE_VALUE);
    };
    // Split the last component off as the match; the rest is the directory.
    let (dir, want) = match spec.rsplit_once('\\') {
        Some((dir, last)) => (dir, last),
        None => (".", spec.as_str()),
    };
    let want = String::from(want);
    let all = want == "*" || want == "*.*";
    let Some(dir_host) = host_path(c, dir) else {
        return c.fail(ERROR_FILE_NOT_FOUND, INVALID_HANDLE_VALUE);
    };
    let Some(paths) = c.host.paths() else {
        return c.fail(super::ERROR_CALL_NOT_IMPLEMENTED, INVALID_HANDLE_VALUE);
    };
    // Open the directory to enumerate it; a plain open with the directory bit.
    let how = ax_abi_port::OpenHow {
        read: true,
        write: false,
        append: false,
        truncate: false,
        create: ax_abi_port::Create::Never,
        directory: true,
        follow: true,
        close_on_exec: true,
        mode: 0,
    };
    let dir_fd = match paths.open(At::Cwd, &dir_host, &how) {
        Ok(fd) => fd as i32,
        Err(errno) => return c.fail_status(nt::status_from_errno(errno), INVALID_HANDLE_VALUE),
    };
    // Collect the matching names and kinds.
    let mut entries: Vec<(String, bool)> = Vec::new();
    let mut overflow = false;
    let _ = paths.read_dir(dir_fd, &mut |name, kind| {
        if entries.len() >= 4096 {
            overflow = true;
            return false;
        }
        if all || name == want {
            entries.push((String::from(name), kind == NodeKind::Directory));
        }
        true
    });
    if let Some(files) = c.host.files() {
        let _ = files.close(dir_fd);
    }
    let _ = overflow;
    if entries.is_empty() {
        return c.fail(ERROR_FILE_NOT_FOUND, INVALID_HANDLE_VALUE);
    }
    // Snapshot into the process heap.
    let Some(peb) = c.peb() else {
        return c.fail(super::ERROR_CALL_NOT_IMPLEMENTED, INVALID_HANDLE_VALUE);
    };
    let Some(heap) = c
        .read_u64(peb + crate::teb_peb::PEB_PROCESS_HEAP)
        .map(|h| h as usize)
    else {
        return c.fail(super::ERROR_CALL_NOT_IMPLEMENTED, INVALID_HANDLE_VALUE);
    };
    let need = FIND_HEADER + entries.len() * FIND_RECORD;
    let Some(block) = super::heap::alloc(c, heap, need) else {
        return c.fail(super::ERROR_NOT_ENOUGH_MEMORY, INVALID_HANDLE_VALUE);
    };
    c.write(block, &FIND_MAGIC.to_le_bytes());
    c.write_u32(block + FIND_COUNT, entries.len() as u32);
    for (i, (name, is_dir)) in entries.iter().enumerate() {
        let rec = block + FIND_HEADER + i * FIND_RECORD;
        // FILE_ATTRIBUTE_DIRECTORY (0x10) or FILE_ATTRIBUTE_NORMAL (0x80).
        c.write_u32(rec, if *is_dir { 0x10 } else { 0x80 });
        let units: Vec<u16> = name.encode_utf16().take(FIND_NAME - 1).collect();
        c.write(rec + 4, &(units.len() as u16).to_le_bytes());
        let bytes: Vec<u8> = units.iter().flat_map(|u| u.to_le_bytes()).collect();
        c.write(rec + 8, &bytes);
    }
    // The first entry, and the cursor left at the second.
    if !write_find_data(c, out, block + FIND_HEADER) {
        return c.fail_status(Ntstatus::ACCESS_VIOLATION, INVALID_HANDLE_VALUE);
    }
    c.write_u32(block + FIND_CURSOR, 1);
    c.set_last_error(0);
    c.finish(block)
}

/// FindNextFileW(hFindFile, lpFindFileData): the next entry from the snapshot,
/// or ERROR_NO_MORE_FILES when it is exhausted.
pub fn find_next_file(c: &mut Call<'_>) -> Dispatch {
    let (block, out) = (c.arg(0), c.arg(1));
    if c.read_u64(block) != Some(FIND_MAGIC) {
        return c.fail(super::ERROR_INVALID_PARAMETER, FALSE);
    }
    let count = c.read_u32(block + FIND_COUNT).unwrap_or(0);
    let cursor = c.read_u32(block + FIND_CURSOR).unwrap_or(count);
    if cursor >= count {
        return c.fail(ERROR_NO_MORE_FILES, FALSE);
    }
    let rec = block + FIND_HEADER + cursor as usize * FIND_RECORD;
    if !write_find_data(c, out, rec) {
        return c.fail_status(Ntstatus::ACCESS_VIOLATION, FALSE);
    }
    c.write_u32(block + FIND_CURSOR, cursor + 1);
    c.finish(TRUE)
}

/// FindClose(hFindFile): free the snapshot.
pub fn find_close(c: &mut Call<'_>) -> Dispatch {
    let block = c.arg(0);
    if c.read_u64(block) == Some(FIND_MAGIC) {
        super::heap::mark_free(c, block);
    }
    c.finish(TRUE)
}

/// SetHandleInformation(hObject, dwMask, dwFlags): inheritance and protection
/// flags on a handle. Nothing here inherits handles across a spawn, so the
/// request is accepted and has no further effect.
pub fn set_handle_information(c: &mut Call<'_>) -> Dispatch {
    c.finish(TRUE)
}

/// GetFinalPathNameByHandleW(hFile, lpszFilePath, cchFilePath, dwFlags): the
/// full path the handle refers to. The default flags want a DOS volume name
/// with the `\\?\` prefix, which is what CPython strips to locate itself; the
/// host names the descriptor and the drive is put back on. The return is the
/// length written, not counting the terminator, or the length needed when the
/// buffer is too small - as the function reports.
pub fn get_final_path_name_by_handle(c: &mut Call<'_>) -> Dispatch {
    let (handle, buf, size) = (c.arg(0), c.arg(1), c.arg(2));
    let Ok(fd) = descriptor(handle) else {
        return c.fail_status(Ntstatus::INVALID_HANDLE, 0);
    };
    let Some(paths) = c.host.paths() else {
        return c.fail(super::ERROR_CALL_NOT_IMPLEMENTED, 0);
    };
    let mut host = String::new();
    if paths.path_of(fd, &mut |p| host.push_str(p)).is_err() {
        return c.fail_status(Ntstatus::INVALID_HANDLE, 0);
    }
    // The host path is single-rooted; Windows sees it under drive Z, spelled
    // with backslashes and prefixed as the object-namespace form the default
    // flags return.
    let win: String = host
        .chars()
        .map(|ch| if ch == '/' { '\\' } else { ch })
        .collect();
    let full = alloc::format!("\\\\?\\Z:{win}");
    let units: Vec<u16> = full.encode_utf16().collect();
    if size <= units.len() {
        return c.finish(units.len() + 1);
    }
    if !write_wide(c, buf, &full) {
        return c.fail_status(Ntstatus::ACCESS_VIOLATION, 0);
    }
    c.set_last_error(0);
    c.finish(units.len())
}
