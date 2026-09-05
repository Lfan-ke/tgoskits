//! Section objects: shared memory the way `CreateFileMapping` and
//! `MapViewOfFile` present it.
//!
//! A section here is a file and its handle is that file's descriptor. Windows
//! keeps the object in the kernel and hands out a handle; a child receives one
//! by inheritance or duplication, and two processes that map the same section
//! see one another's writes. A descriptor already behaves that way - a child
//! starts with its parent's descriptors, and a file mapped shared is one
//! object however many address spaces hold it - so the only thing left to
//! decide is where a section with no file of its own lives. It gets one under
//! the temporary directory: named after itself when it has a name, so another
//! process can open the same one, and unlinked at once when it has none.

use alloc::{format, string::String};

use ax_abi_port::{At, Create, MapRequest, MapSource, OpenHow, Prot};

use super::{
    Call, Dispatch, ERROR_CALL_NOT_IMPLEMENTED, ERROR_INVALID_HANDLE, ERROR_INVALID_PARAMETER,
    ERROR_NOT_ENOUGH_MEMORY, FALSE, INVALID_HANDLE_VALUE, PEB_MAPPINGS, TRUE, heap,
};
use crate::{handle::Handle, nt, teb_peb::PEB_PROCESS_HEAP};

/// `ERROR_ALREADY_EXISTS`: what a create reports when it found the name
/// instead of making it, having returned a handle to it all the same.
const ERROR_ALREADY_EXISTS: u32 = 183;
/// `ERROR_FILE_INVALID`: a section of no size over a file of no size.
const ERROR_FILE_INVALID: u32 = 1006;

/// Where a section with no file of its own is kept.
const SECTION_DIR: &str = "/tmp/.sections";

// `MapViewOfFile`'s access rights (`memoryapi.h`).
const FILE_MAP_COPY: usize = 0x0001;
const FILE_MAP_WRITE: usize = 0x0002;
const FILE_MAP_READ: usize = 0x0004;
const FILE_MAP_EXECUTE: usize = 0x0020;

// `CreateFileMapping`'s page protections (`winnt.h`), only the ones a section
// can be made with.
const PAGE_READONLY: usize = 0x02;
const PAGE_READWRITE: usize = 0x04;
const PAGE_WRITECOPY: usize = 0x08;
const PAGE_EXECUTE_READ: usize = 0x20;
const PAGE_EXECUTE_READWRITE: usize = 0x40;
const PAGE_EXECUTE_WRITECOPY: usize = 0x80;

/// What a mapped view remembers: how much to unmap, and which section it is a
/// view of, so a second caller asking for the same one is given it back.
const VIEW_NEXT: usize = 0;
const VIEW_ADDR: usize = 8;
const VIEW_LEN: usize = 16;
const VIEW_FD: usize = 24;
const VIEW_SIZE: usize = 32;

fn heap_of(c: &Call<'_>) -> Option<usize> {
    c.peb()
        .and_then(|peb| c.read_u64(peb + PEB_PROCESS_HEAP))
        .map(|heap| heap as usize)
}

/// The host path a section name means. Windows namespaces a section with a
/// `Local\` or `Global\` prefix and allows anything but a backslash after it;
/// one tree is all there is here, so the prefix goes and what is left names a
/// file in one directory.
fn path_of(name: &str) -> String {
    let bare = name
        .rsplit('\\')
        .next()
        .filter(|part| !part.is_empty())
        .unwrap_or(name);
    let safe: String = bare
        .chars()
        .map(|ch| if ch.is_ascii_alphanumeric() { ch } else { '_' })
        .collect();
    format!("{SECTION_DIR}/{safe}")
}

fn how(create: Create) -> OpenHow {
    OpenHow {
        read: true,
        write: true,
        append: false,
        truncate: false,
        create,
        directory: false,
        follow: true,
        close_on_exec: false,
        mode: 0o600,
    }
}

/// Open the file a section lives in, making it when it is not there. Reports
/// whether it was already there, which is what `ERROR_ALREADY_EXISTS` says.
fn open_backing(c: &Call<'_>, path: &str, create: bool) -> Result<(i32, bool), i32> {
    let Some(paths) = c.host.paths() else {
        return Err(-1);
    };
    if !create {
        return paths
            .open(At::Cwd, path, &how(Create::Never))
            .map(|fd| (fd as i32, true));
    }
    // The directory is made on the way past rather than at startup: a program
    // that never asks for a section should not leave one behind.
    let _ = paths.mkdir(At::Cwd, SECTION_DIR, 0o777);
    match paths.open(At::Cwd, path, &how(Create::Exclusive)) {
        Ok(fd) => Ok((fd as i32, false)),
        Err(_) => paths
            .open(At::Cwd, path, &how(Create::Never))
            .map(|fd| (fd as i32, true)),
    }
}

/// CreateFileMappingA/W(hFile, lpAttributes, flProtect, dwMaximumSizeHigh,
/// dwMaximumSizeLow, lpName).
pub fn create_file_mapping(c: &mut Call<'_>) -> Dispatch {
    let (file, protect, name) = (c.arg(0), c.arg(2) as u32 as usize, c.arg(5));
    let size = ((c.arg(3) as u32 as u64) << 32) | c.arg(4) as u32 as u64;
    if !matches!(
        protect & 0xFF,
        PAGE_READONLY
            | PAGE_READWRITE
            | PAGE_WRITECOPY
            | PAGE_EXECUTE_READ
            | PAGE_EXECUTE_READWRITE
            | PAGE_EXECUTE_WRITECOPY
    ) {
        return c.fail(ERROR_INVALID_PARAMETER, 0);
    }
    let (Some(files), Some(paths)) = (c.host.files(), c.host.paths()) else {
        return c.fail(ERROR_CALL_NOT_IMPLEMENTED, 0);
    };
    // A section over a file of the caller's is that file; one over
    // INVALID_HANDLE_VALUE is backed by the paging file, which here is a file
    // of our own making.
    let (fd, existed) = if file != INVALID_HANDLE_VALUE && file != 0 {
        // The section keeps a descriptor of its own: closing the section
        // handle must not close the file the caller still holds.
        match super::file::descriptor(file)
            .and_then(|fd| files.dup(fd).map_err(nt::status_from_errno))
        {
            // Nothing was found rather than made here: a section over the
            // caller's own file has no name to have existed already, and
            // saying otherwise is what a named one says.
            Ok(fd) => (fd as i32, false),
            Err(status) => return c.fail_status(status, 0),
        }
    } else {
        match super::file::name_at_arg(c, name) {
            Some(name) => match open_backing(c, &path_of(&name), true) {
                Ok(pair) => pair,
                Err(errno) => return c.fail_status(nt::status_from_errno(errno), 0),
            },
            // No name and no file: a section only this process and the
            // children it makes can reach, so it is made under a name nobody
            // asked for and unlinked the moment it exists.
            None => match anonymous(c) {
                Some(fd) => (fd, false),
                None => return c.fail(ERROR_NOT_ENOUGH_MEMORY, 0),
            },
        }
    };
    // A section is as long as it says, and never shorter than the file it
    // covers: growing is the only direction, so a second opener asking for
    // less does not cut the first one's view away.
    let have = paths.attributes_of(fd).map(|a| a.size).unwrap_or(0);
    if size > have {
        if let Err(errno) = files.ftruncate(fd, size) {
            let _ = files.close(fd);
            return c.fail_status(nt::status_from_errno(errno), 0);
        }
    } else if size == 0 && have == 0 {
        let _ = files.close(fd);
        return c.fail(ERROR_FILE_INVALID, 0);
    }
    let Ok(slot) = usize::try_from(fd) else {
        let _ = files.close(fd);
        return c.fail(ERROR_INVALID_HANDLE, 0);
    };
    c.set_last_error(if existed { ERROR_ALREADY_EXISTS } else { 0 });
    c.finish(Handle::from_slot(slot).0 as usize)
}

/// A section with no name of its own: made under one nobody can collide with,
/// then unlinked, so what is left is a file only the descriptor reaches.
fn anonymous(c: &Call<'_>) -> Option<i32> {
    let paths = c.host.paths()?;
    let pid = c.host.tasks().and_then(|t| t.getpid().ok()).unwrap_or(0);
    let _ = paths.mkdir(At::Cwd, SECTION_DIR, 0o777);
    // Two processes can be here at once and a name can be left behind by one
    // that died between making and unlinking, so the first name that is not
    // taken wins rather than the first name tried.
    (0..MAX_ANONYMOUS).find_map(|n| {
        let path = format!("{SECTION_DIR}/anon.{pid}.{n}");
        let fd = paths.open(At::Cwd, &path, &how(Create::Exclusive)).ok()? as i32;
        let _ = paths.unlink(At::Cwd, &path);
        Some(fd)
    })
}

/// How many names an unnamed section tries before giving up.
const MAX_ANONYMOUS: u32 = 4096;

/// OpenFileMappingW(dwDesiredAccess, bInheritHandle, lpName).
pub fn open_file_mapping(c: &mut Call<'_>) -> Dispatch {
    let Some(name) = super::file::name_at_arg(c, c.arg(2)) else {
        return c.fail(ERROR_INVALID_PARAMETER, 0);
    };
    match open_backing(c, &path_of(&name), false) {
        Ok((fd, _)) => match usize::try_from(fd) {
            Ok(slot) => {
                c.set_last_error(0);
                c.finish(Handle::from_slot(slot).0 as usize)
            }
            Err(_) => c.fail(ERROR_INVALID_HANDLE, 0),
        },
        Err(errno) => c.fail_status(nt::status_from_errno(errno), 0),
    }
}

/// What a view of a section may do and whether its writes are anyone else's,
/// from the access asked for - or nothing when that is an access no view can
/// have. The order is `MapViewOfFile`'s own: write wins over read, and only an
/// access that is neither takes the copy, which is what makes
/// `FILE_MAP_ALL_ACCESS` a shared view rather than a private one despite
/// carrying `FILE_MAP_COPY`'s bit.
fn view_of(access: usize) -> Option<(Prot, bool)> {
    let (mut prot, shared) = if access & FILE_MAP_WRITE != 0 {
        (Prot::READ | Prot::WRITE, true)
    } else if access & FILE_MAP_READ != 0 {
        (Prot::READ, true)
    } else if access & FILE_MAP_COPY != 0 {
        (Prot::READ | Prot::WRITE, false)
    } else {
        return None;
    };
    if access & FILE_MAP_EXECUTE != 0 {
        prot |= Prot::EXEC;
    }
    Some((prot, shared))
}

/// MapViewOfFile(hFileMappingObject, dwDesiredAccess, dwFileOffsetHigh,
/// dwFileOffsetLow, dwNumberOfBytesToMap), and the `Ex` form that also names
/// where the view has to go.
pub fn map_view_of_file(c: &mut Call<'_>, at_address: bool) -> Dispatch {
    let (handle, access, bytes) = (c.arg(0), c.arg(1) as u32 as usize, c.arg(4));
    let want = if at_address { c.arg(5) } else { 0 };
    let offset = (((c.arg(2) as u32 as u64) << 32) | c.arg(3) as u32 as u64) as usize;
    let (Ok(fd), Some(mem), Some(paths)) = (
        super::file::descriptor(handle),
        c.host.mem(),
        c.host.paths(),
    ) else {
        return c.fail(ERROR_INVALID_HANDLE, 0);
    };
    let Some((prot, shared)) = view_of(access) else {
        return c.fail(ERROR_INVALID_PARAMETER, 0);
    };
    let Ok(size) = paths.attributes_of(fd).map(|a| a.size as usize) else {
        return c.fail(ERROR_INVALID_HANDLE, 0);
    };
    if offset >= size && size != 0 {
        return c.fail(ERROR_INVALID_PARAMETER, 0);
    }
    // A length of zero means the rest of the section, which is what a caller
    // that does not care how long it is passes.
    let len = match bytes {
        0 => size - offset,
        n if n <= size - offset => n,
        _ => return c.fail(ERROR_INVALID_PARAMETER, 0),
    };
    if len == 0 {
        return c.fail(ERROR_INVALID_PARAMETER, 0);
    }
    let at = mem.map(&MapRequest {
        addr: want,
        len,
        prot,
        fixed: want != 0,
        shared,
        source: MapSource::File { fd, offset },
    });
    match at {
        Ok(addr) if addr != 0 => {
            remember(c, addr as usize, len, fd);
            c.set_last_error(0);
            c.finish(addr as usize)
        }
        Ok(_) => c.fail(ERROR_NOT_ENOUGH_MEMORY, 0),
        Err(errno) => c.fail_status(nt::status_from_errno(errno), 0),
    }
}

/// Remember how long the view at `addr` is, since unmapping is told only where
/// it starts.
fn remember(c: &Call<'_>, addr: usize, len: usize, fd: i32) {
    let (Some(peb), Some(heap)) = (c.peb(), heap_of(c)) else {
        return;
    };
    let Some(block) = heap::alloc(c, heap, VIEW_SIZE) else {
        return;
    };
    let head = c.read_u64(peb + PEB_MAPPINGS).unwrap_or(0);
    c.write_u64(block + VIEW_NEXT, head);
    c.write_u64(block + VIEW_ADDR, addr as u64);
    c.write_u64(block + VIEW_LEN, len as u64);
    c.write_u32(block + VIEW_FD, fd as u32);
    c.write_u64(peb + PEB_MAPPINGS, block as u64);
}

/// The whole of the section `fd` names, mapped shared and readable and
/// writable, mapping it if this process has not already.
///
/// This is how a section reaches a process that never asked for it: a child
/// starts with its parent's descriptors, so the handle it is handed names the
/// same file, and mapping that file shared puts it on the same pages.
pub(super) fn attach(c: &Call<'_>, fd: i32) -> Option<(usize, bool)> {
    if let Some(addr) = view_for(c, fd) {
        return Some((addr, false));
    }
    let (mem, paths) = (c.host.mem()?, c.host.paths()?);
    let len = paths.attributes_of(fd).ok()?.size as usize;
    // A section holding one object is exactly a page. Anything else is some
    // other file that happens to have been handed to a call that takes a
    // handle, and mapping it whole to find that out would be its own harm.
    if len != PAGE {
        return None;
    }
    let addr = mem
        .map(&MapRequest {
            addr: 0,
            len,
            prot: Prot::READ | Prot::WRITE,
            fixed: false,
            shared: true,
            source: MapSource::File { fd, offset: 0 },
        })
        .ok()? as usize;
    (addr != 0).then(|| {
        remember(c, addr, len, fd);
        (addr, true)
    })
}

/// Unmap the view this process has of the section `fd` names, if it has one.
pub(super) fn detach(c: &Call<'_>, fd: i32) {
    let Some(peb) = c.peb() else { return };
    let mut at = c.read_u64(peb + PEB_MAPPINGS).unwrap_or(0) as usize;
    while at != 0 {
        let next = c.read_u64(at + VIEW_NEXT).unwrap_or(0) as usize;
        if c.read_u32(at + VIEW_FD) == Some(fd as u32)
            && let Some(addr) = c.read_u64(at + VIEW_ADDR)
        {
            let len = c.read_u64(at + VIEW_LEN).unwrap_or(0) as usize;
            if let Some(mem) = c.host.mem() {
                let _ = mem.unmap(addr as usize, len);
            }
            forget(c, addr as usize);
            return;
        }
        at = next;
    }
}

/// A section holding one object: one page, which is the least a mapping can
/// be and all such an object needs.
pub(super) const PAGE: usize = 4096;

/// Where this process already has the section `fd` names mapped, if it does.
pub(super) fn view_for(c: &Call<'_>, fd: i32) -> Option<usize> {
    let peb = c.peb()?;
    let mut at = c.read_u64(peb + PEB_MAPPINGS).unwrap_or(0) as usize;
    while at != 0 {
        if c.read_u32(at + VIEW_FD) == Some(fd as u32) {
            return c.read_u64(at + VIEW_ADDR).map(|addr| addr as usize);
        }
        at = c.read_u64(at + VIEW_NEXT).unwrap_or(0) as usize;
    }
    None
}

/// A section of `len` bytes with no name and no file behind it, mapped shared
/// and reported as the descriptor that names it and where it landed.
pub(super) fn anonymous_shared(c: &Call<'_>, len: usize) -> Option<(i32, usize)> {
    let (files, mem) = (c.host.files()?, c.host.mem()?);
    let fd = anonymous(c)?;
    let map = |fd: i32| {
        files.ftruncate(fd, len as u64).ok()?;
        let addr = mem
            .map(&MapRequest {
                addr: 0,
                len,
                prot: Prot::READ | Prot::WRITE,
                fixed: false,
                shared: true,
                source: MapSource::File { fd, offset: 0 },
            })
            .ok()? as usize;
        (addr != 0).then_some(addr)
    };
    match map(fd) {
        Some(addr) => {
            remember(c, addr, len, fd);
            Some((fd, addr))
        }
        None => {
            let _ = files.close(fd);
            None
        }
    }
}

/// Take the view at `addr` off the list, reporting how long it was.
fn forget(c: &Call<'_>, addr: usize) -> Option<usize> {
    let peb = c.peb()?;
    let mut at = c.read_u64(peb + PEB_MAPPINGS).unwrap_or(0) as usize;
    let mut previous = 0usize;
    while at != 0 {
        let next = c.read_u64(at + VIEW_NEXT).unwrap_or(0) as usize;
        if c.read_u64(at + VIEW_ADDR) == Some(addr as u64) {
            let len = c.read_u64(at + VIEW_LEN)? as usize;
            if previous == 0 {
                c.write_u64(peb + PEB_MAPPINGS, next as u64);
            } else {
                c.write_u64(previous + VIEW_NEXT, next as u64);
            }
            if let Some(heap) = heap_of(c) {
                heap::mark_free(c, heap, at);
            }
            return Some(len);
        }
        previous = at;
        at = next;
    }
    None
}

/// UnmapViewOfFile(lpBaseAddress).
pub fn unmap_view_of_file(c: &mut Call<'_>) -> Dispatch {
    let addr = c.arg(0);
    let Some(len) = forget(c, addr) else {
        return c.fail(ERROR_INVALID_PARAMETER, FALSE);
    };
    let Some(mem) = c.host.mem() else {
        return c.fail(ERROR_CALL_NOT_IMPLEMENTED, FALSE);
    };
    match mem.unmap(addr, len) {
        Ok(_) => {
            c.set_last_error(0);
            c.finish(TRUE)
        }
        Err(errno) => c.fail_status(nt::status_from_errno(errno), FALSE),
    }
}

/// FlushViewOfFile(lpBaseAddress, dwNumberOfBytesToFlush): a length of zero
/// means from `lpBaseAddress` to the end of the view.
pub fn flush_view_of_file(c: &mut Call<'_>) -> Dispatch {
    let (addr, bytes) = (c.arg(0), c.arg(1));
    let Some(mem) = c.host.mem() else {
        return c.fail(ERROR_CALL_NOT_IMPLEMENTED, FALSE);
    };
    let len = match bytes {
        0 => view_len(c, addr).unwrap_or(0),
        n => n,
    };
    match mem.writeback(addr, len) {
        Ok(_) => {
            c.set_last_error(0);
            c.finish(TRUE)
        }
        Err(errno) => c.fail_status(nt::status_from_errno(errno), FALSE),
    }
}

/// How much of the view starting at or covering `addr` is left after it.
fn view_len(c: &Call<'_>, addr: usize) -> Option<usize> {
    let peb = c.peb()?;
    let mut at = c.read_u64(peb + PEB_MAPPINGS).unwrap_or(0) as usize;
    while at != 0 {
        let start = c.read_u64(at + VIEW_ADDR)? as usize;
        let len = c.read_u64(at + VIEW_LEN)? as usize;
        if (start..start + len).contains(&addr) {
            return Some(start + len - addr);
        }
        at = c.read_u64(at + VIEW_NEXT).unwrap_or(0) as usize;
    }
    None
}
