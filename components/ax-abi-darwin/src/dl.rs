//! `dlopen` and its kin: bringing an image in after the program has started.
//!
//! This is the same work [`crate::link`] does before the first instruction -
//! place the image, apply its rebase and bind streams - done from a trap, with
//! the host's memory port instead of the loader's. What the two share is the
//! record of what is loaded: a table in the process's own memory, one entry
//! per image, written at load and added to here. Nothing about the process is
//! kept on this side of the trap, so a lookup reads an image's export trie
//! from where the image itself is mapped, as dyld does.

use alloc::{string::String, vec::Vec};

use ax_abi_port::{At, Create, Host, MapRequest, MapSource, OpenHow, Prot, SysResult};
use ax_binfmt::{AbiError, AbiResult, LoadEnv, dyld, macho};

use crate::{
    PAGE,
    link::{self, Module},
    system::{Library, PRIVATE_DL_ERROR, PRIVATE_DL_TEXT, PRIVATE_MODULES, PRIVATE_MODULES_AT},
    user,
};

const ENOEXEC: i32 = 8;
/// `ENOSYS`, in Darwin's numbering.
const ENOSYS: i32 = 78;

/// One entry of the loaded-image table: where the image's header is, how far
/// it was moved, where it ends, and the path it was loaded by.
pub const ENTRY_LEN: u64 = 256;
pub const ENTRY_HEADER: u64 = 0;
pub const ENTRY_SLIDE: u64 = 8;
pub const ENTRY_END: u64 = 16;
pub const ENTRY_PATH: u64 = 24;
/// How many images the table has room for.
pub const ENTRY_LIMIT: u64 = 64;

/// One table entry, as the loader writes it.
pub fn entry(header: u64, slide: u64, end: u64, path: &str) -> Vec<u8> {
    let mut out = alloc::vec![0u8; ENTRY_LEN as usize];
    out[..8].copy_from_slice(&header.to_le_bytes());
    out[8..16].copy_from_slice(&slide.to_le_bytes());
    out[16..24].copy_from_slice(&end.to_le_bytes());
    let room = (ENTRY_LEN - ENTRY_PATH - 1) as usize;
    let bytes = &path.as_bytes()[..path.len().min(room)];
    out[ENTRY_PATH as usize..ENTRY_PATH as usize + bytes.len()].copy_from_slice(bytes);
    out
}

/// An image the table names.
struct Image {
    /// Where its table entry is.
    at: usize,
    header: u64,
    slide: u64,
    end: u64,
}

fn images(host: &dyn Host, library: &Library) -> Result<Vec<Image>, i32> {
    let table = user::u64_at(host, (library.private() + PRIVATE_MODULES_AT) as usize)? as usize;
    let count = user::u64_at(host, (library.private() + PRIVATE_MODULES) as usize)?;
    let mut out = Vec::new();
    for index in 0..count.min(ENTRY_LIMIT) as usize {
        let at = table + index * ENTRY_LEN as usize;
        out.push(Image {
            at,
            header: user::u64_at(host, at + ENTRY_HEADER as usize)?,
            slide: user::u64_at(host, at + ENTRY_SLIDE as usize)?,
            end: user::u64_at(host, at + ENTRY_END as usize)?,
        });
    }
    Ok(out)
}

/// Every symbol `image` exports and where it is, read from the image as it
/// sits in the process.
fn exports(host: &dyn Host, image: &Image) -> Result<Vec<(String, u64)>, i32> {
    let head = user::bytes(host, image.header as usize, 32)?;
    let commands = u32::from_le_bytes([head[20], head[21], head[22], head[23]]) as usize;
    let head = user::bytes(host, image.header as usize, 32 + commands)?;
    let info = macho::parse(&head).ok_or(ENOEXEC)?;
    let Some(streams) = dyld::info(&head, info.commands_off, info.ncmds, info.sizeofcmds) else {
        return Ok(Vec::new());
    };
    let offset = u64::from(streams.export_off);
    let Some(segment) = info
        .segments(&head)
        .find(|s| (s.fileoff..s.fileoff + s.filesize).contains(&offset))
    else {
        return Ok(Vec::new());
    };
    let at = image.slide + segment.vmaddr + (offset - segment.fileoff);
    let trie = user::bytes(host, at as usize, streams.export_size as usize)?;
    let mut out = Vec::new();
    dyld::exports(&trie, &mut |export| {
        if !export.reexport() {
            out.push((String::from(export.name), image.header + export.address));
        }
    });
    Ok(out)
}

/// Leave `text` for the next `dlerror` to hand back, and answer with null.
fn fail(host: &dyn Host, library: &Library, text: &str) -> SysResult {
    let room = 255.min(text.len());
    user::put_cstr(
        host,
        (library.private() + PRIVATE_DL_TEXT) as usize,
        &text.as_bytes()[..room],
    )?;
    user::put_u64(host, (library.private() + PRIVATE_DL_ERROR) as usize, 1)?;
    host.platform().trace(text);
    Ok(0)
}

/// `dlerror()`: what went wrong since the last call, once.
pub fn dlerror(host: &dyn Host, library: &Library) -> SysResult {
    let flag = (library.private() + PRIVATE_DL_ERROR) as usize;
    if user::u64_at(host, flag)? == 0 {
        return Ok(0);
    }
    user::put_u64(host, flag, 0)?;
    Ok((library.private() + PRIVATE_DL_TEXT) as isize)
}

/// `dladdr(address, info)`: which image an address is in.
pub fn dladdr(host: &dyn Host, library: &Library, address: usize, info: usize) -> SysResult {
    for image in images(host, library)? {
        if (image.header..image.end).contains(&(address as u64)) {
            user::put_u64(host, info, (image.at + ENTRY_PATH as usize) as u64)?;
            user::put_u64(host, info + 8, image.header)?;
            user::put_u64(host, info + 16, 0)?;
            user::put_u64(host, info + 24, 0)?;
            return Ok(1);
        }
    }
    Ok(0)
}

/// `dlsym(handle, name)`. A handle is an image's header; the pseudo-handles
/// (`RTLD_DEFAULT` and the rest, which are small negative numbers) search
/// every image.
pub fn dlsym(host: &dyn Host, library: &Library, handle: usize, name: usize) -> SysResult {
    let mut symbol = String::from("_");
    symbol.push_str(&user::name(host, name)?);
    let everywhere = (handle as isize) < 0 && (handle as isize) >= -8;
    for image in images(host, library)? {
        if !everywhere && image.header != handle as u64 {
            continue;
        }
        if let Some((_, at)) = exports(host, &image)?
            .into_iter()
            .find(|(name, _)| *name == symbol)
        {
            return Ok(at as isize);
        }
    }
    if everywhere && let Some(at) = library.address(&symbol) {
        return Ok(at as isize);
    }
    fail(host, library, &alloc::format!("dlsym: {symbol} not found"))
}

/// The loader's interface over nothing but a log: the fixup pass only reports
/// through it, and everything it would map is mapped here instead.
struct Log<'a>(&'a dyn Host);

impl LoadEnv for Log<'_> {
    fn map_region(
        &mut self,
        _: u64,
        _: u64,
        _: ax_binfmt::Prot,
        _: Option<&[u8]>,
    ) -> AbiResult<()> {
        Err(AbiError::Unsupported)
    }

    fn map_image(&mut self, _: u64, _: u64, _: ax_binfmt::Prot, _: u64, _: u64) -> AbiResult<()> {
        Err(AbiError::Unsupported)
    }

    fn read_image(&mut self, _: u64, _: &mut [u8]) -> AbiResult<usize> {
        Err(AbiError::Unsupported)
    }

    fn trace(&mut self, message: &str) {
        self.0.platform().trace(message);
    }
}

/// The whole of the file at `path`, read through a block of the program's own
/// memory, since that is where the host's read puts what it reads.
fn read_file(host: &dyn Host, path: &str) -> Result<Vec<u8>, i32> {
    let how = OpenHow {
        read: true,
        write: false,
        append: false,
        truncate: false,
        create: Create::Never,
        directory: false,
        follow: true,
        close_on_exec: true,
        mode: 0,
    };
    let paths = host.paths().ok_or(ENOSYS)?;
    let files = host.files().ok_or(ENOSYS)?;
    let mem = host.mem().ok_or(ENOSYS)?;
    let fd = paths.open(At::Cwd, path, &how)? as i32;
    let read = (|| {
        let len = paths.attributes_of(fd)?.size as usize;
        let span = len.div_ceil(PAGE as usize).max(1) * PAGE as usize;
        let scratch = mem.map(&MapRequest {
            addr: 0,
            len: span,
            prot: Prot::READ | Prot::WRITE,
            fixed: false,
            shared: false,
            source: MapSource::Anonymous,
        })? as usize;
        let mut got = 0;
        let outcome = loop {
            if got == len {
                break Ok(());
            }
            match files.pread(fd, scratch + got, len - got, got as u64) {
                Ok(0) => break Ok(()),
                Ok(n) => got += n as usize,
                Err(errno) => break Err(errno),
            }
        };
        let bytes = outcome.and_then(|()| user::bytes(host, scratch, got));
        mem.unmap(scratch, span)?;
        bytes
    })();
    let _ = files.close(fd);
    read
}

fn prot_of(segment: &macho::Segment) -> Prot {
    let mut prot = Prot::empty();
    prot.set(Prot::READ, segment.readable());
    prot.set(Prot::WRITE, segment.writable());
    prot.set(Prot::EXEC, segment.executable());
    prot
}

/// `dlopen(path, mode)`. A null path asks for the program itself.
pub fn dlopen(host: &dyn Host, library: &Library, path: usize) -> SysResult {
    let loaded = images(host, library)?;
    if path == 0 {
        return Ok(loaded.first().map_or(0, |image| image.header as isize));
    }
    let path = user::name(host, path)?;
    for image in &loaded {
        if user::cstr(host, image.at + ENTRY_PATH as usize)? == path.as_bytes() {
            return Ok(image.header as isize);
        }
    }
    if loaded.len() as u64 >= ENTRY_LIMIT {
        return fail(host, library, "dlopen: the loaded-image table is full");
    }
    let bytes = match read_file(host, &path) {
        Ok(bytes) => bytes,
        Err(errno) => {
            return fail(
                host,
                library,
                &alloc::format!("dlopen: {path} could not be read (errno {errno})"),
            );
        }
    };
    let Some(info) = macho::parse(&bytes) else {
        return fail(
            host,
            library,
            &alloc::format!("dlopen: {path} is not a Mach-O image"),
        );
    };

    // Where it goes is the host's to choose: the whole span is reserved in one
    // mapping, which is also what the segments are then written into.
    let unplaced = link::module(path.clone(), bytes, info, 0);
    let span = unplaced.end().div_ceil(PAGE) * PAGE;
    if span == 0 {
        return fail(
            host,
            library,
            &alloc::format!("dlopen: {path} has no segments"),
        );
    }
    let mem = host.mem().ok_or(ENOSYS)?;
    let slide = mem.map(&MapRequest {
        addr: 0,
        len: span as usize,
        prot: Prot::READ | Prot::WRITE,
        fixed: false,
        shared: false,
        source: MapSource::Anonymous,
    })? as u64;
    let Module { bytes, info, .. } = unplaced;
    let mut modules = alloc::vec![link::module(path.clone(), bytes, info, slide)];

    // What the image binds from the images already here.
    let mut known: Vec<(String, u64)> = Vec::new();
    for image in &loaded {
        known.extend(exports(host, image)?);
    }
    known.sort();
    let lookup = |symbol: &str| {
        known
            .binary_search_by(|(name, _)| name.as_str().cmp(symbol))
            .ok()
            .map(|at| known[at].1)
    };
    let fixed = match link::fixups_with(&modules, 0, library, &mut Log(host), &lookup) {
        Ok(fixed) => fixed,
        Err(_) => {
            mem.unmap(slide as usize, span as usize)?;
            return fail(
                host,
                library,
                &alloc::format!("dlopen: {path} names a symbol nothing here provides"),
            );
        }
    };
    link::apply(&mut modules[0], fixed);
    link::thread_locals(&mut modules[0]);
    let module = &modules[0];
    if module.info.initializers(&module.bytes).next().is_some() {
        host.platform().trace(&alloc::format!(
            "dlopen: {path} has initializers, which are not run for an image loaded after start"
        ));
    }

    for segment in &module.segments {
        if segment.initprot == 0 || segment.vmsize == 0 {
            continue;
        }
        let at = (slide + segment.vmaddr) as usize;
        if let Some(data) = segment.file_data(&module.bytes) {
            user::put(host, at, data)?;
        }
    }
    for (va, value) in &module.late {
        user::put_u64(host, *va as usize, *value)?;
    }
    for segment in &module.segments {
        if segment.initprot == 0 || segment.vmsize == 0 {
            continue;
        }
        let len = segment.vmsize.div_ceil(PAGE) * PAGE;
        mem.protect(
            (slide + segment.vmaddr) as usize,
            len as usize,
            prot_of(segment),
        )?;
    }

    let table = user::u64_at(host, (library.private() + PRIVATE_MODULES_AT) as usize)? as usize;
    let at = table + loaded.len() * ENTRY_LEN as usize;
    user::put(host, at, &entry(module.base, slide, slide + span, &path))?;
    user::put_u64(
        host,
        (library.private() + PRIVATE_MODULES) as usize,
        loaded.len() as u64 + 1,
    )?;
    host.platform()
        .trace(&alloc::format!("{path} at {:#x}+{span:#x}", module.base));
    Ok(module.base as isize)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_table_entry_holds_the_path_and_its_terminator() {
        let e = entry(0x1000, 0x1000, 0x5000, "/lib/mod.so");
        assert_eq!(e.len(), ENTRY_LEN as usize);
        assert_eq!(
            &e[ENTRY_PATH as usize..ENTRY_PATH as usize + 11],
            b"/lib/mod.so"
        );
        assert_eq!(e[ENTRY_PATH as usize + 11], 0);
        let long = "x".repeat(400);
        let e = entry(0, 0, 0, &long);
        assert_eq!(
            e[ENTRY_LEN as usize - 1],
            0,
            "a long path is cut, not left unterminated"
        );
    }
}
