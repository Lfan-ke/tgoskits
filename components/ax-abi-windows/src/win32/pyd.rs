//! Loading a library at run time: what `LoadLibraryExW` does for a file the
//! process has not got yet - a CPython extension module (`.pyd`) most often.
//!
//! The image is read, mapped at an address the host chooses, relocated for it,
//! and bound against what the process already holds: a real DLL's exports are
//! read from its mapped image, a system library's entries are served by their
//! stubs. It is then entered in the loader list so `GetProcAddress` and
//! `GetModuleHandleW` find it. `DllMain` is not run: a trap cannot call back
//! into the program, and an extension module's entry is CRT boilerplate.

use alloc::{vec, vec::Vec};

use ax_abi_port::{At, Create, MapRequest, MapSource, OpenHow, Prot};
use ax_binfmt::pe::{self, ImportedSymbol, PeInfo, Reloc};

use super::{Call, Win32Call, mapped};
use crate::{
    bind_section, dll, image_extent, relocate_section,
    teb_peb::{
        LDR_BASE_NAME, LDR_DLL_BASE, LDR_ENTRY_POINT, LDR_ENTRY_SIZE, LDR_FLAGS, LDR_FULL_NAME,
        LDR_IN_LOAD_ORDER, LDR_IN_MEMORY_ORDER, LDR_LOAD_COUNT, LDR_LOAD_LINKS, LDR_MEMORY_LINKS,
        LDR_SIZE_OF_IMAGE, LDR_TLS_INDEX, PEB_LDR, PEB_PROCESS_HEAP,
    },
    thunk,
};

const PAGE: usize = 0x1000;

/// Read a guest file whole. The file port reads into user memory, so the bytes
/// land in a scratch mapping first and are copied out of it.
fn read_whole(c: &Call<'_>, host: &str) -> Option<Vec<u8>> {
    let (paths, files, mem) = (c.host.paths()?, c.host.files()?, c.host.mem()?);
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
    let fd = paths.open(At::Cwd, host, &how).ok()? as i32;
    let read = (|| {
        let size = paths.attributes_of(fd).ok()?.size as usize;
        let len = size.max(1).next_multiple_of(PAGE);
        let scratch = mem
            .map(&MapRequest {
                addr: 0,
                len,
                prot: Prot::READ | Prot::WRITE,
                fixed: false,
                shared: false,
                source: MapSource::Anonymous,
            })
            .ok()? as usize;
        let mut got = 0;
        while got < size {
            match files.read(fd, scratch + got, size - got) {
                Ok(n) if n > 0 => got += n as usize,
                _ => break,
            }
        }
        let mut out = vec![0u8; got];
        let ok = c.host.platform().read_user(scratch, &mut out).is_ok();
        let _ = mem.unmap(scratch, len);
        ok.then_some(out)
    })();
    let _ = files.close(fd);
    read
}

/// Where `symbol` from `lib` is in this process: a stub for a system library,
/// otherwise an export read from the mapped image of a library already loaded.
fn resolve(c: &Call<'_>, lib: &str, symbol: ImportedSymbol<'_>) -> Option<u64> {
    if dll::is_system(lib) {
        let call = match symbol {
            ImportedSymbol::Name(name) => Win32Call::resolve(lib, name),
            ImportedSymbol::Ordinal(n) => Win32Call::by_ordinal(lib, n),
        }?;
        let (which, at) = call.place();
        let base = super::runtime::module_named(c, dll::SYSTEM_NAMES[which])?;
        return Some((base + thunk::MODULE_HEADER + at * thunk::STUB_LEN) as u64);
    }
    let base = super::runtime::module_named(c, lib)?;
    let exports = mapped::exports(c, base)?;
    let at = match symbol {
        ImportedSymbol::Name(name) => mapped::by_name(c, base, &exports, name.as_bytes()),
        ImportedSymbol::Ordinal(n) => mapped::by_ordinal(c, base, &exports, u32::from(n)),
    }?;
    Some(at as u64)
}

/// A section's characteristics as the memory port spells protection.
fn port_prot(sec: &pe::Section) -> Prot {
    let mut prot = Prot::empty();
    prot.set(Prot::READ, sec.readable());
    prot.set(Prot::WRITE, sec.writable());
    prot.set(Prot::EXEC, sec.executable());
    prot
}

fn write_units(c: &Call<'_>, at: usize, units: &[u16]) -> bool {
    let bytes: Vec<u8> = units.iter().flat_map(|u| u.to_le_bytes()).collect();
    c.write(at, &bytes)
}

/// Enter the module in the loader list: one `LDR_DATA_TABLE_ENTRY` from the
/// process heap, its names after it, appended to the load- and memory-order
/// rings the way the initial list was built.
fn register(c: &Call<'_>, base: usize, pe: &PeInfo, size: usize, path: &str) -> Option<()> {
    let peb = c.peb()?;
    let heap = c.read_u64(peb + PEB_PROCESS_HEAP)? as usize;
    let ldr = c.read_u64(peb + PEB_LDR)? as usize;
    let name = path.rsplit(['\\', '/']).next().unwrap_or(path);
    let full: Vec<u16> = path.encode_utf16().chain([0]).collect();
    let short: Vec<u16> = name.encode_utf16().chain([0]).collect();
    let entry = super::heap::alloc(c, heap, LDR_ENTRY_SIZE + (full.len() + short.len()) * 2)?;
    if !super::zero(c, entry, LDR_ENTRY_SIZE) {
        return None;
    }
    let full_at = entry + LDR_ENTRY_SIZE;
    let short_at = full_at + full.len() * 2;
    if !write_units(c, full_at, &full) || !write_units(c, short_at, &short) {
        return None;
    }
    c.write_u64(entry + LDR_DLL_BASE, base as u64);
    let entry_point = (pe.entry_rva != 0).then(|| base as u64 + u64::from(pe.entry_rva));
    c.write_u64(entry + LDR_ENTRY_POINT, entry_point.unwrap_or(0));
    c.write_u32(entry + LDR_SIZE_OF_IMAGE, size as u32);
    for (field, at, units) in [
        (LDR_FULL_NAME, full_at, &full),
        (LDR_BASE_NAME, short_at, &short),
    ] {
        let len = ((units.len() - 1) * 2) as u16;
        c.write(entry + field, &len.to_le_bytes());
        c.write(entry + field + 2, &(len + 2).to_le_bytes());
        c.write_u64(entry + field + 8, at as u64);
    }
    // LDRP_IMAGE_DLL, pinned, no TLS slot: as the initial list gives a library.
    c.write_u32(entry + LDR_FLAGS, 0x4);
    c.write(entry + LDR_LOAD_COUNT, &u16::MAX.to_le_bytes());
    c.write(entry + LDR_TLS_INDEX, &(-1i16 as u16).to_le_bytes());
    for (head, link) in [
        (LDR_IN_LOAD_ORDER, LDR_LOAD_LINKS),
        (LDR_IN_MEMORY_ORDER, LDR_MEMORY_LINKS),
    ] {
        let head = ldr + head;
        let here = entry + link;
        let tail = c.read_u64(head + 8)? as usize;
        c.write_u64(here, head as u64);
        c.write_u64(here + 8, tail as u64);
        c.write_u64(tail, here as u64);
        c.write_u64(head + 8, here as u64);
    }
    Some(())
}

/// Map the library at `text` (a Windows path) into the process and link it.
/// The base is the module handle.
pub(super) fn load_library(c: &mut Call<'_>, text: &str) -> Option<usize> {
    // A name without an extension means the `.dll`, as Windows takes it.
    let named;
    let text = match text.rsplit(['\\', '/']).next() {
        Some(stem) if !stem.contains('.') => {
            named = alloc::format!("{text}.dll");
            named.as_str()
        }
        _ => text,
    };
    let host = super::file::host_path(c, text)?;
    let bytes = read_whole(c, &host)?;
    let pe = pe::parse(&bytes)?;
    if !pe.pe64 {
        return None;
    }
    // Every import must resolve before anything is mapped, as at load.
    let mut binds: Vec<(u32, u64)> = Vec::new();
    if let Some(imports) = pe.imports(&bytes) {
        for import in imports {
            let lib = dll::canonical(import.library);
            let Some(value) = resolve(c, &lib, import.symbol) else {
                let what = match import.symbol {
                    ImportedSymbol::Name(name) => alloc::string::String::from(name),
                    ImportedSymbol::Ordinal(n) => alloc::format!("#{n}"),
                };
                c.host.platform().trace(&alloc::format!(
                    "LoadLibraryExW: {text}: {lib}!{what} is not provided"
                ));
                return None;
            };
            binds.push((import.thunk, value));
        }
    }
    let mem = c.host.mem()?;
    let size = image_extent(&pe, &bytes) as usize;
    let base = mem
        .map(&MapRequest {
            addr: 0,
            len: size.next_multiple_of(PAGE),
            prot: Prot::READ | Prot::WRITE,
            fixed: false,
            shared: false,
            source: MapSource::Anonymous,
        })
        .ok()? as usize;
    let delta = (base as u64).wrapping_sub(pe.image_base);
    let relocs: Vec<Reloc> = match pe.relocations(&bytes) {
        Some(it) => it.collect(),
        None if delta != 0 => return None,
        None => Vec::new(),
    };
    let headers = (pe.size_of_headers(&bytes)? as usize).min(bytes.len());
    if !c.write(base, &bytes[..headers]) {
        return None;
    }
    for sec in pe.sections(&bytes) {
        let mut page = vec![0u8; sec.vsize as usize];
        if let Some(raw) = sec.raw_data(&bytes) {
            let n = raw.len().min(page.len());
            page[..n].copy_from_slice(&raw[..n]);
        }
        relocate_section(&mut page, &sec, &relocs, delta).ok()?;
        bind_section(&mut page, &sec, &binds, &[]).ok()?;
        let va = base + sec.rva as usize;
        if !c.write(va, &page) {
            return None;
        }
        let _ = mem.protect(
            va,
            (sec.vsize as usize).next_multiple_of(PAGE),
            port_prot(&sec),
        );
    }
    register(c, base, &pe, size, text)?;
    Some(base)
}
