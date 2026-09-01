//! Windows NT personality for ArceOS/StarryOS.
//!
//! This crate teaches ArceOS to load and run PE/COFF (`.exe`) images as a
//! `SysAbi` alongside the native Linux one, mapping Windows execution onto
//! the shared `ax_*` primitives (an address space via [`LoadEnv`], a trap frame
//! via [`TrapEnv`]). It targets the NT-native ABI - a `subsystem == NATIVE` PE
//! that links only ntdll and issues NT syscalls directly - which is the smallest
//! surface that runs a real `.exe`; a Win32 shim is an optional `win32` feature.
//!
//! The loader here (map sections, apply base relocations) is transcribed from
//! ReactOS `dll/ntdll/ldr` and the PE/COFF spec; the header parsing it builds on
//! lives in [`ax_binfmt::pe`]. NT syscall dispatch arrives in a later phase.

#![cfg_attr(not(test), no_std)]
#![feature(used_with_arg)]

extern crate alloc;

pub mod handle;
pub mod nt;
pub mod teb_peb;
pub mod thunk;
pub mod win32;

use alloc::{vec, vec::Vec};

use ax_binfmt::{
    AbiError, AbiResult, ImageFormat, LoadEnv, LoadRequest, Loaded, Prot,
    pe::{self, PeInfo, Reloc, Section},
};
use ax_dispatch::{Abi, Dispatch, SysAbi, TrapEnv};

/// The Windows NT personality: recognizes PE images and loads them.
#[derive(Debug, Clone, Copy, Default)]
pub struct WindowsAbi;

impl SysAbi for WindowsAbi {
    fn abi(&self) -> Abi {
        Abi::Windows
    }

    fn handle_syscall(&self, env: &mut dyn TrapEnv) -> Dispatch {
        let host = ax_crate_interface::call_interface!(ax_abi_port::CurrentHost::current);
        // A program that links against the Windows API arrives on a number this
        // package reserved for its own entry points; one that issues the trap
        // itself arrives on an NT number. Both are this package's.
        if win32::Win32Call::from_nr(env.nr() as u32).is_some() {
            return win32::dispatch(env, host);
        }
        nt::dispatch(env, host)
    }
}

/// Map a parsed PE image into `env` at `load_base`, applying base relocations
/// when that differs from the image's preferred base. Mirrors the map + fix-up
/// sequence ntdll's loader performs (`LdrpMapDll` + `LdrRelocateImage`).
fn map_image(
    pe: &PeInfo,
    image: &[u8],
    load_base: u64,
    binds: &[(u32, u64)],
    env: &mut dyn LoadEnv,
) -> AbiResult<()> {
    let delta = load_base.wrapping_sub(pe.image_base);
    // A non-zero delta needs a relocation directory; a stripped image cannot move.
    let relocs: Vec<Reloc> = match pe.relocations(image) {
        Some(it) => it.collect(),
        None if delta != 0 => return Err(AbiError::Unsupported),
        None => Vec::new(),
    };

    for sec in pe.sections(image) {
        let va = load_base + sec.rva as u64;
        let range = sec.rva..sec.rva + sec.vsize;
        let bound = binds.iter().any(|(rva, _)| range.contains(rva));
        if delta == 0 && !bound {
            // At its preferred base nothing is rewritten, so the section maps
            // from the file and its pages arrive as they are touched - the same
            // reason `binfmt_elf` uses `vm_mmap` for a `PT_LOAD`.
            env.map_image(
                va,
                sec.vsize as u64,
                section_prot(&sec),
                sec.raw_ptr as u64,
                sec.raw_ptr as u64 + sec.raw_size as u64,
            )?;
            continue;
        }
        // A section that is rewritten - relocated, or holding an address
        // table that was bound - cannot come straight from the page cache.
        let mut page = vec![0u8; sec.vsize as usize];
        if let Some(raw) = sec.raw_data(image) {
            let n = raw.len().min(page.len());
            page[..n].copy_from_slice(&raw[..n]);
        }
        relocate_section(&mut page, &sec, &relocs, delta)?;
        bind_section(&mut page, &sec, binds)?;
        env.map_region(va, sec.vsize as u64, section_prot(&sec), Some(&page))?;
    }
    Ok(())
}

/// Write the bound addresses that fall inside `sec` into its page buffer, before
/// it is mapped. Each is an eight-byte address table entry in a PE32+ image.
fn bind_section(page: &mut [u8], sec: &Section, binds: &[(u32, u64)]) -> AbiResult<()> {
    let range = sec.rva..sec.rva + sec.vsize;
    for (rva, value) in binds.iter().filter(|(rva, _)| range.contains(rva)) {
        let at = (rva - sec.rva) as usize;
        let slot = page.get_mut(at..at + 8).ok_or(AbiError::MalformedImage)?;
        slot.copy_from_slice(&value.to_le_bytes());
    }
    Ok(())
}

/// Where the image ends, as an offset from its base: the first address free for
/// anything the loader adds alongside it.
fn image_extent(pe: &PeInfo, image: &[u8]) -> u64 {
    pe.sections(image)
        .map(|sec| sec.rva as u64 + sec.vsize as u64)
        .max()
        .unwrap_or(0)
}

const PAGE: u64 = 0x1000;

fn page_up(at: u64) -> u64 {
    at.div_ceil(PAGE) * PAGE
}

/// Apply the relocations that fall inside `sec` to its freshly-built page buffer,
/// before it is mapped. Only `REL_DIR64` (PE32+) is expected; anything else is
/// rejected rather than silently skipped.
fn relocate_section(page: &mut [u8], sec: &Section, relocs: &[Reloc], delta: u64) -> AbiResult<()> {
    let range = sec.rva..sec.rva + sec.vsize;
    for reloc in relocs.iter().filter(|r| range.contains(&r.rva)) {
        let at = (reloc.rva - sec.rva) as usize;
        match reloc.kind {
            pe::REL_DIR64 => {
                let slot = page.get_mut(at..at + 8).ok_or(AbiError::MalformedImage)?;
                let patched = u64::from_le_bytes(slot.try_into().unwrap()).wrapping_add(delta);
                slot.copy_from_slice(&patched.to_le_bytes());
            }
            _ => return Err(AbiError::Unsupported),
        }
    }
    Ok(())
}

/// Translate a section's `Characteristics` into a mapping protection.
fn section_prot(sec: &Section) -> Prot {
    let mut prot = Prot::empty();
    prot.set(Prot::READ, sec.readable());
    prot.set(Prot::WRITE, sec.writable());
    prot.set(Prot::EXEC, sec.executable());
    prot
}

#[cfg(test)]
mod tests {
    use super::*;

    // Records every mapping a loader requests, so tests can assert on placement,
    // protection and (relocated) contents.
    #[derive(Default)]
    struct RecordingEnv {
        maps: Vec<(u64, Prot, Vec<u8>)>,
        from_file: Vec<(u64, u64)>,
        reset: bool,
        sizes: Vec<u64>,
    }

    impl LoadEnv for RecordingEnv {
        fn map_region(
            &mut self,
            va: u64,
            len: u64,
            prot: Prot,
            init: Option<&[u8]>,
        ) -> AbiResult<()> {
            let mut page = vec![0u8; len as usize];
            if let Some(data) = init {
                page[..data.len()].copy_from_slice(data);
            }
            self.maps.push((va, prot, page));
            Ok(())
        }

        fn map_image(
            &mut self,
            va: u64,
            len: u64,
            prot: Prot,
            offset: u64,
            file_end: u64,
        ) -> AbiResult<()> {
            // Nothing is copied: the range says which part of the file backs
            // this mapping, and `len` the size it occupies once mapped.
            self.maps.push((va, prot, Vec::new()));
            self.from_file.push((offset, file_end));
            self.sizes.push(len);
            Ok(())
        }

        fn read_image(&mut self, _at: u64, _out: &mut [u8]) -> AbiResult<usize> {
            Ok(0)
        }
        fn reset(&mut self) -> AbiResult<()> {
            self.reset = true;
            Ok(())
        }
    }

    const PE_OFF: usize = 0x80;
    const OPT: usize = PE_OFF + 4 + 20;
    const OPT_SIZE: usize = 240;
    const SECT_TABLE: usize = OPT + OPT_SIZE;

    // Build a PE32+ image with the given sections; each section's raw bytes are
    // placed at its `raw_ptr`. `reloc_dir` optionally sets the base-reloc dir.
    fn synth(image_base: u64, entry_rva: u32, sections: &[(Section, &[u8])]) -> Vec<u8> {
        let end = sections
            .iter()
            .map(|(s, _)| s.raw_ptr as usize + s.raw_size as usize)
            .chain(core::iter::once(SECT_TABLE + sections.len() * 40))
            .max()
            .unwrap();
        let mut b = vec![0u8; end + 0x40];
        b[0..2].copy_from_slice(b"MZ");
        b[0x3C..0x40].copy_from_slice(&(PE_OFF as u32).to_le_bytes());
        b[PE_OFF..PE_OFF + 4].copy_from_slice(b"PE\0\0");
        let coff = PE_OFF + 4;
        b[coff + 2..coff + 4].copy_from_slice(&(sections.len() as u16).to_le_bytes());
        b[coff + 16..coff + 18].copy_from_slice(&(OPT_SIZE as u16).to_le_bytes());
        b[OPT..OPT + 2].copy_from_slice(&0x20Bu16.to_le_bytes());
        b[OPT + 16..OPT + 20].copy_from_slice(&entry_rva.to_le_bytes());
        b[OPT + 24..OPT + 32].copy_from_slice(&image_base.to_le_bytes());
        b[OPT + 68..OPT + 70].copy_from_slice(&1u16.to_le_bytes()); // NATIVE subsystem
        b[OPT + 108..OPT + 112].copy_from_slice(&16u32.to_le_bytes()); // NumberOfRvaAndSizes
        for (i, (s, data)) in sections.iter().enumerate() {
            let off = SECT_TABLE + i * 40;
            b[off + 8..off + 12].copy_from_slice(&s.vsize.to_le_bytes());
            b[off + 12..off + 16].copy_from_slice(&s.rva.to_le_bytes());
            b[off + 16..off + 20].copy_from_slice(&s.raw_size.to_le_bytes());
            b[off + 20..off + 24].copy_from_slice(&s.raw_ptr.to_le_bytes());
            b[off + 36..off + 40].copy_from_slice(&s.characteristics.to_le_bytes());
            let raw = s.raw_ptr as usize;
            b[raw..raw + data.len()].copy_from_slice(data);
        }
        b
    }

    fn sect(rva: u32, vsize: u32, raw_size: u32, raw_ptr: u32, chr: u32) -> Section {
        Section {
            rva,
            vsize,
            raw_size,
            raw_ptr,
            characteristics: chr,
        }
    }

    const RX: u32 = 0x2000_0000 | 0x4000_0000; // execute | read
    const RW: u32 = 0x8000_0000 | 0x4000_0000; // write | read

    #[test]
    fn loads_sections_with_protection_and_zero_fill() {
        let text = sect(0x1000, 0x2000, 4, 0x400, RX);
        let data = sect(0x3000, 0x1000, 2, 0x600, RW);
        let img = synth(
            0x1_4000_0000,
            0x1000,
            &[(text, &[0x90, 0x90, 0x90, 0x90]), (data, &[1, 2])],
        );

        let mut env = RecordingEnv::default();
        let loaded = PeFormat
            .load(
                &LoadRequest {
                    image: &img,
                    load_base: 0,
                    args: &[],
                    envs: &[],
                },
                &mut env,
            )
            .expect("load");
        assert_eq!(loaded.entry, 0x1_4000_1000);
        assert_eq!(env.maps.len(), 2);

        let (va, prot, _) = &env.maps[0];
        assert_eq!(*va, 0x1_4000_1000);
        assert_eq!(*prot, Prot::READ | Prot::EXEC);
        // The section occupies its virtual size, of which only the raw range
        // comes from the file; the host zero-fills the tail.
        assert_eq!(env.sizes[0], 0x2000);
        let (off, end) = env.from_file[0];
        assert_eq!(end - off, 4);

        let (va, prot, _) = &env.maps[1];
        assert_eq!(*va, 0x1_4000_3000);
        assert_eq!(*prot, Prot::READ | Prot::WRITE);
    }

    #[test]
    fn applies_dir64_relocations_when_base_moves() {
        // .text holds an absolute pointer (image_base + 0x1000) that must be
        // fixed up by the load delta; a .reloc section describes that fixup.
        let ptr = (0x1_4000_0000u64 + 0x1000).to_le_bytes();
        let text = sect(0x1000, 0x1000, 8, 0x400, RX);
        // .reloc: one block for page 0x1000 with a single DIR64 entry at +0.
        let mut reloc = Vec::new();
        reloc.extend_from_slice(&0x1000u32.to_le_bytes()); // page RVA
        reloc.extend_from_slice(&(8u32 + 2).to_le_bytes()); // SizeOfBlock
        // One DIR64 entry at page offset 0 (type in the high 4 bits).
        reloc.extend_from_slice(&(pe::REL_DIR64 << 12).to_le_bytes());
        let reloc_sec = sect(0x2000, 0x1000, reloc.len() as u32, 0x600, 0x4000_0000);
        let mut img = synth(0x1_4000_0000, 0x1000, &[(text, &ptr), (reloc_sec, &reloc)]);
        // Point the base-relocation data directory at the .reloc section.
        let dd = OPT + 112 + pe::DIR_BASERELOC * 8;
        img[dd..dd + 4].copy_from_slice(&0x2000u32.to_le_bytes());
        img[dd + 4..dd + 8].copy_from_slice(&(reloc.len() as u32).to_le_bytes());

        let pe = pe::parse(&img).unwrap();
        let new_base = 0x1_8000_0000u64;
        let mut env = RecordingEnv::default();
        map_image(&pe, &img, new_base, &[], &mut env).expect("relocated load");

        // The pointer in .text now reads image_base_moved + 0x1000.
        let text_page = &env.maps[0].2;
        let got = u64::from_le_bytes(text_page[..8].try_into().unwrap());
        assert_eq!(got, new_base + 0x1000);
    }

    #[test]
    fn rejects_relocation_of_a_stripped_image() {
        let text = sect(0x1000, 0x1000, 4, 0x400, RX);
        let img = synth(0x1_4000_0000, 0x1000, &[(text, &[0; 4])]);
        let pe = pe::parse(&img).unwrap();
        let mut env = RecordingEnv::default();
        // No reloc directory, but the base must move -> cannot relocate.
        assert_eq!(
            map_image(&pe, &img, 0x1_8000_0000, &[], &mut env),
            Err(AbiError::Unsupported)
        );
    }

    const RO: u32 = 0x4000_0000; // read only

    #[test]
    fn loads_a_realistic_toolchain_layout() {
        // A typical MinGW/MSVC x64 layout: code, read-only data, writable data,
        // and a .bss whose virtual size exceeds its (zero) raw size.
        let text = sect(0x1000, 0x1000, 0x40, 0x400, RX);
        let rdata = sect(0x2000, 0x1000, 0x20, 0x600, RO);
        let data = sect(0x3000, 0x1000, 0x10, 0x800, RW);
        let bss = sect(0x4000, 0x1000, 0, 0, RW);
        let img = synth(
            0x1_4000_0000,
            0x1000,
            &[
                (text, &[0x90; 0x40]),
                (rdata, &[0xAB; 0x20]),
                (data, &[0xCD; 0x10]),
                (bss, &[]),
            ],
        );

        let mut env = RecordingEnv::default();
        PeFormat
            .load(
                &LoadRequest {
                    image: &img,
                    load_base: 0,
                    args: &[],
                    envs: &[],
                },
                &mut env,
            )
            .expect("load");
        assert_eq!(env.maps.len(), 4);
        assert_eq!(env.maps[0].1, Prot::READ | Prot::EXEC);
        assert_eq!(env.maps[1].1, Prot::READ);
        assert_eq!(env.maps[2].1, Prot::READ | Prot::WRITE);
        // .bss occupies its virtual size with nothing coming from the file.
        let (va, prot, _) = &env.maps[3];
        assert_eq!(*va, 0x1_4000_4000);
        assert_eq!(*prot, Prot::READ | Prot::WRITE);
        assert_eq!(env.sizes[3], 0x1000);
        let (off, end) = env.from_file[3];
        assert_eq!(end, off);
    }

    #[test]
    fn rejects_non_pe_and_pe32() {
        let mut env = RecordingEnv::default();
        assert!(!PeFormat.recognizes(b"\x7fELF"));
        assert_eq!(
            PeFormat.load(
                &LoadRequest {
                    image: b"not pe",
                    load_base: 0,
                    args: &[],
                    envs: &[]
                },
                &mut env
            ),
            Err(AbiError::MalformedImage)
        );
    }

    /// A section whose bytes are an import directory taking one `symbol` from
    /// kernel32; the address table entry for it is at RVA 0x1060.
    fn import_section(symbol: &[u8]) -> Vec<u8> {
        let mut data = vec![0u8; 0x200];
        // IMAGE_IMPORT_DESCRIPTOR at the section's start (RVA 0x1000).
        data[0x00..0x04].copy_from_slice(&0x1040u32.to_le_bytes()); // OriginalFirstThunk
        data[0x0C..0x10].copy_from_slice(&0x1080u32.to_le_bytes()); // Name
        data[0x10..0x14].copy_from_slice(&0x1060u32.to_le_bytes()); // FirstThunk
        // The descriptor after it stays zeroed, which ends the table.
        data[0x40..0x48].copy_from_slice(&0x1090u64.to_le_bytes()); // one by-name thunk
        data[0x80..0x8D].copy_from_slice(b"KERNEL32.dll\0");
        data[0x92..0x92 + symbol.len()].copy_from_slice(symbol);
        data
    }

    /// An image whose only section is `import_section(symbol)`, with the import
    /// directory pointed at it.
    fn image_importing(symbol: &[u8]) -> Vec<u8> {
        let data = import_section(symbol);
        let mut img = synth(
            0x1_4000_0000,
            0x1000,
            &[(sect(0x1000, 0x200, 0x200, 0x400, RX), &data)],
        );
        let dir = OPT + 112 + pe::DIR_IMPORT * 8;
        img[dir..dir + 4].copy_from_slice(&0x1000u32.to_le_bytes());
        img[dir + 4..dir + 8].copy_from_slice(&40u32.to_le_bytes());
        img
    }

    #[test]
    fn binds_an_import_to_a_stub_mapped_past_the_image() {
        use crate::{thunk, win32::Win32Call};

        let img = image_importing(b"WriteFile\0");
        let mut env = RecordingEnv::default();
        let loaded = PeFormat
            .load(
                &LoadRequest {
                    image: &img,
                    load_base: 0,
                    args: &[],
                    envs: &[],
                },
                &mut env,
            )
            .expect("an import this package serves is bound");
        assert_eq!(loaded.entry, 0x1_4000_1000);

        // The image spans one page from RVA 0x1000, so the stubs land on the
        // page after it.
        let stubs_va = 0x1_4000_2000;
        let (_, prot, code) = env
            .maps
            .iter()
            .find(|(va, ..)| *va == stubs_va)
            .expect("a stub region past the image");
        assert_eq!(*prot, Prot::READ | Prot::EXEC);
        assert_eq!(&code[..thunk::STUB_LEN], &thunk::stub(Win32Call::WriteFile));

        // The section holding the address table was rewritten rather than
        // mapped from the file, and its one entry now points at the stub.
        let (_, _, page) = env
            .maps
            .iter()
            .find(|(va, ..)| *va == 0x1_4000_1000)
            .expect("the import section is mapped from a rewritten buffer");
        assert_eq!(
            u64::from_le_bytes(page[0x60..0x68].try_into().unwrap()),
            stubs_va
        );
        assert!(
            env.from_file.is_empty(),
            "nothing came straight from the file"
        );
    }

    #[test]
    fn refuses_an_image_that_needs_a_library_without_touching_the_space() {
        // A real kernel32 export, but not one the synthesized library serves.
        let img = image_importing(b"CreateMutexW\0");

        let mut env = RecordingEnv::default();
        let err = PeFormat
            .load(
                &LoadRequest {
                    image: &img,
                    load_base: 0,
                    args: &[],
                    envs: &[],
                },
                &mut env,
            )
            .expect_err("an image needing a library is refused");

        assert_eq!(err, AbiError::MissingLibrary);
        // Refused before the space was prepared: an image that cannot run must
        // not cost the caller the one it already had.
        assert!(!env.reset);
        assert!(env.maps.is_empty());
    }
}

impl ImageFormat for PeFormat {
    fn abi(&self) -> Abi {
        Abi::Windows
    }

    fn recognizes(&self, image: &[u8]) -> bool {
        ax_binfmt::detect(image) == Some(Abi::Windows)
    }

    fn load(&self, req: &LoadRequest<'_>, env: &mut dyn LoadEnv) -> AbiResult<Loaded> {
        let pe = pe::parse(req.image).ok_or(AbiError::MalformedImage)?;
        if !pe.pe64 {
            // Only PE32+ is in scope; a 32-bit image is a distinct ABI.
            return Err(AbiError::Unsupported);
        }
        // Honor the image's preferred base, so a well-formed image needs no
        // relocation; relocation is exercised only when the base must change.
        let base = pe.image_base;
        // The stubs go on the page after the image, where an import binds to
        // an address the image's own relocations never move.
        let stubs_va = page_up(base + image_extent(&pe, req.image));
        // Bound before anything is mapped, so an import this package cannot
        // serve is refused while the caller still has the space it came with.
        let thunks = thunk::bind(&pe, req.image, stubs_va)?;
        // The image is this package's from here, so the space it goes into is
        // torn down and prepared. Doing it after the checks is what lets a
        // malformed image be refused without destroying the caller's.
        env.reset()?;
        map_image(&pe, req.image, base, &thunks.binds, env)?;
        if !thunks.code.is_empty() {
            env.map_region(
                stubs_va,
                page_up(thunks.code.len() as u64),
                Prot::READ | Prot::EXEC,
                Some(&thunks.code),
            )?;
        }
        Ok(Loaded {
            entry: base + pe.entry_rva as u64,
            stack: 0,
        })
    }
}

fn windows() -> &'static dyn SysAbi {
    static IT: WindowsAbi = WindowsAbi;
    &IT
}

ax_dispatch::register_sysabi!(windows);

/// The executable format this package loads. Kept apart from the type that
/// services traps because they are separate capabilities: a package may
/// provide either, and this one provides both.
#[derive(Debug, Clone, Copy, Default)]
pub struct PeFormat;

/// The same package registers twice, once per capability: it knows how to map
/// this format, and it knows how to service the traps that follow.
fn windows_format() -> &'static dyn ImageFormat {
    static IT: PeFormat = PeFormat;
    &IT
}

ax_binfmt::register_binfmt!(windows_format);
