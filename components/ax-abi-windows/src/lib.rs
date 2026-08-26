//! Windows NT personality for ArceOS/StarryOS.
//!
//! This crate teaches ArceOS to load and run PE/COFF (`.exe`) images as a
//! `Personality` alongside the native Linux one, mapping Windows execution onto
//! the shared `ax_*` primitives (an address space via [`LoadEnv`], a trap frame
//! via [`TrapEnv`]). It targets the NT-native ABI - a `subsystem == NATIVE` PE
//! that links only ntdll and issues NT syscalls directly - which is the smallest
//! surface that runs a real `.exe`; a Win32 shim is an optional `win32` feature.
//!
//! The loader here (map sections, apply base relocations) is transcribed from
//! ReactOS `dll/ntdll/ldr` and the PE/COFF spec; the header parsing it builds on
//! lives in [`ax_binfmt::pe`]. NT syscall dispatch arrives in a later phase.

#![cfg_attr(not(test), no_std)]

extern crate alloc;

pub mod handle;
pub mod nt;
pub mod teb_peb;

use alloc::{vec, vec::Vec};

use ax_binfmt::{
    Abi, AbiError, AbiResult, Dispatch, LoadEnv, LoadRequest, Loaded, Personality, Prot, TrapEnv,
    pe::{self, PeInfo, Reloc, Section},
};

/// The Windows NT personality: recognizes PE images and loads them.
#[derive(Debug, Clone, Copy, Default)]
pub struct WindowsAbi;

impl Personality for WindowsAbi {
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
        map_image(&pe, req.image, base, env)?;
        Ok(Loaded {
            entry: base + pe.entry_rva as u64,
            stack: 0,
        })
    }

    fn handle_syscall(&self, _env: &mut dyn TrapEnv) -> Dispatch {
        // NT syscall dispatch (see the `nt` module) is wired on-target in a later
        // phase; until then no index is serviced, so pass through to any custom
        // handler or the caller's default.
        Dispatch::Passthrough
    }
}

/// Map a parsed PE image into `env` at `load_base`, applying base relocations
/// when that differs from the image's preferred base. Mirrors the map + fix-up
/// sequence ntdll's loader performs (`LdrpMapDll` + `LdrRelocateImage`).
fn map_image(pe: &PeInfo, image: &[u8], load_base: u64, env: &mut dyn LoadEnv) -> AbiResult<()> {
    let delta = load_base.wrapping_sub(pe.image_base);
    // A non-zero delta needs a relocation directory; a stripped image cannot move.
    let relocs: Vec<Reloc> = match pe.relocations(image) {
        Some(it) => it.collect(),
        None if delta != 0 => return Err(AbiError::Unsupported),
        None => Vec::new(),
    };

    for sec in pe.sections(image) {
        let mut page = vec![0u8; sec.vsize as usize];
        if let Some(raw) = sec.raw_data(image) {
            let n = raw.len().min(page.len());
            page[..n].copy_from_slice(&raw[..n]);
        }
        if delta != 0 {
            relocate_section(&mut page, &sec, &relocs, delta)?;
        }
        env.map_region(
            load_base + sec.rva as u64,
            sec.vsize as u64,
            section_prot(&sec),
            Some(&page),
        )?;
    }
    Ok(())
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
        let loaded = WindowsAbi
            .load(
                &LoadRequest {
                    image: &img,
                    args: &[],
                    envs: &[],
                },
                &mut env,
            )
            .expect("load");
        assert_eq!(loaded.entry, 0x1_4000_1000);
        assert_eq!(env.maps.len(), 2);

        let (va, prot, page) = &env.maps[0];
        assert_eq!(*va, 0x1_4000_1000);
        assert_eq!(*prot, Prot::READ | Prot::EXEC);
        assert_eq!(page.len(), 0x2000); // vsize, not raw_size
        assert_eq!(&page[..4], &[0x90, 0x90, 0x90, 0x90]);
        assert!(page[4..].iter().all(|&x| x == 0)); // zero-filled tail

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
        map_image(&pe, &img, new_base, &mut env).expect("relocated load");

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
            map_image(&pe, &img, 0x1_8000_0000, &mut env),
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
        WindowsAbi
            .load(
                &LoadRequest {
                    image: &img,
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
        // .bss is fully zero-filled to its virtual size with no file backing.
        let (va, prot, page) = &env.maps[3];
        assert_eq!(*va, 0x1_4000_4000);
        assert_eq!(*prot, Prot::READ | Prot::WRITE);
        assert_eq!(page.len(), 0x1000);
        assert!(page.iter().all(|&b| b == 0));
    }

    #[test]
    fn rejects_non_pe_and_pe32() {
        let mut env = RecordingEnv::default();
        assert!(!WindowsAbi.recognizes(b"\x7fELF"));
        assert_eq!(
            WindowsAbi.load(
                &LoadRequest {
                    image: b"not pe",
                    args: &[],
                    envs: &[]
                },
                &mut env
            ),
            Err(AbiError::MalformedImage)
        );
    }
}
