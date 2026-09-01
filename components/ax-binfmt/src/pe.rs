//! PE/COFF header parsing: the binfmt layer's knowledge of the Windows image
//! format, mirroring how Linux keeps ELF parsing inside `fs/binfmt_elf.c`.
//!
//! `ax-abi-windows` reuses this module to reach a PE's entry point, walk its
//! section table for mapping, and locate the base-relocation directory - it does
//! not re-decode the headers. Field offsets follow the PE/COFF specification and
//! ReactOS `sdk/lib/rtl/image.c` (`RtlImageNtHeader`, `RtlImageRvaToSection`,
//! `RtlImageDirectoryEntryToData`).

/// Data-directory index of the base-relocation table (`IMAGE_DIRECTORY_ENTRY_BASERELOC`).
pub const DIR_BASERELOC: usize = 5;
/// Data-directory index of the import table (`IMAGE_DIRECTORY_ENTRY_IMPORT`).
pub const DIR_IMPORT: usize = 1;
/// Data-directory index of the export table (`IMAGE_DIRECTORY_ENTRY_EXPORT`).
pub const DIR_EXPORT: usize = 0;

/// Base-relocation padding entry, ignored (`IMAGE_REL_BASED_ABSOLUTE`).
pub const REL_ABSOLUTE: u16 = 0;
/// 64-bit base relocation for PE32+ (`IMAGE_REL_BASED_DIR64`): patch a `u64`.
pub const REL_DIR64: u16 = 10;

// Section `Characteristics` access flags (PE/COFF spec IMAGE_SCN_MEM_*).
const SCN_MEM_EXECUTE: u32 = 0x2000_0000;
const SCN_MEM_READ: u32 = 0x4000_0000;
const SCN_MEM_WRITE: u32 = 0x8000_0000;

// Optional-header magic values (IMAGE_NT_OPTIONAL_HDR{32,64}_MAGIC).
const OPT_MAGIC_PE32: u16 = 0x10B;
const OPT_MAGIC_PE32_PLUS: u16 = 0x20B;

/// The parsed PE headers a loader needs before mapping sections.
///
/// Only load-bearing fields are decoded eagerly; the section table and data
/// directories are walked lazily from the image via [`PeInfo::sections`] and
/// [`PeInfo::data_dir`], keeping this `Copy` and free of allocation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PeInfo {
    /// `true` for PE32+ (64-bit) - the only shape StarryOS would execute.
    pub pe64: bool,
    /// Preferred load address (`OptionalHeader.ImageBase`).
    pub image_base: u64,
    /// Entry point as an RVA; absolute entry is `image_base + entry_rva`.
    pub entry_rva: u32,
    /// Windows subsystem id (1 = native/ntdll-only, 2 = GUI, 3 = console).
    pub subsystem: u16,
    /// Number of section headers following the optional header.
    pub sections: u16,
    /// File offset of the optional header; the section table and data
    /// directories are located relative to it.
    pub opt_off: usize,
    /// `FileHeader.SizeOfOptionalHeader`; the section table begins at
    /// `opt_off + opt_size`.
    pub opt_size: u16,
}

impl PeInfo {
    /// Absolute virtual address of the entry point at the preferred base.
    pub const fn entry_va(&self) -> u64 {
        self.image_base + self.entry_rva as u64
    }

    /// A `subsystem == 1` (NATIVE) image links only ntdll and issues NT syscalls
    /// directly - the cheapest first target (fewest DLL dependencies).
    pub const fn is_native(&self) -> bool {
        self.subsystem == 1
    }

    /// Iterate the section table. The iterator borrows `image` and yields one
    /// [`Section`] per header, stopping early on a truncated table rather than
    /// reading out of bounds.
    pub fn sections<'a>(&self, image: &'a [u8]) -> Sections<'a> {
        Sections {
            image,
            next: self.opt_off + self.opt_size as usize,
            remaining: self.sections,
        }
    }

    /// The `index`-th data directory (RVA + byte size), or `None` when the image
    /// declares fewer directories or the entry is empty. Mirrors
    /// `RtlImageDirectoryEntryToData`'s bounds and zero-VA checks.
    pub fn data_dir(&self, image: &[u8], index: usize) -> Option<DataDir> {
        // DataDirectory begins at a fixed optional-header offset (PE32+: 112,
        // PE32: 96), preceded by NumberOfRvaAndSizes.
        let (num_off, dir_off) = if self.pe64 { (108, 112) } else { (92, 96) };
        let count = read_u32(image, self.opt_off + num_off)?;
        if index as u32 >= count {
            return None;
        }
        let base = self.opt_off + dir_off + index * 8;
        let rva = read_u32(image, base)?;
        let size = read_u32(image, base + 4)?;
        (rva != 0).then_some(DataDir { rva, size })
    }

    /// Translate an RVA to a file offset by finding the section that contains it,
    /// mirroring `RtlImageRvaToVa`. Returns `None` when no section covers `rva`.
    pub fn rva_to_file(&self, image: &[u8], rva: u32) -> Option<usize> {
        self.sections(image)
            .find(|s| rva >= s.rva && rva < s.rva + s.raw_size)
            .map(|s| (s.raw_ptr + (rva - s.rva)) as usize)
    }

    /// Iterate the base-relocation table, yielding one [`Reloc`] per fixup.
    /// Returns `None` when the image has no relocation directory (e.g. a
    /// fixed-base image); an empty iterator means the directory is present but
    /// carries no fixups. Mirrors the block walk in ReactOS
    /// `LdrRelocateImageWithBias`.
    pub fn relocations<'a>(&self, image: &'a [u8]) -> Option<Relocations<'a>> {
        let dir = self.data_dir(image, DIR_BASERELOC)?;
        let start = self.rva_to_file(image, dir.rva)?;
        Some(Relocations {
            image,
            block: start,
            end: start + dir.size as usize,
            entry: 0,
            entry_end: 0,
            page_rva: 0,
        })
    }

    /// Walk the import directory, naming every library the image needs and what
    /// it takes from each.
    ///
    /// A program that reaches the system through a library rather than through
    /// the trap instruction says so here, so this is what tells a loader whether
    /// an image can run with the packages present or is asking for a layer that
    /// is not there yet. Mirrors `RtlImageDirectoryEntryToData` walking
    /// `IMAGE_IMPORT_DESCRIPTOR` and the thunk arrays behind it.
    pub fn imports<'a>(&self, image: &'a [u8]) -> Option<Imports<'a>> {
        let dir = self.data_dir(image, DIR_IMPORT)?;
        let start = self.rva_to_file(image, dir.rva)?;
        Some(Imports {
            pe: *self,
            image,
            descriptor: start,
            iat: 0,
            thunk: 0,
            library: None,
        })
    }

    /// Walk the export directory, naming what the image offers and where each
    /// entry sits.
    ///
    /// The counterpart of [`imports`](Self::imports): binding one image's
    /// imports means finding them among another's exports, so a loader needs
    /// both sides. Mirrors ReactOS `LdrpGetProcedureAddress` walking
    /// `IMAGE_EXPORT_DIRECTORY`.
    ///
    /// A forwarder - an entry whose address falls inside the directory itself,
    /// naming another library rather than code - is reported as such rather
    /// than as an address that would jump into the table.
    pub fn exports<'a>(&self, image: &'a [u8]) -> Option<Exports<'a>> {
        let dir = self.data_dir(image, DIR_EXPORT)?;
        let at = self.rva_to_file(image, dir.rva)?;
        let count = read_u32(image, at + 24)?;
        Some(Exports {
            pe: *self,
            image,
            dir,
            names: self.rva_to_file(image, read_u32(image, at + 32)?)?,
            ordinals: self.rva_to_file(image, read_u32(image, at + 36)?)?,
            functions: self.rva_to_file(image, read_u32(image, at + 28)?)?,
            ordinal_base: read_u32(image, at + 16)?,
            index: 0,
            count,
        })
    }
}

/// Where an exported name leads.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExportTarget<'a> {
    /// An RVA into this image.
    Rva(u32),
    /// Another library's entry, as `library.symbol`, which the exporting image
    /// spells in place of an address.
    Forwarder(&'a str),
}

/// One exported name and where it leads.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Export<'a> {
    /// The exported name.
    pub name: &'a str,
    /// Its ordinal, biased by the directory's base as callers see it.
    pub ordinal: u32,
    /// What it resolves to.
    pub target: ExportTarget<'a>,
}

/// Iterator over an image's named exports.
pub struct Exports<'a> {
    pe: PeInfo,
    image: &'a [u8],
    dir: DataDir,
    names: usize,
    ordinals: usize,
    functions: usize,
    ordinal_base: u32,
    index: u32,
    count: u32,
}

impl<'a> Iterator for Exports<'a> {
    type Item = Export<'a>;

    fn next(&mut self) -> Option<Export<'a>> {
        if self.index >= self.count {
            return None;
        }
        let i = self.index as usize;
        self.index += 1;

        let name_rva = read_u32(self.image, self.names + i * 4)?;
        let name = ascii_at(self.image, self.pe.rva_to_file(self.image, name_rva)?)?;
        // The ordinal table is indexed the same as the name table and holds the
        // index into the function table, unbiased.
        let slot = read_u16(self.image, self.ordinals + i * 2)? as usize;
        let rva = read_u32(self.image, self.functions + slot * 4)?;

        // An address inside the export directory is a forwarder string, not code.
        let target = if rva >= self.dir.rva && rva < self.dir.rva + self.dir.size {
            ExportTarget::Forwarder(ascii_at(self.image, self.pe.rva_to_file(self.image, rva)?)?)
        } else {
            ExportTarget::Rva(rva)
        };
        Some(Export {
            name,
            ordinal: self.ordinal_base + slot as u32,
            target,
        })
    }
}

/// One thing an image takes from a library: a name, or an ordinal for an entry
/// exported without one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ImportedSymbol<'a> {
    /// Imported by name, as `IMAGE_IMPORT_BY_NAME` spells it.
    Name(&'a str),
    /// Imported by ordinal (`IMAGE_ORDINAL_FLAG` set in the thunk).
    Ordinal(u16),
}

/// One import: which library, and what is taken from it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Import<'a> {
    /// The library's name as the descriptor spells it, e.g. `KERNEL32.dll`.
    pub library: &'a str,
    /// The symbol taken from it.
    pub symbol: ImportedSymbol<'a>,
    /// Where this symbol's address table entry is, as an RVA. The name table
    /// says what to resolve and this says where to put the answer; a loader
    /// walks the two in step, as `import_dll` does.
    pub thunk: u32,
}

/// Iterator over every symbol every imported library supplies.
pub struct Imports<'a> {
    pe: PeInfo,
    image: &'a [u8],
    /// File offset of the descriptor being walked.
    descriptor: usize,
    /// File offset of the next thunk within the current library, or 0 before a
    /// library has been entered.
    thunk: usize,
    /// The library the current thunks belong to.
    library: Option<&'a str>,
    /// RVA of the address table entry the next symbol answers to. It advances
    /// with the name table even when the two are the same array.
    iat: u32,
}

/// `IMAGE_IMPORT_DESCRIPTOR`: five 32-bit words, terminated by an all-zero one.
const IMPORT_DESCRIPTOR_LEN: usize = 20;
/// `IMAGE_ORDINAL_FLAG64`: the thunk names an ordinal rather than an RVA.
const IMPORT_ORDINAL_FLAG64: u64 = 1 << 63;
/// The same for PE32.
const IMPORT_ORDINAL_FLAG32: u32 = 1 << 31;

/// Read a NUL-terminated ASCII string at a file offset.
fn ascii_at(image: &[u8], off: usize) -> Option<&str> {
    let rest = image.get(off..)?;
    let end = rest.iter().position(|b| *b == 0)?;
    core::str::from_utf8(&rest[..end]).ok()
}

impl<'a> Iterator for Imports<'a> {
    type Item = Import<'a>;

    fn next(&mut self) -> Option<Import<'a>> {
        loop {
            // Enter the next library when the current one has no more thunks.
            let Some(library) = self.library else {
                let name_rva = read_u32(self.image, self.descriptor + 12)?;
                let first_thunk = read_u32(self.image, self.descriptor + 16)?;
                // An all-zero descriptor ends the table.
                if name_rva == 0 && first_thunk == 0 {
                    return None;
                }
                // The name table is preferred: it survives the loader writing
                // resolved addresses over the address table.
                let original = read_u32(self.image, self.descriptor)?;
                let thunks = if original != 0 { original } else { first_thunk };
                self.library = Some(ascii_at(
                    self.image,
                    self.pe.rva_to_file(self.image, name_rva)?,
                )?);
                self.thunk = self.pe.rva_to_file(self.image, thunks)?;
                self.iat = first_thunk;
                continue;
            };

            let (raw, width) = if self.pe.pe64 {
                (read_u64(self.image, self.thunk)?, 8)
            } else {
                (u64::from(read_u32(self.image, self.thunk)?), 4)
            };
            if raw == 0 {
                // End of this library's thunks; move to the next descriptor.
                self.library = None;
                self.descriptor += IMPORT_DESCRIPTOR_LEN;
                continue;
            }
            self.thunk += width;
            let thunk = self.iat;
            self.iat += width as u32;

            let ordinal = if self.pe.pe64 {
                raw & IMPORT_ORDINAL_FLAG64 != 0
            } else {
                raw as u32 & IMPORT_ORDINAL_FLAG32 != 0
            };
            let symbol = if ordinal {
                ImportedSymbol::Ordinal(raw as u16)
            } else {
                // IMAGE_IMPORT_BY_NAME: a 2-byte hint, then the name.
                let at = self.pe.rva_to_file(self.image, raw as u32)?;
                ImportedSymbol::Name(ascii_at(self.image, at + 2)?)
            };
            return Some(Import {
                library,
                symbol,
                thunk,
            });
        }
    }
}

/// A data-directory entry: an RVA and byte size.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DataDir {
    /// Directory contents as an RVA into the mapped image.
    pub rva: u32,
    /// Directory size in bytes.
    pub size: u32,
}

/// One section header, reduced to the fields a loader maps.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Section {
    /// Destination RVA of the mapped section (`VirtualAddress`).
    pub rva: u32,
    /// Size of the section once mapped; the tail beyond `raw_size` is zero-fill.
    pub vsize: u32,
    /// Bytes of initialized data in the file (`SizeOfRawData`).
    pub raw_size: u32,
    /// File offset of the initialized data (`PointerToRawData`).
    pub raw_ptr: u32,
    /// `Characteristics` bitfield; use [`Section::readable`] etc. to interpret.
    pub characteristics: u32,
}

impl Section {
    /// Whether the section maps as readable (`IMAGE_SCN_MEM_READ`).
    pub const fn readable(&self) -> bool {
        self.characteristics & SCN_MEM_READ != 0
    }
    /// Whether the section maps as writable (`IMAGE_SCN_MEM_WRITE`).
    pub const fn writable(&self) -> bool {
        self.characteristics & SCN_MEM_WRITE != 0
    }
    /// Whether the section maps as executable (`IMAGE_SCN_MEM_EXECUTE`).
    pub const fn executable(&self) -> bool {
        self.characteristics & SCN_MEM_EXECUTE != 0
    }

    /// The initialized bytes of this section within `image`, or `None` if the
    /// file range is truncated. The `vsize - raw_size` tail is zero-fill and not
    /// returned.
    pub fn raw_data<'a>(&self, image: &'a [u8]) -> Option<&'a [u8]> {
        let start = self.raw_ptr as usize;
        bytes(image, start, self.raw_size as usize)
    }
}

/// Iterator over a PE section table. Yields nothing further once the declared
/// count is reached or a header would read past the end of the image.
pub struct Sections<'a> {
    image: &'a [u8],
    next: usize,
    remaining: u16,
}

impl Iterator for Sections<'_> {
    type Item = Section;

    fn next(&mut self) -> Option<Section> {
        if self.remaining == 0 {
            return None;
        }
        let off = self.next;
        // A section header is 40 bytes: name[8], VirtualSize@8, VirtualAddress@12,
        // SizeOfRawData@16, PointerToRawData@20, ..., Characteristics@36.
        let section = Section {
            vsize: read_u32(self.image, off + 8)?,
            rva: read_u32(self.image, off + 12)?,
            raw_size: read_u32(self.image, off + 16)?,
            raw_ptr: read_u32(self.image, off + 20)?,
            characteristics: read_u32(self.image, off + 36)?,
        };
        self.next = off + 40;
        self.remaining -= 1;
        Some(section)
    }
}

/// One base-relocation fixup: the RVA to patch and its kind (`REL_*`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Reloc {
    /// RVA of the value to fix up (`block page RVA + entry offset`).
    pub rva: u32,
    /// Relocation kind (`IMAGE_REL_BASED_*`); [`REL_DIR64`] is the PE32+ case.
    pub kind: u16,
}

/// Iterator over base-relocation fixups across all blocks. `IMAGE_REL_BASED_ABSOLUTE`
/// padding entries are skipped; a truncated table ends iteration.
pub struct Relocations<'a> {
    image: &'a [u8],
    block: usize,
    end: usize,
    entry: usize,
    entry_end: usize,
    page_rva: u32,
}

impl Iterator for Relocations<'_> {
    type Item = Reloc;

    fn next(&mut self) -> Option<Reloc> {
        loop {
            // Advance across empty/exhausted blocks. Each block is an 8-byte
            // header (page RVA, SizeOfBlock) followed by 2-byte type/offset entries.
            while self.entry >= self.entry_end {
                if self.block + 8 > self.end {
                    return None;
                }
                let page_rva = read_u32(self.image, self.block)?;
                let size = read_u32(self.image, self.block + 4)? as usize;
                if size < 8 {
                    return None;
                }
                self.page_rva = page_rva;
                self.entry = self.block + 8;
                self.entry_end = (self.block + size).min(self.end);
                self.block += size;
            }
            let word = read_u16(self.image, self.entry)?;
            self.entry += 2;
            let kind = word >> 12;
            let offset = (word & 0xFFF) as u32;
            if kind == REL_ABSOLUTE {
                continue;
            }
            return Some(Reloc {
                rva: self.page_rva + offset,
                kind,
            });
        }
    }
}

/// Parse a PE image's headers far enough to map it. Returns `None` on any
/// malformed or truncated header, so a caller can cleanly report `ENOEXEC`
/// without trusting attacker-controlled offsets.
pub fn parse(image: &[u8]) -> Option<PeInfo> {
    // DOS header carries `e_lfanew` at 0x3C, pointing at the PE signature.
    let pe_off = read_u32(image, 0x3C)? as usize;
    if bytes(image, pe_off, 4)? != b"PE\0\0" {
        return None;
    }

    // COFF file header (20 bytes) follows the 4-byte signature, then the
    // optional header whose magic selects the 32/64-bit layout.
    let coff = pe_off + 4;
    let sections = read_u16(image, coff + 2)?;
    let opt_size = read_u16(image, coff + 16)?;
    let opt = coff + 20;
    let pe64 = match read_u16(image, opt)? {
        OPT_MAGIC_PE32_PLUS => true,
        OPT_MAGIC_PE32 => false,
        _ => return None,
    };

    // AddressOfEntryPoint sits at optional-header +16 in both layouts;
    // ImageBase is 8 bytes @ +24 (PE32+) or 4 bytes @ +28 (PE32);
    // Subsystem is 2 bytes @ +68 in both layouts.
    let entry_rva = read_u32(image, opt + 16)?;
    let image_base = if pe64 {
        read_u64(image, opt + 24)?
    } else {
        read_u32(image, opt + 28)? as u64
    };
    let subsystem = read_u16(image, opt + 68)?;

    Some(PeInfo {
        pe64,
        image_base,
        entry_rva,
        subsystem,
        sections,
        opt_off: opt,
        opt_size,
    })
}

fn bytes(b: &[u8], off: usize, len: usize) -> Option<&[u8]> {
    b.get(off..off.checked_add(len)?)
}

fn read_u16(b: &[u8], off: usize) -> Option<u16> {
    bytes(b, off, 2).map(|s| u16::from_le_bytes([s[0], s[1]]))
}

fn read_u32(b: &[u8], off: usize) -> Option<u32> {
    bytes(b, off, 4).map(|s| u32::from_le_bytes([s[0], s[1], s[2], s[3]]))
}

fn read_u64(b: &[u8], off: usize) -> Option<u64> {
    bytes(b, off, 8).map(|s| {
        let mut a = [0u8; 8];
        a.copy_from_slice(s);
        u64::from_le_bytes(a)
    })
}

#[cfg(test)]
mod tests {
    use alloc::{vec, vec::Vec};

    use super::*;

    const PE_OFF: usize = 0x80;
    const SECT_ALIGN: usize = 40;

    // Build a minimal well-formed PE32+ image with `sections` section headers and
    // a full data directory, enough for every accessor to read real fields.
    fn synth(image_base: u64, entry_rva: u32, subsystem: u16, sections: u16) -> Vec<u8> {
        let opt = PE_OFF + 4 + 20;
        let opt_size: usize = 240; // covers the 16 data directories.
        let sect_table = opt + opt_size;
        let mut b = vec![0u8; sect_table + sections as usize * SECT_ALIGN + 0x400];
        b[0..2].copy_from_slice(b"MZ");
        b[0x3C..0x40].copy_from_slice(&(PE_OFF as u32).to_le_bytes());
        b[PE_OFF..PE_OFF + 4].copy_from_slice(b"PE\0\0");
        let coff = PE_OFF + 4;
        b[coff + 2..coff + 4].copy_from_slice(&sections.to_le_bytes());
        b[coff + 16..coff + 18].copy_from_slice(&(opt_size as u16).to_le_bytes());
        b[opt..opt + 2].copy_from_slice(&OPT_MAGIC_PE32_PLUS.to_le_bytes());
        b[opt + 16..opt + 20].copy_from_slice(&entry_rva.to_le_bytes());
        b[opt + 24..opt + 32].copy_from_slice(&image_base.to_le_bytes());
        b[opt + 68..opt + 70].copy_from_slice(&subsystem.to_le_bytes());
        b[opt + 108..opt + 112].copy_from_slice(&16u32.to_le_bytes()); // NumberOfRvaAndSizes
        b
    }

    fn put_section(b: &mut [u8], idx: usize, s: Section) {
        let opt = PE_OFF + 4 + 20;
        let off = opt + 240 + idx * SECT_ALIGN;
        b[off + 8..off + 12].copy_from_slice(&s.vsize.to_le_bytes());
        b[off + 12..off + 16].copy_from_slice(&s.rva.to_le_bytes());
        b[off + 16..off + 20].copy_from_slice(&s.raw_size.to_le_bytes());
        b[off + 20..off + 24].copy_from_slice(&s.raw_ptr.to_le_bytes());
        b[off + 36..off + 40].copy_from_slice(&s.characteristics.to_le_bytes());
    }

    fn put_data_dir(b: &mut [u8], index: usize, rva: u32, size: u32) {
        let opt = PE_OFF + 4 + 20;
        let base = opt + 112 + index * 8;
        b[base..base + 4].copy_from_slice(&rva.to_le_bytes());
        b[base + 4..base + 8].copy_from_slice(&size.to_le_bytes());
    }

    #[test]
    fn parses_a_native_pe64() {
        let pe = parse(&synth(0x1_4000_0000, 0x1000, 1, 3)).expect("valid PE32+");
        assert!(pe.pe64);
        assert_eq!(pe.image_base, 0x1_4000_0000);
        assert_eq!(pe.entry_va(), 0x1_4000_1000);
        assert!(pe.is_native());
        assert_eq!(pe.sections, 3);
    }

    #[test]
    fn walks_the_section_table() {
        let mut b = synth(0x1_4000_0000, 0x1000, 3, 2);
        put_section(
            &mut b,
            0,
            Section {
                rva: 0x1000,
                vsize: 0x2000,
                raw_size: 0x1000,
                raw_ptr: 0x400,
                characteristics: SCN_MEM_READ | SCN_MEM_EXECUTE,
            },
        );
        put_section(
            &mut b,
            1,
            Section {
                rva: 0x3000,
                vsize: 0x1000,
                raw_size: 0x200,
                raw_ptr: 0x1400,
                characteristics: SCN_MEM_READ | SCN_MEM_WRITE,
            },
        );
        let pe = parse(&b).unwrap();
        let secs: Vec<Section> = pe.sections(&b).collect();
        assert_eq!(secs.len(), 2);
        assert_eq!(secs[0].rva, 0x1000);
        assert!(secs[0].executable() && secs[0].readable() && !secs[0].writable());
        assert_eq!(secs[1].rva, 0x3000);
        assert!(secs[1].writable() && !secs[1].executable());
    }

    #[test]
    fn reads_present_and_absent_data_dirs() {
        let mut b = synth(0x1_4000_0000, 0x1000, 3, 1);
        put_data_dir(&mut b, DIR_BASERELOC, 0x5000, 0x40);
        let pe = parse(&b).unwrap();
        assert_eq!(
            pe.data_dir(&b, DIR_BASERELOC),
            Some(DataDir {
                rva: 0x5000,
                size: 0x40
            })
        );
        // An untouched (zero-VA) directory reads as absent.
        assert_eq!(pe.data_dir(&b, DIR_IMPORT), None);
    }

    #[test]
    fn iterates_base_relocations() {
        let mut b = synth(0x1_4000_0000, 0x1000, 3, 1);
        // A single `.reloc` section maps RVA 0x4000 to file offset 0x400.
        put_section(
            &mut b,
            0,
            Section {
                rva: 0x4000,
                vsize: 0x1000,
                raw_size: 0x100,
                raw_ptr: 0x400,
                characteristics: SCN_MEM_READ,
            },
        );
        // One block for page 0x1000: two DIR64 fixups plus an ABSOLUTE pad.
        let block = 0x400;
        b[block..block + 4].copy_from_slice(&0x1000u32.to_le_bytes()); // page RVA
        b[block + 4..block + 8].copy_from_slice(&(8u32 + 6).to_le_bytes()); // SizeOfBlock
        let entry = |kind: u16, off: u16| (kind << 12 | off).to_le_bytes();
        b[block + 8..block + 10].copy_from_slice(&entry(REL_DIR64, 0x010));
        b[block + 10..block + 12].copy_from_slice(&entry(REL_DIR64, 0x020));
        b[block + 12..block + 14].copy_from_slice(&entry(REL_ABSOLUTE, 0));
        put_data_dir(&mut b, DIR_BASERELOC, 0x4000, 8 + 6);

        let pe = parse(&b).unwrap();
        let relocs: Vec<Reloc> = pe.relocations(&b).unwrap().collect();
        assert_eq!(
            relocs,
            [
                Reloc {
                    rva: 0x1010,
                    kind: REL_DIR64
                },
                Reloc {
                    rva: 0x1020,
                    kind: REL_DIR64
                },
            ]
        );
    }

    #[test]
    fn no_reloc_directory_is_none() {
        let b = synth(0x1_4000_0000, 0x1000, 3, 1);
        assert!(parse(&b).unwrap().relocations(&b).is_none());
    }

    #[test]
    fn truncated_section_table_stops_cleanly() {
        let mut b = synth(0x1_4000_0000, 0x1000, 3, 4);
        b.truncate(PE_OFF + 4 + 20 + 240 + SECT_ALIGN); // room for one header only
        let pe = parse(&b).unwrap();
        // Declared four sections, but iteration stops when a header runs past EOF.
        assert_eq!(pe.sections(&b).count(), 1);
    }

    #[test]
    fn rejects_pe32_and_bad_magic() {
        let mut b = synth(0, 0, 3, 1);
        let opt = PE_OFF + 4 + 20;
        b[opt..opt + 2].copy_from_slice(&OPT_MAGIC_PE32.to_le_bytes());
        assert!(!parse(&b).unwrap().pe64);
        b[opt..opt + 2].copy_from_slice(&0xDEADu16.to_le_bytes());
        assert_eq!(parse(&b), None);
    }

    #[test]
    fn truncated_header_and_missing_signature_rejected() {
        let mut b = synth(0x1_4000_0000, 0x1000, 1, 3);
        b[PE_OFF] = b'X';
        assert_eq!(parse(&b), None);
        let mut b = synth(0x1_4000_0000, 0x1000, 1, 3);
        b.truncate(0x84);
        assert_eq!(parse(&b), None);
    }

    /// A PE whose import directory names one library and takes two things from
    /// it: one by name, one by ordinal.
    fn synth_with_imports() -> Vec<u8> {
        let mut b = synth(0x1_4000_0000, 0x1000, 3, 1);
        // One section maps RVA 0x1000 onto file offset 0x400.
        put_section(
            &mut b,
            0,
            Section {
                rva: 0x1000,
                vsize: 0x200,
                raw_ptr: 0x400,
                raw_size: 0x200,
                characteristics: SCN_MEM_READ,
            },
        );
        put_data_dir(&mut b, DIR_IMPORT, 0x1000, 40);

        // IMAGE_IMPORT_DESCRIPTOR at RVA 0x1000 (file 0x400).
        b[0x400..0x404].copy_from_slice(&0x1040u32.to_le_bytes()); // OriginalFirstThunk
        b[0x40C..0x410].copy_from_slice(&0x1080u32.to_le_bytes()); // Name
        b[0x410..0x414].copy_from_slice(&0x1060u32.to_le_bytes()); // FirstThunk
        // The next descriptor is left zeroed, which ends the table.

        // Name table at RVA 0x1040 (file 0x440): one by-name, one by-ordinal.
        b[0x440..0x448].copy_from_slice(&0x1090u64.to_le_bytes());
        b[0x448..0x450].copy_from_slice(&(IMPORT_ORDINAL_FLAG64 | 7).to_le_bytes());
        // A zero thunk ends this library's list.

        b[0x480..0x48D].copy_from_slice(b"KERNEL32.dll\0");
        // IMAGE_IMPORT_BY_NAME: a hint, then the name.
        b[0x490..0x492].copy_from_slice(&0u16.to_le_bytes());
        b[0x492..0x49C].copy_from_slice(b"WriteFile\0");
        b
    }

    #[test]
    fn walks_the_import_directory() {
        let b = synth_with_imports();
        let pe = parse(&b).expect("valid PE32+");

        let imports: Vec<Import> = pe.imports(&b).expect("an import directory").collect();

        assert_eq!(
            imports,
            vec![
                // FirstThunk is at RVA 0x1060, and each PE32+ entry is eight
                // bytes, so the two symbols answer to consecutive slots.
                Import {
                    library: "KERNEL32.dll",
                    symbol: ImportedSymbol::Name("WriteFile"),
                    thunk: 0x1060,
                },
                Import {
                    library: "KERNEL32.dll",
                    symbol: ImportedSymbol::Ordinal(7),
                    thunk: 0x1068,
                },
            ]
        );
    }

    #[test]
    fn an_image_without_an_import_directory_has_no_imports() {
        // The direct-syscall images this kernel runs today reach the system
        // through the trap instruction, so they import nothing at all.
        let b = synth(0x1_4000_0000, 0x1000, 1, 1);
        let pe = parse(&b).expect("valid PE32+");
        assert!(pe.imports(&b).is_none());
    }

    /// A PE that exports two names: one at an address of its own, one forwarded
    /// to another library.
    fn synth_with_exports() -> Vec<u8> {
        let mut b = synth(0x1_4000_0000, 0x1000, 3, 1);
        put_section(
            &mut b,
            0,
            Section {
                rva: 0x1000,
                vsize: 0x200,
                raw_ptr: 0x400,
                raw_size: 0x200,
                characteristics: SCN_MEM_READ,
            },
        );
        // The directory spans RVA 0x1000..0x1100; an address inside it is a
        // forwarder string rather than code.
        put_data_dir(&mut b, DIR_EXPORT, 0x1000, 0x100);

        // IMAGE_EXPORT_DIRECTORY at RVA 0x1000 (file 0x400).
        b[0x410..0x414].copy_from_slice(&5u32.to_le_bytes()); // Base
        b[0x414..0x418].copy_from_slice(&2u32.to_le_bytes()); // NumberOfFunctions
        b[0x418..0x41C].copy_from_slice(&2u32.to_le_bytes()); // NumberOfNames
        b[0x41C..0x420].copy_from_slice(&0x1040u32.to_le_bytes()); // AddressOfFunctions
        b[0x420..0x424].copy_from_slice(&0x1050u32.to_le_bytes()); // AddressOfNames
        b[0x424..0x428].copy_from_slice(&0x1060u32.to_le_bytes()); // AddressOfNameOrdinals

        b[0x440..0x444].copy_from_slice(&0x2000u32.to_le_bytes()); // Alpha -> code
        b[0x444..0x448].copy_from_slice(&0x10C0u32.to_le_bytes()); // Beta -> forwarder
        b[0x450..0x454].copy_from_slice(&0x1090u32.to_le_bytes());
        b[0x454..0x458].copy_from_slice(&0x10A0u32.to_le_bytes());
        b[0x460..0x462].copy_from_slice(&0u16.to_le_bytes());
        b[0x462..0x464].copy_from_slice(&1u16.to_le_bytes());
        b[0x490..0x496].copy_from_slice(b"Alpha\0");
        b[0x4A0..0x4A5].copy_from_slice(b"Beta\0");
        b[0x4C0..0x4D0].copy_from_slice(b"OTHER.dll.Gamma\0");
        b
    }

    #[test]
    fn walks_the_export_directory() {
        let b = synth_with_exports();
        let pe = parse(&b).expect("valid PE32+");

        let exports: Vec<Export> = pe.exports(&b).expect("an export directory").collect();

        assert_eq!(
            exports,
            vec![
                Export {
                    name: "Alpha",
                    ordinal: 5,
                    target: ExportTarget::Rva(0x2000),
                },
                Export {
                    name: "Beta",
                    ordinal: 6,
                    target: ExportTarget::Forwarder("OTHER.dll.Gamma"),
                },
            ]
        );
    }

    #[test]
    fn an_image_that_exports_nothing_has_no_export_directory() {
        let b = synth(0x1_4000_0000, 0x1000, 1, 1);
        let pe = parse(&b).expect("valid PE32+");
        assert!(pe.exports(&b).is_none());
    }
}
