//! PE/COFF header parsing, reduced to what a loader needs to reach `entry`.
//!
//! This is the binfmt layer's knowledge of the Windows image format, mirroring
//! how Linux keeps ELF header parsing inside `fs/binfmt_elf.c`. `ax-abi-windows`
//! reuses [`parse`] instead of re-decoding the headers. Field offsets follow the
//! PE/COFF specification and ReactOS `sdk/lib/rtl/image.c` (`RtlImageNtHeader`).

/// The slice of a PE image a loader needs before mapping sections.
///
/// Only load-bearing fields are decoded; section bodies, imports and relocations
/// are read later by the Windows personality against the mapped image.
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
}

// Optional-header magic values (PE/COFF spec, IMAGE_NT_OPTIONAL_HDR{32,64}_MAGIC).
const OPT_MAGIC_PE32: u16 = 0x10B;
const OPT_MAGIC_PE32_PLUS: u16 = 0x20B;

/// Parse a PE image's headers far enough to locate its entry point. Returns
/// `None` on any malformed or truncated header, so a caller can cleanly report
/// `ENOEXEC` without trusting attacker-controlled offsets.
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
    use super::*;

    // A minimal well-formed PE32+ image: DOS stub + PE sig + COFF + optional
    // header, enough for `parse` to read every field it needs.
    fn synth(image_base: u64, entry_rva: u32, subsystem: u16, sections: u16) -> Vec<u8> {
        let pe_off: usize = 0x80;
        let mut b = vec![0u8; pe_off + 4 + 20 + 240];
        b[0..2].copy_from_slice(b"MZ");
        b[0x3C..0x40].copy_from_slice(&(pe_off as u32).to_le_bytes());
        b[pe_off..pe_off + 4].copy_from_slice(b"PE\0\0");
        let coff = pe_off + 4;
        b[coff + 2..coff + 4].copy_from_slice(&sections.to_le_bytes());
        let opt = coff + 20;
        b[opt..opt + 2].copy_from_slice(&OPT_MAGIC_PE32_PLUS.to_le_bytes());
        b[opt + 16..opt + 20].copy_from_slice(&entry_rva.to_le_bytes());
        b[opt + 24..opt + 32].copy_from_slice(&image_base.to_le_bytes());
        b[opt + 68..opt + 70].copy_from_slice(&subsystem.to_le_bytes());
        b
    }

    #[test]
    fn parses_a_native_pe64() {
        let pe = parse(&synth(0x1_4000_0000, 0x1000, 1, 3)).expect("valid PE32+");
        assert!(pe.pe64);
        assert_eq!(pe.image_base, 0x1_4000_0000);
        assert_eq!(pe.entry_rva, 0x1000);
        assert_eq!(pe.entry_va(), 0x1_4000_1000);
        assert!(pe.is_native());
        assert_eq!(pe.sections, 3);
    }

    #[test]
    fn console_subsystem_is_not_native() {
        let pe = parse(&synth(0x1_4000_0000, 0x2000, 3, 5)).unwrap();
        assert!(!pe.is_native());
        assert_eq!(pe.subsystem, 3);
    }

    #[test]
    fn rejects_pe32_and_bad_magic() {
        // A 32-bit optional header magic is recognized but reported as PE32.
        let mut b = synth(0, 0, 3, 1);
        let opt = 0x80 + 4 + 20;
        b[opt..opt + 2].copy_from_slice(&OPT_MAGIC_PE32.to_le_bytes());
        assert!(!parse(&b).unwrap().pe64);
        // A garbage magic is rejected outright.
        b[opt..opt + 2].copy_from_slice(&0xDEADu16.to_le_bytes());
        assert_eq!(parse(&b), None);
    }

    #[test]
    fn truncated_header_is_rejected() {
        let mut b = synth(0x1_4000_0000, 0x1000, 1, 3);
        b.truncate(0x84); // cut inside the optional header
        assert_eq!(parse(&b), None);
    }

    #[test]
    fn missing_pe_signature_is_rejected() {
        let mut b = synth(0x1_4000_0000, 0x1000, 1, 3);
        b[0x80] = b'X'; // corrupt the "PE\0\0" signature
        assert_eq!(parse(&b), None);
    }
}
