//! Mach-O header parsing for 64-bit thin executables (macOS/Darwin).
//!
//! The binfmt layer's knowledge of the Mach-O format, alongside [`crate::pe`].
//! `ax-abi-darwin` reuses this to map segments and find the entry point rather
//! than re-decoding load commands. Offsets follow `<mach-o/loader.h>`
//! (`mach_header_64`, `segment_command_64`, `entry_point_command`). Fat/universal
//! archives are recognized by [`crate::detect`] but not parsed here; a thin slice
//! is expected.

/// 64-bit little-endian Mach-O magic (`MH_MAGIC_64`).
pub const MH_MAGIC_64: u32 = 0xFEED_FACF;

// Load-command kinds we act on (`<mach-o/loader.h>`).
const LC_SEGMENT_64: u32 = 0x19;
const LC_MAIN: u32 = 0x8000_0028;

// `mach_header_64` is 32 bytes; load commands follow it.
const HEADER_LEN: usize = 32;

/// Parsed Mach-O header: enough to walk load commands.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MachoInfo {
    /// File offset where load commands begin (just past the header).
    pub commands_off: usize,
    /// Number of load commands.
    pub ncmds: u32,
    /// Total byte size of the load-command region.
    pub sizeofcmds: u32,
}

impl MachoInfo {
    /// Iterate the `LC_SEGMENT_64` load commands, yielding one [`Segment`] each.
    pub fn segments<'a>(&self, image: &'a [u8]) -> Segments<'a> {
        Segments {
            image,
            next: self.commands_off,
            end: self.commands_off + self.sizeofcmds as usize,
            remaining: self.ncmds,
        }
    }

    /// The entry point virtual address from `LC_MAIN`, translated through the
    /// segment that contains its file offset. Returns `None` if there is no
    /// `LC_MAIN` or no segment covers it (e.g. a legacy `LC_UNIXTHREAD` image).
    pub fn entry(&self, image: &[u8]) -> Option<u64> {
        let entryoff = self.main_entryoff(image)?;
        self.segments(image)
            .find(|s| (s.fileoff..s.fileoff + s.filesize).contains(&entryoff))
            .map(|s| s.vmaddr + (entryoff - s.fileoff))
    }

    /// The `entryoff` field of the `LC_MAIN` command, if present.
    fn main_entryoff(&self, image: &[u8]) -> Option<u64> {
        let mut off = self.commands_off;
        let end = self.commands_off + self.sizeofcmds as usize;
        for _ in 0..self.ncmds {
            if off + 8 > end {
                break;
            }
            let cmd = read_u32(image, off)?;
            let size = read_u32(image, off + 4)? as usize;
            if size < 8 {
                break;
            }
            if cmd == LC_MAIN {
                return read_u64(image, off + 8);
            }
            off += size;
        }
        None
    }
}

/// One `LC_SEGMENT_64` mapping (coarser than a PE section).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Segment {
    /// Destination virtual address (`vmaddr`).
    pub vmaddr: u64,
    /// Mapped size; the tail beyond `filesize` is zero-fill (`vmsize`).
    pub vmsize: u64,
    /// File offset of the segment's initialized bytes (`fileoff`).
    pub fileoff: u64,
    /// Count of initialized bytes in the file (`filesize`).
    pub filesize: u64,
    /// Initial protection bits (`initprot`); `VM_PROT_*` match `PROT_*`
    /// (READ=1, WRITE=2, EXECUTE=4).
    pub initprot: u32,
}

impl Segment {
    /// Whether the segment maps readable (`VM_PROT_READ`).
    pub const fn readable(&self) -> bool {
        self.initprot & 0x1 != 0
    }
    /// Whether the segment maps writable (`VM_PROT_WRITE`).
    pub const fn writable(&self) -> bool {
        self.initprot & 0x2 != 0
    }
    /// Whether the segment maps executable (`VM_PROT_EXECUTE`).
    pub const fn executable(&self) -> bool {
        self.initprot & 0x4 != 0
    }

    /// The initialized bytes of this segment within `image`, or `None` if the
    /// file range is truncated. The `vmsize - filesize` tail is zero-fill.
    pub fn file_data<'a>(&self, image: &'a [u8]) -> Option<&'a [u8]> {
        let start = self.fileoff as usize;
        image.get(start..start.checked_add(self.filesize as usize)?)
    }
}

/// Iterator over a Mach-O image's `LC_SEGMENT_64` commands, skipping others.
pub struct Segments<'a> {
    image: &'a [u8],
    next: usize,
    end: usize,
    remaining: u32,
}

impl Iterator for Segments<'_> {
    type Item = Segment;

    fn next(&mut self) -> Option<Segment> {
        while self.remaining > 0 && self.next + 8 <= self.end {
            let off = self.next;
            let cmd = read_u32(self.image, off)?;
            let size = read_u32(self.image, off + 4)? as usize;
            if size < 8 {
                return None;
            }
            self.next = off + size;
            self.remaining -= 1;
            if cmd == LC_SEGMENT_64 {
                // segment_command_64: vmaddr@24, vmsize@32, fileoff@40,
                // filesize@48, maxprot@56, initprot@60.
                return Some(Segment {
                    vmaddr: read_u64(self.image, off + 24)?,
                    vmsize: read_u64(self.image, off + 32)?,
                    fileoff: read_u64(self.image, off + 40)?,
                    filesize: read_u64(self.image, off + 48)?,
                    initprot: read_u32(self.image, off + 60)?,
                });
            }
        }
        None
    }
}

/// Parse a thin 64-bit Mach-O header. Returns `None` for other magics
/// (32-bit, big-endian, or a fat archive) or a truncated header.
pub fn parse(image: &[u8]) -> Option<MachoInfo> {
    if read_u32(image, 0)? != MH_MAGIC_64 {
        return None;
    }
    Some(MachoInfo {
        commands_off: HEADER_LEN,
        ncmds: read_u32(image, 16)?,
        sizeofcmds: read_u32(image, 20)?,
    })
}

fn read_u32(b: &[u8], off: usize) -> Option<u32> {
    b.get(off..off + 4)
        .map(|s| u32::from_le_bytes([s[0], s[1], s[2], s[3]]))
}

fn read_u64(b: &[u8], off: usize) -> Option<u64> {
    b.get(off..off + 8).map(|s| {
        let mut a = [0u8; 8];
        a.copy_from_slice(s);
        u64::from_le_bytes(a)
    })
}

#[cfg(test)]
mod tests {
    use alloc::{vec, vec::Vec};

    use super::*;

    // Build a thin Mach-O with one __TEXT segment and an LC_MAIN command.
    fn synth(text_vmaddr: u64, entryoff: u64) -> Vec<u8> {
        let seg_len = 72usize;
        let main_len = 24usize;
        let sizeofcmds = seg_len + main_len;
        let mut b = vec![0u8; HEADER_LEN + sizeofcmds + 0x100];
        b[0..4].copy_from_slice(&MH_MAGIC_64.to_le_bytes());
        b[12..16].copy_from_slice(&2u32.to_le_bytes()); // MH_EXECUTE
        b[16..20].copy_from_slice(&2u32.to_le_bytes()); // ncmds
        b[20..24].copy_from_slice(&(sizeofcmds as u32).to_le_bytes());

        let seg = HEADER_LEN;
        b[seg..seg + 4].copy_from_slice(&LC_SEGMENT_64.to_le_bytes());
        b[seg + 4..seg + 8].copy_from_slice(&(seg_len as u32).to_le_bytes());
        b[seg + 24..seg + 32].copy_from_slice(&text_vmaddr.to_le_bytes()); // vmaddr
        b[seg + 32..seg + 40].copy_from_slice(&0x4000u64.to_le_bytes()); // vmsize
        b[seg + 40..seg + 48].copy_from_slice(&0u64.to_le_bytes()); // fileoff
        b[seg + 48..seg + 56].copy_from_slice(&0x1000u64.to_le_bytes()); // filesize
        b[seg + 60..seg + 64].copy_from_slice(&0x5u32.to_le_bytes()); // initprot RX

        let main = seg + seg_len;
        b[main..main + 4].copy_from_slice(&LC_MAIN.to_le_bytes());
        b[main + 4..main + 8].copy_from_slice(&(main_len as u32).to_le_bytes());
        b[main + 8..main + 16].copy_from_slice(&entryoff.to_le_bytes());
        b
    }

    #[test]
    fn parses_header_and_segment() {
        let b = synth(0x1_0000_0000, 0x800);
        let macho = parse(&b).expect("thin macho");
        assert_eq!(macho.ncmds, 2);
        let segs: Vec<Segment> = macho.segments(&b).collect();
        assert_eq!(segs.len(), 1);
        assert_eq!(segs[0].vmaddr, 0x1_0000_0000);
        assert!(segs[0].readable() && segs[0].executable() && !segs[0].writable());
    }

    #[test]
    fn resolves_lc_main_entry() {
        // entryoff 0x800 lies in __TEXT [fileoff 0, +0x1000): entry = vmaddr+0x800.
        let b = synth(0x1_0000_0000, 0x800);
        assert_eq!(parse(&b).unwrap().entry(&b), Some(0x1_0000_0800));
    }

    #[test]
    fn rejects_non_macho_and_truncation() {
        assert_eq!(parse(b"\x7fELF"), None);
        assert_eq!(parse(&[0xCA, 0xFE, 0xBA, 0xBE]), None); // fat archive, not thin
        let mut b = synth(0x1_0000_0000, 0x800);
        b.truncate(HEADER_LEN + 8);
        assert_eq!(parse(&b).unwrap().segments(&b).count(), 0);
    }
}
