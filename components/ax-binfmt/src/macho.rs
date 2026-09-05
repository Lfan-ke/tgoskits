//! Mach-O header parsing for 64-bit thin executables (macOS/Darwin).
//!
//! The binfmt layer's knowledge of the Mach-O format, alongside [`crate::pe`].
//! `ax-abi-darwin` reuses this to map segments and find the entry point rather
//! than re-decoding load commands. Offsets follow `<mach-o/loader.h>`
//! (`mach_header_64`, `segment_command_64`, `entry_point_command`). A
//! fat/universal archive is a directory of thin images, so it is opened here
//! by picking the slice for the architecture this is built for - the official
//! macOS CPython ships that way.

/// 64-bit little-endian Mach-O magic (`MH_MAGIC_64`).
pub const MH_MAGIC_64: u32 = 0xFEED_FACF;

// A universal archive's header and entries are big-endian, whichever way the
// slices themselves run (`<mach-o/fat.h>`).
const FAT_MAGIC: u32 = 0xCAFE_BABE;
const FAT_MAGIC_64: u32 = 0xCAFE_BABF;

/// The `cputype` of the slice to take: the architecture this is built for.
const CPU_TYPE: u32 = if cfg!(target_arch = "aarch64") {
    0x0100_000C // CPU_TYPE_ARM64
} else {
    0x0100_0007 // CPU_TYPE_X86_64
};

// Load-command kinds we act on (`<mach-o/loader.h>`).
const LC_SEGMENT_64: u32 = 0x19;
const LC_MAIN: u32 = 0x8000_0028;
// The four ways an image names a library it needs. A bind's library ordinal
// counts these in the order they appear, whichever kind each one is, so they
// are reported as one list.
const LC_LOAD_DYLIB: u32 = 0x0C;
const LC_LOAD_WEAK_DYLIB: u32 = 0x8000_0018;
const LC_REEXPORT_DYLIB: u32 = 0x8000_001F;
const LC_LOAD_UPWARD_DYLIB: u32 = 0x8000_0023;

/// `S_MOD_INIT_FUNC_POINTERS`: a section of function pointers to call before
/// a program's `main`, which is what a C++ constructor at file scope and a
/// `__attribute__((constructor))` compile to.
const S_MOD_INIT_FUNC_POINTERS: u32 = 0x9;

// `mach_header_64` is 32 bytes; load commands follow it.
const HEADER_LEN: usize = 32;
// `section_64` is 80 bytes, and a segment's sections follow its command.
const SECTION_LEN: usize = 80;
const SEGMENT_LEN: usize = 72;

/// Parsed Mach-O header: enough to walk load commands.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MachoInfo {
    /// Where the slice this header belongs to starts in the file: zero for an
    /// image that is one slice already, and the archive's offset for a slice
    /// out of a universal one. Every file offset a load command names is
    /// measured from here.
    pub base: usize,
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
            base: self.base as u64,
            next: self.commands_off,
            end: self.commands_off + self.sizeofcmds as usize,
            remaining: self.ncmds,
        }
    }

    /// The libraries this image needs, in the order a bind's library ordinal
    /// counts them.
    pub fn dylibs<'a>(&self, image: &'a [u8]) -> Dylibs<'a> {
        Dylibs {
            image,
            next: self.commands_off,
            end: self.commands_off + self.sizeofcmds as usize,
            remaining: self.ncmds,
        }
    }

    /// The initializers the image wants run before `main`, each reported as
    /// the address of a section of function pointers and its byte length.
    ///
    /// dyld runs these after binding and before the entry point, in the order
    /// the sections appear, and hands each one the same four arguments `main`
    /// gets (`dyld3::MachOAnalyzer::forEachInitializer`).
    pub fn initializers<'a>(&self, image: &'a [u8]) -> Initializers<'a> {
        Initializers {
            image,
            sect: 0,
            next: self.commands_off,
            end: self.commands_off + self.sizeofcmds as usize,
            remaining: self.ncmds,
        }
    }

    /// The entry point virtual address from `LC_MAIN`, translated through the
    /// segment that contains its file offset. Returns `None` if there is no
    /// `LC_MAIN` or no segment covers it (e.g. a legacy `LC_UNIXTHREAD` image).
    pub fn entry(&self, image: &[u8]) -> Option<u64> {
        // `entryoff` is measured from the slice, and a segment's `fileoff` is
        // reported from the file, so the two are brought to the same origin.
        let entryoff = self.base as u64 + self.main_entryoff(image)?;
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

/// One library an image names, and whether it will settle for it being
/// missing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Dylib<'a> {
    pub path: &'a str,
    pub weak: bool,
    /// Whether what this library exports counts as this image's own exports,
    /// which is what a framework's umbrella library is for.
    pub reexport: bool,
}

/// Iterator over the libraries an image names.
pub struct Dylibs<'a> {
    image: &'a [u8],
    next: usize,
    end: usize,
    remaining: u32,
}

impl<'a> Iterator for Dylibs<'a> {
    type Item = Dylib<'a>;

    fn next(&mut self) -> Option<Dylib<'a>> {
        while self.remaining > 0 && self.next + 8 <= self.end {
            let off = self.next;
            let cmd = read_u32(self.image, off)?;
            let size = read_u32(self.image, off + 4)? as usize;
            if size < 8 {
                return None;
            }
            self.next = off + size;
            self.remaining -= 1;
            if !matches!(
                cmd,
                LC_LOAD_DYLIB | LC_LOAD_WEAK_DYLIB | LC_REEXPORT_DYLIB | LC_LOAD_UPWARD_DYLIB
            ) {
                continue;
            }
            // dylib_command: the name is an `lc_str`, an offset from the
            // command's own start, and runs to its NUL.
            let at = off + read_u32(self.image, off + 8)? as usize;
            if at >= off + size {
                continue;
            }
            let rest = self.image.get(at..off + size)?;
            let len = rest.iter().position(|b| *b == 0).unwrap_or(rest.len());
            let path = core::str::from_utf8(&rest[..len]).ok()?;
            return Some(Dylib {
                path,
                weak: cmd == LC_LOAD_WEAK_DYLIB,
                reexport: cmd == LC_REEXPORT_DYLIB,
            });
        }
        None
    }
}

/// One run of function pointers an image wants called before `main`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Initializer {
    /// Where the pointers are, as the image names the address.
    pub vmaddr: u64,
    /// How many bytes of them there are.
    pub len: u64,
}

/// Iterator over an image's `__mod_init_func` sections.
pub struct Initializers<'a> {
    image: &'a [u8],
    /// The load command being read, and how far into its sections the walk is.
    next: usize,
    sect: u32,
    end: usize,
    remaining: u32,
}

impl Iterator for Initializers<'_> {
    type Item = Initializer;

    fn next(&mut self) -> Option<Initializer> {
        while self.remaining > 0 && self.next + 8 <= self.end {
            let off = self.next;
            let cmd = read_u32(self.image, off)?;
            let size = read_u32(self.image, off + 4)? as usize;
            if size < 8 {
                return None;
            }
            // segment_command_64: nsects@64, with the sections after it.
            let nsects = if cmd == LC_SEGMENT_64 {
                read_u32(self.image, off + 64)?
            } else {
                0
            };
            while self.sect < nsects {
                let sect = off + SEGMENT_LEN + self.sect as usize * SECTION_LEN;
                self.sect += 1;
                if sect + SECTION_LEN > off + size {
                    break;
                }
                // section_64: addr@32, size@40, flags@64; a section's kind is
                // the low byte of its flags.
                if read_u32(self.image, sect + 64)? & 0xFF != S_MOD_INIT_FUNC_POINTERS {
                    continue;
                }
                return Some(Initializer {
                    vmaddr: read_u64(self.image, sect + 32)?,
                    len: read_u64(self.image, sect + 40)?,
                });
            }
            self.next = off + size;
            self.sect = 0;
            self.remaining -= 1;
        }
        None
    }
}

/// Iterator over a Mach-O image's `LC_SEGMENT_64` commands, skipping others.
pub struct Segments<'a> {
    image: &'a [u8],
    base: u64,
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
                    fileoff: self.base + read_u64(self.image, off + 40)?,
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
    let base = slice_at(image)?;
    if read_u32(image, base)? != MH_MAGIC_64 {
        return None;
    }
    Some(MachoInfo {
        base,
        commands_off: base + HEADER_LEN,
        ncmds: read_u32(image, base + 16)?,
        sizeofcmds: read_u32(image, base + 20)?,
    })
}

/// Where the image to read starts: the front of a thin file, or the slice a
/// universal archive holds for this architecture.
fn slice_at(image: &[u8]) -> Option<usize> {
    let magic = read_u32(image, 0)?;
    if magic != FAT_MAGIC.swap_bytes() && magic != FAT_MAGIC_64.swap_bytes() {
        return Some(0);
    }
    // fat_arch is cputype, cpusubtype, offset, size, align; fat_arch_64 widens
    // offset and size and adds a reserved word.
    let wide = magic == FAT_MAGIC_64.swap_bytes();
    let (entry, offset_at) = if wide { (32, 8) } else { (20, 8) };
    let count = read_u32(image, 4)?.swap_bytes() as usize;
    (0..count).find_map(|i| {
        let at = 8 + i * entry;
        (read_u32(image, at)?.swap_bytes() == CPU_TYPE).then_some(())?;
        let offset = if wide {
            read_u64(image, at + offset_at)?.swap_bytes() as usize
        } else {
            read_u32(image, at + offset_at)?.swap_bytes() as usize
        };
        (offset < image.len()).then_some(offset)
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

    // A segment command carrying `count` sections, the `init`-th of which is
    // a __mod_init_func run of pointers at `addr`.
    fn segment_with_sections(count: u32, init: u32, addr: u64, len: u64) -> Vec<u8> {
        let size = SEGMENT_LEN + count as usize * SECTION_LEN;
        let mut cmd = vec![0u8; size];
        cmd[0..4].copy_from_slice(&LC_SEGMENT_64.to_le_bytes());
        cmd[4..8].copy_from_slice(&(size as u32).to_le_bytes());
        cmd[64..68].copy_from_slice(&count.to_le_bytes());
        for at in 0..count as usize {
            let sect = SEGMENT_LEN + at * SECTION_LEN;
            let kind = if at as u32 == init {
                S_MOD_INIT_FUNC_POINTERS
            } else {
                0
            };
            cmd[sect + 32..sect + 40].copy_from_slice(&addr.to_le_bytes());
            cmd[sect + 40..sect + 48].copy_from_slice(&len.to_le_bytes());
            cmd[sect + 64..sect + 68].copy_from_slice(&kind.to_le_bytes());
        }
        cmd
    }

    #[test]
    fn finds_every_run_of_initializers_across_segments() {
        let first = segment_with_sections(3, 1, 0x1000, 0x8);
        let second = segment_with_sections(2, 1, 0x2000, 0x10);
        let sizeofcmds = first.len() + second.len();
        let mut b = vec![0u8; HEADER_LEN + sizeofcmds];
        b[0..4].copy_from_slice(&MH_MAGIC_64.to_le_bytes());
        b[16..20].copy_from_slice(&2u32.to_le_bytes());
        b[20..24].copy_from_slice(&(sizeofcmds as u32).to_le_bytes());
        b[HEADER_LEN..HEADER_LEN + first.len()].copy_from_slice(&first);
        b[HEADER_LEN + first.len()..].copy_from_slice(&second);

        let info = parse(&b).expect("a thin image");
        let found: Vec<Initializer> = info.initializers(&b).collect();
        assert_eq!(
            found,
            [
                Initializer {
                    vmaddr: 0x1000,
                    len: 0x8
                },
                Initializer {
                    vmaddr: 0x2000,
                    len: 0x10
                },
            ]
        );
    }

    #[test]
    fn an_image_with_no_initializers_reports_none() {
        let b = synth(0x1_0000_0000, 0x40);
        let info = parse(&b).expect("a thin image");
        assert_eq!(info.initializers(&b).count(), 0);
    }

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

    // Wrap `thin` in a universal archive with a decoy slice in front of it.
    fn fat(thin: &[u8], wide: bool) -> (Vec<u8>, usize) {
        let entry = if wide { 32usize } else { 20 };
        let head = 8 + entry * 2;
        let decoy_at = (head + 0xF) & !0xF;
        let ours_at = decoy_at + 0x100;
        let mut b = vec![0u8; ours_at + thin.len()];
        let magic = if wide { FAT_MAGIC_64 } else { FAT_MAGIC };
        b[0..4].copy_from_slice(&magic.swap_bytes().to_le_bytes());
        b[4..8].copy_from_slice(&2u32.swap_bytes().to_le_bytes());
        let mut put = |i: usize, cpu: u32, at: usize, len: usize| {
            let a = 8 + i * entry;
            b[a..a + 4].copy_from_slice(&cpu.swap_bytes().to_le_bytes());
            if wide {
                b[a + 8..a + 16].copy_from_slice(&(at as u64).swap_bytes().to_le_bytes());
                b[a + 16..a + 24].copy_from_slice(&(len as u64).swap_bytes().to_le_bytes());
            } else {
                b[a + 8..a + 12].copy_from_slice(&(at as u32).swap_bytes().to_le_bytes());
                b[a + 12..a + 16].copy_from_slice(&(len as u32).swap_bytes().to_le_bytes());
            }
        };
        // A slice for some other architecture comes first, as the official
        // macOS builds put x86_64 and arm64 side by side.
        put(0, CPU_TYPE ^ 0xF, decoy_at, 0x100);
        put(1, CPU_TYPE, ours_at, thin.len());
        b[ours_at..ours_at + thin.len()].copy_from_slice(thin);
        (b, ours_at)
    }

    #[test]
    fn takes_its_own_slice_out_of_a_universal_archive() {
        for wide in [false, true] {
            let thin = synth(0x1_0000_0000, 0x800);
            let (image, at) = fat(&thin, wide);
            let macho = parse(&image).expect("a slice for this architecture");
            assert_eq!(macho.base, at, "the slice was found");
            assert_eq!(macho.ncmds, 2);
            // File offsets come back measured from the file, not the slice, so
            // whatever maps the segments needs no arithmetic of its own.
            let segs: Vec<Segment> = macho.segments(&image).collect();
            assert_eq!(segs[0].fileoff, at as u64);
            assert_eq!(segs[0].vmaddr, 0x1_0000_0000);
            // And the entry still resolves through that segment.
            assert_eq!(macho.entry(&image), Some(0x1_0000_0800));
        }
    }

    #[test]
    fn an_archive_without_this_architecture_is_not_an_image() {
        let thin = synth(0x1_0000_0000, 0x800);
        let (mut image, _) = fat(&thin, false);
        // Change the one slice that matched, and nothing is left to load.
        image[8 + 20..8 + 24].copy_from_slice(&(CPU_TYPE ^ 0xF0).swap_bytes().to_le_bytes());
        assert!(parse(&image).is_none());
    }

    /// An image whose load commands are only `LC_LOAD_DYLIB` and friends, so
    /// the order a bind's ordinal counts them can be checked.
    fn with_dylibs(paths: &[(&str, u32)]) -> Vec<u8> {
        let mut cmds: Vec<u8> = Vec::new();
        for (path, cmd) in paths {
            let len = (24 + path.len() + 1).next_multiple_of(8);
            cmds.extend_from_slice(&cmd.to_le_bytes());
            cmds.extend_from_slice(&(len as u32).to_le_bytes());
            cmds.extend_from_slice(&24u32.to_le_bytes()); // name offset
            cmds.extend_from_slice(&[0u8; 12]); // timestamp and two versions
            let head = cmds.len();
            cmds.resize(head + len - 24, 0);
            cmds[head..head + path.len()].copy_from_slice(path.as_bytes());
        }
        let mut b = vec![0u8; HEADER_LEN + cmds.len()];
        b[0..4].copy_from_slice(&MH_MAGIC_64.to_le_bytes());
        b[12..16].copy_from_slice(&2u32.to_le_bytes());
        b[16..20].copy_from_slice(&(paths.len() as u32).to_le_bytes());
        b[20..24].copy_from_slice(&(cmds.len() as u32).to_le_bytes());
        b[HEADER_LEN..].copy_from_slice(&cmds);
        b
    }

    #[test]
    fn lists_the_libraries_an_image_needs_in_order() {
        let b = with_dylibs(&[
            ("/usr/lib/libSystem.B.dylib", LC_LOAD_DYLIB),
            (
                "/System/Library/Frameworks/CoreFoundation",
                LC_LOAD_WEAK_DYLIB,
            ),
            ("/Library/Frameworks/Python", LC_REEXPORT_DYLIB),
        ]);
        let m = parse(&b).expect("thin macho");
        let libs: Vec<Dylib> = m.dylibs(&b).collect();
        assert_eq!(libs.len(), 3, "every kind of load command counts");
        assert_eq!(libs[0].path, "/usr/lib/libSystem.B.dylib");
        assert!(!libs[0].weak && !libs[0].reexport);
        assert!(libs[1].weak, "a weak load is one the image can do without");
        assert!(
            libs[2].reexport,
            "a re-export lends its exports to this image"
        );
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
