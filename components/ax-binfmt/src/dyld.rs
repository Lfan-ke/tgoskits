//! The `LC_DYLD_INFO_ONLY` opcode streams: rebase and bind.
//!
//! A Mach-O image says how to fix itself up in two bytecode streams rather
//! than in relocation tables. The rebase stream names the places holding an
//! address that has to move with the image, and the bind stream names the
//! places holding an address that comes from another library, along with the
//! symbol each one wants. Both are the same shape: an opcode byte whose top
//! nibble is the operation and whose bottom nibble is a small immediate,
//! followed by ULEB or SLEB operands, run over a little machine with a
//! current segment, offset, type and - for binds - symbol, library and
//! addend.
//!
//! This module only reads: it walks a stream and reports what it says to do,
//! leaving the doing to whoever has the mapped image. The opcodes and their
//! operands are those of `<mach-o/loader.h>`; dyld's own interpreter
//! (`dyld3::MachOLoaded::forEachRebase` and `forEachBind`) is the reference
//! for how the operands compose.

/// `LC_DYLD_INFO_ONLY`, and the older `LC_DYLD_INFO` it replaced; both carry
/// the same command.
const LC_DYLD_INFO: u32 = 0x22;
const LC_DYLD_INFO_ONLY: u32 = 0x8000_0022;

/// Where each stream is, as `dyld_info_command` records it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct DyldInfo {
    pub rebase_off: u32,
    pub rebase_size: u32,
    pub bind_off: u32,
    pub bind_size: u32,
    pub weak_bind_off: u32,
    pub weak_bind_size: u32,
    pub lazy_bind_off: u32,
    pub lazy_bind_size: u32,
    pub export_off: u32,
    pub export_size: u32,
}

/// What a rebase entry holds: a pointer, or a 32-bit slot in text.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RebaseKind {
    Pointer,
    TextAbsolute32,
    TextPcRel32,
}

impl RebaseKind {
    fn from(value: u8) -> Option<Self> {
        Some(match value {
            1 => Self::Pointer,
            2 => Self::TextAbsolute32,
            3 => Self::TextPcRel32,
            _ => return None,
        })
    }
}

/// One place the image wants fixed up, named the way the stream names it:
/// by segment and offset within it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Rebase {
    pub segment: u8,
    pub offset: u64,
    pub kind: RebaseKind,
}

/// Which library a bind takes its symbol from. The negative ordinals are
/// dyld's own: the image itself, the program, or every library in turn.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Source {
    /// The n-th `LC_LOAD_DYLIB`, counting from one.
    Library(u32),
    /// `BIND_SPECIAL_DYLIB_SELF`.
    Own,
    /// `BIND_SPECIAL_DYLIB_MAIN_EXECUTABLE`.
    Program,
    /// `BIND_SPECIAL_DYLIB_FLAT_LOOKUP`, and the weak form after it: every
    /// library, in load order.
    Anywhere,
}

/// One place the image wants an address from elsewhere written into.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Bind<'a> {
    pub segment: u8,
    pub offset: u64,
    pub kind: RebaseKind,
    pub source: Source,
    pub symbol: &'a str,
    pub addend: i64,
    /// Whether the image will settle for this symbol being missing, which is
    /// `BIND_SYMBOL_FLAGS_WEAK_IMPORT`.
    pub weak: bool,
}

/// The `LC_DYLD_INFO_ONLY` command of an image, if it has one.
pub fn info(image: &[u8], commands_off: usize, ncmds: u32, sizeofcmds: u32) -> Option<DyldInfo> {
    let end = commands_off + sizeofcmds as usize;
    let mut off = commands_off;
    for _ in 0..ncmds {
        if off + 8 > end {
            break;
        }
        let cmd = read_u32(image, off)?;
        let size = read_u32(image, off + 4)? as usize;
        if size < 8 {
            break;
        }
        if cmd == LC_DYLD_INFO_ONLY || cmd == LC_DYLD_INFO {
            let at = |n: usize| read_u32(image, off + 8 + n * 4);
            return Some(DyldInfo {
                rebase_off: at(0)?,
                rebase_size: at(1)?,
                bind_off: at(2)?,
                bind_size: at(3)?,
                weak_bind_off: at(4)?,
                weak_bind_size: at(5)?,
                lazy_bind_off: at(6)?,
                lazy_bind_size: at(7)?,
                export_off: at(8)?,
                export_size: at(9)?,
            });
        }
        off += size;
    }
    None
}

/// A stream reader: the bytes, and how far along them the machine is.
struct Stream<'a> {
    bytes: &'a [u8],
    at: usize,
}

impl<'a> Stream<'a> {
    fn byte(&mut self) -> Option<u8> {
        let byte = *self.bytes.get(self.at)?;
        self.at += 1;
        Some(byte)
    }

    /// An unsigned LEB128, as the operands are written.
    fn uleb(&mut self) -> Option<u64> {
        let mut value = 0u64;
        let mut shift = 0;
        loop {
            let byte = self.byte()?;
            if shift < 64 {
                value |= u64::from(byte & 0x7F) << shift;
            }
            shift += 7;
            if byte & 0x80 == 0 {
                return Some(value);
            }
            if shift > 70 {
                return None;
            }
        }
    }

    /// A signed LEB128, which only the addend is written as.
    fn sleb(&mut self) -> Option<i64> {
        let mut value = 0i64;
        let mut shift = 0;
        loop {
            let byte = self.byte()?;
            if shift < 64 {
                value |= i64::from(byte & 0x7F) << shift;
            }
            shift += 7;
            if byte & 0x80 == 0 {
                // Sign-extend from the last bit written.
                if shift < 64 && byte & 0x40 != 0 {
                    value |= -1i64 << shift;
                }
                return Some(value);
            }
            if shift > 70 {
                return None;
            }
        }
    }

    /// A NUL-terminated name, which a symbol is written as.
    fn name(&mut self) -> Option<&'a str> {
        let start = self.at;
        while *self.bytes.get(self.at)? != 0 {
            self.at += 1;
        }
        let text = core::str::from_utf8(self.bytes.get(start..self.at)?).ok()?;
        self.at += 1;
        Some(text)
    }
}

/// How wide a pointer the stream is fixing up. Both slices this loads are
/// 64-bit, and the opcodes scale their offsets by it.
const POINTER: u64 = 8;

/// Walk the rebase stream, reporting each place it names.
///
/// A stream that runs out mid-operand stops; a malformed image cannot be
/// fixed up, and this says so by having reported less than it should rather
/// than by reading past the end of the stream.
pub fn rebases(stream: &[u8], mut each: impl FnMut(Rebase)) {
    const DONE: u8 = 0x00;
    const SET_TYPE_IMM: u8 = 0x10;
    const SET_SEGMENT_AND_OFFSET_ULEB: u8 = 0x20;
    const ADD_ADDR_ULEB: u8 = 0x30;
    const ADD_ADDR_IMM_SCALED: u8 = 0x40;
    const DO_REBASE_IMM_TIMES: u8 = 0x50;
    const DO_REBASE_ULEB_TIMES: u8 = 0x60;
    const DO_REBASE_ADD_ADDR_ULEB: u8 = 0x70;
    const DO_REBASE_ULEB_TIMES_SKIPPING_ULEB: u8 = 0x80;

    let mut s = Stream {
        bytes: stream,
        at: 0,
    };
    let (mut segment, mut offset) = (0u8, 0u64);
    let mut kind = RebaseKind::Pointer;
    fn run(
        each: &mut dyn FnMut(Rebase),
        segment: u8,
        kind: RebaseKind,
        offset: &mut u64,
        times: u64,
        skip: u64,
    ) {
        for _ in 0..times {
            each(Rebase {
                segment,
                offset: *offset,
                kind,
            });
            *offset = offset.wrapping_add(POINTER + skip);
        }
    }
    while let Some(byte) = s.byte() {
        let (op, immediate) = (byte & 0xF0, byte & 0x0F);
        match op {
            DONE => return,
            SET_TYPE_IMM => match RebaseKind::from(immediate) {
                Some(next) => kind = next,
                None => return,
            },
            SET_SEGMENT_AND_OFFSET_ULEB => {
                segment = immediate;
                match s.uleb() {
                    Some(value) => offset = value,
                    None => return,
                }
            }
            ADD_ADDR_ULEB => match s.uleb() {
                Some(value) => offset = offset.wrapping_add(value),
                None => return,
            },
            ADD_ADDR_IMM_SCALED => offset = offset.wrapping_add(u64::from(immediate) * POINTER),
            DO_REBASE_IMM_TIMES => run(
                &mut each,
                segment,
                kind,
                &mut offset,
                u64::from(immediate),
                0,
            ),
            DO_REBASE_ULEB_TIMES => match s.uleb() {
                Some(times) => run(&mut each, segment, kind, &mut offset, times, 0),
                None => return,
            },
            DO_REBASE_ADD_ADDR_ULEB => {
                let Some(skip) = s.uleb() else { return };
                run(&mut each, segment, kind, &mut offset, 1, skip);
            }
            DO_REBASE_ULEB_TIMES_SKIPPING_ULEB => {
                let (Some(times), Some(skip)) = (s.uleb(), s.uleb()) else {
                    return;
                };
                run(&mut each, segment, kind, &mut offset, times, skip);
            }
            _ => return,
        }
    }
}

/// Walk a bind stream - the ordinary one, the weak one, or the lazy one -
/// reporting each place it names and what belongs there.
pub fn binds<'a>(stream: &'a [u8], mut each: impl FnMut(Bind<'a>)) {
    const DONE: u8 = 0x00;
    const SET_DYLIB_ORDINAL_IMM: u8 = 0x10;
    const SET_DYLIB_ORDINAL_ULEB: u8 = 0x20;
    const SET_DYLIB_SPECIAL_IMM: u8 = 0x30;
    const SET_SYMBOL_TRAILING_FLAGS_IMM: u8 = 0x40;
    const SET_TYPE_IMM: u8 = 0x50;
    const SET_ADDEND_SLEB: u8 = 0x60;
    const SET_SEGMENT_AND_OFFSET_ULEB: u8 = 0x70;
    const ADD_ADDR_ULEB: u8 = 0x80;
    const DO_BIND: u8 = 0x90;
    const DO_BIND_ADD_ADDR_ULEB: u8 = 0xA0;
    const DO_BIND_ADD_ADDR_IMM_SCALED: u8 = 0xB0;
    const DO_BIND_ULEB_TIMES_SKIPPING_ULEB: u8 = 0xC0;
    /// `BIND_SYMBOL_FLAGS_WEAK_IMPORT`.
    const WEAK_IMPORT: u8 = 0x1;

    let mut s = Stream {
        bytes: stream,
        at: 0,
    };
    let (mut segment, mut offset) = (0u8, 0u64);
    let mut kind = RebaseKind::Pointer;
    let mut source = Source::Library(1);
    let mut symbol = "";
    let mut addend = 0i64;
    let mut weak = false;
    while let Some(byte) = s.byte() {
        let (op, immediate) = (byte & 0xF0, byte & 0x0F);
        match op {
            // A lazy stream is a sequence of entries each ending in DONE, so
            // this is the end of one entry rather than of the stream.
            DONE => {}
            SET_DYLIB_ORDINAL_IMM => source = Source::Library(u32::from(immediate)),
            SET_DYLIB_ORDINAL_ULEB => match s.uleb() {
                Some(value) => source = Source::Library(value as u32),
                None => return,
            },
            // The immediate is a negative number in its low nibble.
            SET_DYLIB_SPECIAL_IMM => {
                source = match immediate {
                    0 => Source::Own,
                    // -1, -2 and -3 as four-bit two's complement.
                    0xF => Source::Program,
                    0xE | 0xD => Source::Anywhere,
                    _ => return,
                }
            }
            SET_SYMBOL_TRAILING_FLAGS_IMM => {
                weak = immediate & WEAK_IMPORT != 0;
                match s.name() {
                    Some(name) => symbol = name,
                    None => return,
                }
            }
            SET_TYPE_IMM => match RebaseKind::from(immediate) {
                Some(next) => kind = next,
                None => return,
            },
            SET_ADDEND_SLEB => match s.sleb() {
                Some(value) => addend = value,
                None => return,
            },
            SET_SEGMENT_AND_OFFSET_ULEB => {
                segment = immediate;
                match s.uleb() {
                    Some(value) => offset = value,
                    None => return,
                }
            }
            ADD_ADDR_ULEB => match s.uleb() {
                Some(value) => offset = offset.wrapping_add(value),
                None => return,
            },
            DO_BIND => {
                each(Bind {
                    segment,
                    offset,
                    kind,
                    source,
                    symbol,
                    addend,
                    weak,
                });
                offset = offset.wrapping_add(POINTER);
            }
            DO_BIND_ADD_ADDR_ULEB => {
                let Some(skip) = s.uleb() else { return };
                each(Bind {
                    segment,
                    offset,
                    kind,
                    source,
                    symbol,
                    addend,
                    weak,
                });
                offset = offset.wrapping_add(POINTER).wrapping_add(skip);
            }
            DO_BIND_ADD_ADDR_IMM_SCALED => {
                each(Bind {
                    segment,
                    offset,
                    kind,
                    source,
                    symbol,
                    addend,
                    weak,
                });
                offset = offset
                    .wrapping_add(POINTER)
                    .wrapping_add(u64::from(immediate) * POINTER);
            }
            DO_BIND_ULEB_TIMES_SKIPPING_ULEB => {
                let (Some(times), Some(skip)) = (s.uleb(), s.uleb()) else {
                    return;
                };
                for _ in 0..times {
                    each(Bind {
                        segment,
                        offset,
                        kind,
                        source,
                        symbol,
                        addend,
                        weak,
                    });
                    offset = offset.wrapping_add(POINTER).wrapping_add(skip);
                }
            }
            _ => return,
        }
    }
}

fn read_u32(image: &[u8], off: usize) -> Option<u32> {
    Some(u32::from_le_bytes(
        image.get(off..off + 4)?.try_into().ok()?,
    ))
}

#[cfg(test)]
mod tests {
    use alloc::vec::Vec;

    use super::*;

    /// A stream that names three pointers in one segment: two in a run, then
    /// one further along, which is the shape a linker emits most.
    #[test]
    fn a_rebase_stream_names_every_pointer_it_walks_over() {
        let stream = [
            0x11, // SET_TYPE_IMM(REBASE_TYPE_POINTER)
            0x21, 0x10, // SET_SEGMENT_AND_OFFSET_ULEB(segment 1, 0x10)
            0x52, // DO_REBASE_IMM_TIMES(2)
            0x30, 0x02, // ADD_ADDR_ULEB(2)
            0x51, // DO_REBASE_IMM_TIMES(1)
            0x00, // DONE
        ];
        let mut found = Vec::new();
        rebases(&stream, |r| found.push((r.segment, r.offset, r.kind)));
        assert_eq!(
            found,
            [
                (1, 0x10, RebaseKind::Pointer),
                (1, 0x18, RebaseKind::Pointer),
                // Two ULEB bytes were skipped past the second pointer.
                (1, 0x22, RebaseKind::Pointer),
            ]
        );
    }

    /// The skipping form: a table of pointers with a gap between each.
    #[test]
    fn a_rebase_run_leaves_the_gap_it_is_told_to() {
        let stream = [
            0x11, // SET_TYPE_IMM(pointer)
            0x20, 0x00, // segment 0, offset 0
            0x80, 0x03, 0x08, // DO_REBASE_ULEB_TIMES_SKIPPING_ULEB(3, 8)
            0x00,
        ];
        let mut found = Vec::new();
        rebases(&stream, |r| found.push(r.offset));
        assert_eq!(
            found,
            [0, 0x10, 0x20],
            "eight bytes of pointer, eight skipped"
        );
    }

    /// A truncated operand ends the walk rather than reading past the stream.
    #[test]
    fn a_stream_that_stops_mid_operand_stops_the_walk() {
        // SET_SEGMENT_AND_OFFSET_ULEB with a ULEB that never ends.
        let stream = [0x20, 0x80];
        let mut found = 0;
        rebases(&stream, |_| found += 1);
        assert_eq!(found, 0);
    }

    #[test]
    fn a_bind_stream_carries_the_symbol_library_and_addend() {
        let mut stream = Vec::new();
        stream.push(0x11u8); // SET_DYLIB_ORDINAL_IMM(1)
        stream.push(0x40); // SET_SYMBOL_TRAILING_FLAGS_IMM(no flags)
        stream.extend_from_slice(b"_malloc\0");
        stream.push(0x51); // SET_TYPE_IMM(pointer)
        stream.push(0x70); // SET_SEGMENT_AND_OFFSET_ULEB(segment 0)
        stream.push(0x08); // offset 8
        stream.push(0x90); // DO_BIND
        stream.push(0x41); // SET_SYMBOL_TRAILING_FLAGS_IMM(WEAK_IMPORT)
        stream.extend_from_slice(b"_maybe\0");
        stream.push(0x62); // SET_ADDEND_SLEB(2)
        stream.push(0x02);
        stream.push(0xA0); // DO_BIND_ADD_ADDR_ULEB
        stream.push(0x10); // skip 16
        stream.push(0x90); // DO_BIND
        stream.push(0x00); // DONE

        let mut found = Vec::new();
        binds(&stream, |b| {
            found.push((b.segment, b.offset, b.symbol, b.addend, b.weak, b.source))
        });
        assert_eq!(
            found,
            [
                (0, 8, "_malloc", 0, false, Source::Library(1)),
                (0, 16, "_maybe", 2, true, Source::Library(1)),
                // Eight for the pointer just bound, then the sixteen skipped.
                (0, 40, "_maybe", 2, true, Source::Library(1)),
            ]
        );
    }

    /// The special ordinals are a negative number in four bits.
    #[test]
    fn the_special_library_ordinals_are_read_as_the_negatives_they_are() {
        for (immediate, want) in [
            (0x0u8, Source::Own),
            (0xF, Source::Program),
            (0xE, Source::Anywhere),
            (0xD, Source::Anywhere),
        ] {
            let mut stream = alloc::vec![0x30 | immediate, 0x40];
            stream.extend_from_slice(b"_s\0");
            stream.extend_from_slice(&[0x70, 0x00, 0x90, 0x00]);
            let mut found = None;
            binds(&stream, |b| found = Some(b.source));
            assert_eq!(found, Some(want), "immediate {immediate:#x}");
        }
    }

    /// A lazy stream is one entry per symbol, each ended by DONE; the walk
    /// keeps going rather than stopping at the first.
    #[test]
    fn a_lazy_stream_reports_every_entry_in_it() {
        let mut stream = Vec::new();
        for (name, offset) in [(&b"_one\0"[..], 0x00u8), (&b"_two\0"[..], 0x08)] {
            stream.extend_from_slice(&[0x72, offset, 0x11, 0x40]);
            stream.extend_from_slice(name);
            stream.extend_from_slice(&[0x90, 0x00]);
        }
        let mut found = Vec::new();
        binds(&stream, |b| found.push((b.offset, b.symbol)));
        assert_eq!(found, [(0x00, "_one"), (0x08, "_two")]);
    }
}
