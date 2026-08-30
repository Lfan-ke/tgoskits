//! Darwin (macOS) personality for ArceOS/StarryOS.
//!
//! Teaches ArceOS to load Mach-O (`.macho`) executables as a `SysAbi`,
//! mapping Darwin execution onto the shared `ax_*` primitives just as
//! `ax-abi-windows` does for PE. This is the loader half: map `LC_SEGMENT_64`
//! segments and find the `LC_MAIN` entry point, transcribed from
//! `<mach-o/loader.h>` atop [`ax_binfmt::macho`]. Darwin binaries are dyld-based
//! and position-independent; dyld and chained fixups (the Mach-O analogue of PE
//! imports/relocations) arrive in a later phase. The BSD calls it services live
//! in [`bsd`]; Mach traps belong to a layer that is not here yet.

#![cfg_attr(not(test), no_std)]
#![feature(used_with_arg)]

pub mod bsd;

extern crate alloc;

use ax_binfmt::{
    AbiError, AbiResult, ImageFormat, LoadEnv, LoadRequest, Loaded, Prot,
    macho::{self, Segment},
};
use ax_dispatch::{Abi, Dispatch, SysAbi, TrapEnv};

/// The Darwin personality: recognizes Mach-O images and loads them.
#[derive(Debug, Clone, Copy, Default)]
pub struct DarwinAbi;

impl SysAbi for DarwinAbi {
    fn abi(&self) -> Abi {
        Abi::Darwin
    }

    fn handle_syscall(&self, env: &mut dyn TrapEnv) -> Dispatch {
        bsd::dispatch(
            env,
            ax_crate_interface::call_interface!(ax_abi_port::CurrentHost::current),
        )
    }
}

/// Translate a segment's `initprot` bits into a mapping protection.
fn segment_prot(seg: &Segment) -> Prot {
    let mut prot = Prot::empty();
    prot.set(Prot::READ, seg.readable());
    prot.set(Prot::WRITE, seg.writable());
    prot.set(Prot::EXEC, seg.executable());
    prot
}

#[cfg(test)]
mod tests {
    use alloc::vec::Vec;

    use super::*;

    #[derive(Default)]
    struct RecordingEnv {
        maps: Vec<(u64, Prot, usize)>,
        from_file: Vec<(u64, u64)>,
    }

    impl LoadEnv for RecordingEnv {
        fn map_region(
            &mut self,
            va: u64,
            len: u64,
            prot: Prot,
            _init: Option<&[u8]>,
        ) -> AbiResult<()> {
            self.maps.push((va, prot, len as usize));
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
            self.maps.push((va, prot, len as usize));
            self.from_file.push((offset, file_end));
            Ok(())
        }

        fn read_image(&mut self, _at: u64, _out: &mut [u8]) -> AbiResult<usize> {
            Ok(0)
        }
    }

    const HEADER_LEN: usize = 32;
    const LC_SEGMENT_64: u32 = 0x19;
    const LC_MAIN: u32 = 0x8000_0028;

    // Build a Mach-O with __PAGEZERO, a __TEXT (RX) segment, and LC_MAIN.
    fn synth() -> Vec<u8> {
        let seg = 72usize;
        let main = 24usize;
        let sizeofcmds = seg * 2 + main;
        let mut b = vec![0u8; HEADER_LEN + sizeofcmds + 0x100];
        b[0..4].copy_from_slice(&macho::MH_MAGIC_64.to_le_bytes());
        b[16..20].copy_from_slice(&3u32.to_le_bytes()); // ncmds
        b[20..24].copy_from_slice(&(sizeofcmds as u32).to_le_bytes());

        // __PAGEZERO: vmaddr 0, 4 GiB, no access - must be skipped.
        let pz = HEADER_LEN;
        b[pz..pz + 4].copy_from_slice(&LC_SEGMENT_64.to_le_bytes());
        b[pz + 4..pz + 8].copy_from_slice(&(seg as u32).to_le_bytes());
        b[pz + 32..pz + 40].copy_from_slice(&0x1_0000_0000u64.to_le_bytes()); // vmsize
        b[pz + 60..pz + 64].copy_from_slice(&0u32.to_le_bytes()); // initprot none

        // __TEXT: RX, vmaddr 0x1_0000_0000.
        let tx = pz + seg;
        b[tx..tx + 4].copy_from_slice(&LC_SEGMENT_64.to_le_bytes());
        b[tx + 4..tx + 8].copy_from_slice(&(seg as u32).to_le_bytes());
        b[tx + 24..tx + 32].copy_from_slice(&0x1_0000_0000u64.to_le_bytes()); // vmaddr
        b[tx + 32..tx + 40].copy_from_slice(&0x1000u64.to_le_bytes()); // vmsize
        b[tx + 48..tx + 56].copy_from_slice(&0x400u64.to_le_bytes()); // filesize
        b[tx + 60..tx + 64].copy_from_slice(&0x5u32.to_le_bytes()); // RX

        let m = tx + seg;
        b[m..m + 4].copy_from_slice(&LC_MAIN.to_le_bytes());
        b[m + 4..m + 8].copy_from_slice(&(main as u32).to_le_bytes());
        // entryoff must fall within __TEXT's file range [0, filesize=0x400).
        b[m + 8..m + 16].copy_from_slice(&0x200u64.to_le_bytes());
        b
    }

    #[test]
    fn loads_segments_skipping_pagezero() {
        let img = synth();
        let mut env = RecordingEnv::default();
        let loaded = DarwinAbi
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
        // Only __TEXT is mapped; __PAGEZERO is skipped.
        assert_eq!(env.maps.len(), 1);
        assert_eq!(env.maps[0].0, 0x1_0000_0000);
        assert_eq!(env.maps[0].1, Prot::READ | Prot::EXEC);
        assert_eq!(loaded.entry, 0x1_0000_0200);
    }

    // Write a segment_command_64 at `off`.
    fn put_segment(
        b: &mut [u8],
        off: usize,
        vmaddr: u64,
        vmsize: u64,
        fileoff: u64,
        filesize: u64,
        initprot: u32,
    ) {
        b[off..off + 4].copy_from_slice(&LC_SEGMENT_64.to_le_bytes());
        b[off + 4..off + 8].copy_from_slice(&72u32.to_le_bytes());
        b[off + 24..off + 32].copy_from_slice(&vmaddr.to_le_bytes());
        b[off + 32..off + 40].copy_from_slice(&vmsize.to_le_bytes());
        b[off + 40..off + 48].copy_from_slice(&fileoff.to_le_bytes());
        b[off + 48..off + 56].copy_from_slice(&filesize.to_le_bytes());
        b[off + 60..off + 64].copy_from_slice(&initprot.to_le_bytes());
    }

    #[test]
    fn loads_a_realistic_clang_layout() {
        // A typical clang x64 executable: __PAGEZERO guard, __TEXT (RX),
        // __DATA (RW), __LINKEDIT (R), plus LC_MAIN.
        let seg = 72usize;
        let main = 24usize;
        let sizeofcmds = seg * 4 + main;
        let mut b = vec![0u8; HEADER_LEN + sizeofcmds + 0x100];
        b[0..4].copy_from_slice(&macho::MH_MAGIC_64.to_le_bytes());
        b[16..20].copy_from_slice(&5u32.to_le_bytes()); // ncmds
        b[20..24].copy_from_slice(&(sizeofcmds as u32).to_le_bytes());

        let mut off = HEADER_LEN;
        put_segment(&mut b, off, 0, 0x1_0000_0000, 0, 0, 0); // __PAGEZERO
        off += seg;
        put_segment(&mut b, off, 0x1_0000_0000, 0x1000, 0, 0x400, 0x5); // __TEXT RX
        off += seg;
        put_segment(&mut b, off, 0x1_0000_1000, 0x1000, 0x400, 0x200, 0x3); // __DATA RW
        off += seg;
        put_segment(&mut b, off, 0x1_0000_2000, 0x1000, 0x600, 0x100, 0x1); // __LINKEDIT R
        off += seg;
        b[off..off + 4].copy_from_slice(&LC_MAIN.to_le_bytes());
        b[off + 4..off + 8].copy_from_slice(&(main as u32).to_le_bytes());
        b[off + 8..off + 16].copy_from_slice(&0x100u64.to_le_bytes()); // entryoff in __TEXT

        let mut env = RecordingEnv::default();
        let loaded = DarwinAbi
            .load(
                &LoadRequest {
                    image: &b,
                    load_base: 0,
                    args: &[],
                    envs: &[],
                },
                &mut env,
            )
            .expect("load");
        // __PAGEZERO skipped; __TEXT/__DATA/__LINKEDIT mapped with their prots.
        assert_eq!(env.maps.len(), 3);
        assert_eq!(
            env.maps[0],
            (0x1_0000_0000, Prot::READ | Prot::EXEC, 0x1000)
        );
        assert_eq!(
            env.maps[1],
            (0x1_0000_1000, Prot::READ | Prot::WRITE, 0x1000)
        );
        assert_eq!(env.maps[2], (0x1_0000_2000, Prot::READ, 0x1000));
        assert_eq!(loaded.entry, 0x1_0000_0100);
    }

    #[test]
    fn recognizes_only_mach_o() {
        assert!(DarwinAbi.recognizes(&[0xFE, 0xED, 0xFA, 0xCF]));
        assert!(!DarwinAbi.recognizes(b"MZ"));
        let mut env = RecordingEnv::default();
        assert_eq!(
            DarwinAbi.load(
                &LoadRequest {
                    image: b"\x7fELF",
                    load_base: 0,
                    args: &[],
                    envs: &[]
                },
                &mut env
            ),
            Err(AbiError::MalformedImage)
        );
    }
}

impl ImageFormat for DarwinAbi {
    fn abi(&self) -> Abi {
        Abi::Darwin
    }

    fn recognizes(&self, image: &[u8]) -> bool {
        ax_binfmt::detect(image) == Some(Abi::Darwin)
    }

    fn load(&self, req: &LoadRequest<'_>, env: &mut dyn LoadEnv) -> AbiResult<Loaded> {
        let macho = macho::parse(req.image).ok_or(AbiError::MalformedImage)?;
        // No LC_MAIN means a legacy LC_UNIXTHREAD entry, which is out of scope.
        let entry = macho.entry(req.image).ok_or(AbiError::Unsupported)?;

        for seg in macho.segments(req.image) {
            // __PAGEZERO and other no-access reservations are address-space
            // guards, not backed by pages; skip them rather than map gigabytes.
            if seg.initprot == 0 || seg.vmsize == 0 {
                continue;
            }
            // Map from the file rather than copying it in: a segment's
            // `fileoff`/`filesize` are the same shape as an ELF `PT_LOAD`'s
            // `p_offset`/`p_filesz`, so it gets the same demand paging.
            env.map_image(
                seg.vmaddr,
                seg.vmsize,
                segment_prot(&seg),
                seg.fileoff,
                seg.fileoff + seg.filesize,
            )?;
        }
        Ok(Loaded { entry, stack: 0 })
    }
}

fn darwin() -> &'static dyn SysAbi {
    static IT: DarwinAbi = DarwinAbi;
    &IT
}

ax_dispatch::register_sysabi!(darwin);

/// The same package registers twice, once per capability: it knows how to
/// map this format, and it knows how to service the traps that follow.
fn darwin_format() -> &'static dyn ImageFormat {
    static IT: DarwinAbi = DarwinAbi;
    &IT
}

ax_binfmt::register_binfmt!(darwin_format);
