//! Darwin (macOS) personality for ArceOS/StarryOS.
//!
//! Teaches ArceOS to load Mach-O (`.macho`) executables as a `SysAbi`,
//! mapping Darwin execution onto the shared `ax_*` primitives just as
//! `ax-abi-windows` does for PE. This is the loader half: map `LC_SEGMENT_64`
//! segments and find the `LC_MAIN` entry point, transcribed from
//! `<mach-o/loader.h>` atop [`ax_binfmt::macho`]. Darwin binaries are dyld-based
//! and position-independent; what dyld does for them - the rebase and bind
//! opcode streams of `LC_DYLD_INFO_ONLY`, which is what the 3.14 binaries
//! carry rather than chained fixups - is read by [`ax_binfmt::dyld`] and
//! applied in a later phase, once there is a libSystem to bind against. The
//! BSD calls it services live in [`bsd`]; Mach traps belong to a layer that
//! is not here yet.

#![cfg_attr(not(test), no_std)]
#![feature(used_with_arg)]

pub mod bsd;
pub mod heap;
pub mod libc;
pub mod link;
pub mod start;
pub mod system;

#[cfg(test)]
mod testing;

extern crate alloc;

/// The page a Darwin x86_64 image is laid out in.
pub(crate) const PAGE: u64 = 0x1000;

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
        let host = ax_crate_interface::call_interface!(ax_abi_port::CurrentHost::current);
        // The library's own stubs carry numbers outside every Darwin class,
        // so which of the two layers a trap belongs to is the number itself.
        match libc::dispatch(env, host) {
            Dispatch::Passthrough => bsd::dispatch(env, host),
            handled => handled,
        }
    }
}

fn page_up(at: u64) -> u64 {
    at.div_ceil(PAGE) * PAGE
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
        /// The program, as the host would read it back.
        image: Vec<u8>,
        maps: Vec<(u64, Prot, usize)>,
        wrote: Vec<(u64, Vec<u8>)>,
        from_file: Vec<(u64, u64)>,
        reset: bool,
    }

    impl RecordingEnv {
        fn on(image: &[u8]) -> RecordingEnv {
            RecordingEnv {
                image: image.to_vec(),
                ..RecordingEnv::default()
            }
        }

        /// Whether anything was mapped over `va`.
        fn mapped(&self, va: u64) -> bool {
            self.maps
                .iter()
                .any(|(at, _, len)| (*at..*at + *len as u64).contains(&va))
        }
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

        fn read_image(&mut self, at: u64, out: &mut [u8]) -> AbiResult<usize> {
            let from = self.image.get(at as usize..).unwrap_or(&[]);
            let n = out.len().min(from.len());
            out[..n].copy_from_slice(&from[..n]);
            Ok(n)
        }
        fn image_len(&self) -> u64 {
            self.image.len() as u64
        }
        fn stack_top(&self) -> u64 {
            0x7FFF_0000
        }
        fn write(&mut self, va: u64, bytes: &[u8]) -> AbiResult<()> {
            self.wrote.push((va, bytes.to_vec()));
            Ok(())
        }
        fn reset(&mut self) -> AbiResult<()> {
            self.reset = true;
            Ok(())
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
        let mut env = RecordingEnv::on(&img);
        let loaded = MachoFormat
            .load(
                &LoadRequest {
                    image: &img,
                    path: "",
                    load_base: 0,
                    args: &[],
                    envs: &[],
                },
                &mut env,
            )
            .expect("load");
        // Only __TEXT is mapped from the image; __PAGEZERO is skipped. The
        // rest of what is mapped is the system's own: its variables, its
        // stubs, the code the process starts on, and the stack.
        assert_eq!(env.maps[0].0, 0x1_0000_0000);
        assert_eq!(env.maps[0].1, Prot::READ | Prot::EXEC);
        assert_eq!(env.maps.len(), 5);
        // The program does not begin at its own `main` any more: it begins at
        // the code that calls it and exits with what it returns.
        assert_ne!(loaded.entry, 0x1_0000_0200);
        assert!(env.mapped(loaded.entry), "the start code is mapped");
        assert!(
            env.mapped(loaded.thread_pointer),
            "the thread block is mapped"
        );
        assert_eq!(loaded.stack % 16, 0);
        assert!(
            env.wrote.iter().any(|(at, _)| *at == loaded.stack),
            "what the process starts on was written to the stack"
        );
        // `environ` is filled in, and with an address on the stack that was
        // just laid out rather than with nothing.
        assert!(
            env.wrote.iter().any(|(_, bytes)| bytes.len() == 8 && {
                let value = u64::from_le_bytes(bytes[..].try_into().unwrap());
                (loaded.stack..0x7FFF_0000).contains(&value)
            }),
            "environ points into the stack"
        );
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

        let mut env = RecordingEnv::on(&b);
        let loaded = MachoFormat
            .load(
                &LoadRequest {
                    image: &b,
                    path: "",
                    load_base: 0,
                    args: &[],
                    envs: &[],
                },
                &mut env,
            )
            .expect("load");
        // __PAGEZERO skipped; __TEXT/__DATA/__LINKEDIT mapped with their prots.
        assert_eq!(env.maps.len(), 3 + 4);
        assert_eq!(
            env.maps[0],
            (0x1_0000_0000, Prot::READ | Prot::EXEC, 0x1000)
        );
        assert_eq!(
            env.maps[1],
            (0x1_0000_1000, Prot::READ | Prot::WRITE, 0x1000)
        );
        assert_eq!(env.maps[2], (0x1_0000_2000, Prot::READ, 0x1000));
        assert!(env.mapped(loaded.entry), "the start code is mapped");
        assert!(
            env.reset,
            "the space was prepared before anything was placed"
        );
    }

    #[test]
    fn recognizes_only_mach_o() {
        assert!(MachoFormat.recognizes(&[0xFE, 0xED, 0xFA, 0xCF]));
        assert!(!MachoFormat.recognizes(b"MZ"));
        let mut env = RecordingEnv::on(b"\x7fELF");
        assert_eq!(
            MachoFormat.load(
                &LoadRequest {
                    image: b"\x7fELF",
                    path: "",
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

impl ImageFormat for MachoFormat {
    fn abi(&self) -> Abi {
        Abi::Darwin
    }

    fn recognizes(&self, image: &[u8]) -> bool {
        ax_binfmt::detect(image) == Some(Abi::Darwin)
    }

    fn load(&self, req: &LoadRequest<'_>, env: &mut dyn LoadEnv) -> AbiResult<Loaded> {
        let bytes = link::read_all(env)?;
        let macho = macho::parse(&bytes).ok_or(AbiError::MalformedImage)?;
        // No LC_MAIN means a legacy LC_UNIXTHREAD entry, which is out of scope.
        let main = macho.entry(&bytes).ok_or(AbiError::Unsupported)?;
        // Everything the set needs is read and resolved before anything is
        // mapped, so a program whose libraries are missing or whose symbols
        // nothing provides is refused while the caller still has the address
        // space it came with.
        let linked = link::link(bytes, req.path, env)?;
        let exit = linked
            .system
            .address("_exit")
            .ok_or(AbiError::MissingLibrary)?;
        let inits = linked.initializers();
        let start_va = linked.system.base + linked.system.extent();

        env.reset()?;
        for module in &linked.modules {
            for seg in &module.segments {
                // __PAGEZERO and other no-access reservations are address
                // space guards, not backed by pages; skip them rather than
                // map gigabytes.
                if seg.initprot == 0 || seg.vmsize == 0 {
                    continue;
                }
                env.map_region(
                    module.slide + seg.vmaddr,
                    seg.vmsize,
                    segment_prot(seg),
                    seg.file_data(&module.bytes),
                )?;
            }
            // What the fixups could not write into the file's own bytes,
            // because it lands in a segment's zero-filled tail.
            for (va, value) in &module.late {
                env.write(*va, &value.to_le_bytes())?;
            }
        }

        // The library the system provides: its variables are what the program
        // stores through, its stubs are what the program calls.
        let system = &linked.system;
        env.map_region(
            system.base,
            system.code_off(),
            Prot::READ | Prot::WRITE,
            Some(&system.vars()),
        )?;
        let code = system.code();
        env.map_region(
            system.base + system.code_off(),
            code.len() as u64,
            Prot::READ | Prot::EXEC,
            Some(&code),
        )?;

        let stack = start::stack(env.stack_top(), req.path, req.args, req.envs);
        // The one variable that starts with a value rather than a zero:
        // `environ` names the run of pointers the stack already carries, and
        // `getenv` reads it from the first call.
        if let Some(at) = system.address("_environ") {
            env.write(at, &stack.envp.to_le_bytes())?;
        }
        // And where the program was run from, which is the one thing
        // `_NSGetExecutablePath` has to have and cannot work out.
        env.write(
            system.private() + system::PRIVATE_EXEC_PATH,
            &stack.exec_path.to_le_bytes(),
        )?;
        let start = start::code(start::Entry { main, exit }, &inits, &stack);
        env.map_region(
            start_va,
            start.len() as u64,
            Prot::READ | Prot::EXEC,
            Some(&start),
        )?;
        // The block the thread reaches through `gs`: where its errno lives,
        // and where the pthread family will keep the rest of what a thread
        // has to have.
        let tsd_va = page_up(start_va + start.len() as u64);
        env.map_region(
            tsd_va,
            start::TSD_LEN,
            Prot::READ | Prot::WRITE,
            Some(&start::tsd(tsd_va, system.base)),
        )?;
        // The host already mapped a stack; what goes on it is written, not
        // mapped over.
        env.write(stack.sp, &stack.bytes)?;

        Ok(Loaded {
            entry: start_va,
            stack: stack.sp,
            thread_pointer: tsd_va,
        })
    }
}

fn darwin() -> &'static dyn SysAbi {
    static IT: DarwinAbi = DarwinAbi;
    &IT
}

ax_dispatch::register_sysabi!(darwin);

/// The executable format this package loads. Kept apart from the type that
/// services traps because they are separate capabilities: a package may
/// provide either, and this one provides both.
#[derive(Debug, Clone, Copy, Default)]
pub struct MachoFormat;

/// The same package registers twice, once per capability: it knows how to map
/// this format, and it knows how to service the traps that follow.
fn darwin_format() -> &'static dyn ImageFormat {
    static IT: MachoFormat = MachoFormat;
    &IT
}

ax_binfmt::register_binfmt!(darwin_format);
