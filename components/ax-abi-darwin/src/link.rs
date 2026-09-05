//! Placing an image's libraries and fixing the whole set up: what dyld does
//! between `execve` and a program's first instruction.
//!
//! Every Mach-O carries two opcode streams instead of relocation tables. The
//! rebase stream names the places holding an address of the image's own,
//! which move with it; the bind stream names the places holding an address
//! that belongs to another library, and the symbol each one wants. Reading
//! them is [`ax_binfmt::dyld`]'s job; this module is what has the images, so
//! it is what places them and applies what the streams say.
//!
//! Binding is eager here. dyld defers most of it - a lazy pointer starts out
//! pointing at `dyld_stub_binder` and is filled in at the first call - but
//! deferring costs a resident binder, and a loader that resolves everything
//! before the program runs refuses a broken set of libraries while the host
//! still has the address space it came with, rather than at an arbitrary
//! later call.

use alloc::{
    format,
    string::{String, ToString},
    vec::Vec,
};

use ax_binfmt::{
    AbiError, AbiResult, LoadEnv,
    dyld::{self, Bind, RebaseKind, Source},
    macho::{self, MachoInfo, Segment},
};

use crate::{PAGE, system::Library};

/// How deep a chain of libraries the walk follows before it decides the set
/// loops. Nothing sane nests this far; a cycle is what this bounds.
const DEPTH_LIMIT: usize = 32;

/// One image in the process: the program, or a library it reached.
#[derive(Debug)]
pub struct Module {
    /// How the load command that reached it spells its path, which is also
    /// how a bind names the library it wants.
    pub name: String,
    /// The whole file it was read from.
    pub bytes: Vec<u8>,
    pub info: MachoInfo,
    /// Added to every address the image names.
    pub slide: u64,
    /// Where its mach header lands, which is what an export's address in the
    /// trie is measured from.
    pub base: u64,
    /// Its `LC_SEGMENT_64` commands, in the order a fixup counts them.
    pub segments: Vec<Segment>,
    /// The libraries it names, in the order a bind's ordinal counts them.
    pub libs: Vec<String>,
    /// Fixups whose target is past the file's own bytes - the zero-filled
    /// tail of a segment - to write once the segment is mapped.
    pub late: Vec<(u64, u64)>,
}

impl Module {
    /// Where `symbol` is in this image, if it exports it.
    fn export(&self, symbol: &str) -> Option<u64> {
        let info = dyld::info(
            &self.bytes,
            self.info.commands_off,
            self.info.ncmds,
            self.info.sizeofcmds,
        )?;
        let at = self.info.base + info.export_off as usize;
        let trie = self.bytes.get(at..at + info.export_size as usize)?;
        let mut found = None;
        dyld::exports(trie, &mut |export| {
            if export.name == symbol && !export.reexport() {
                found = Some(export.address);
            }
        });
        found.map(|address| self.base + address)
    }

    /// The address one past the last byte the image occupies.
    fn end(&self) -> u64 {
        self.segments
            .iter()
            .filter(|s| s.vmsize != 0)
            .map(|s| self.slide + s.vmaddr + s.vmsize)
            .max()
            .unwrap_or(self.slide)
    }
}

/// Everything a program needs mapped before it starts.
#[derive(Debug)]
pub struct Linked {
    /// The program first, then every library it reached, which is also the
    /// order they are placed in.
    pub modules: Vec<Module>,
    /// The libraries the system provides itself, placed past them all.
    pub system: Library,
}

/// Read the program's libraries, place the set, and resolve every fixup in it.
///
/// `path` is where the program was found; a library that names itself relative
/// to it, as `@executable_path` and `@loader_path` do, is resolved against it.
pub fn link(bytes: Vec<u8>, path: &str, env: &mut dyn LoadEnv) -> AbiResult<Linked> {
    let info = macho::parse(&bytes).ok_or(AbiError::MalformedImage)?;
    let program = module(path.to_string(), bytes, info, 0);
    let mut next = page_up(program.end());
    let mut modules = alloc::vec![program];

    let mut at = 0;
    while at < modules.len() {
        if at == DEPTH_LIMIT {
            return Err(AbiError::Unsupported);
        }
        for lib in modules[at].libs.clone() {
            if provided(&lib) || modules.iter().any(|m| m.name == lib) {
                continue;
            }
            let bytes = match read(&lib, path, &modules[at].name, env) {
                Ok(bytes) => bytes,
                Err(err) => {
                    env.trace(&format!(
                        "{lib} is needed by {} and is not here",
                        modules[at].name
                    ));
                    return Err(err);
                }
            };
            let info = macho::parse(&bytes).ok_or(AbiError::MalformedImage)?;
            let module = module(lib, bytes, info, next);
            next = page_up(module.end());
            modules.push(module);
        }
        at += 1;
    }

    let system = Library::new(next);
    for at in 0..modules.len() {
        let fixed = fixups(&modules, at, &system, env)?;
        apply(&mut modules[at], fixed);
    }
    Ok(Linked { modules, system })
}

/// Read one image's header and settle where it goes.
fn module(name: String, bytes: Vec<u8>, info: MachoInfo, slide: u64) -> Module {
    let segments: Vec<Segment> = info.segments(&bytes).collect();
    // An image's own addresses are measured from its mach header, which is in
    // whichever segment starts at the front of the file - not `__PAGEZERO`,
    // which reserves address space and holds no bytes at all.
    let base = slide
        + segments
            .iter()
            .find(|s| s.fileoff == info.base as u64 && s.filesize != 0)
            .map_or(0, |s| s.vmaddr);
    Module {
        libs: info.dylibs(&bytes).map(|d| d.path.to_string()).collect(),
        name,
        bytes,
        info,
        slide,
        base,
        segments,
        late: Vec::new(),
    }
}

/// Whether the system provides `path` itself rather than reading it.
fn provided(path: &str) -> bool {
    path.starts_with("/usr/lib/") || path.starts_with("/System/Library/")
}

/// Read the library `lib` names, resolving the prefixes dyld resolves.
fn read(lib: &str, program: &str, loader: &str, env: &mut dyn LoadEnv) -> AbiResult<Vec<u8>> {
    for candidate in [
        lib.replace("@executable_path", dir_of(program)),
        lib.replace("@loader_path", dir_of(loader)),
        // `@rpath` is a search list the image carries; until one is read from
        // `LC_RPATH`, the loader's own directory is the one entry dyld would
        // almost always find it in.
        lib.replace("@rpath", dir_of(loader)),
    ] {
        if env.interpret(&candidate).is_ok() {
            return read_all(env);
        }
    }
    Err(AbiError::MissingLibrary)
}

/// The directory part of `path`, without its trailing separator.
fn dir_of(path: &str) -> &str {
    path.rsplit_once('/').map_or("", |(dir, _)| dir)
}

/// Read the whole of the image the host is on.
fn read_all(env: &mut dyn LoadEnv) -> AbiResult<Vec<u8>> {
    let len = env.image_len() as usize;
    let mut bytes = alloc::vec![0u8; len];
    let mut got = 0;
    while got < len {
        match env.read_image(got as u64, &mut bytes[got..])? {
            0 => break,
            n => got += n,
        }
    }
    bytes.truncate(got);
    Ok(bytes)
}

/// One place to write, named by where it is in the file and in memory, since
/// a fixup past the file's own bytes can only be written once mapped.
struct Fix {
    file: u64,
    va: u64,
    value: u64,
    kind: RebaseKind,
}

/// What both streams of module `at` say to write.
fn fixups(
    modules: &[Module],
    at: usize,
    system: &Library,
    env: &mut dyn LoadEnv,
) -> AbiResult<Vec<Fix>> {
    let module = &modules[at];
    let Some(info) = dyld::info(
        &module.bytes,
        module.info.commands_off,
        module.info.ncmds,
        module.info.sizeofcmds,
    ) else {
        // An image with no `LC_DYLD_INFO` holds no addresses that move and
        // asks for none, which is what a static image looks like.
        return Ok(Vec::new());
    };
    let stream = |off: u32, size: u32| {
        let start = module.info.base + off as usize;
        module
            .bytes
            .get(start..start + size as usize)
            .unwrap_or(&[])
    };

    let mut out = Vec::new();
    let mut bad = None;
    dyld::rebases(
        stream(info.rebase_off, info.rebase_size),
        |rebase| match place(module, rebase.segment, rebase.offset) {
            Some((file, va)) => out.push(Fix {
                file,
                va,
                value: read_at(module, file, rebase.kind).wrapping_add(module.slide),
                kind: rebase.kind,
            }),
            None => bad = Some(AbiError::MalformedImage),
        },
    );
    if let Some(err) = bad {
        return Err(err);
    }

    let mut missing: Option<String> = None;
    {
        let mut each = |bind: Bind<'_>| {
            let Some((file, va)) = place(module, bind.segment, bind.offset) else {
                missing = Some(String::from(
                    "a bind names a segment the image does not have",
                ));
                return;
            };
            let target = resolve(modules, at, system, &bind);
            let value = match target {
                Some(target) => target.wrapping_add(bind.addend as u64),
                // A weak import the set does not have is a zero the program is
                // expected to test, which is the whole point of declaring it weak.
                None if bind.weak => 0,
                None => {
                    missing = Some(format!("{}: {} is not provided", module.name, bind.symbol));
                    return;
                }
            };
            out.push(Fix {
                file,
                va,
                value,
                kind: bind.kind,
            });
        };
        dyld::binds(stream(info.bind_off, info.bind_size), &mut each);
        dyld::binds(stream(info.weak_bind_off, info.weak_bind_size), &mut each);
        dyld::binds(stream(info.lazy_bind_off, info.lazy_bind_size), &mut each);
    }
    if let Some(why) = missing {
        env.trace(&why);
        return Err(AbiError::MissingLibrary);
    }
    Ok(out)
}

/// Where a fixup lands, as a file offset and an address.
fn place(module: &Module, segment: u8, offset: u64) -> Option<(u64, u64)> {
    let seg = module.segments.get(segment as usize)?;
    Some((seg.fileoff + offset, module.slide + seg.vmaddr + offset))
}

/// What the image already holds where a rebase points, which is the address
/// before it moved.
fn read_at(module: &Module, file: u64, kind: RebaseKind) -> u64 {
    let at = file as usize;
    match kind {
        RebaseKind::Pointer => module
            .bytes
            .get(at..at + 8)
            .map_or(0, |b| u64::from_le_bytes(b.try_into().unwrap_or([0; 8]))),
        _ => module.bytes.get(at..at + 4).map_or(0, |b| {
            u64::from(u32::from_le_bytes(b.try_into().unwrap_or([0; 4])))
        }),
    }
}

/// What a bind's symbol leads to, in whichever image the bind names.
fn resolve(modules: &[Module], at: usize, system: &Library, bind: &Bind<'_>) -> Option<u64> {
    let from = |name: &str| {
        if provided(name) {
            system.address(bind.symbol)
        } else {
            modules
                .iter()
                .find(|m| m.name == name)
                .and_then(|m| m.export(bind.symbol))
        }
    };
    match bind.source {
        Source::Library(ordinal) => from(modules[at].libs.get(ordinal as usize - 1)?),
        Source::Own => modules[at].export(bind.symbol),
        Source::Program => modules[0].export(bind.symbol),
        Source::Anywhere => modules
            .iter()
            .find_map(|m| m.export(bind.symbol))
            .or_else(|| system.address(bind.symbol)),
    }
}

/// Write what the streams said into the image, leaving what falls past the
/// file's own bytes for the caller to write once the segment is mapped.
fn apply(module: &mut Module, fixed: Vec<Fix>) {
    for fix in fixed {
        let at = fix.file as usize;
        let wrote = match fix.kind {
            RebaseKind::Pointer => module
                .bytes
                .get_mut(at..at + 8)
                .map(|slot| slot.copy_from_slice(&fix.value.to_le_bytes())),
            _ => module
                .bytes
                .get_mut(at..at + 4)
                .map(|slot| slot.copy_from_slice(&(fix.value as u32).to_le_bytes())),
        };
        if wrote.is_none() {
            module.late.push((fix.va, fix.value));
        }
    }
}

fn page_up(at: u64) -> u64 {
    at.div_ceil(PAGE) * PAGE
}

#[cfg(test)]
mod tests {
    use alloc::collections::BTreeMap;

    use super::*;

    const LC_SEGMENT_64: u32 = 0x19;
    const LC_LOAD_DYLIB: u32 = 0xC;
    const LC_DYLD_INFO_ONLY: u32 = 0x8000_0022;
    const HEADER_LEN: usize = 32;

    /// Builds one Mach-O out of parts, the way a linker lays one out: a
    /// header, the load commands, then the file the commands point into.
    #[derive(Default)]
    struct Build {
        commands: Vec<u8>,
        ncmds: u32,
        file: Vec<u8>,
    }

    impl Build {
        fn segment(&mut self, name: &str, vmaddr: u64, fileoff: u64, len: u64, prot: u32) {
            let mut cmd = alloc::vec![0u8; 72];
            cmd[0..4].copy_from_slice(&LC_SEGMENT_64.to_le_bytes());
            cmd[4..8].copy_from_slice(&72u32.to_le_bytes());
            cmd[8..8 + name.len()].copy_from_slice(name.as_bytes());
            cmd[24..32].copy_from_slice(&vmaddr.to_le_bytes());
            cmd[32..40].copy_from_slice(&len.to_le_bytes());
            cmd[40..48].copy_from_slice(&fileoff.to_le_bytes());
            cmd[48..56].copy_from_slice(&len.to_le_bytes());
            cmd[60..64].copy_from_slice(&prot.to_le_bytes());
            self.push(&cmd);
        }

        fn dylib(&mut self, path: &str) {
            let len = (24 + path.len() + 1).div_ceil(8) * 8;
            let mut cmd = alloc::vec![0u8; len];
            cmd[0..4].copy_from_slice(&LC_LOAD_DYLIB.to_le_bytes());
            cmd[4..8].copy_from_slice(&(len as u32).to_le_bytes());
            cmd[8..12].copy_from_slice(&24u32.to_le_bytes());
            cmd[24..24 + path.len()].copy_from_slice(path.as_bytes());
            self.push(&cmd);
        }

        /// The `LC_DYLD_INFO_ONLY` command, with each stream placed in the
        /// file as it is added.
        fn info(&mut self, rebase: &[u8], bind: &[u8], trie: &[u8]) {
            let mut cmd = alloc::vec![0u8; 48];
            cmd[0..4].copy_from_slice(&LC_DYLD_INFO_ONLY.to_le_bytes());
            cmd[4..8].copy_from_slice(&48u32.to_le_bytes());
            for (at, stream) in [(8, rebase), (16, bind), (40, trie)] {
                let off = self.file.len() as u32;
                self.file.extend_from_slice(stream);
                cmd[at..at + 4].copy_from_slice(&off.to_le_bytes());
                cmd[at + 4..at + 8].copy_from_slice(&(stream.len() as u32).to_le_bytes());
            }
            self.push(&cmd);
        }

        fn push(&mut self, cmd: &[u8]) {
            self.commands.extend_from_slice(cmd);
            self.ncmds += 1;
        }

        /// The whole image. Load commands sit in the head of the file, which
        /// the `__TEXT` segment covers, as a real image has them.
        fn finish(mut self, file_len: usize) -> Vec<u8> {
            let head_len = HEADER_LEN + self.commands.len();
            if self.file.len() < file_len.max(head_len) {
                self.file.resize(file_len.max(head_len), 0);
            }
            let mut out = self.file;
            out[0..4].copy_from_slice(&macho::MH_MAGIC_64.to_le_bytes());
            out[16..20].copy_from_slice(&self.ncmds.to_le_bytes());
            out[20..24].copy_from_slice(&(self.commands.len() as u32).to_le_bytes());
            out[HEADER_LEN..head_len].copy_from_slice(&self.commands);
            out
        }
    }

    fn uleb(mut value: u64) -> Vec<u8> {
        let mut out = Vec::new();
        loop {
            let byte = (value & 0x7F) as u8;
            value >>= 7;
            out.push(if value == 0 { byte } else { byte | 0x80 });
            if value == 0 {
                return out;
            }
        }
    }

    /// A rebase stream naming one pointer in segment `seg` at `offset`.
    fn rebase_one(seg: u8, offset: u64) -> Vec<u8> {
        let mut out = alloc::vec![0x11u8, 0x20 | seg];
        out.extend(uleb(offset));
        out.push(0x51);
        out.push(0x00);
        out
    }

    /// A bind stream naming one symbol from one library at one place.
    fn bind_one(ordinal: u8, symbol: &str, seg: u8, offset: u64) -> Vec<u8> {
        let mut out = alloc::vec![0x10 | ordinal, 0x40];
        out.extend_from_slice(symbol.as_bytes());
        out.push(0);
        out.push(0x51);
        out.push(0x70 | seg);
        out.extend(uleb(offset));
        out.push(0x90);
        out.push(0x00);
        out
    }

    /// An export trie naming one symbol at one address.
    fn trie_one(symbol: &str, address: u64) -> Vec<u8> {
        let terminal: Vec<u8> = uleb(0).into_iter().chain(uleb(address)).collect();
        let child = alloc::vec![0u8, 1];
        let mut out = child;
        out.extend_from_slice(symbol.as_bytes());
        out.push(0);
        // The child's offset is past the root, which is what has been built
        // so far plus the offset's own byte.
        let at = out.len() + 1;
        out.extend(uleb(at as u64));
        out.push(terminal.len() as u8);
        out.extend(terminal);
        out.push(0);
        out
    }

    /// A library exporting `_hello`, with a pointer of its own to rebase and
    /// a symbol of libSystem's to bind.
    fn library() -> Vec<u8> {
        let mut b = Build::default();
        b.segment("__TEXT", 0, 0, 0x1000, 5);
        b.segment("__DATA", 0x1000, 0x1000, 0x1000, 3);
        b.segment("__LINKEDIT", 0x2000, 0x2000, 0x1000, 1);
        b.dylib("/usr/lib/libSystem.B.dylib");
        b.file.resize(0x2000, 0);
        // The pointer that moves with the image, and the slot libSystem's
        // fills in.
        b.file[0x1000..0x1008].copy_from_slice(&0x1234u64.to_le_bytes());
        b.info(
            &rebase_one(1, 0),
            &bind_one(1, "_write", 1, 8),
            &trie_one("_hello", 0x800),
        );
        b.finish(0x3000)
    }

    /// A program binding one symbol from the library and one from libSystem.
    fn program() -> Vec<u8> {
        let mut b = Build::default();
        b.segment("__PAGEZERO", 0, 0, 0, 0);
        b.segment("__TEXT", 0x1_0000_0000, 0, 0x1000, 5);
        b.segment("__DATA", 0x1_0000_1000, 0x1000, 0x1000, 3);
        b.segment("__LINKEDIT", 0x1_0000_2000, 0x2000, 0x1000, 1);
        b.dylib("/lib/libhello.dylib");
        b.dylib("/usr/lib/libSystem.B.dylib");
        b.file.resize(0x2000, 0);
        let mut binds = bind_one(1, "_hello", 2, 0);
        binds.extend(bind_one(2, "_write", 2, 8));
        b.info(&[], &binds, &[]);
        b.finish(0x3000)
    }

    #[derive(Default)]
    struct Files {
        files: BTreeMap<String, Vec<u8>>,
        on: Vec<u8>,
        traced: Vec<String>,
    }

    impl LoadEnv for Files {
        fn map_region(
            &mut self,
            _: u64,
            _: u64,
            _: ax_binfmt::Prot,
            _: Option<&[u8]>,
        ) -> AbiResult<()> {
            Ok(())
        }
        fn map_image(
            &mut self,
            _: u64,
            _: u64,
            _: ax_binfmt::Prot,
            _: u64,
            _: u64,
        ) -> AbiResult<()> {
            Ok(())
        }
        fn read_image(&mut self, at: u64, out: &mut [u8]) -> AbiResult<usize> {
            let from = self.on.get(at as usize..).unwrap_or(&[]);
            let n = out.len().min(from.len());
            out[..n].copy_from_slice(&from[..n]);
            Ok(n)
        }
        fn interpret(&mut self, path: &str) -> AbiResult<()> {
            match self.files.get(path) {
                Some(bytes) => {
                    self.on = bytes.clone();
                    Ok(())
                }
                None => Err(AbiError::MissingLibrary),
            }
        }
        fn image_len(&self) -> u64 {
            self.on.len() as u64
        }
        fn trace(&mut self, message: &str) {
            self.traced.push(message.to_string());
        }
    }

    fn word(module: &Module, file: usize) -> u64 {
        u64::from_le_bytes(module.bytes[file..file + 8].try_into().unwrap())
    }

    fn link_program(env: &mut Files) -> AbiResult<Linked> {
        env.files
            .insert(String::from("/lib/libhello.dylib"), library());
        link(program(), "/bin/prog", env)
    }

    #[test]
    fn reaches_the_library_the_program_names() {
        let mut env = Files::default();
        let linked = link_program(&mut env).expect("the set is complete");
        assert_eq!(linked.modules.len(), 2);
        assert_eq!(linked.modules[1].name, "/lib/libhello.dylib");
        // The program keeps the addresses its own header fixes; the library
        // is placed past it, on a page boundary.
        assert_eq!(linked.modules[0].slide, 0);
        assert_eq!(linked.modules[0].base, 0x1_0000_0000);
        assert_eq!(linked.modules[1].slide, 0x1_0000_3000);
        assert_eq!(linked.modules[1].base, 0x1_0000_3000);
        assert!(linked.system.base >= linked.modules[1].slide + 0x3000);
    }

    #[test]
    fn a_bind_lands_on_the_address_the_library_exports() {
        let mut env = Files::default();
        let linked = link_program(&mut env).expect("the set is complete");
        let hello = linked.modules[1].base + 0x800;
        assert_eq!(word(&linked.modules[0], 0x1000), hello);
    }

    #[test]
    fn a_bind_on_a_library_the_system_provides_lands_on_its_stub() {
        let mut env = Files::default();
        let linked = link_program(&mut env).expect("the set is complete");
        let write = linked
            .system
            .address("_write")
            .expect("libSystem has write");
        assert_eq!(word(&linked.modules[0], 0x1008), write);
        // The library binds the same symbol, and gets the same address.
        assert_eq!(word(&linked.modules[1], 0x1008), write);
    }

    #[test]
    fn a_rebase_moves_the_pointer_by_the_slide() {
        let mut env = Files::default();
        let linked = link_program(&mut env).expect("the set is complete");
        assert_eq!(
            word(&linked.modules[1], 0x1000),
            0x1234 + linked.modules[1].slide
        );
    }

    #[test]
    fn refuses_a_program_whose_library_is_not_here() {
        let mut env = Files::default();
        let err = link(program(), "/bin/prog", &mut env).expect_err("the library is missing");
        assert_eq!(err, AbiError::MissingLibrary);
        assert!(env.traced.iter().any(|m| m.contains("/lib/libhello.dylib")));
    }

    #[test]
    fn refuses_a_symbol_nothing_provides() {
        let mut b = Build::default();
        b.segment("__TEXT", 0x1_0000_0000, 0, 0x1000, 5);
        b.segment("__DATA", 0x1_0000_1000, 0x1000, 0x1000, 3);
        b.dylib("/usr/lib/libSystem.B.dylib");
        b.file.resize(0x2000, 0);
        b.info(&[], &bind_one(1, "_no_such_call", 1, 0), &[]);
        let mut env = Files::default();
        let err = link(b.finish(0x2000), "/bin/prog", &mut env).expect_err("nothing has it");
        assert_eq!(err, AbiError::MissingLibrary);
        assert!(env.traced.iter().any(|m| m.contains("_no_such_call")));
    }
}
