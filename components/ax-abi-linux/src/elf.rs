//! ELF, as an executable format the Linux domain owns.
//!
//! The kernel used to parse and map ELF itself, which made it the one format
//! that did not go through the registry. It is a format like the others: it
//! registers, it recognizes an image by its magic, and it places the image
//! through the load port. What is left in a hosting kernel is what only a
//! kernel can do - the address space, its own fixed mappings, the page cache.
//!
//! Everything here is Linux's own: the segment rules, the interpreter chain,
//! the auxiliary vector, and the initial process stack that `argc`, `argv`,
//! `envp` and `auxv` are laid out on.

use alloc::{string::String, vec, vec::Vec};

use ax_binfmt::{AbiError, AbiResult, ImageFormat, LoadEnv, LoadRequest, Loaded, Prot};
use ax_dispatch::Abi;
use kernel_elf_parser::{AuxEntry, AuxType, ELFHeaders, ELFHeadersBuilder, ELFParser};

const PAGE_SIZE: usize = 4096;

/// Linux bounds `PT_INTERP` this way, and the path is untrusted metadata.
const MAX_INTERPRETER_PATH_LEN: u64 = 256;

/// How much of the head is read to find the headers, matching the page a
/// kernel would fault in anyway.
const HEADER_WINDOW: usize = 4096;

/// The ELF format.
#[derive(Debug, Clone, Copy, Default)]
pub struct ElfFormat;

impl ImageFormat for ElfFormat {
    fn abi(&self) -> Abi {
        Abi::Linux
    }

    fn recognizes(&self, image: &[u8]) -> bool {
        ax_binfmt::detect(image) == Some(Abi::Linux)
    }

    fn load(&self, req: &LoadRequest<'_>, env: &mut dyn LoadEnv) -> AbiResult<Loaded> {
        // Parse before anything is torn down: a malformed image must leave the
        // caller's address space alone, which is what lets execve report
        // ENOEXEC and carry on.
        let head = read_headers(env)?;
        let table = read_ph_table(&head, env)?;
        let headers = parse_headers(&head, &table)?;
        let elf = ELFParser::new(&headers, req.load_base as usize)
            .map_err(|_| AbiError::MalformedImage)?;

        env.reset()?;
        map_segments(&elf, env)?;
        relocate_if_pie(&elf, req.load_base, env)?;

        // A dynamic image names the interpreter that should run it. Both stay
        // mapped: this one's segments are placed, then the interpreter's, at a
        // base clear of everything already there. The interpreter's buffers
        // live only as long as reading it takes.
        let ldso = match interpreter_path(&elf, env)? {
            Some(path) => {
                env.interpret(&path)?;
                let head = read_headers(env)?;
                let table = read_ph_table(&head, env)?;
                let headers = parse_headers(&head, &table)?;
                let base = (env.mapped_end() as usize).next_multiple_of(0x100000);
                let ldso = ELFParser::new(&headers, base).map_err(|_| AbiError::MalformedImage)?;
                map_segments(&ldso, env)?;
                relocate_if_pie(&ldso, base as u64, env)?;
                Some((ldso.entry(), ldso.base()))
            }
            None => None,
        };

        let entry = ldso.map_or_else(|| elf.entry(), |(entry, _)| entry);
        let mut auxv = elf
            .aux_vector(PAGE_SIZE, ldso.map(|(_, base)| base))
            .collect::<Vec<_>>();
        auxv.push(AuxEntry::new(
            AuxType::HWCAP,
            env.cpu_capabilities() as usize,
        ));
        auxv.push(AuxEntry::new(AuxType::UID, 0));
        auxv.push(AuxEntry::new(AuxType::EUID, 0));
        auxv.push(AuxEntry::new(AuxType::GID, 0));
        auxv.push(AuxEntry::new(AuxType::EGID, 0));
        auxv.push(AuxEntry::new(AuxType::SECURE, 0));

        // The host republishes these; Linux exposes them under procfs.
        let pairs: Vec<(usize, usize)> = auxv
            .iter()
            .map(|e| (e.get_type() as usize, e.value()))
            .collect();
        env.record_metadata(&pairs);

        let stack = place_stack(req.args, req.envs, &auxv, env)?;
        Ok(Loaded {
            entry: entry as u64,
            stack,
            thread_pointer: 0,
        })
    }
}

fn elf() -> &'static dyn ImageFormat {
    static IT: ElfFormat = ElfFormat;
    &IT
}

ax_binfmt::register_binfmt!(elf);

/// Read the head of the image, where the file and program headers live.
fn read_headers(env: &mut dyn LoadEnv) -> AbiResult<Vec<u8>> {
    let mut head = vec![0u8; HEADER_WINDOW];
    let read = env.read_image(0, &mut head)?;
    head.truncate(read);
    Ok(head)
}

/// Read the program-header table, which may lie past the head window.
fn read_ph_table(head: &[u8], env: &mut dyn LoadEnv) -> AbiResult<Vec<u8>> {
    let builder = ELFHeadersBuilder::new(head).map_err(|_| AbiError::MalformedImage)?;
    let range = builder.ph_range();
    if range.end as usize <= head.len() {
        return Ok(head[range.start as usize..range.end as usize].to_vec());
    }
    let mut table = vec![0u8; (range.end - range.start) as usize];
    env.read_image(range.start, &mut table)?;
    Ok(table)
}

/// Parse the headers out of buffers the caller keeps alive. The parser borrows
/// them, so they outlive it by living in the caller's frame rather than by
/// being leaked.
fn parse_headers<'a>(head: &'a [u8], table: &'a [u8]) -> AbiResult<ELFHeaders<'a>> {
    ELFHeadersBuilder::new(head)
        .map_err(|_| AbiError::MalformedImage)?
        .build(table)
        .map_err(|_| AbiError::MalformedImage)
}

/// Map every `PT_LOAD`, from the file so its pages arrive on demand.
fn map_segments(elf: &ELFParser<'_>, env: &mut dyn LoadEnv) -> AbiResult<()> {
    // A `PT_TLS` init image may sit past the last `PT_LOAD`'s file extent, and
    // the dynamic linker faults it in through that mapping, so the last
    // segment's file contribution has to reach far enough to cover it.
    let tls_end: u64 = elf
        .headers()
        .ph
        .iter()
        .filter(|ph| ph.get_type() == Ok(xmas_elf::program::Type::Tls))
        .map(|ph| ph.offset + ph.file_size)
        .max()
        .unwrap_or(0);

    let loads: Vec<_> = elf
        .headers()
        .ph
        .iter()
        .filter(|ph| ph.get_type() == Ok(xmas_elf::program::Type::Load))
        .collect();
    let last = loads.len().wrapping_sub(1);

    for (i, ph) in loads.iter().enumerate() {
        let vaddr = ph.virtual_addr as usize + elf.base();
        let pad = vaddr % PAGE_SIZE;
        // ELF requires a segment's virtual address and file offset to agree
        // modulo the page size. This is untrusted metadata, so a mismatch is
        // refused rather than trusted.
        if pad != ph.offset as usize % PAGE_SIZE {
            return Err(AbiError::MalformedImage);
        }
        let len = (ph.mem_size as usize + pad).next_multiple_of(PAGE_SIZE);
        let file_end = if i == last && tls_end > ph.offset + ph.file_size {
            tls_end
        } else {
            ph.offset + ph.file_size
        };
        env.map_image(
            (vaddr - pad) as u64,
            len as u64,
            segment_prot(ph.flags),
            ph.offset - pad as u64,
            file_end,
        )?;
    }
    Ok(())
}

fn segment_prot(flags: xmas_elf::program::Flags) -> Prot {
    let mut prot = Prot::empty();
    if flags.is_read() {
        prot |= Prot::READ;
    }
    if flags.is_write() {
        prot |= Prot::WRITE;
    }
    if flags.is_execute() {
        prot |= Prot::EXEC;
    }
    prot
}

/// The path in `PT_INTERP`, when the image names one.
fn interpreter_path(elf: &ELFParser<'_>, env: &mut dyn LoadEnv) -> AbiResult<Option<String>> {
    let Some(ph) = elf
        .headers()
        .ph
        .iter()
        .find(|ph| ph.get_type() == Ok(xmas_elf::program::Type::Interp))
    else {
        return Ok(None);
    };
    let len = ph.file_size;
    let end = ph.offset.checked_add(len).ok_or(AbiError::MalformedImage)?;
    if !(2..=MAX_INTERPRETER_PATH_LEN).contains(&len) || end > env.image_len() {
        return Err(AbiError::MalformedImage);
    }
    let mut data = vec![0u8; len as usize];
    if env.read_image(ph.offset, &mut data)? != data.len() {
        return Err(AbiError::MalformedImage);
    }
    let path = data
        .split(|b| *b == 0)
        .next()
        .and_then(|s| core::str::from_utf8(s).ok())
        .ok_or(AbiError::MalformedImage)?;
    Ok(Some(String::from(path)))
}

/// Lay out the initial process stack: the strings, then the pointer vectors
/// and the auxiliary vector that `_start` reads off the stack pointer.
fn place_stack(
    args: &[&str],
    envs: &[&str],
    auxv: &[AuxEntry],
    env: &mut dyn LoadEnv,
) -> AbiResult<u64> {
    let top = env.stack_top() as usize;
    let mut image: Vec<u8> = Vec::new();
    // Everything is prepended, so the image is built from the top down and the
    // returned position is where the stack pointer will be.
    let push = |image: &mut Vec<u8>, src: &[u8]| -> usize {
        let mut next = Vec::with_capacity(src.len() + image.len());
        next.extend_from_slice(src);
        next.extend_from_slice(image);
        *image = next;
        top - image.len()
    };

    let random = push(&mut image, b"0123456789abcdef");
    let env_ptrs: Vec<usize> = envs
        .iter()
        .map(|s| {
            push(&mut image, b"\0");
            push(&mut image, s.as_bytes())
        })
        .collect();
    let arg_ptrs: Vec<usize> = args
        .iter()
        .map(|s| {
            push(&mut image, b"\0");
            push(&mut image, s.as_bytes())
        })
        .collect();

    let word = size_of::<usize>();
    let null = vec![0u8; word];
    let sp = push(&mut image, &null);
    push(&mut image, &vec![0u8; sp % 16]);
    if (envs.len() + args.len() + 3) & 1 != 0 {
        push(&mut image, &null);
    }

    let has_random = auxv.iter().any(|e| e.get_type() == AuxType::RANDOM);
    let has_execfn = auxv.iter().any(|e| e.get_type() == AuxType::EXECFN);
    // Prepending puts the terminator down first, so user memory reads as the
    // supplied entries, then AT_RANDOM, AT_EXECFN, AT_NULL. Without AT_NULL,
    // musl keeps reading argv padding as auxv and can enable AT_SECURE.
    push(&mut image, &entry_bytes(AuxType::NULL, 0));
    if !has_execfn {
        push(&mut image, &entry_bytes(AuxType::EXECFN, arg_ptrs[0]));
    }
    if !has_random {
        push(&mut image, &entry_bytes(AuxType::RANDOM, random));
    }
    for e in auxv.iter().rev() {
        push(&mut image, &entry_bytes(e.get_type(), e.value()));
    }

    push(&mut image, &null);
    for p in env_ptrs.iter().rev() {
        push(&mut image, &p.to_ne_bytes());
    }
    push(&mut image, &null);
    for p in arg_ptrs.iter().rev() {
        push(&mut image, &p.to_ne_bytes());
    }
    let sp = push(&mut image, &args.len().to_ne_bytes());

    env.write(sp as u64, &image)?;
    Ok(sp as u64)
}

fn entry_bytes(ty: AuxType, value: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(2 * size_of::<usize>());
    out.extend_from_slice(&(ty as usize).to_ne_bytes());
    out.extend_from_slice(&value.to_ne_bytes());
    out
}

/// Apply the relative relocations a static-pie image carries. Only riscv64
/// produces them here; elsewhere the loader has nothing to do.
#[cfg(not(target_arch = "riscv64"))]
fn relocate_if_pie(_elf: &ELFParser<'_>, _base: u64, _env: &mut dyn LoadEnv) -> AbiResult<()> {
    Ok(())
}

#[cfg(target_arch = "riscv64")]
fn relocate_if_pie(elf: &ELFParser<'_>, base: u64, env: &mut dyn LoadEnv) -> AbiResult<()> {
    use xmas_elf::header::{Class, Type};

    if elf.headers().header.pt1.class() != Class::SixtyFour
        || elf.headers().header.pt2.type_().as_type() != Type::SharedObject
    {
        return Ok(());
    }
    riscv::relocate(elf, base as usize, env)
}

#[cfg(target_arch = "riscv64")]
mod riscv {
    use super::*;

    const R_RISCV_64: u32 = 2;
    const R_RISCV_RELATIVE: u32 = 3;

    const DYN_ENTRY: usize = 16;
    const RELA_ENTRY: usize = 24;
    const SYM_ENTRY: usize = 24;

    pub(super) fn relocate(
        elf: &ELFParser<'_>,
        base: usize,
        env: &mut dyn LoadEnv,
    ) -> AbiResult<()> {
        let ph = &elf.headers().ph;
        let Some(dynamic) = ph
            .iter()
            .find(|p| p.get_type() == Ok(xmas_elf::program::Type::Dynamic))
        else {
            return Ok(());
        };
        let size = dynamic.file_size as usize;
        if dynamic.offset as usize + size > env.image_len() as usize {
            return Err(AbiError::MalformedImage);
        }
        let mut data = vec![0u8; size];
        env.read_image(dynamic.offset, &mut data)?;

        let (mut rela, mut rela_size, mut symtab) = (0u64, 0u64, 0u64);
        for chunk in data.as_chunks::<DYN_ENTRY>().0 {
            let tag = u64::from_le_bytes(chunk[0..8].try_into().unwrap());
            let value = u64::from_le_bytes(chunk[8..16].try_into().unwrap());
            match tag {
                0 => break,
                6 => symtab = value,
                7 => rela = value,
                8 => rela_size = value,
                _ => {}
            }
        }
        if rela == 0 || rela_size == 0 {
            return Ok(());
        }

        let at = file_offset(rela, ph).ok_or(AbiError::MalformedImage)?;
        let len = env.image_len() as usize;
        for i in 0..rela_size as usize / RELA_ENTRY {
            let entry_at = at + i * RELA_ENTRY;
            if entry_at + RELA_ENTRY > len {
                break;
            }
            let mut entry = [0u8; RELA_ENTRY];
            env.read_image(entry_at as u64, &mut entry)?;
            let offset = u64::from_le_bytes(entry[0..8].try_into().unwrap()) as usize;
            let info = u64::from_le_bytes(entry[8..16].try_into().unwrap());
            let addend = i64::from_le_bytes(entry[16..24].try_into().unwrap());

            match (info & 0xffff_ffff) as u32 {
                R_RISCV_RELATIVE => {
                    let value = (base as i64 + addend) as u64;
                    env.write((base + offset) as u64, &value.to_le_bytes())?;
                }
                R_RISCV_64 if symtab != 0 => {
                    let sym_at = file_offset(symtab, ph).ok_or(AbiError::MalformedImage)?
                        + (info >> 32) as usize * SYM_ENTRY;
                    if sym_at + SYM_ENTRY > len {
                        continue;
                    }
                    let mut sym = [0u8; SYM_ENTRY];
                    env.read_image(sym_at as u64, &mut sym)?;
                    let st_value = u64::from_le_bytes(sym[8..16].try_into().unwrap());
                    if st_value == 0 {
                        continue;
                    }
                    let value = (base as i64 + st_value as i64 + addend) as u64;
                    env.write((base + offset) as u64, &value.to_le_bytes())?;
                }
                // R_RISCV_COPY moves a symbol's bytes out of the interpreter's
                // image, which only arises once one is mapped; anything else is
                // a relocation this domain does not apply.
                _ => {}
            }
        }
        Ok(())
    }

    /// Where a virtual address falls in the file, through the `PT_LOAD` that
    /// covers it.
    fn file_offset(vaddr: u64, ph: &[xmas_elf::program::ProgramHeader64]) -> Option<usize> {
        ph.iter()
            .filter(|s| s.get_type() == Ok(xmas_elf::program::Type::Load))
            .find(|s| (s.virtual_addr..s.virtual_addr + s.file_size).contains(&vaddr))
            .map(|s| (s.offset + (vaddr - s.virtual_addr)) as usize)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A host with no demand paging: it records what was asked for, and serves
    /// reads out of the image it was handed.
    #[derive(Default)]
    struct Recorder {
        image: Vec<u8>,
        /// (va, len, prot, file offset, file end)
        mapped: Vec<(u64, u64, Prot, u64, u64)>,
        written: Vec<(u64, usize)>,
        end: u64,
        interpreted: Option<String>,
        reset: bool,
    }

    impl LoadEnv for Recorder {
        fn map_region(
            &mut self,
            _va: u64,
            _len: u64,
            _p: Prot,
            _i: Option<&[u8]>,
        ) -> AbiResult<()> {
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
            self.mapped.push((va, len, prot, offset, file_end));
            self.end = self.end.max(va + len);
            Ok(())
        }
        fn read_image(&mut self, at: u64, out: &mut [u8]) -> AbiResult<usize> {
            let at = at as usize;
            let n = out.len().min(self.image.len().saturating_sub(at));
            out[..n].copy_from_slice(&self.image[at..at + n]);
            Ok(n)
        }
        fn interpret(&mut self, path: &str) -> AbiResult<()> {
            self.interpreted = Some(String::from(path));
            Ok(())
        }
        fn reset(&mut self) -> AbiResult<()> {
            self.reset = true;
            Ok(())
        }
        fn write(&mut self, va: u64, bytes: &[u8]) -> AbiResult<()> {
            self.written.push((va, bytes.len()));
            Ok(())
        }
        fn image_len(&self) -> u64 {
            self.image.len() as u64
        }
        fn mapped_end(&self) -> u64 {
            self.end
        }
        fn stack_top(&self) -> u64 {
            0x4000_0000
        }
        fn cpu_capabilities(&self) -> u64 {
            0xcafe
        }
    }

    const PT_LOAD: u32 = 1;
    const PF_R: u32 = 4;
    const PF_X: u32 = 1;

    /// A 64-bit little-endian ELF executable with one read-execute PT_LOAD
    /// whose memory size exceeds its file size, so the zero-fill tail shows up.
    fn synth(entry: u64, filesz: u64, memsz: u64) -> Vec<u8> {
        let ph_off = 64u64;
        let mut b = vec![0u8; 0x2000];
        b[..4].copy_from_slice(b"\x7fELF");
        b[4] = 2; // 64-bit
        b[5] = 1; // little endian
        b[6] = 1; // version
        b[16..18].copy_from_slice(&2u16.to_le_bytes()); // ET_EXEC
        b[18..20].copy_from_slice(&0x3eu16.to_le_bytes()); // x86-64
        b[20..24].copy_from_slice(&1u32.to_le_bytes());
        b[24..32].copy_from_slice(&entry.to_le_bytes());
        b[32..40].copy_from_slice(&ph_off.to_le_bytes());
        b[52..54].copy_from_slice(&64u16.to_le_bytes()); // ehsize
        b[54..56].copy_from_slice(&56u16.to_le_bytes()); // phentsize
        b[56..58].copy_from_slice(&1u16.to_le_bytes()); // phnum

        let p = ph_off as usize;
        b[p..p + 4].copy_from_slice(&PT_LOAD.to_le_bytes());
        b[p + 4..p + 8].copy_from_slice(&(PF_R | PF_X).to_le_bytes());
        b[p + 8..p + 16].copy_from_slice(&0u64.to_le_bytes()); // offset
        b[p + 16..p + 24].copy_from_slice(&0x1000u64.to_le_bytes()); // vaddr
        b[p + 24..p + 32].copy_from_slice(&0x1000u64.to_le_bytes()); // paddr
        b[p + 32..p + 40].copy_from_slice(&filesz.to_le_bytes());
        b[p + 40..p + 48].copy_from_slice(&memsz.to_le_bytes());
        b[p + 48..p + 56].copy_from_slice(&0x1000u64.to_le_bytes()); // align
        b
    }

    #[test]
    fn a_load_segment_is_mapped_from_the_file_not_copied() {
        let mut env = Recorder {
            image: synth(0x1000, 0x800, 0x2000),
            ..Recorder::default()
        };
        let loaded = ElfFormat
            .load(
                &LoadRequest {
                    image: &env.image.clone(),
                    path: "",
                    load_base: 0,
                    args: &["/bin/x"],
                    envs: &[],
                },
                &mut env,
            )
            .expect("load");

        assert_eq!(loaded.entry, 0x1000);
        // One segment, occupying its memory size, with only the file portion
        // coming from the file - the rest is the host's zero fill.
        assert_eq!(env.mapped.len(), 1);
        let (va, len, prot, offset, file_end) = env.mapped[0];
        assert_eq!(va, 0x1000);
        assert_eq!(len, 0x2000);
        assert_eq!(prot, Prot::READ | Prot::EXEC);
        assert_eq!((offset, file_end), (0, 0x800));
        // Nothing was torn down before the headers parsed, and the stack was
        // written below its top.
        assert!(env.reset);
        assert_eq!(env.written.len(), 1);
        assert!(loaded.stack < env.stack_top() && loaded.stack.is_multiple_of(16));
    }

    #[test]
    fn a_segment_whose_offset_disagrees_with_its_address_is_refused() {
        // ELF requires vaddr and file offset to agree modulo the page size.
        let mut image = synth(0x1000, 0x800, 0x1000);
        let p = 64 + 8;
        image[p..p + 8].copy_from_slice(&1u64.to_le_bytes());
        let mut env = Recorder {
            image: image.clone(),
            ..Recorder::default()
        };
        let err = ElfFormat
            .load(
                &LoadRequest {
                    image: &image,
                    path: "",
                    load_base: 0,
                    args: &["/bin/x"],
                    envs: &[],
                },
                &mut env,
            )
            .unwrap_err();
        assert_eq!(err, AbiError::MalformedImage);
    }

    #[test]
    fn a_non_elf_image_is_not_claimed() {
        assert!(!ElfFormat.recognizes(b"MZ\0\0"));
        assert!(ElfFormat.recognizes(b"\x7fELF"));
        assert_eq!(ElfFormat.abi(), Abi::Linux);
    }
}
