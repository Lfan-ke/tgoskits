//! User address space management.

use alloc::{borrow::ToOwned, string::String, vec, vec::Vec};
use core::iter;

use ax_fs_ng::vfs::{CachedFile, FileBackend};
use ax_memory_addr::{MemoryAddr, PAGE_SIZE_4K, VirtAddr};
use ax_runtime::hal::{mem::virt_to_phys, paging::MappingFlags};
use axfs_ng_vfs::Location;

use crate::{
    StarryError, StarryResult,
    config::{USER_SPACE_BASE, USER_SPACE_SIZE},
    mm::aspace::{AddrSpace, Backend},
    task::AsThread,
};

// Linux's exec path bounds chained binary-format rewrites and returns ELOOP
// for a too-deep interpreter chain. Give the recursive script loader the same
// bounded failure behavior.
const MAX_INTERPRETER_RECURSION: usize = 5;

/// Largest argv/envp stack image accepted by execve.
///
/// Linux derives this from the process stack limit and allows argv/envp to use
/// at most one quarter of it. StarryOS has a fixed 8 MiB user stack, so this
/// yields a 2 MiB limit while leaving room for the ELF auxiliary vector and
/// stack alignment.
pub(crate) const MAX_EXEC_ARG_BYTES: usize = crate::config::USER_STACK_SIZE / 4;

/// Reject argv/envp sets that cannot fit within the exec argument budget.
///
/// Count both C-string terminators and the two terminating pointer slots: all
/// of them become part of the initial user stack image.
pub(crate) fn validate_exec_arg_size(args: &[String], envs: &[String]) -> StarryResult {
    let pointer_count = args
        .len()
        .checked_add(envs.len())
        .and_then(|count| count.checked_add(2))
        .ok_or(StarryError::ArgumentListTooLong)?;
    let mut total = pointer_count
        .checked_mul(size_of::<usize>())
        .ok_or(StarryError::ArgumentListTooLong)?;

    for value in args.iter().chain(envs.iter()) {
        total = total
            .checked_add(
                value
                    .len()
                    .checked_add(1)
                    .ok_or(StarryError::ArgumentListTooLong)?,
            )
            .ok_or(StarryError::ArgumentListTooLong)?;
    }

    if total > MAX_EXEC_ARG_BYTES {
        return Err(StarryError::ArgumentListTooLong);
    }
    Ok(())
}

// RISC-V relocation types
#[cfg(target_arch = "riscv64")]
const R_RISCV_RELATIVE: u32 = 3;
#[cfg(target_arch = "riscv64")]
const R_RISCV_JUMP_SLOT: u32 = 5;
#[cfg(target_arch = "riscv64")]
const R_RISCV_64: u32 = 2;
#[cfg(target_arch = "riscv64")]
const R_RISCV_COPY: u32 = 4;


/// Creates a new empty user address space.
pub fn new_user_aspace_empty() -> StarryResult<AddrSpace> {
    AddrSpace::new_empty(VirtAddr::from_usize(USER_SPACE_BASE), USER_SPACE_SIZE)
}

/// If the target architecture requires it, the kernel portion of the address
/// space will be copied to the user address space.
pub fn copy_from_kernel(_aspace: &mut AddrSpace) -> StarryResult {
    #[cfg(not(any(target_arch = "aarch64", target_arch = "loongarch64")))]
    {
        // ARMv8 (aarch64) and LoongArch64 use separate page tables for user space
        // (aarch64: TTBR0_EL1, LoongArch64: PGDL), so there is no need to copy the
        // kernel portion to the user page table.
        let kspace = ax_mm::kernel_aspace().lock();
        // SAFETY: the global kernel address space outlives every user address
        // space, whose managed regions are restricted to user-space addresses.
        unsafe {
            _aspace.page_table_mut().share_root_entries_from(
                kspace.page_table(),
                kspace.base(),
                kspace.size(),
            )
        }
        .map_err(|_| StarryError::BadState)?;
    }
    Ok(())
}

/// Map the signal trampoline to the user address space.
pub fn map_trampoline(aspace: &mut AddrSpace) -> StarryResult {
    let signal_trampoline_paddr =
        virt_to_phys(starry_signal::arch::signal_trampoline_address().into());
    aspace.map_linear(
        crate::config::SIGNAL_TRAMPOLINE.into(),
        signal_trampoline_paddr,
        PAGE_SIZE_4K,
        MappingFlags::READ | MappingFlags::EXECUTE | MappingFlags::USER,
    )?;
    Ok(())
}



/// Map the elf file to the user address space.
///
/// # Arguments
/// - `uspace`: The address space of the user app.
/// - `elf`: The elf file.
///

/// Convert a virtual address to a file offset using PT_LOAD segments.
///
/// This function searches through the program headers to find which PT_LOAD
/// segment contains the given virtual address, then calculates the
/// corresponding file offset.
///

/// Apply relocations for static-pie binaries.
///






/// Load the user app to the user address space.
///
/// The executable is identified by an already-resolved [`Location`] — the
/// caller resolves and opens it once (mirroring Linux's `do_open_execat`,
/// which honors `AT_SYMLINK_NOFOLLOW` at that single lookup), and this never
/// re-resolves the main executable from its pathname. Interpreters reached
/// through a `.sh` redirect or a `#!` shebang are resolved here by path, which
/// is Linux's `open_exec(interp)` and legitimately follows symlinks.
///
/// # Arguments
/// - `uspace`: The address space of the user app.
/// - `loc`: The resolved executable to load.
/// - `path`: The pathname the executable was invoked as, used for the `.sh`
///   redirect and for the script name an interpreter receives in `argv`.
/// - `args`: The arguments of the user app.
/// - `envs`: The environment variables of the user app.
///
/// # Returns
/// - The entry point of the user app.
/// - The stack pointer of the user app.
/// Lends a personality the address space `exec` is building, so an image the
/// kernel does not parse itself is still mapped by the package that does.
struct ExecSpace<'a> {
    uspace: &'a mut AddrSpace,
    /// The file being loaded. An interpreter replaces it, so a loader never
    /// holds a file itself and there is no handle to invent.
    image: CachedFile,
    /// What the format asked to have kept, which for Linux is the auxiliary
    /// vector procfs publishes.
    metadata: Vec<(usize, usize)>,
}

impl<'a> ExecSpace<'a> {
    fn new(uspace: &'a mut AddrSpace, image: CachedFile) -> Self {
        Self {
            uspace,
            image,
            metadata: Vec::new(),
        }
    }
}

impl ax_binfmt::LoadEnv for ExecSpace<'_> {
    fn map_region(
        &mut self,
        va: u64,
        len: u64,
        prot: ax_binfmt::Prot,
        init: Option<&[u8]>,
    ) -> ax_binfmt::AbiResult<()> {
        let at = VirtAddr::from_usize(va as usize);
        let start = at.align_down_4k();
        let size = (at - start + len as usize).align_up_4k();
        let mut flags = MappingFlags::USER;
        if prot.contains(ax_binfmt::Prot::READ) {
            flags |= MappingFlags::READ;
        }
        if prot.contains(ax_binfmt::Prot::WRITE) {
            flags |= MappingFlags::WRITE | MappingFlags::READ;
        }
        if prot.contains(ax_binfmt::Prot::EXEC) {
            flags |= MappingFlags::EXECUTE;
        }
        (|| -> StarryResult<()> {
            self.uspace.map(
                start,
                size,
                flags,
                true,
                Backend::new_alloc(start, PAGE_SIZE_4K, "[image]"),
            )?;
            self.uspace.populate_area(start, size, flags)?;
            if let Some(init) = init {
                self.uspace.write(at, init)?;
            }
            Ok(())
        })()
        .map_err(|_| ax_binfmt::AbiError::MapFailed)
    }

    fn map_image(
        &mut self,
        va: u64,
        len: u64,
        prot: ax_binfmt::Prot,
        offset: u64,
        file_end: u64,
    ) -> ax_binfmt::AbiResult<()> {
        let cache = self.image.clone();
        let at = VirtAddr::from_usize(va as usize);
        let start = at.align_down_4k();
        let size = (at - start + len as usize).align_up_4k();
        // Copy-on-write over the page cache: the pages arrive as they are
        // touched, which is what makes a large image cheap to start.
        let backend = Backend::new_cow(
            at,
            PAGE_SIZE_4K,
            FileBackend::Cached(cache),
            offset,
            Some(file_end),
            false,
        );
        self.uspace
            .map(start, size, prot_flags(prot), false, backend)
            .map_err(|_| ax_binfmt::AbiError::MapFailed)
    }

    fn read_image(&mut self, at: u64, out: &mut [u8]) -> ax_binfmt::AbiResult<usize> {
        self.image
            .read_at(out, at)
            .map_err(|_| ax_binfmt::AbiError::MalformedImage)
    }

    fn interpret(&mut self, path: &str) -> ax_binfmt::AbiResult<()> {
        let loc = ax_fs_ng::vfs::current_fs_context()
            .lock()
            .resolve(path)
            .map_err(|_| ax_binfmt::AbiError::UnknownFormat)?;
        self.image =
            CachedFile::get_or_create(loc).map_err(|_| ax_binfmt::AbiError::UnknownFormat)?;
        Ok(())
    }

    fn reset(&mut self) -> ax_binfmt::AbiResult<()> {
        self.uspace.clear();
        (|| -> StarryResult<()> {
            map_trampoline(self.uspace)?;
            let top = VirtAddr::from_usize(crate::config::USER_STACK_TOP);
            let size = crate::config::USER_STACK_SIZE;
            let start = top - size;
            self.uspace.map(
                start,
                size,
                MappingFlags::READ | MappingFlags::WRITE | MappingFlags::USER,
                false,
                Backend::new_alloc(start, PAGE_SIZE_4K, "[stack]"),
            )?;
            self.uspace
                .populate_area(start, size, MappingFlags::READ | MappingFlags::WRITE)?;
            let heap = VirtAddr::from_usize(crate::config::USER_HEAP_BASE);
            self.uspace.map(
                heap,
                crate::config::USER_HEAP_SIZE,
                MappingFlags::READ | MappingFlags::WRITE | MappingFlags::USER,
                true,
                Backend::new_alloc(heap, PAGE_SIZE_4K, "[heap]"),
            )
        })()
        .map_err(|_| ax_binfmt::AbiError::MapFailed)
    }

    fn record_metadata(&mut self, pairs: &[(usize, usize)]) {
        self.metadata.extend_from_slice(pairs);
    }

    fn write(&mut self, va: u64, bytes: &[u8]) -> ax_binfmt::AbiResult<()> {
        self.uspace
            .write(VirtAddr::from_usize(va as usize), bytes)
            .map_err(|_| ax_binfmt::AbiError::MapFailed)
    }

    fn image_len(&self) -> u64 {
        self.image.location().len().unwrap_or(0)
    }

    fn mapped_end(&self) -> u64 {
        self.uspace
            .areas()
            .map(|area| area.end().as_usize() as u64)
            .max()
            .unwrap_or(crate::config::USER_SPACE_BASE as u64)
    }

    fn stack_top(&self) -> u64 {
        crate::config::USER_STACK_TOP as u64
    }

    fn cpu_capabilities(&self) -> u64 {
        ax_runtime::hal::cpu::cap::elf_hwcap() as u64
    }
}

/// The mapping flags a neutral protection asks for.
fn prot_flags(prot: ax_binfmt::Prot) -> MappingFlags {
    let mut flags = MappingFlags::USER;
    if prot.contains(ax_binfmt::Prot::READ) {
        flags |= MappingFlags::READ;
    }
    if prot.contains(ax_binfmt::Prot::WRITE) {
        flags |= MappingFlags::WRITE | MappingFlags::READ;
    }
    if prot.contains(ax_binfmt::Prot::EXEC) {
        flags |= MappingFlags::EXECUTE;
    }
    flags
}

pub fn load_user_app(
    uspace: &mut AddrSpace,
    loc: Location,
    path: &str,
    args: &[String],
    envs: &[String],
) -> StarryResult<(VirtAddr, VirtAddr, Vec<(usize, usize)>)> {
    validate_exec_arg_size(args, envs)?;

    load_user_app_with_depth(uspace, loc, path, args, envs, 0)
}

fn load_user_app_with_depth(
    uspace: &mut AddrSpace,
    loc: Location,
    path: &str,
    args: &[String],
    envs: &[String],
    interpreter_depth: usize,
) -> StarryResult<(VirtAddr, VirtAddr, Vec<(usize, usize)>)> {
    // `/proc/self/exe` is available in procfs; busybox can `readlink` it
    // to re-exec itself as a shell on ENOEXEC, provided the busybox build
    // includes that fallback (Alpine's prebuilt binary may not).
    if path.ends_with(".sh") {
        if interpreter_depth >= MAX_INTERPRETER_RECURSION {
            return Err(StarryError::FilesystemLoop);
        }
        let new_args: Vec<String> = iter::once("/bin/sh".to_owned())
            .chain(args.iter().cloned())
            .collect();
        let sh = ax_fs_ng::vfs::current_fs_context()
            .lock()
            .resolve("/bin/sh")?;
        return load_user_app_with_depth(
            uspace,
            sh,
            "/bin/sh",
            &new_args,
            envs,
            interpreter_depth + 1,
        );
    }

    // Every format goes through the registry, ELF included: the kernel reads
    // enough of the head to recognize it and to honour a shebang, and hands
    // the rest to whichever package claims it.
    let head = {
        let cache = CachedFile::get_or_create(loc.clone())?;
        let mut head = vec![0u8; 4096];
        let read = cache.read_at(&mut head[..], 0)?;
        head.truncate(read);
        head
    };

    if head.starts_with(b"#!") {
        if interpreter_depth >= MAX_INTERPRETER_RECURSION {
            return Err(StarryError::FilesystemLoop);
        }
        let line = &head[2..head.len().min(256)];
        let pos = line.iter().position(|c| *c == b'\n').unwrap_or(line.len());
        let line = core::str::from_utf8(&line[..pos]).map_err(|_| StarryError::InvalidInput)?;
        let new_args: Vec<String> = line
            .trim()
            .splitn(2, |c: char| c.is_ascii_whitespace())
            .map(|s| s.trim_ascii().to_owned())
            .chain(iter::once(path.to_owned()))
            .chain(args.iter().skip(1).cloned())
            .collect();
        // Open the interpreter by path, which is Linux's `open_exec(interp)`
        // and legitimately follows symlinks.
        let interp = ax_fs_ng::vfs::current_fs_context()
            .lock()
            .resolve(&new_args[0])?;
        return load_user_app_with_depth(
            uspace,
            interp,
            &new_args[0],
            &new_args,
            envs,
            interpreter_depth + 1,
        );
    }

    let format = ax_abi::dispatch(&head).map_err(|_| StarryError::InvalidExecutable)?;
    let arg_refs: Vec<&str> = args.iter().map(String::as_str).collect();
    let env_refs: Vec<&str> = envs.iter().map(String::as_str).collect();
    let mut space = ExecSpace::new(uspace, CachedFile::get_or_create(loc)?);
    let loaded = format
        .load(
            &ax_binfmt::LoadRequest {
                image: &head,
                load_base: crate::config::USER_SPACE_BASE as u64,
                args: &arg_refs,
                envs: &env_refs,
            },
            &mut space,
        )
        .map_err(|err| {
            warn!("exec {path}: {err}");
            match err {
                // A format claimed the image and found it broken. That is not
                // the same as nothing claiming it, and execve tells them apart:
                // only the latter falls back to running the file as a script.
                ax_binfmt::AbiError::MalformedImage
                | ax_binfmt::AbiError::Unsupported
                | ax_binfmt::AbiError::MissingLibrary => StarryError::MalformedExecutable,
                _ => StarryError::InvalidExecutable,
            }
        })?;
    let auxv = space.metadata;

    // From here the process speaks that ABI. Resolve which registered
    // implementation serves it once, now, so its traps are an index.
    let slot = ax_dispatch::slot_of(format.abi()).ok_or_else(|| {
        warn!("exec {path}: no package services the {:?} ABI", format.abi());
        StarryError::InvalidExecutable
    })?;
    // At boot the caller is still the kernel task and the process does not
    // exist yet; it starts out speaking the ABI its image was loaded with, so
    // there is nothing to record here.
    if let Some(thread) = ax_task::current().try_as_thread() {
        thread
            .proc_data
            .abi_slot
            .store(slot as u32 + 1, core::sync::atomic::Ordering::Relaxed);
    }

    // A format that laid out the initial stack itself reports where it left
    // the pointer; one that did not reports zero and takes the stack the host
    // prepared, as its top.
    let sp = match loaded.stack {
        0 => VirtAddr::from_usize(crate::config::USER_STACK_TOP),
        at => VirtAddr::from_usize(at as usize),
    };
    Ok((VirtAddr::from_usize(loaded.entry as usize), sp, auxv))
}
