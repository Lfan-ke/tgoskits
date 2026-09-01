//! Minimal TEB and PEB images for a loaded NT process (x86-64).
//!
//! ntdll reaches the Thread Environment Block through `gs:[0x30]` and, from it,
//! the Process Environment Block; a NATIVE image cannot start until both exist
//! with a few self-referential fields set. This module lays those two blocks out
//! in memory. The field offsets are the stable x64 layout that ntdll, Wine and
//! WSL depend on (`ntdll` `RtlGetCurrentPeb`, ReactOS `ndk/pstypes.h`); only the
//! load-bearing early fields are populated - the loader table and process
//! parameters are filled once syscalls run.

use alloc::{vec, vec::Vec};

// TEB field offsets (x86-64). The TEB begins with an NT_TIB.
/// `NT_TIB.StackBase` - top of the initial user stack.
pub const TEB_STACK_BASE: usize = 0x08;
/// `NT_TIB.StackLimit` - bottom (guard end) of the initial user stack.
pub const TEB_STACK_LIMIT: usize = 0x10;
/// `NT_TIB.Self` - the TEB's own virtual address (ntdll reads `gs:[0x30]`).
pub const TEB_SELF: usize = 0x30;
/// `TEB.ThreadLocalStoragePointer` - the array of this thread's TLS blocks,
/// one per module with a TLS directory, indexed by the slot the loader wrote
/// into that module's `AddressOfIndex` (`gs:[0x58]`; Wine marks it `02c/0058`).
pub const TEB_TLS_POINTER: usize = 0x58;
/// `TEB.ProcessEnvironmentBlock` - pointer to the PEB (`gs:[0x60]`).
pub const TEB_PEB: usize = 0x60;
/// `TEB.LastErrorValue` - the `ULONG` `GetLastError` reports. Wine's
/// `include/winternl.h` marks the field `034/0068`, the 32- and 64-bit offsets.
pub const TEB_LAST_ERROR: usize = 0x68;
/// Bytes reserved for the TEB; larger than the fields used so later phases can
/// populate more without moving the block.
pub const TEB_SIZE: usize = 0x1800;

// PEB field offsets (x86-64).
/// `PEB.BeingDebugged`.
pub const PEB_BEING_DEBUGGED: usize = 0x02;
/// `PEB.ImageBaseAddress` - where the main image was mapped.
pub const PEB_IMAGE_BASE: usize = 0x10;
/// `PEB.Ldr` - pointer to the loader data (populated once modules load).
pub const PEB_LDR: usize = 0x18;
/// `PEB.ProcessParameters` - command line, environment, std handles.
pub const PEB_PROCESS_PARAMS: usize = 0x20;
/// `PEB.ProcessHeap` - the heap `GetProcessHeap` answers with.
pub const PEB_PROCESS_HEAP: usize = 0x30;
/// `PEB.TlsBitmap` - pointer to the `RTL_BITMAP` over [`PEB_TLS_BITMAP_BITS`].
pub const PEB_TLS_BITMAP: usize = 0x78;
/// `PEB.TlsBitmapBits` - the 64 bits `TlsAlloc` allocates from.
pub const PEB_TLS_BITMAP_BITS: usize = 0x80;
/// `PEB.NumberOfProcessors`.
pub const PEB_NUMBER_OF_PROCESSORS: usize = 0xB8;
/// `PEB.OSMajorVersion`, and the three words after it: minor, build, platform.
pub const PEB_OS_MAJOR: usize = 0x118;
/// Past the real PEB, which ends near 0x7c8: the `RTL_BITMAP` the TLS bitmap
/// pointer names, and the words kernelbase keeps in its own data on Windows -
/// the pointer cookie and the top-level exception filter. Kept in the same
/// page so every per-process word is reachable from the TEB.
pub const PEB_PRIVATE: usize = 0xF00;
/// Bytes reserved for the PEB: the page it occupies.
pub const PEB_SIZE: usize = 0x1000;

/// `TEB.TlsSlots[64]` (`e10/1480`), what `TlsGetValue` reads for a small index.
pub const TEB_TLS_SLOTS: usize = 0x1480;
/// `TEB.TlsExpansionSlots` (`f94/1780`): the pointer to the next 1024 slots.
pub const TEB_TLS_EXPANSION: usize = 0x1780;

// PEB_LDR_DATA (x86-64): the three module lists the loader publishes.
/// `PEB_LDR_DATA.InLoadOrderModuleList`.
pub const LDR_IN_LOAD_ORDER: usize = 0x10;
/// `PEB_LDR_DATA.InMemoryOrderModuleList`.
pub const LDR_IN_MEMORY_ORDER: usize = 0x20;
/// `PEB_LDR_DATA.InInitializationOrderModuleList`.
pub const LDR_IN_INIT_ORDER: usize = 0x30;
/// Bytes a `PEB_LDR_DATA` occupies, rounded to a paragraph.
pub const LDR_DATA_SIZE: usize = 0x60;

// LDR_DATA_TABLE_ENTRY (x86-64). Only the front, which every reader agrees on,
// is laid out; the entry is padded so later fields have room.
/// `InLoadOrderLinks`, `InMemoryOrderLinks`, `InInitializationOrderLinks`.
pub const LDR_LOAD_LINKS: usize = 0x00;
pub const LDR_MEMORY_LINKS: usize = 0x10;
pub const LDR_INIT_LINKS: usize = 0x20;
/// `DllBase`, `EntryPoint`, `SizeOfImage`.
pub const LDR_DLL_BASE: usize = 0x30;
pub const LDR_ENTRY_POINT: usize = 0x38;
pub const LDR_SIZE_OF_IMAGE: usize = 0x40;
/// `FullDllName` and `BaseDllName`, each a `UNICODE_STRING`.
pub const LDR_FULL_NAME: usize = 0x48;
pub const LDR_BASE_NAME: usize = 0x58;
/// `Flags`, `LoadCount`, `TlsIndex`.
pub const LDR_FLAGS: usize = 0x68;
pub const LDR_LOAD_COUNT: usize = 0x6C;
pub const LDR_TLS_INDEX: usize = 0x6E;
/// Bytes reserved per entry.
pub const LDR_ENTRY_SIZE: usize = 0x120;

/// Where a process's control blocks live in its address space, plus the initial
/// stack bounds, so [`build`] can write the self-referential pointers ntdll
/// reads through `gs`.
#[derive(Debug, Clone, Copy)]
pub struct BlockLayout {
    /// Virtual address the TEB will be mapped at.
    pub teb_va: u64,
    /// Virtual address the PEB will be mapped at.
    pub peb_va: u64,
    /// Base address the main image was mapped at.
    pub image_base: u64,
    /// Top of the initial user stack.
    pub stack_base: u64,
    /// Bottom of the initial user stack.
    pub stack_limit: u64,
}

/// Build the TEB and PEB byte images to map at `layout.teb_va` and
/// `layout.peb_va`. The returned buffers are zero except for the load-bearing
/// fields, which is what a fresh NATIVE process needs to reach ntdll's init.
pub fn build(layout: &BlockLayout) -> (Vec<u8>, Vec<u8>) {
    let mut teb = vec![0u8; TEB_SIZE];
    put_u64(&mut teb, TEB_STACK_BASE, layout.stack_base);
    put_u64(&mut teb, TEB_STACK_LIMIT, layout.stack_limit);
    put_u64(&mut teb, TEB_SELF, layout.teb_va);
    put_u64(&mut teb, TEB_PEB, layout.peb_va);

    let mut peb = vec![0u8; PEB_SIZE];
    put_u64(&mut peb, PEB_IMAGE_BASE, layout.image_base);

    (teb, peb)
}

fn put_u64(block: &mut [u8], off: usize, value: u64) {
    block[off..off + 8].copy_from_slice(&value.to_le_bytes());
}

fn put_u32(block: &mut [u8], off: usize, value: u32) {
    block[off..off + 4].copy_from_slice(&value.to_le_bytes());
}

fn put_u16(block: &mut [u8], off: usize, value: u16) {
    block[off..off + 2].copy_from_slice(&value.to_le_bytes());
}

/// Fill in what the PEB says about the process once the loader knows it: the
/// module list, the heap, the TLS bitmap, and the machine and OS a program
/// asks about. The version is Windows 10 (10.0.19041), the oldest a current
/// C runtime and CPython accept, and the machine has one processor, which is
/// also what makes a critical section never spin.
pub fn fill_peb(peb: &mut [u8], peb_va: u64, ldr_va: u64, heap_va: u64) {
    put_u64(peb, PEB_LDR, ldr_va);
    put_u64(peb, PEB_PROCESS_HEAP, heap_va);
    // RTL_BITMAP { SizeOfBitMap, Buffer } in the private area, over the bits.
    put_u64(peb, PEB_TLS_BITMAP, peb_va + PEB_PRIVATE as u64);
    put_u32(peb, PEB_PRIVATE, 64);
    put_u64(peb, PEB_PRIVATE + 8, peb_va + PEB_TLS_BITMAP_BITS as u64);
    put_u32(peb, PEB_NUMBER_OF_PROCESSORS, 1);
    put_u32(peb, PEB_OS_MAJOR, 10);
    put_u32(peb, PEB_OS_MAJOR + 4, 0);
    put_u32(peb, PEB_OS_MAJOR + 8, 19041);
    put_u32(peb, PEB_OS_MAJOR + 12, 2); // VER_PLATFORM_WIN32_NT
}

/// One module as the loader list describes it.
#[derive(Debug, Clone, Copy)]
pub struct LdrModule<'a> {
    pub base: u64,
    /// The entry point, or zero for a module without one.
    pub entry: u64,
    pub size: u64,
    /// Where it was loaded from, and the name imports know it by.
    pub path: &'a str,
    pub name: &'a str,
    /// The TLS slot the module was given, or -1 for none.
    pub tls_index: i16,
}

/// The `PEB_LDR_DATA` and one `LDR_DATA_TABLE_ENTRY` per module, to map at
/// `at`, with the names as UTF-16 after the entries. The load and memory
/// order lists hold every module as given; the initialization order list
/// holds `init_order`, which is what `process_attach` produced.
pub fn build_ldr(modules: &[LdrModule<'_>], init_order: &[usize], at: u64) -> Vec<u8> {
    let entries_at = LDR_DATA_SIZE;
    let strings_at = entries_at + modules.len() * LDR_ENTRY_SIZE;
    let mut out = vec![0u8; strings_at];
    put_u32(&mut out, 0, LDR_DATA_SIZE as u32); // Length
    out[4] = 1; // Initialized

    let entry_va = |i: usize| at + (entries_at + i * LDR_ENTRY_SIZE) as u64;
    // A LIST_ENTRY ring through `link` of each listed entry, from the head in
    // the PEB_LDR_DATA; an empty list points the head at itself.
    let mut ring = |head: usize, link: usize, order: &[usize]| {
        let head_va = at + head as u64;
        let mut prev = (head, head_va);
        for &i in order {
            let here = entries_at + i * LDR_ENTRY_SIZE + link;
            let here_va = entry_va(i) + link as u64;
            put_u64(&mut out, prev.0, here_va); // prev.Flink
            put_u64(&mut out, here + 8, prev.1); // here.Blink
            prev = (here, here_va);
        }
        put_u64(&mut out, prev.0, head_va);
        put_u64(&mut out, head + 8, prev.1);
    };
    let all: Vec<usize> = (0..modules.len()).collect();
    ring(LDR_IN_LOAD_ORDER, LDR_LOAD_LINKS, &all);
    ring(LDR_IN_MEMORY_ORDER, LDR_MEMORY_LINKS, &all);
    ring(LDR_IN_INIT_ORDER, LDR_INIT_LINKS, init_order);

    for (i, module) in modules.iter().enumerate() {
        let e = entries_at + i * LDR_ENTRY_SIZE;
        put_u64(&mut out, e + LDR_DLL_BASE, module.base);
        put_u64(&mut out, e + LDR_ENTRY_POINT, module.entry);
        put_u32(&mut out, e + LDR_SIZE_OF_IMAGE, module.size as u32);
        for (field, text) in [(LDR_FULL_NAME, module.path), (LDR_BASE_NAME, module.name)] {
            let start = out.len();
            for unit in text.encode_utf16() {
                out.extend_from_slice(&unit.to_le_bytes());
            }
            let len = (out.len() - start) as u16;
            out.extend_from_slice(&[0, 0]);
            put_u16(&mut out, e + field, len);
            put_u16(&mut out, e + field + 2, len + 2);
            put_u64(&mut out, e + field + 8, at + start as u64);
        }
        // LDRP_IMAGE_DLL for a library; a pinned load count, as the loader
        // gives a module the program imports.
        put_u32(&mut out, e + LDR_FLAGS, if i == 0 { 0 } else { 0x4 });
        put_u16(&mut out, e + LDR_LOAD_COUNT, u16::MAX);
        put_u16(&mut out, e + LDR_TLS_INDEX, module.tls_index as u16);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn read_u64(block: &[u8], off: usize) -> u64 {
        u64::from_le_bytes(block[off..off + 8].try_into().unwrap())
    }

    #[test]
    fn teb_carries_self_peb_and_stack_pointers() {
        let layout = BlockLayout {
            teb_va: 0x7FFF_0000_0000,
            peb_va: 0x7FFE_0000_0000,
            image_base: 0x1_4000_0000,
            stack_base: 0x10_0000,
            stack_limit: 0x0E_0000,
        };
        let (teb, peb) = build(&layout);
        assert_eq!(teb.len(), TEB_SIZE);
        assert_eq!(read_u64(&teb, TEB_SELF), layout.teb_va);
        assert_eq!(read_u64(&teb, TEB_PEB), layout.peb_va);
        assert_eq!(read_u64(&teb, TEB_STACK_BASE), layout.stack_base);
        assert_eq!(read_u64(&teb, TEB_STACK_LIMIT), layout.stack_limit);
        assert_eq!(read_u64(&peb, PEB_IMAGE_BASE), layout.image_base);
    }

    #[test]
    fn unset_fields_are_zero() {
        let (_, peb) = build(&BlockLayout {
            teb_va: 0x1000,
            peb_va: 0x2000,
            image_base: 0x1_4000_0000,
            stack_base: 0x8000,
            stack_limit: 0x4000,
        });
        // Ldr and ProcessParameters are populated in a later phase.
        assert_eq!(read_u64(&peb, PEB_LDR), 0);
        assert_eq!(read_u64(&peb, PEB_PROCESS_PARAMS), 0);
        assert_eq!(peb[PEB_BEING_DEBUGGED], 0);
    }
}
