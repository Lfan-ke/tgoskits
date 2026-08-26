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
/// `TEB.ProcessEnvironmentBlock` - pointer to the PEB (`gs:[0x60]`).
pub const TEB_PEB: usize = 0x60;
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
/// Bytes reserved for the PEB.
pub const PEB_SIZE: usize = 0x400;

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
