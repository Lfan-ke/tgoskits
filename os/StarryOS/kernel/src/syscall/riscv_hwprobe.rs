//! `riscv_hwprobe(2)` — query supported RISC-V hardware extensions.
//!
//! Syscall signature (Linux 6.4+):
//!
//! ```c
//! long riscv_hwprobe(struct riscv_hwprobe *pairs,
//!                    size_t pair_count, size_t cpu_count,
//!                    cpu_set_t *cpus, unsigned int flags);
//!
//! struct riscv_hwprobe {
//!     __s64 key;
//!     __u64 value;
//! };
//! ```
//!
//! The kernel iterates the `pairs` array. For every recognised key it fills
//! in `value`. For unrecognised keys it sets `pair.key = -1` and leaves the
//! value at zero (per the man page / kernel uABI). The return value is 0 on
//! success.
//!
//! This is a minimal stub for qemu-virt riscv64. We advertise the IMA base
//! behaviour with no multi-letter extensions and fast misaligned access so
//! Python / portable-atomic / numpy probes don't crash with ENOSYS.

use alloc::{vec, vec::Vec};
use core::mem::MaybeUninit;

use ax_errno::{AxError, AxResult};
use starry_vm::{vm_read_slice, vm_write_slice};

/// `struct riscv_hwprobe` — see `arch/riscv/include/uapi/asm/hwprobe.h`.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
struct RiscvHwprobe {
    key: i64,
    value: u64,
}

// Keys (see Linux `Documentation/arch/riscv/hwprobe.rst`).
const RISCV_HWPROBE_KEY_MVENDORID: i64 = 0;
const RISCV_HWPROBE_KEY_MARCHID: i64 = 1;
const RISCV_HWPROBE_KEY_MIMPID: i64 = 2;
const RISCV_HWPROBE_KEY_BASE_BEHAVIOR: i64 = 3;
const RISCV_HWPROBE_KEY_IMA_EXT_0: i64 = 4;
const RISCV_HWPROBE_KEY_CPUPERF_0: i64 = 5;
const RISCV_HWPROBE_KEY_ZICBOZ_BLOCK_SIZE: i64 = 6;
const RISCV_HWPROBE_KEY_HIGHEST_VIRT_ADDRESS: i64 = 7;
const RISCV_HWPROBE_KEY_TIME_CSR_FREQ: i64 = 8;
const RISCV_HWPROBE_KEY_MISALIGNED_SCALAR_PERF: i64 = 9;
const RISCV_HWPROBE_KEY_MISALIGNED_VECTOR_PERF: i64 = 10;
const RISCV_HWPROBE_KEY_VENDOR_EXT_THEAD_0: i64 = 11;

// Values.
/// rv64 IMA + Zicsr + Zifencei + Zicntr + Zihpm.
const RISCV_HWPROBE_BASE_BEHAVIOR_IMA: u64 = 1 << 0;

/// `RISCV_HWPROBE_KEY_CPUPERF_0` legacy field — kept as "fast unaligned"
/// (value 4) for backward compatibility with userspace that still reads it.
const RISCV_HWPROBE_MISALIGNED_FAST: u64 = 4;
/// Scalar misaligned performance (new key 9).
const RISCV_HWPROBE_MISALIGNED_SCALAR_FAST: u64 = 3;

/// Stub implementation of `riscv_hwprobe(2)`.
///
/// Arguments mirror the kernel ABI: `pairs` is a pointer to a userspace array
/// of `pair_count` `struct riscv_hwprobe` entries. The `cpu_count`, `cpus`
/// and `flags` arguments describe which CPU set the user wants to probe — on
/// the single-CPU qemu virt platform we ignore them and answer for the only
/// hart we know about.
pub fn sys_riscv_hwprobe(
    pairs: *mut u8,
    pair_count: usize,
    _cpu_count: usize,
    _cpus: *mut u8,
    _flags: u32,
) -> AxResult<isize> {
    debug!("sys_riscv_hwprobe <= pairs={pairs:?} pair_count={pair_count}");

    if pair_count == 0 {
        return Ok(0);
    }
    if pairs.is_null() {
        return Err(AxError::BadAddress);
    }

    let typed_ptr = pairs as *mut RiscvHwprobe;

    // Read the requested pairs from userspace so we can inspect `key`.
    let mut buf: Vec<MaybeUninit<RiscvHwprobe>> = vec![MaybeUninit::uninit(); pair_count];
    vm_read_slice(typed_ptr, &mut buf)?;
    // SAFETY: `vm_read_slice` filled every slot with bytes from user memory.
    let mut pairs_vec: Vec<RiscvHwprobe> = buf
        .into_iter()
        .map(|slot| unsafe { slot.assume_init() })
        .collect();

    for p in pairs_vec.iter_mut() {
        match p.key {
            RISCV_HWPROBE_KEY_MVENDORID
            | RISCV_HWPROBE_KEY_MARCHID
            | RISCV_HWPROBE_KEY_MIMPID => {
                // Unknown hardware identifiers — Linux reports 0 on qemu virt too.
                p.value = 0;
            }
            RISCV_HWPROBE_KEY_BASE_BEHAVIOR => {
                p.value = RISCV_HWPROBE_BASE_BEHAVIOR_IMA;
            }
            RISCV_HWPROBE_KEY_IMA_EXT_0 => {
                // Conservatively report no multi-letter extensions. Userspace
                // (numpy, portable-atomic, jupyter probes) only needs a valid
                // answer here, not an accurate one.
                p.value = 0;
            }
            RISCV_HWPROBE_KEY_CPUPERF_0 => {
                p.value = RISCV_HWPROBE_MISALIGNED_FAST;
            }
            RISCV_HWPROBE_KEY_MISALIGNED_SCALAR_PERF => {
                p.value = RISCV_HWPROBE_MISALIGNED_SCALAR_FAST;
            }
            RISCV_HWPROBE_KEY_MISALIGNED_VECTOR_PERF => {
                // No vector unit in qemu virt by default → "unsupported" (0).
                p.value = 0;
            }
            RISCV_HWPROBE_KEY_ZICBOZ_BLOCK_SIZE
            | RISCV_HWPROBE_KEY_HIGHEST_VIRT_ADDRESS
            | RISCV_HWPROBE_KEY_TIME_CSR_FREQ
            | RISCV_HWPROBE_KEY_VENDOR_EXT_THEAD_0 => {
                p.value = 0;
            }
            _ => {
                // Per the man page: "If the kernel does not recognise a key,
                // it sets pair.key to -1 and pair.value to 0."
                p.key = -1;
                p.value = 0;
            }
        }
    }

    vm_write_slice(typed_ptr, &pairs_vec)?;
    Ok(0)
}
