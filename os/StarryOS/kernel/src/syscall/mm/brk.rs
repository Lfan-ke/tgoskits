use ax_memory_addr::{PAGE_SIZE_4K, VirtAddr, align_up_4k};
use ax_runtime::hal::paging::MappingFlags;
use ax_task::current;
use linux_raw_sys::general::RLIMIT_DATA;

use crate::{
    StarryError, StarryResult,
    config::{USER_HEAP_BASE, USER_HEAP_SIZE, USER_HEAP_SIZE_MAX},
    mm::Backend,
    task::AsThread,
};

/// The program break as it stands.
pub(crate) fn heap_top() -> usize {
    current().as_thread().proc_data.get_heap_top() as usize
}

/// Move the program break to `addr`, mapping or unmapping to match. Errors when
/// the address is outside the heap window, past `RLIMIT_DATA`, or unmappable.
pub(crate) fn set_heap_top(addr: usize) -> StarryResult<()> {
    let curr = current();
    let proc_data = &curr.as_thread().proc_data;
    let current_top = proc_data.get_heap_top() as usize;

    // Check address is within valid heap range
    if !(USER_HEAP_BASE..=USER_HEAP_BASE + USER_HEAP_SIZE_MAX).contains(&addr) {
        return Err(StarryError::InvalidInput);
    }

    // Check RLIMIT_DATA: Linux limits heap expansion by RLIMIT_DATA.
    // The limit applies to (new_brk - start_brk) + (end_data - start_data).
    // Since we don't have end_data - start_data, we approximate by checking
    // (addr - USER_HEAP_BASE) against the soft limit.
    // RLIM_INFINITY (u64::MAX) means unlimited.
    let rlimit_data = proc_data.rlim.read()[RLIMIT_DATA].current;
    if rlimit_data != u64::MAX {
        let heap_size = addr.saturating_sub(USER_HEAP_BASE);
        if heap_size > rlimit_data as usize {
            return Err(StarryError::InvalidInput);
        }
    }

    let new_top_aligned = align_up_4k(addr);
    let current_top_aligned = align_up_4k(current_top);
    // Initial heap region end address (already mapped during ELF loading)
    let initial_heap_end = USER_HEAP_BASE + USER_HEAP_SIZE;

    // Only map new pages when expanding beyond already mapped region
    // Expansion start should be the greater of initial_heap_end and current_top_aligned
    if new_top_aligned > current_top_aligned {
        let expand_start = VirtAddr::from(initial_heap_end.max(current_top_aligned));
        let expand_size = new_top_aligned.saturating_sub(expand_start.as_usize());

        if expand_size > 0 {
            let aspace_arc = proc_data.aspace();
            let mut aspace = aspace_arc.lock();
            if aspace
                .map(
                    expand_start,
                    expand_size,
                    MappingFlags::READ | MappingFlags::WRITE | MappingFlags::USER,
                    false,
                    Backend::new_alloc(expand_start, PAGE_SIZE_4K, "[heap]"),
                )
                .is_err()
            {
                return Err(StarryError::InvalidInput);
            }
            drop(aspace);
        }
    } else if new_top_aligned < current_top_aligned {
        // Only unmap pages beyond the initially mapped heap region.
        let shrink_start = VirtAddr::from(initial_heap_end.max(new_top_aligned));
        let shrink_size = current_top_aligned.saturating_sub(shrink_start.as_usize());

        if shrink_size > 0
            && proc_data
                .aspace()
                .lock()
                .unmap(shrink_start, shrink_size)
                .is_err()
        {
            return Err(StarryError::InvalidInput);
        }
    }

    proc_data.set_heap_top(addr);
    Ok(())
}

pub fn sys_brk(addr: usize) -> StarryResult<isize> {
    let current_top = heap_top();
    // brk(0) queries, and a refused move reports the break that still stands
    // rather than an error.
    if addr == 0 {
        return Ok(current_top as isize);
    }
    Ok(set_heap_top(addr).map_or(current_top as isize, |()| addr as isize))
}
