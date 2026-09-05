//! The allocator behind `malloc` and its family.
//!
//! libSystem's allocator is user code on a real machine, and so is the memory
//! it hands out. Here the code is on this side of the trap but the memory -
//! and every word of bookkeeping - is still the program's own: a block carries
//! its size in a header just below what the caller is handed, and the head of
//! the free list lives in the synthesized library's private words. Nothing
//! about a process's heap is kept here, so a second process has a second heap
//! by construction and an `exec` forgets the first one for free.
//!
//! It is a first-fit free list over runs taken from the memory port, which is
//! what a small allocator is before anyone measures it. Three things it does
//! not do, all worth doing once a program runs long enough to care: runs are
//! never given back, neighbouring free blocks are never merged, and what is
//! left of a run when a request outgrows it is abandoned rather than put on
//! the list.

use ax_abi_port::{Host, MapRequest, MapSource, Prot, SysResult};

use crate::system::Library;

/// `ENOMEM`.
const ENOMEM: i32 = 12;
/// Every block starts on this boundary, which is what the C ABI asks of a
/// pointer that may hold any type.
const ALIGN: usize = 16;
/// A block's header: its whole size, then the next free block.
const HEADER: usize = 16;
/// How much address space a new run takes at least. A run is mapped once and
/// carved up many times, so this is the trade between wasted space and traps.
const RUN: usize = 1 << 20;
/// A block is only split when the remainder can hold a header and something.
const SPLIT: usize = HEADER + ALIGN;

/// Where the allocator keeps its three words, inside the library's private
/// area: the free list, and the bounds of the run being carved up.
const FREE_LIST: u64 = 0;
const NEXT: u64 = 8;
const END: u64 = 16;

/// Hand back `len` bytes, or zero if there is no room.
pub fn malloc(host: &dyn Host, at: &Library, len: usize) -> SysResult {
    // C says a request for nothing still answers with a pointer that can be
    // freed, so it is rounded up like any other. A length that cannot have a
    // header and its rounding added to it is one no allocator can satisfy,
    // and saying so is the only safe answer - wrapping would hand back a
    // block far smaller than the caller asked for.
    let Some(want) = len
        .max(1)
        .checked_add(HEADER + ALIGN - 1)
        .map(|room| room / ALIGN * ALIGN)
    else {
        return Err(ENOMEM);
    };
    if let Some(block) = take_free(host, at, want)? {
        return Ok(block as isize);
    }
    let block = carve(host, at, want)?;
    Ok(block as isize)
}

/// Give `addr` back. A null pointer is a request to do nothing, which is what
/// makes `free(NULL)` safe.
pub fn free(host: &dyn Host, at: &Library, addr: usize) -> SysResult {
    if addr == 0 {
        return Ok(0);
    }
    let block = addr - HEADER;
    let head = word(host, at, FREE_LIST)?;
    put(host, block as u64 + 8, head)?;
    put_private(host, at, FREE_LIST, block as u64)?;
    Ok(0)
}

/// Hand back `count * size` zeroed bytes.
pub fn calloc(host: &dyn Host, at: &Library, count: usize, size: usize) -> SysResult {
    let Some(len) = count.checked_mul(size) else {
        return Err(ENOMEM);
    };
    let addr = malloc(host, at, len)? as usize;
    if addr != 0 {
        zero(host, addr, len)?;
    }
    Ok(addr as isize)
}

/// Move `addr`'s contents into a block of `len` bytes.
pub fn realloc(host: &dyn Host, at: &Library, addr: usize, len: usize) -> SysResult {
    if addr == 0 {
        return malloc(host, at, len);
    }
    let had = read_word(host, (addr - HEADER) as u64)? as usize - HEADER;
    if had >= len {
        return Ok(addr as isize);
    }
    let moved = malloc(host, at, len)? as usize;
    if moved == 0 {
        return Ok(0);
    }
    copy(host, moved, addr, had)?;
    free(host, at, addr)?;
    Ok(moved as isize)
}

/// The first free block big enough, unlinked and split if there is enough
/// left over to be worth a header.
fn take_free(host: &dyn Host, at: &Library, want: usize) -> Result<Option<usize>, i32> {
    let mut previous: Option<u64> = None;
    let mut block = word(host, at, FREE_LIST)?;
    while block != 0 {
        let whole = read_word(host, block)? as usize;
        let next = read_word(host, block + 8)?;
        if whole >= want {
            match previous {
                Some(before) => put(host, before + 8, next)?,
                None => put_private(host, at, FREE_LIST, next)?,
            }
            if whole - want >= SPLIT {
                let rest = block + want as u64;
                put(host, rest, (whole - want) as u64)?;
                put(host, block, want as u64)?;
                free(host, at, rest as usize + HEADER)?;
            }
            return Ok(Some(block as usize + HEADER));
        }
        previous = Some(block);
        block = next;
    }
    Ok(None)
}

/// Take `want` bytes off the run being carved, mapping a new one first if
/// what is left will not cover it.
fn carve(host: &dyn Host, at: &Library, want: usize) -> Result<usize, i32> {
    let mut next = word(host, at, NEXT)? as usize;
    let mut end = word(host, at, END)? as usize;
    if next == 0 || end - next < want {
        let Some(len) = want.checked_next_multiple_of(RUN) else {
            return Err(ENOMEM);
        };
        let run = host.mem().ok_or(ENOMEM)?.map(&MapRequest {
            addr: 0,
            len,
            prot: Prot::READ | Prot::WRITE,
            fixed: false,
            shared: false,
            source: MapSource::Anonymous,
        })? as usize;
        next = run;
        end = run + len;
    }
    put(host, next as u64, want as u64)?;
    put_private(host, at, NEXT, (next + want) as u64)?;
    put_private(host, at, END, end as u64)?;
    Ok(next + HEADER)
}

/// One of the allocator's own words.
fn word(host: &dyn Host, at: &Library, which: u64) -> Result<u64, i32> {
    read_word(host, at.private() + which)
}

fn put_private(host: &dyn Host, at: &Library, which: u64, value: u64) -> Result<(), i32> {
    put(host, at.private() + which, value)
}

fn read_word(host: &dyn Host, addr: u64) -> Result<u64, i32> {
    let mut out = [0u8; 8];
    host.platform().read_user(addr as usize, &mut out)?;
    Ok(u64::from_le_bytes(out))
}

fn put(host: &dyn Host, addr: u64, value: u64) -> Result<(), i32> {
    host.platform()
        .write_user(addr as usize, &value.to_le_bytes())?;
    Ok(())
}

/// Fill `len` bytes at `addr` with zeroes, a chunk at a time so a large
/// request does not want a buffer its own size.
fn zero(host: &dyn Host, addr: usize, len: usize) -> Result<(), i32> {
    let empty = [0u8; 256];
    let mut done = 0;
    while done < len {
        let step = empty.len().min(len - done);
        host.platform().write_user(addr + done, &empty[..step])?;
        done += step;
    }
    Ok(())
}

/// Move `len` bytes from `from` to `to`, likewise.
fn copy(host: &dyn Host, to: usize, from: usize, len: usize) -> Result<(), i32> {
    let mut buf = [0u8; 256];
    let mut done = 0;
    while done < len {
        let step = buf.len().min(len - done);
        host.platform().read_user(from + done, &mut buf[..step])?;
        host.platform().write_user(to + done, &buf[..step])?;
        done += step;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use ax_abi_port::Platform;

    use super::*;
    use crate::testing::MockHost;

    /// A host with room for the library's own words, and the library that
    /// names them.
    fn ready() -> (MockHost, Library) {
        let host = MockHost::default();
        host.mem.borrow_mut().resize(0x1_0000, 0);
        (host, Library::new(0x8000))
    }

    fn read(host: &MockHost, at: usize, len: usize) -> alloc::vec::Vec<u8> {
        host.mem.borrow()[at..at + len].to_vec()
    }

    #[test]
    fn what_is_handed_out_is_aligned_and_does_not_overlap() {
        let (host, at) = ready();
        let first = malloc(&host, &at, 10).unwrap() as usize;
        let second = malloc(&host, &at, 10).unwrap() as usize;
        assert_ne!(first, 0);
        assert_eq!(first % ALIGN, 0, "a pointer any type can live at");
        assert_eq!(second % ALIGN, 0);
        assert!(second >= first + 10, "{first:#x} and {second:#x} overlap");
        // What the caller got is writable and stays written.
        host.write_user(first, b"0123456789").unwrap();
        assert_eq!(read(&host, first, 10), b"0123456789");
        assert_eq!(read(&host, second, 10), [0; 10], "and separate");
    }

    #[test]
    fn a_freed_block_is_handed_out_again() {
        let (host, at) = ready();
        let first = malloc(&host, &at, 64).unwrap() as usize;
        free(&host, &at, first).unwrap();
        let again = malloc(&host, &at, 64).unwrap() as usize;
        assert_eq!(again, first, "the free list is what a second request finds");
    }

    #[test]
    fn a_free_block_is_split_when_the_rest_is_worth_keeping() {
        let (host, at) = ready();
        let big = malloc(&host, &at, 512).unwrap() as usize;
        free(&host, &at, big).unwrap();
        let small = malloc(&host, &at, 16).unwrap() as usize;
        assert_eq!(small, big, "it takes the front of the block it found");
        // The tail went back on the list rather than being lost with it.
        let rest = malloc(&host, &at, 64).unwrap() as usize;
        assert!(
            rest > small && rest < small + 512,
            "{rest:#x} came from the tail"
        );
    }

    #[test]
    fn freeing_nothing_is_allowed_and_does_nothing() {
        let (host, at) = ready();
        assert_eq!(free(&host, &at, 0), Ok(0));
        let after = malloc(&host, &at, 8).unwrap() as usize;
        assert_ne!(after, 0);
    }

    #[test]
    fn calloc_hands_back_zeroes_even_over_reused_memory() {
        let (host, at) = ready();
        let dirty = malloc(&host, &at, 64).unwrap() as usize;
        host.write_user(dirty, &[0xAB; 64]).unwrap();
        free(&host, &at, dirty).unwrap();
        let clean = calloc(&host, &at, 8, 8).unwrap() as usize;
        assert_eq!(clean, dirty, "the same memory came back");
        assert_eq!(read(&host, clean, 64), [0; 64], "and it was cleared");
    }

    #[test]
    fn calloc_refuses_a_product_that_does_not_fit() {
        let (host, at) = ready();
        assert_eq!(calloc(&host, &at, usize::MAX, 2), Err(ENOMEM));
    }

    #[test]
    fn realloc_keeps_the_contents_and_grows() {
        let (host, at) = ready();
        let small = malloc(&host, &at, 16).unwrap() as usize;
        host.write_user(small, b"keep me around!!").unwrap();
        let big = realloc(&host, &at, small, 128).unwrap() as usize;
        assert_ne!(big, small, "a bigger block is elsewhere");
        assert_eq!(read(&host, big, 16), b"keep me around!!");
        // Shrinking, and a null pointer, are both defined the other way.
        assert_eq!(realloc(&host, &at, big, 8).unwrap() as usize, big);
        assert_ne!(realloc(&host, &at, 0, 32).unwrap(), 0);
    }

    #[test]
    fn a_request_for_nothing_still_answers_with_a_pointer() {
        let (host, at) = ready();
        let empty = malloc(&host, &at, 0).unwrap() as usize;
        assert_ne!(empty, 0);
        assert_eq!(free(&host, &at, empty), Ok(0));
    }

    #[test]
    fn a_length_that_cannot_be_rounded_up_is_refused_rather_than_wrapped() {
        let (host, at) = ready();
        assert_eq!(malloc(&host, &at, usize::MAX), Err(ENOMEM));
        assert_eq!(malloc(&host, &at, usize::MAX - 8), Err(ENOMEM));
        // And one just inside it is still asked for honestly, which the run
        // it needs is what refuses.
        assert!(malloc(&host, &at, usize::MAX / 2).is_err());
    }

    #[test]
    fn a_request_bigger_than_a_run_gets_a_run_of_its_own() {
        let (host, at) = ready();
        let huge = malloc(&host, &at, RUN * 2).unwrap() as usize;
        assert_ne!(huge, 0);
        assert!(host.mapped.borrow().unwrap().len >= RUN * 2);
        host.write_user(huge + RUN, b"reaches").unwrap();
        assert_eq!(read(&host, huge + RUN, 7), b"reaches");
    }
}
