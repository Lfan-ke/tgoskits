//! The calling program's memory, in the shapes a C library reads and writes.
//!
//! Every body behind a libSystem stub runs on the far side of a trap, so what
//! the C original does with a pointer becomes a read or a write through the
//! host here. These are the few shapes that recur: a word, a run of bytes, a
//! terminated string.

use alloc::vec::Vec;

use ax_abi_port::Host;

/// `EFAULT`.
pub const EFAULT: i32 = 14;

/// How far a walk for a terminator goes before the string is called
/// unterminated, which is what a corrupted pointer looks like.
const TEXT_LIMIT: usize = 1 << 20;

/// The page a read is kept inside, so a string that ends just short of an
/// unmapped page is still read in full.
const PAGE: usize = 4096;

pub fn bytes(host: &dyn Host, at: usize, len: usize) -> Result<Vec<u8>, i32> {
    let mut out = alloc::vec![0u8; len];
    if len != 0 {
        host.platform().read_user(at, &mut out)?;
    }
    Ok(out)
}

pub fn put(host: &dyn Host, at: usize, data: &[u8]) -> Result<(), i32> {
    if !data.is_empty() {
        host.platform().write_user(at, data)?;
    }
    Ok(())
}

pub fn u64_at(host: &dyn Host, at: usize) -> Result<u64, i32> {
    let mut word = [0u8; 8];
    host.platform().read_user(at, &mut word)?;
    Ok(u64::from_le_bytes(word))
}

pub fn u32_at(host: &dyn Host, at: usize) -> Result<u32, i32> {
    let mut word = [0u8; 4];
    host.platform().read_user(at, &mut word)?;
    Ok(u32::from_le_bytes(word))
}

pub fn i32_at(host: &dyn Host, at: usize) -> Result<i32, i32> {
    Ok(u32_at(host, at)? as i32)
}

pub fn put_u64(host: &dyn Host, at: usize, value: u64) -> Result<(), i32> {
    put(host, at, &value.to_le_bytes())
}

pub fn put_u32(host: &dyn Host, at: usize, value: u32) -> Result<(), i32> {
    put(host, at, &value.to_le_bytes())
}

pub fn put_i32(host: &dyn Host, at: usize, value: i32) -> Result<(), i32> {
    put(host, at, &value.to_le_bytes())
}

/// The string at `at`, without its terminator.
pub fn cstr(host: &dyn Host, at: usize) -> Result<Vec<u8>, i32> {
    let mut out = Vec::new();
    let mut at = at;
    while out.len() < TEXT_LIMIT {
        let room = PAGE - (at % PAGE);
        let mut chunk = [0u8; PAGE];
        host.platform().read_user(at, &mut chunk[..room])?;
        match chunk[..room].iter().position(|byte| *byte == 0) {
            Some(end) => {
                out.extend_from_slice(&chunk[..end]);
                return Ok(out);
            }
            None => {
                out.extend_from_slice(&chunk[..room]);
                at += room;
            }
        }
    }
    Err(EFAULT)
}

/// The wide string at `at`, without its terminator. A `wchar_t` is four bytes
/// on Darwin.
pub fn wstr(host: &dyn Host, at: usize) -> Result<Vec<u32>, i32> {
    let mut out = Vec::new();
    let mut at = at;
    while out.len() < TEXT_LIMIT {
        let room = (PAGE - (at % PAGE)) & !3;
        let room = if room == 0 { 4 } else { room };
        let chunk = bytes(host, at, room)?;
        for word in chunk.as_chunks::<4>().0 {
            let value = u32::from_le_bytes(*word);
            if value == 0 {
                return Ok(out);
            }
            out.push(value);
        }
        at += room;
    }
    Err(EFAULT)
}

/// `text` and its terminator.
pub fn put_cstr(host: &dyn Host, at: usize, text: &[u8]) -> Result<(), i32> {
    put(host, at, text)?;
    put(host, at + text.len(), &[0])
}

/// The string at `at` as a path or a name, which has to be UTF-8 for the host
/// to resolve it.
pub fn name(host: &dyn Host, at: usize) -> Result<alloc::string::String, i32> {
    alloc::string::String::from_utf8(cstr(host, at)?).map_err(|_| 22)
}
