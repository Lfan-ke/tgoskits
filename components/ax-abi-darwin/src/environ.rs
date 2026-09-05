//! Changing the environment.
//!
//! `environ` starts out as the run of pointers the kernel left on the stack,
//! which is exactly as long as the environment the program was given and has
//! nowhere to put another entry. So the first change moves it: the array is
//! copied to the heap with room to spare and `environ` is pointed at the copy,
//! which is what a C library does and why `environ` is documented as a
//! variable a program may read but should not assume it can extend.
//!
//! An entry that is replaced leaves its old string behind. Freeing it would be
//! wrong: a caller is allowed to still be holding what `getenv` handed back.

use ax_abi_port::{Host, SysResult};

use crate::system::{Library, PRIVATE_ENVIRON_ROOM};

/// How many entries a walk reads before it decides the array has no end.
const LIMIT: usize = 4096;
/// How much room the array gets past what it already holds, the first time it
/// is copied and every time it is grown.
const SPARE: usize = 16;
/// The longest name or value this layer copies.
const TEXT: usize = 1024;

const ENOMEM: i32 = 12;
const EINVAL: i32 = 22;

/// `setenv(name, value, overwrite)`.
pub fn set(host: &dyn Host, at: &Library, a: &[usize; 6]) -> SysResult {
    let (name, value, overwrite) = (a[0], a[1], a[2] != 0);
    let (name, name_len) = text(host, name)?;
    if name_len == 0 || name[..name_len].contains(&b'=') {
        return Err(EINVAL);
    }
    let (value, value_len) = text(host, value)?;
    let array = array_of(host, at)?;
    let found = find(host, array, &name[..name_len])?;
    if found.is_some() && !overwrite {
        return Ok(0);
    }
    // "NAME=VALUE" as one string in the program's own memory.
    let len = name_len + 1 + value_len;
    let entry = crate::heap::malloc(host, at, len + 1)? as usize;
    if entry == 0 {
        return Err(ENOMEM);
    }
    host.platform().write_user(entry, &name[..name_len])?;
    host.platform().write_user(entry + name_len, b"=")?;
    host.platform()
        .write_user(entry + name_len + 1, &value[..value_len])?;
    host.platform().write_user(entry + len, b"\0")?;

    match found {
        Some(slot) => put(host, slot, entry as u64)?,
        None => append(host, at, entry as u64)?,
    }
    Ok(0)
}

/// `unsetenv(name)`: the entry goes and the ones after it move down.
pub fn unset(host: &dyn Host, at: &Library, name_at: usize) -> SysResult {
    let (name, len) = text(host, name_at)?;
    if len == 0 || name[..len].contains(&b'=') {
        return Err(EINVAL);
    }
    let array = array_of(host, at)?;
    let Some(slot) = find(host, array, &name[..len])? else {
        return Ok(0);
    };
    let mut from = slot + 8;
    let mut to = slot;
    loop {
        let entry = word(host, from)?;
        put(host, to, entry)?;
        if entry == 0 {
            return Ok(0);
        }
        from += 8;
        to += 8;
    }
}

/// Where the array is, taking it over first if it is still the kernel's.
fn array_of(host: &dyn Host, at: &Library) -> Result<usize, i32> {
    let room = word(host, (at.private() + PRIVATE_ENVIRON_ROOM) as usize)?;
    let variable = at.address("_environ").ok_or(EINVAL)? as usize;
    let array = word(host, variable)? as usize;
    if room != 0 {
        return Ok(array);
    }
    let count = length(host, array)?;
    let moved = grow(host, at, array, count, count + SPARE)?;
    put(host, variable, moved as u64)?;
    put(
        host,
        (at.private() + PRIVATE_ENVIRON_ROOM) as usize,
        (count + SPARE) as u64,
    )?;
    Ok(moved)
}

/// A copy of `array`'s `count` entries with room for `room` of them.
fn grow(
    host: &dyn Host,
    at: &Library,
    array: usize,
    count: usize,
    room: usize,
) -> Result<usize, i32> {
    let moved = crate::heap::malloc(host, at, (room + 1) * 8)? as usize;
    if moved == 0 {
        return Err(ENOMEM);
    }
    for index in 0..count {
        let entry = word(host, array + index * 8)?;
        put(host, moved + index * 8, entry)?;
    }
    put(host, moved + count * 8, 0)?;
    Ok(moved)
}

/// Put `entry` on the end, making room for it first if there is none.
fn append(host: &dyn Host, at: &Library, entry: u64) -> Result<(), i32> {
    let variable = at.address("_environ").ok_or(EINVAL)? as usize;
    let room_at = (at.private() + PRIVATE_ENVIRON_ROOM) as usize;
    let mut array = word(host, variable)? as usize;
    let mut room = word(host, room_at)? as usize;
    let count = length(host, array)?;
    if count + 1 > room {
        room = count + SPARE;
        array = grow(host, at, array, count, room)?;
        put(host, variable, array as u64)?;
        put(host, room_at, room as u64)?;
    }
    put(host, array + count * 8, entry)?;
    put(host, array + (count + 1) * 8, 0)?;
    Ok(())
}

/// Which slot holds `name`, if any.
fn find(host: &dyn Host, array: usize, name: &[u8]) -> Result<Option<usize>, i32> {
    for index in 0..LIMIT {
        let slot = array + index * 8;
        let entry = word(host, slot)? as usize;
        if entry == 0 {
            return Ok(None);
        }
        let (line, len) = text(host, entry)?;
        if len > name.len() && line[..name.len()] == *name && line[name.len()] == b'=' {
            return Ok(Some(slot));
        }
    }
    Ok(None)
}

/// How many entries the array holds, not counting the null that ends it.
fn length(host: &dyn Host, array: usize) -> Result<usize, i32> {
    for index in 0..LIMIT {
        if word(host, array + index * 8)? == 0 {
            return Ok(index);
        }
    }
    Ok(LIMIT)
}

fn text(host: &dyn Host, at: usize) -> Result<([u8; TEXT], usize), i32> {
    let mut out = [0u8; TEXT];
    let len = host.platform().read_user_cstr(at, &mut out)? as usize;
    Ok((out, len))
}

fn word(host: &dyn Host, at: usize) -> Result<u64, i32> {
    let mut out = [0u8; 8];
    host.platform().read_user(at, &mut out)?;
    Ok(u64::from_le_bytes(out))
}

fn put(host: &dyn Host, at: usize, value: u64) -> Result<(), i32> {
    host.platform().write_user(at, &value.to_le_bytes())?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use ax_abi_port::Platform;

    use super::*;
    use crate::testing::MockHost;

    /// A host whose environment holds one entry, and the library that names
    /// it. Everything the tests write goes at a fixed place so the addresses
    /// in the assertions mean something.
    fn ready() -> (MockHost, Library) {
        let host = MockHost::default();
        host.mem.borrow_mut().resize(0x1_0000, 0);
        let at = Library::new(0x8000);
        {
            let mut mem = host.mem.borrow_mut();
            mem[0x300..0x30A].copy_from_slice(b"PATH=/bin\0");
            mem[0x200..0x208].copy_from_slice(&0x300u64.to_le_bytes());
            let variable = at.address("_environ").unwrap() as usize;
            mem[variable..variable + 8].copy_from_slice(&0x200u64.to_le_bytes());
        }
        (host, at)
    }

    /// What `environ` names now, as strings.
    fn seen(host: &MockHost, at: &Library) -> alloc::vec::Vec<alloc::string::String> {
        let variable = at.address("_environ").unwrap() as usize;
        let array = word(host, variable).unwrap() as usize;
        let mut out = alloc::vec::Vec::new();
        for index in 0.. {
            let entry = word(host, array + index * 8).unwrap() as usize;
            if entry == 0 {
                return out;
            }
            let (line, len) = text(host, entry).unwrap();
            out.push(alloc::string::String::from_utf8_lossy(&line[..len]).into_owned());
        }
        out
    }

    fn put_name(host: &MockHost, at: usize, text: &[u8]) {
        host.write_user(at, text).unwrap();
    }

    #[test]
    fn a_new_name_moves_the_array_off_the_stack_and_joins_it() {
        let (host, at) = ready();
        put_name(&host, 0x100, b"HOME\0");
        put_name(&host, 0x120, b"/root\0");
        assert_eq!(set(&host, &at, &[0x100, 0x120, 1, 0, 0, 0]), Ok(0));
        assert_eq!(seen(&host, &at), ["PATH=/bin", "HOME=/root"]);
        // The array is no longer the one on the stack, because that one had
        // no room for a second entry.
        let variable = at.address("_environ").unwrap() as usize;
        assert_ne!(word(&host, variable).unwrap(), 0x200);
    }

    #[test]
    fn a_name_that_is_there_is_replaced_only_when_asked() {
        let (host, at) = ready();
        put_name(&host, 0x100, b"PATH\0");
        put_name(&host, 0x120, b"/usr/bin\0");
        assert_eq!(set(&host, &at, &[0x100, 0x120, 0, 0, 0, 0]), Ok(0));
        assert_eq!(seen(&host, &at), ["PATH=/bin"], "not overwriting leaves it");
        assert_eq!(set(&host, &at, &[0x100, 0x120, 1, 0, 0, 0]), Ok(0));
        assert_eq!(seen(&host, &at), ["PATH=/usr/bin"]);
    }

    #[test]
    fn a_name_with_a_separator_in_it_is_not_a_name() {
        let (host, at) = ready();
        put_name(&host, 0x100, b"A=B\0");
        put_name(&host, 0x120, b"x\0");
        assert_eq!(set(&host, &at, &[0x100, 0x120, 1, 0, 0, 0]), Err(EINVAL));
        put_name(&host, 0x140, b"\0");
        assert_eq!(set(&host, &at, &[0x140, 0x120, 1, 0, 0, 0]), Err(EINVAL));
    }

    #[test]
    fn unsetting_moves_the_rest_down_and_missing_is_not_a_failure() {
        let (host, at) = ready();
        put_name(&host, 0x100, b"A\0");
        put_name(&host, 0x120, b"1\0");
        set(&host, &at, &[0x100, 0x120, 1, 0, 0, 0]).unwrap();
        put_name(&host, 0x140, b"B\0");
        set(&host, &at, &[0x140, 0x120, 1, 0, 0, 0]).unwrap();
        assert_eq!(seen(&host, &at), ["PATH=/bin", "A=1", "B=1"]);

        put_name(&host, 0x160, b"A\0");
        assert_eq!(unset(&host, &at, 0x160), Ok(0));
        assert_eq!(seen(&host, &at), ["PATH=/bin", "B=1"]);
        // One that is not there is simply not there.
        assert_eq!(unset(&host, &at, 0x160), Ok(0));
        assert_eq!(seen(&host, &at), ["PATH=/bin", "B=1"]);
    }

    #[test]
    fn the_array_grows_when_it_runs_out_of_room() {
        let (host, at) = ready();
        // More entries than the spare room the first move gives it.
        for index in 0..SPARE + 4 {
            let name = alloc::format!("N{index}\0");
            put_name(&host, 0x100, name.as_bytes());
            put_name(&host, 0x180, b"v\0");
            set(&host, &at, &[0x100, 0x180, 1, 0, 0, 0]).unwrap();
        }
        let names = seen(&host, &at);
        assert_eq!(
            names.len(),
            SPARE + 5,
            "the one it started with, and the rest"
        );
        assert_eq!(names[SPARE + 4], alloc::format!("N{}=v", SPARE + 3));
    }
}
