//! The `FILE` family.
//!
//! A `FILE` here is four words in the program's own memory: the descriptor it
//! stands for and the two flags C asks a stream to remember, whether it has
//! reached the end and whether something went wrong. The three a program
//! starts with sit in the synthesized library's private area, and
//! `__stdinp`, `__stdoutp` and `__stderrp` are filled in with their addresses
//! at load, which is what makes `stdout` a usable pointer from the first
//! instruction.
//!
//! Nothing is buffered: every write goes to the descriptor as it is made.
//! That is a buffering choice C allows - it is what `setvbuf(_IONBF)` asks
//! for - so a program cannot tell it apart from a conforming implementation
//! except by how often the write happens. `fflush` therefore has nothing to
//! do, which is also why it always succeeds.

use ax_abi_port::{Host, SysResult};

use crate::system::{Library, PRIVATE_STREAMS};

/// How much room one stream takes.
pub const FILE_LEN: u64 = 16;
/// Its descriptor, then the two things C asks it to remember.
const FD: u64 = 0;
const FLAGS: u64 = 4;
/// A word of its own the stream lends to a caller that has a byte to write
/// and nowhere in its own memory to write it from.
const SPARE: u64 = 8;
/// `feof` and `ferror` in one word.
const EOF_SEEN: u32 = 1;
const ERROR_SEEN: u32 = 2;

/// `EOF`, which every one of these reports failure with.
const EOF: isize = -1;
/// `EBADF`.
const EBADF: i32 = 9;
/// `EINVAL`.
const EINVAL: i32 = 22;
/// `ENOMEM`.
const ENOMEM: i32 = 12;

/// Where the stream numbered `which` is: 0 in, 1 out, 2 error.
pub fn standard(at: &Library, which: u64) -> u64 {
    at.private() + PRIVATE_STREAMS + which * FILE_LEN
}

/// The three streams as they start out, for the loader to place.
pub fn initial() -> alloc::vec::Vec<u8> {
    let mut out = alloc::vec![0u8; 3 * FILE_LEN as usize];
    for fd in 0..3u32 {
        let at = fd as usize * FILE_LEN as usize;
        out[at..at + 4].copy_from_slice(&fd.to_le_bytes());
    }
    out
}

/// Write `len` bytes at `uaddr` to `file`'s descriptor, reporting how many
/// went, and remembering a failure the way C asks a stream to.
fn write(host: &dyn Host, file: usize, uaddr: usize, len: usize) -> Result<usize, i32> {
    if len == 0 {
        return Ok(0);
    }
    let fd = descriptor(host, file)?;
    match host.files().ok_or(EBADF)?.write(fd, uaddr, len) {
        Ok(wrote) => Ok(wrote as usize),
        Err(errno) => {
            mark(host, file, ERROR_SEEN)?;
            Err(errno)
        }
    }
}

/// `fwrite(ptr, size, count, file)`: how many whole items went, not bytes.
pub fn fwrite(host: &dyn Host, a: &[usize; 6]) -> SysResult {
    let (ptr, size, count, file) = (a[0], a[1], a[2], a[3]);
    let Some(len) = size.checked_mul(count) else {
        return Ok(0);
    };
    if len == 0 {
        return Ok(0);
    }
    let wrote = write(host, file, ptr, len).unwrap_or(0);
    Ok((wrote / size.max(1)) as isize)
}

/// `fread(ptr, size, count, file)`, likewise.
pub fn fread(host: &dyn Host, a: &[usize; 6]) -> SysResult {
    let (ptr, size, count, file) = (a[0], a[1], a[2], a[3]);
    let Some(len) = size.checked_mul(count) else {
        return Ok(0);
    };
    if len == 0 {
        return Ok(0);
    }
    let fd = descriptor(host, file)?;
    match host.files().ok_or(EBADF)?.read(fd, ptr, len) {
        Ok(0) => {
            mark(host, file, EOF_SEEN)?;
            Ok(0)
        }
        Ok(read) => Ok(read / (size.max(1) as isize)),
        Err(errno) => {
            mark(host, file, ERROR_SEEN)?;
            Err(errno)
        }
    }
}

/// `fputs(s, file)`: the string without its terminator, and a non-negative
/// number if it went.
pub fn fputs(host: &dyn Host, a: &[usize; 6]) -> SysResult {
    let (at, file) = (a[0], a[1]);
    let len = len_of(host, at)?;
    match write(host, file, at, len) {
        Ok(_) => Ok(0),
        Err(_) => Ok(EOF),
    }
}

/// `puts(s)`: the string and a newline, to the standard output.
pub fn puts(host: &dyn Host, at: &Library, a: &[usize; 6]) -> SysResult {
    let file = standard(at, 1) as usize;
    let len = len_of(host, a[0])?;
    if write(host, file, a[0], len).is_err() {
        return Ok(EOF);
    }
    // The newline `puts` adds and `fputs` does not. It goes out of the
    // stream's own spare word, because a write names memory the program owns
    // and this byte is not in any.
    let scratch = file + SPARE as usize;
    host.platform().write_user(scratch, b"\n")?;
    match write(host, file, scratch, 1) {
        Ok(_) => Ok(0),
        Err(_) => Ok(EOF),
    }
}

/// `fputc(c, file)` and `putc`: one byte, answered with the byte.
pub fn fputc(host: &dyn Host, a: &[usize; 6]) -> SysResult {
    let (byte, file) = (a[0] as u8, a[1]);
    // The byte is the caller's argument, not in its memory, so it goes out
    // through a place the program owns: the stream's own spare word.
    let scratch = file + SPARE as usize;
    host.platform().write_user(scratch, &[byte])?;
    match write(host, file, scratch, 1) {
        Ok(_) => Ok(isize::from(byte)),
        Err(_) => Ok(EOF),
    }
}

/// `fileno(file)`.
pub fn fileno(host: &dyn Host, file: usize) -> SysResult {
    Ok(descriptor(host, file)? as isize)
}

/// `feof(file)` and `ferror(file)`.
pub fn status(host: &dyn Host, file: usize, which: u32) -> SysResult {
    Ok(isize::from(flags(host, file)? & which != 0))
}

/// `clearerr(file)`: both flags go.
pub fn clearerr(host: &dyn Host, file: usize) -> SysResult {
    host.platform()
        .write_user((file as u64 + FLAGS) as usize, &0u32.to_le_bytes())?;
    Ok(0)
}

/// `fclose(file)`: the descriptor goes; the stream itself is the caller's to
/// have come from somewhere, so nothing is freed here.
pub fn fclose(host: &dyn Host, file: usize) -> SysResult {
    let fd = descriptor(host, file)?;
    host.files().ok_or(EBADF)?.close(fd)
}

fn descriptor(host: &dyn Host, file: usize) -> Result<i32, i32> {
    if file == 0 {
        return Err(EBADF);
    }
    let mut word = [0u8; 4];
    host.platform().read_user(file + FD as usize, &mut word)?;
    Ok(i32::from_le_bytes(word))
}

fn flags(host: &dyn Host, file: usize) -> Result<u32, i32> {
    let mut word = [0u8; 4];
    host.platform()
        .read_user(file + FLAGS as usize, &mut word)?;
    Ok(u32::from_le_bytes(word))
}

fn mark(host: &dyn Host, file: usize, which: u32) -> Result<(), i32> {
    let now = flags(host, file)? | which;
    host.platform()
        .write_user(file + FLAGS as usize, &now.to_le_bytes())?;
    Ok(())
}

/// How long the string at `at` is, without its terminator.
fn len_of(host: &dyn Host, at: usize) -> Result<usize, i32> {
    let mut buf = [0u8; 4096];
    Ok(host.platform().read_user_cstr(at, &mut buf)? as usize)
}

#[cfg(test)]
mod tests {
    use ax_abi_port::Platform;

    use super::*;
    use crate::testing::MockHost;

    /// A host with the three streams in place, and where they are.
    fn ready() -> (MockHost, Library) {
        let host = MockHost::default();
        host.mem.borrow_mut().resize(0x1_0000, 0);
        let at = Library::new(0x8000);
        host.write_user((at.private() + PRIVATE_STREAMS) as usize, &initial())
            .unwrap();
        (host, at)
    }

    #[test]
    fn the_three_streams_stand_for_the_three_descriptors() {
        let (host, at) = ready();
        for which in 0..3u64 {
            let file = standard(&at, which) as usize;
            assert_eq!(fileno(&host, file).unwrap(), which as isize);
        }
    }

    #[test]
    fn what_is_written_reaches_the_descriptor_the_stream_stands_for() {
        let (host, at) = ready();
        let out = standard(&at, 1) as usize;
        host.write_user(0x200, b"hello").unwrap();
        // fwrite(ptr, size, count, file) answers in items, not bytes.
        let wrote = fwrite(&host, &[0x200, 1, 5, out, 0, 0]).unwrap();
        assert_eq!(wrote, 5);
        assert_eq!(*host.wrote.borrow(), Some((1, 0x200, 5)));

        // A count of nothing writes nothing and is not an error.
        assert_eq!(fwrite(&host, &[0x200, 0, 5, out, 0, 0]).unwrap(), 0);

        // fputs stops at the terminator and does not write it.
        host.write_user(0x300, b"abc\0").unwrap();
        assert_eq!(fputs(&host, &[0x300, out, 0, 0, 0, 0]).unwrap(), 0);
        assert_eq!(*host.wrote.borrow(), Some((1, 0x300, 3)));
    }

    #[test]
    fn puts_adds_the_newline_that_fputs_does_not() {
        let (host, at) = ready();
        host.write_user(0x300, b"line\0").unwrap();
        assert_eq!(puts(&host, &at, &[0x300, 0, 0, 0, 0, 0]).unwrap(), 0);
        // The last write is the newline, out of the stream's own spare word.
        let out = standard(&at, 1) as usize;
        assert_eq!(*host.wrote.borrow(), Some((1, out + SPARE as usize, 1)));
        assert_eq!(host.mem.borrow()[out + SPARE as usize], b'\n');
    }

    #[test]
    fn a_byte_goes_out_of_memory_the_program_owns() {
        let (host, at) = ready();
        let err = standard(&at, 2) as usize;
        assert_eq!(
            fputc(&host, &[b'!' as usize, err, 0, 0, 0, 0]).unwrap(),
            b'!' as isize
        );
        assert_eq!(*host.wrote.borrow(), Some((2, err + SPARE as usize, 1)));
        assert_eq!(host.mem.borrow()[err + SPARE as usize], b'!');
    }

    #[test]
    fn a_failed_write_is_remembered_on_the_stream() {
        let (host, at) = ready();
        let file = standard(&at, 1) as usize;
        // A stream over a descriptor the host will not take.
        host.write_user(file, &(-1i32).to_le_bytes()).unwrap();
        host.write_user(0x200, b"x").unwrap();
        assert_eq!(fwrite(&host, &[0x200, 1, 1, file, 0, 0]).unwrap(), 0);
        assert_eq!(status(&host, file, 2).unwrap(), 1, "ferror says so");
        assert_eq!(status(&host, file, 1).unwrap(), 0, "and it is not the end");
        clearerr(&host, file).unwrap();
        assert_eq!(status(&host, file, 2).unwrap(), 0);
    }

    #[test]
    fn a_stream_can_be_made_over_a_descriptor_and_over_a_name() {
        let (host, at) = ready();
        let file = fdopen(&host, &at, 7).unwrap() as usize;
        assert_ne!(file, 0);
        assert_eq!(fileno(&host, file).unwrap(), 7);
        assert_eq!(status(&host, file, 1).unwrap(), 0, "a new stream is clean");

        host.write_user(0x400, b"/tmp/f\0").unwrap();
        host.write_user(0x420, b"w\0").unwrap();
        let made = fopen(&host, &at, 0x400, 0x420).unwrap() as usize;
        assert_ne!(made, 0);
        let (_, name, how) = host.opened.borrow().clone().expect("the name was opened");
        assert_eq!(name, "/tmp/f");
        assert!(how.write && how.truncate && !how.read);
        assert_eq!(how.create, ax_abi_port::Create::IfAbsent);
    }

    #[test]
    fn a_mode_string_says_which_way_the_stream_goes() {
        let read = mode(b"r").unwrap();
        assert!(read.read && !read.write && !read.truncate);
        assert_eq!(read.create, ax_abi_port::Create::Never);
        let update = mode(b"r+").unwrap();
        assert!(update.read && update.write && !update.truncate);
        let append = mode(b"a").unwrap();
        assert!(append.append && !append.truncate);
        let exclusive = mode(b"wx").unwrap();
        assert_eq!(exclusive.create, ax_abi_port::Create::Exclusive);
        // `b` is allowed and changes nothing; a mode that names no direction
        // is not a mode.
        assert!(mode(b"rb").unwrap().read);
        assert!(mode(b"z").is_none());
        assert!(mode(b"").is_none());
    }

    #[test]
    fn a_stream_with_no_descriptor_behind_it_is_refused() {
        let (host, _) = ready();
        assert_eq!(fileno(&host, 0), Err(EBADF));
    }
}

/// A stream over an already-open descriptor. The stream itself comes from the
/// heap, so `fclose` on it leaves a block the caller can no longer name -
/// which is what closing a stream does to its own storage anyway.
pub fn fdopen(host: &dyn Host, at: &Library, fd: i32) -> SysResult {
    let file = crate::heap::malloc(host, at, FILE_LEN as usize)? as usize;
    if file == 0 {
        return Err(ENOMEM);
    }
    host.platform()
        .write_user(file, &[0u8; FILE_LEN as usize])?;
    host.platform().write_user(file, &fd.to_le_bytes())?;
    Ok(file as isize)
}

/// `fopen(path, mode)`: the name opened the way the mode word asks, then a
/// stream over it.
pub fn fopen(host: &dyn Host, at: &Library, path_at: usize, mode_at: usize) -> SysResult {
    let mut name = [0u8; 1024];
    let len = host.platform().read_user_cstr(path_at, &mut name)? as usize;
    let name = core::str::from_utf8(&name[..len]).map_err(|_| EINVAL)?;
    let mut spelled = [0u8; 16];
    let len = host.platform().read_user_cstr(mode_at, &mut spelled)? as usize;
    let how = mode(&spelled[..len]).ok_or(EINVAL)?;
    let fd = host
        .paths()
        .ok_or(EBADF)?
        .open(ax_abi_port::At::Cwd, name, &how)? as i32;
    fdopen(host, at, fd)
}

/// What a mode string asks for, or `None` for one that says nothing valid.
/// The first letter decides; `+` adds the other direction, and the modifiers
/// after it are `b` (which changes nothing here), `x` and `e`.
fn mode(spelled: &[u8]) -> Option<ax_abi_port::OpenHow> {
    let (first, rest) = spelled.split_first()?;
    let plus = rest.contains(&b'+');
    let mut how = ax_abi_port::OpenHow {
        read: *first == b'r' || plus,
        write: *first != b'r' || plus,
        append: *first == b'a',
        truncate: *first == b'w',
        create: if *first == b'r' {
            ax_abi_port::Create::Never
        } else {
            ax_abi_port::Create::IfAbsent
        },
        directory: false,
        follow: true,
        close_on_exec: rest.contains(&b'e'),
        mode: 0o666,
    };
    if !matches!(*first, b'r' | b'w' | b'a') {
        return None;
    }
    if rest.contains(&b'x') {
        how.create = ax_abi_port::Create::Exclusive;
    }
    Some(how)
}
