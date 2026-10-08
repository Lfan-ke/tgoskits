//! Files beyond read and write: descriptor flags, directories, the working
//! directory, and what the system says about itself.

use alloc::{string::String, vec::Vec};

use ax_abi_port::{At, Create, Host, NodeKind, OpenHow, SysResult, UtsField};

use crate::{
    system::{ATEXIT_LIMIT, Library, PRIVATE_ATEXIT, PRIVATE_SIGNALS},
    user,
};

const EBADF: i32 = 9;
const EINVAL: i32 = 22;
const ENOTTY: i32 = 25;
const ERANGE: i32 = 34;
const EIO: i32 = 5;
/// `ENOSYS`, in Darwin's numbering.
const ENOSYS: i32 = 78;

/// The Darwin release this personality answers as: macOS 11, which is what
/// the binaries it is built against ask for.
pub const DARWIN_RELEASE: &str = "20.6.0";
/// macOS 11.0.0, as `__availability_version_check` spells a version.
const MACOS_VERSION: u32 = 11 << 16;

/// `fcntl` commands, from Darwin's `<sys/fcntl.h>`.
mod cmd {
    pub const DUPFD: usize = 0;
    pub const GETFD: usize = 1;
    pub const SETFD: usize = 2;
    pub const DUPFD_CLOEXEC: usize = 67;
}

/// `fcntl(fd, cmd, arg)`, for the commands that are about the descriptor
/// itself. The rest are named in the host's log when a program asks.
pub fn fcntl(host: &dyn Host, fd: i32, command: usize, arg: usize) -> SysResult {
    let files = host.files().ok_or(EBADF)?;
    match command {
        cmd::GETFD => Ok(isize::from(files.close_on_exec(fd)?)),
        cmd::SETFD => files.set_close_on_exec(fd, arg & 1 != 0),
        cmd::DUPFD | cmd::DUPFD_CLOEXEC => {
            let copy = files.dup(fd)? as i32;
            if command == cmd::DUPFD_CLOEXEC {
                files.set_close_on_exec(copy, true)?;
            }
            Ok(copy as isize)
        }
        _ => {
            host.platform().trace(&alloc::format!(
                "fcntl command {command} is not implemented"
            ));
            Err(EINVAL)
        }
    }
}

/// `ioctl(fd, request, ...)`: the two requests that are `FD_CLOEXEC` by
/// another name. Anything else is a terminal request this layer has no
/// terminal to ask.
pub fn ioctl(host: &dyn Host, fd: i32, request: usize) -> SysResult {
    const FIOCLEX: usize = 0x2000_6601;
    const FIONCLEX: usize = 0x2000_6602;
    let files = host.files().ok_or(EBADF)?;
    match request {
        FIOCLEX => files.set_close_on_exec(fd, true),
        FIONCLEX => files.set_close_on_exec(fd, false),
        _ => {
            files.validate(fd)?;
            Err(ENOTTY)
        }
    }
}

/// `isatty(fd)`: a character device is a terminal here. Zero comes with
/// `errno`, which is how `isatty` says no.
pub fn isatty(host: &dyn Host, errno: usize, fd: i32) -> SysResult {
    let kind = host.paths().ok_or(ENOSYS)?.attributes_of(fd)?.kind;
    if kind == NodeKind::CharDevice {
        return Ok(1);
    }
    user::put_i32(host, errno, ENOTTY)?;
    Ok(0)
}

/// A `DIR` is a block from the program's heap: the descriptor, where the
/// names read from it are, how far the walk has got, and the `struct dirent`
/// each `readdir` answers with.
mod dir {
    pub const FD: usize = 0;
    pub const NAMES: usize = 8;
    pub const LEN: usize = 16;
    pub const CURSOR: usize = 24;
    pub const ENTRY: usize = 32;
    /// Darwin's 64-bit-inode `struct dirent`.
    pub const ENTRY_LEN: usize = 1048;
    pub const D_NAMLEN: usize = 18;
    pub const D_TYPE: usize = 20;
    pub const D_NAME: usize = 21;
    pub const BLOCK: usize = ENTRY + ENTRY_LEN;
}

fn dirent_type(kind: NodeKind) -> u8 {
    match kind {
        NodeKind::Fifo => 1,
        NodeKind::CharDevice => 2,
        NodeKind::Directory => 4,
        NodeKind::BlockDevice => 6,
        NodeKind::File => 8,
        NodeKind::Symlink => 10,
        NodeKind::Socket => 12,
    }
}

/// `fdopendir(fd)`. The directory is read once, here, so that a walk sees one
/// consistent listing however the directory changes under it.
pub fn fdopendir(host: &dyn Host, library: &Library, fd: i32) -> SysResult {
    let mut names = Vec::new();
    host.paths()
        .ok_or(ENOSYS)?
        .read_dir(fd, &mut |name: &str, kind: NodeKind| {
            let bytes = &name.as_bytes()[..name.len().min(1023)];
            names.push(dirent_type(kind));
            names.extend_from_slice(&(bytes.len() as u16).to_le_bytes());
            names.extend_from_slice(bytes);
            true
        })?;
    let block = crate::heap::malloc(host, library, dir::BLOCK)? as usize;
    let list = if names.is_empty() {
        0
    } else {
        let list = crate::heap::malloc(host, library, names.len())? as usize;
        user::put(host, list, &names)?;
        list
    };
    user::put_u64(host, block + dir::FD, fd as u64)?;
    user::put_u64(host, block + dir::NAMES, list as u64)?;
    user::put_u64(host, block + dir::LEN, names.len() as u64)?;
    user::put_u64(host, block + dir::CURSOR, 0)?;
    Ok(block as isize)
}

/// `opendir(path)`.
pub fn opendir(host: &dyn Host, library: &Library, path: usize) -> SysResult {
    let name = user::name(host, path)?;
    let how = OpenHow {
        read: true,
        write: false,
        append: false,
        truncate: false,
        create: Create::Never,
        directory: true,
        follow: true,
        close_on_exec: true,
        mode: 0,
    };
    let paths = host.paths().ok_or(ENOSYS)?;
    let fd = paths.open(At::Cwd, &name, &how)? as i32;
    fdopendir(host, library, fd).inspect_err(|_| {
        if let Some(files) = host.files() {
            let _ = files.close(fd);
        }
    })
}

/// `readdir(dir)`: the next name, or null once there are no more.
pub fn readdir(host: &dyn Host, block: usize) -> SysResult {
    let list = user::u64_at(host, block + dir::NAMES)? as usize;
    let len = user::u64_at(host, block + dir::LEN)? as usize;
    let cursor = user::u64_at(host, block + dir::CURSOR)? as usize;
    if cursor + 3 > len {
        return Ok(0);
    }
    let head = user::bytes(host, list + cursor, 3)?;
    let name_len = u16::from_le_bytes([head[1], head[2]]) as usize;
    let name = user::bytes(host, list + cursor + 3, name_len)?;
    let entry = block + dir::ENTRY;
    let mut fixed = [0u8; dir::D_NAME];
    // An entry with a zero inode reads as a deleted one, so every name gets
    // one that is not.
    fixed[..8].copy_from_slice(&(cursor as u64 + 1).to_le_bytes());
    fixed[16..18].copy_from_slice(&(dir::ENTRY_LEN as u16).to_le_bytes());
    fixed[dir::D_NAMLEN..dir::D_NAMLEN + 2].copy_from_slice(&(name_len as u16).to_le_bytes());
    fixed[dir::D_TYPE] = head[0];
    user::put(host, entry, &fixed)?;
    user::put_cstr(host, entry + dir::D_NAME, &name)?;
    user::put_u64(host, block + dir::CURSOR, (cursor + 3 + name_len) as u64)?;
    Ok(entry as isize)
}

/// `rewinddir(dir)`.
pub fn rewinddir(host: &dyn Host, block: usize) -> SysResult {
    user::put_u64(host, block + dir::CURSOR, 0)?;
    Ok(0)
}

/// `closedir(dir)`.
pub fn closedir(host: &dyn Host, library: &Library, block: usize) -> SysResult {
    let fd = user::u64_at(host, block + dir::FD)? as i32;
    let list = user::u64_at(host, block + dir::NAMES)? as usize;
    if list != 0 {
        crate::heap::free(host, library, list)?;
    }
    crate::heap::free(host, library, block)?;
    host.files().ok_or(EBADF)?.close(fd)
}

/// `dirfd(dir)`.
pub fn dirfd(host: &dyn Host, block: usize) -> SysResult {
    Ok(user::u64_at(host, block + dir::FD)? as i32 as isize)
}

/// `unlink(path)` and `rmdir(path)`.
pub fn unlink(host: &dyn Host, path: usize, directory: bool) -> SysResult {
    let name = user::name(host, path)?;
    host.paths()
        .ok_or(ENOSYS)?
        .unlink(At::Cwd, &name, directory)
}

/// `rename(from, to)`.
pub fn rename(host: &dyn Host, from: usize, to: usize) -> SysResult {
    let from = user::name(host, from)?;
    let to = user::name(host, to)?;
    host.paths()
        .ok_or(ENOSYS)?
        .rename(At::Cwd, &from, At::Cwd, &to)
}

/// `mkdir(path, mode)`.
pub fn mkdir(host: &dyn Host, path: usize, mode: u32) -> SysResult {
    let name = user::name(host, path)?;
    host.paths()
        .ok_or(ENOSYS)?
        .make_dir(At::Cwd, &name, mode & 0o7777)
}

/// `atexit(function)`: kept for `exit` to call, last first.
pub fn atexit(host: &dyn Host, library: &Library, function: usize) -> SysResult {
    const ENOMEM: i32 = 12;
    let list = (library.private() + PRIVATE_ATEXIT) as usize;
    let count = user::u64_at(host, list)?;
    if count + 1 >= ATEXIT_LIMIT {
        return Err(ENOMEM);
    }
    user::put_u64(host, list + 8 + count as usize * 8, function as u64)?;
    user::put_u64(host, list, count + 1)?;
    Ok(0)
}

/// The host's name for what `fd` is open on.
fn path_of(host: &dyn Host, fd: i32) -> Result<String, i32> {
    let mut path = String::new();
    host.paths()
        .ok_or(ENOSYS)?
        .path_of(fd, &mut |text: &str| path.push_str(text))?;
    Ok(path)
}

/// Open `name` only to ask what it is called, and close it again.
fn resolved(host: &dyn Host, name: &str, directory: bool) -> Result<String, i32> {
    let how = OpenHow {
        read: true,
        write: false,
        append: false,
        truncate: false,
        create: Create::Never,
        directory,
        follow: true,
        close_on_exec: true,
        mode: 0,
    };
    let fd = host.paths().ok_or(ENOSYS)?.open(At::Cwd, name, &how)? as i32;
    let path = path_of(host, fd);
    if let Some(files) = host.files() {
        let _ = files.close(fd);
    }
    path
}

/// `getcwd(buf, size)`. A null buffer asks for one from the heap, which is
/// the extension Darwin has and callers use.
pub fn getcwd(host: &dyn Host, library: &Library, buf: usize, size: usize) -> SysResult {
    let path = resolved(host, ".", true)?;
    let buf = if buf == 0 {
        crate::heap::malloc(host, library, path.len() + 1)? as usize
    } else if size < path.len() + 1 {
        return Err(ERANGE);
    } else {
        buf
    };
    user::put_cstr(host, buf, path.as_bytes())?;
    Ok(buf as isize)
}

/// `realpath(path, resolved)`: the name the host knows the file by.
pub fn realpath(host: &dyn Host, library: &Library, path: usize, out: usize) -> SysResult {
    let name = user::name(host, path)?;
    let kind = host
        .paths()
        .ok_or(ENOSYS)?
        .attributes(At::Cwd, &name, true)?
        .kind;
    let full = resolved(host, &name, kind == NodeKind::Directory)?;
    let out = if out == 0 {
        crate::heap::malloc(host, library, full.len() + 1)? as usize
    } else {
        out
    };
    user::put_cstr(host, out, full.as_bytes())?;
    Ok(out as isize)
}

/// `readlink(path, buf, size)`: as much of the target as fits, without a
/// terminator. What is not a link is refused the way Darwin does.
pub fn readlink(host: &dyn Host, path: usize, buf: usize, size: usize) -> SysResult {
    let name = user::name(host, path)?;
    let kind = host
        .paths()
        .ok_or(ENOSYS)?
        .attributes(At::Cwd, &name, false)?
        .kind;
    if kind != NodeKind::Symlink {
        return Err(EINVAL);
    }
    let mut target = String::new();
    host.paths()
        .ok_or(ENOSYS)?
        .read_link(At::Cwd, &name, &mut |text: &str| target.push_str(text))?;
    let fits = target.len().min(size);
    user::put(host, buf, &target.as_bytes()[..fits])?;
    Ok(fits as isize)
}

/// `uname(name)`: Darwin's five fields of 256 bytes. The system is this
/// personality's Darwin, on the machine and under the node name the host
/// reports.
pub fn uname(host: &dyn Host, at: usize) -> SysResult {
    const FIELD: usize = 256;
    let mut node = String::from("localhost");
    let mut machine = String::from("x86_64");
    let mut kernel = String::new();
    if let Some(system) = host.system() {
        system.uname(&mut |field: UtsField, text: &str| match field {
            UtsField::NodeName => node = String::from(text),
            UtsField::Machine => machine = String::from(text),
            UtsField::Release => kernel = String::from(text),
            _ => {}
        });
    }
    let version =
        alloc::format!("Darwin Kernel Version {DARWIN_RELEASE}: StarryOS {kernel} ax-abi-darwin");
    let mut out = alloc::vec![0u8; 5 * FIELD];
    let fields = [
        "Darwin",
        node.as_str(),
        DARWIN_RELEASE,
        version.as_str(),
        machine.as_str(),
    ];
    for (index, text) in fields.into_iter().enumerate() {
        let bytes = &text.as_bytes()[..text.len().min(FIELD - 1)];
        out[index * FIELD..index * FIELD + bytes.len()].copy_from_slice(bytes);
    }
    user::put(host, at, &out)?;
    Ok(0)
}

/// `CCRandomGenerateBytes(bytes, count)`, which answers with a status rather
/// than through `errno`.
pub fn random(host: &dyn Host, at: usize, len: usize) -> SysResult {
    const RNG_FAILURE: isize = -4308;
    match host.random() {
        Some(random) if random.fill(at, len, true).is_ok() => Ok(0),
        _ => Ok(RNG_FAILURE),
    }
}

/// `getentropy(buf, len)`: at most 256 bytes a call.
pub fn getentropy(host: &dyn Host, at: usize, len: usize) -> SysResult {
    if len > 256 {
        return Err(EIO);
    }
    host.random().ok_or(ENOSYS)?.fill(at, len, true)?;
    Ok(0)
}

/// `__availability_version_check(count, versions)`: whether the system is at
/// least the version asked about, which is what `@available` compiles to.
pub fn available(host: &dyn Host, count: usize, versions: usize) -> SysResult {
    for index in 0..count.min(16) {
        let version = user::u32_at(host, versions + index * 8 + 4)?;
        if version > MACOS_VERSION {
            return Ok(0);
        }
    }
    Ok(1)
}

/// How many signals Darwin numbers.
const NSIG: usize = 32;
/// Darwin's `struct sigaction`: the handler, the mask, the flags.
const ACTION_LEN: usize = 16;
const SIGKILL: usize = 9;
const SIGSTOP: usize = 17;

/// `sigaction(signal, action, old)`. Dispositions are kept and read back; no
/// signal is delivered to a Darwin program yet, so a handler installed here
/// is not called, and the host's log says so the first time one is installed.
pub fn sigaction(
    host: &dyn Host,
    library: &Library,
    signal: usize,
    action: usize,
    old: usize,
) -> SysResult {
    if signal == 0 || signal >= NSIG {
        return Err(EINVAL);
    }
    let slot = (library.private() + PRIVATE_SIGNALS) as usize + signal * ACTION_LEN;
    if old != 0 {
        let now = user::bytes(host, slot, ACTION_LEN)?;
        user::put(host, old, &now)?;
    }
    if action != 0 {
        if signal == SIGKILL || signal == SIGSTOP {
            return Err(EINVAL);
        }
        let new = user::bytes(host, action, ACTION_LEN)?;
        let handler = u64::from_le_bytes(new[..8].try_into().unwrap_or([0; 8]));
        let noted = (library.private() + PRIVATE_SIGNALS) as usize;
        if handler > 1 && user::u64_at(host, noted)? == 0 {
            user::put_u64(host, noted, 1)?;
            host.platform()
                .trace("sigaction: handlers are recorded, but signals are not delivered yet");
        }
        user::put(host, slot, &new)?;
    }
    Ok(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::MockHost;

    fn ready() -> (MockHost, Library) {
        let host = MockHost::default();
        host.mem.borrow_mut().resize(0x2_0000, 0);
        (host, Library::new(0x8000))
    }

    #[test]
    fn a_disposition_is_kept_and_read_back() {
        let (host, library) = ready();
        host.mem.borrow_mut()[0x200..0x208].copy_from_slice(&1u64.to_le_bytes());
        assert_eq!(sigaction(&host, &library, 13, 0x200, 0), Ok(0));
        assert_eq!(sigaction(&host, &library, 13, 0, 0x300), Ok(0));
        assert_eq!(user::u64_at(&host, 0x300), Ok(1), "SIG_IGN came back");
        assert_eq!(sigaction(&host, &library, 2, 0, 0x300), Ok(0));
        assert_eq!(
            user::u64_at(&host, 0x300),
            Ok(0),
            "another signal is untouched"
        );
        assert_eq!(sigaction(&host, &library, SIGKILL, 0x200, 0), Err(EINVAL));
        assert_eq!(sigaction(&host, &library, 0, 0x200, 0), Err(EINVAL));
        assert_eq!(sigaction(&host, &library, 64, 0x200, 0), Err(EINVAL));
    }

    #[test]
    fn a_version_newer_than_this_system_is_not_available() {
        let (host, _) = ready();
        // One (platform, version) pair: macOS 10.15, then macOS 12.
        host.mem.borrow_mut()[0x204..0x208].copy_from_slice(&(10u32 << 16 | 15 << 8).to_le_bytes());
        assert_eq!(available(&host, 1, 0x200), Ok(1));
        host.mem.borrow_mut()[0x204..0x208].copy_from_slice(&(12u32 << 16).to_le_bytes());
        assert_eq!(available(&host, 1, 0x200), Ok(0));
    }
}
