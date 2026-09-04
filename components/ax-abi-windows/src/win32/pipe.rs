//! Named pipes.
//!
//! A Windows named pipe is a connection between two processes reached by a
//! name - `\\.\pipe\something` - rather than by a file, and in message mode
//! each write is one read. The host has the same thing under another name: a
//! local socket bound to an abstract name, which no file system entry stands
//! for and which keeps message boundaries when it carries datagrams over a
//! connection. So a pipe here is that socket, and the calls below are the
//! Windows spelling of bind, listen, accept and connect.
//!
//! `multiprocessing` is what asks for these: its `Pipe()` makes a pipe in
//! message mode, connects to it from the same process, and hands the two ends
//! to a parent and a child.

use alloc::vec::Vec;

use ax_abi_port::{Address, Domain, SocketKind};
use ax_dispatch::Dispatch;

use super::{Call, FALSE, TRUE};
use crate::{handle::Handle, nt::Ntstatus};

/// `INVALID_HANDLE_VALUE`, which is what a pipe that cannot be made answers.
const INVALID_HANDLE: usize = usize::MAX;

/// `ERROR_PIPE_CONNECTED`: the client was already there when the server went
/// to wait for it, which is a success reported as a failure.
const ERROR_PIPE_CONNECTED: u32 = 535;
/// `ERROR_PATH_NOT_FOUND` and `ERROR_FILE_NOT_FOUND`, as a name that is not a
/// pipe and a pipe that is not there report.
const ERROR_PATH_NOT_FOUND: u32 = 3;
const ERROR_FILE_NOT_FOUND: u32 = 2;
/// `ERROR_BROKEN_PIPE`: the other end has gone.
const ERROR_BROKEN_PIPE: u32 = 109;

/// The name a pipe path carries, or nothing when the path is not one.
///
/// Windows spells a pipe on this machine `\\.\pipe\NAME`, and also accepts
/// `\\?\pipe\NAME` and a host part of `.` for the local machine. The name
/// that comes out is what the socket is bound to.
pub(super) fn name_of(path: &str) -> Option<&str> {
    let rest = path
        .strip_prefix("\\\\.\\")
        .or_else(|| path.strip_prefix("\\\\?\\"))?;
    let rest = rest
        .strip_prefix("pipe\\")
        .or_else(|| rest.strip_prefix("PIPE\\"))?;
    (!rest.is_empty()).then_some(rest)
}

/// The address a pipe name means: the name itself, in the machine's own
/// namespace.
fn address(name: &str) -> Option<Address> {
    Address::local(name.as_bytes())
}

/// Where the pipes this process has hang: a word of the PEB's reserved area
/// holding the first of them, or zero.
const PEB_PIPES: usize = super::PEB_PIPES;

/// What is remembered about one pipe: which descriptor it is, and the tail of
/// a message that did not fit the last read.
const PIPE_NEXT: usize = 0;
const PIPE_FD: usize = 8;
/// The block holding the rest of a message, and how much of it has been read.
const PIPE_TAIL: usize = 16;
const PIPE_TAKEN: usize = 24;
const PIPE_LEFT: usize = 32;
const PIPE_SIZE: usize = 40;

/// `ERROR_MORE_DATA`: the message was longer than the read asked for, and the
/// rest is still there. A message-mode pipe says this rather than tearing a
/// message in half without telling anyone.
pub(super) const ERROR_MORE_DATA: u32 = 234;

fn heap_of(c: &Call<'_>) -> Option<usize> {
    c.peb()
        .and_then(|peb| c.read_u64(peb + crate::teb_peb::PEB_PROCESS_HEAP))
        .map(|heap| heap as usize)
}

/// The block this process keeps for `fd`, if it is a pipe.
fn pipe_at(c: &Call<'_>, fd: i32) -> Option<usize> {
    let peb = c.peb()?;
    let mut at = c.read_u64(peb + PEB_PIPES).unwrap_or(0) as usize;
    while at != 0 {
        if c.read_u32(at + PIPE_FD) == Some(fd as u32) {
            return Some(at);
        }
        at = c.read_u64(at + PIPE_NEXT).unwrap_or(0) as usize;
    }
    None
}

/// Whether a descriptor is one end of a pipe, which decides whether a read of
/// it keeps message boundaries.
pub(super) fn is_pipe(c: &Call<'_>, fd: i32) -> bool {
    pipe_at(c, fd).is_some()
}

/// Remember that `fd` is one end of a pipe.
fn remember(c: &mut Call<'_>, fd: i32) {
    if pipe_at(c, fd).is_some() {
        return;
    }
    let (Some(peb), Some(heap)) = (c.peb(), heap_of(c)) else {
        return;
    };
    let Some(block) = super::heap::alloc(c, heap, PIPE_SIZE) else {
        return;
    };
    if !super::zero(c, block, PIPE_SIZE) {
        return;
    }
    let head = c.read_u64(peb + PEB_PIPES).unwrap_or(0);
    c.write_u64(block + PIPE_NEXT, head);
    c.write_u32(block + PIPE_FD, fd as u32);
    c.write_u64(peb + PEB_PIPES, block as u64);
}

/// Forget a pipe, which closing its handle does; the number goes back to the
/// host and the next thing to have it is not a pipe.
pub(super) fn forget(c: &mut Call<'_>, fd: i32) {
    let Some(peb) = c.peb() else { return };
    let mut at = c.read_u64(peb + PEB_PIPES).unwrap_or(0) as usize;
    let mut previous = 0usize;
    while at != 0 {
        let next = c.read_u64(at + PIPE_NEXT).unwrap_or(0) as usize;
        if c.read_u32(at + PIPE_FD) == Some(fd as u32) {
            if previous == 0 {
                c.write_u64(peb + PEB_PIPES, next as u64);
            } else {
                c.write_u64(previous + PIPE_NEXT, next as u64);
            }
            drop_tail(c, at);
            if let Some(heap) = heap_of(c) {
                super::heap::mark_free(c, heap, at);
            }
        } else {
            previous = at;
        }
        at = next;
    }
}

/// Give back the block holding the rest of a message.
fn drop_tail(c: &mut Call<'_>, pipe: usize) {
    let tail = c.read_u64(pipe + PIPE_TAIL).unwrap_or(0) as usize;
    if tail != 0 {
        if let Some(heap) = heap_of(c) {
            super::heap::mark_free(c, heap, tail);
        }
        c.write_u64(pipe + PIPE_TAIL, 0);
        c.write_u64(pipe + PIPE_TAKEN, 0);
        c.write_u64(pipe + PIPE_LEFT, 0);
    }
}

/// How much of the message being read is still waiting, tail and socket
/// together, which is what `PeekNamedPipe` reports.
fn waiting(c: &Call<'_>, fd: i32) -> usize {
    let Some(pipe) = pipe_at(c, fd) else { return 0 };
    let (left, taken) = (
        c.read_u64(pipe + PIPE_LEFT).unwrap_or(0) as usize,
        c.read_u64(pipe + PIPE_TAKEN).unwrap_or(0) as usize,
    );
    left.saturating_sub(taken)
}

/// Read one message, or as much of it as the caller has room for.
///
/// Windows keeps the rest of a message that did not fit and gives it to the
/// next read, reporting ERROR_MORE_DATA meanwhile; the host's messages are
/// whole or gone, so the rest is kept here instead.
///
/// Whether the message is finished, and how much was read.
pub(super) fn read(
    c: &mut Call<'_>,
    fd: i32,
    buffer: usize,
    len: usize,
) -> Result<(usize, bool), i32> {
    let Some(pipe) = pipe_at(c, fd) else {
        return Err(ax_abi_port::EBADF);
    };
    // What is left of the last message comes first.
    let left = waiting(c, fd);
    if left != 0 {
        let tail = c.read_u64(pipe + PIPE_TAIL).unwrap_or(0) as usize;
        let taken = c.read_u64(pipe + PIPE_TAKEN).unwrap_or(0) as usize;
        let moved = len.min(left);
        if !copy(c, tail + taken, buffer, moved) {
            return Err(ax_abi_port::EFAULT);
        }
        c.write_u64(pipe + PIPE_TAKEN, (taken + moved) as u64);
        if taken + moved >= c.read_u64(pipe + PIPE_LEFT).unwrap_or(0) as usize {
            drop_tail(c, pipe);
            return Ok((moved, true));
        }
        return Ok((moved, false));
    }
    let Some(sockets) = c.host.sockets() else {
        return Err(ax_abi_port::ENOSYS);
    };
    // How long the next message is decides whether it fits.
    let size = sockets.pending(fd).unwrap_or(0);
    if size <= len {
        return sockets.recv(fd, buffer, len, false).map(|(n, _)| (n, true));
    }
    let Some(heap) = heap_of(c) else {
        return Err(ax_abi_port::ENOMEM);
    };
    let Some(block) = super::heap::alloc(c, heap, size) else {
        return Err(ax_abi_port::ENOMEM);
    };
    let read = match sockets.recv(fd, block, size, false) {
        Ok((read, _)) => read,
        Err(errno) => {
            super::heap::mark_free(c, heap, block);
            return Err(errno);
        }
    };
    if !copy(c, block, buffer, len.min(read)) {
        super::heap::mark_free(c, heap, block);
        return Err(ax_abi_port::EFAULT);
    }
    c.write_u64(pipe + PIPE_TAIL, block as u64);
    c.write_u64(pipe + PIPE_TAKEN, len as u64);
    c.write_u64(pipe + PIPE_LEFT, read as u64);
    Ok((len.min(read), read <= len))
}

/// Copy `len` bytes of the program's own memory, which is where both the tail
/// and the caller's buffer are.
fn copy(c: &Call<'_>, from: usize, to: usize, len: usize) -> bool {
    let mut chunk = [0u8; 256];
    let mut moved = 0;
    while moved < len {
        let n = (len - moved).min(chunk.len());
        if c.host
            .platform()
            .read_user(from + moved, &mut chunk[..n])
            .is_err()
            || !c.write(to + moved, &chunk[..n])
        {
            return false;
        }
        moved += n;
    }
    true
}

/// A socket for one end of a pipe. Message mode is what a pipe is used in
/// here, so the socket keeps message boundaries.
fn socket(c: &Call<'_>) -> Option<i32> {
    c.host
        .sockets()?
        .open(Domain::Local, SocketKind::SeqPacket)
        .ok()
}

/// CreateNamedPipeW(name, openMode, pipeMode, maxInstances, outBuffer,
/// inBuffer, timeout, security): the listening end of a pipe.
///
/// The handle is the pipe until a client arrives; `ConnectNamedPipe` turns it
/// into the connection, which is what Windows does with the same handle.
pub fn create_named_pipe(c: &mut Call<'_>) -> Dispatch {
    let (name_at, instances) = (c.arg(0), c.arg(3) as u32);
    let Some(path) = super::file::name_at_arg(c, name_at) else {
        return c.fail(super::ERROR_INVALID_PARAMETER, INVALID_HANDLE);
    };
    let (Some(name), Some(sockets)) = (name_of(&path), c.host.sockets()) else {
        return c.fail(ERROR_PATH_NOT_FOUND, INVALID_HANDLE);
    };
    let Some(at) = address(name) else {
        return c.fail(super::ERROR_INVALID_PARAMETER, INVALID_HANDLE);
    };
    let Some(fd) = socket(c) else {
        return c.fail(super::ERROR_NOT_ENOUGH_MEMORY, INVALID_HANDLE);
    };
    // A pipe that cannot take its name is one that is already there, which is
    // what a second instance of a first-instance-only pipe means.
    let backlog = instances.clamp(1, 255);
    if sockets.bind(fd, &at).is_err() || sockets.listen(fd, backlog).is_err() {
        let _ = c.host.files().map(|files| files.close(fd));
        return c.fail(ERROR_PATH_NOT_FOUND, INVALID_HANDLE);
    }
    remember(c, fd);
    c.set_last_error(0);
    c.finish(Handle::from_slot(fd as usize).0 as usize)
}

/// ConnectNamedPipe(handle, overlapped): wait for a client, and become the
/// connection to it.
///
/// Windows leaves the caller holding the same handle, now naming the
/// connected instance rather than the listener, so the accepted socket is
/// moved onto the descriptor the handle already names.
pub fn connect_named_pipe(c: &mut Call<'_>) -> Dispatch {
    let (handle, overlapped) = (c.arg(0), c.arg(1));
    let (Ok(fd), Some(sockets), Some(files)) = (
        super::file::descriptor(handle),
        c.host.sockets(),
        c.host.files(),
    ) else {
        return c.fail_status(Ntstatus::INVALID_HANDLE, FALSE);
    };
    let taken = match sockets.accept(fd) {
        Ok((taken, _)) => taken,
        Err(errno) => return c.fail_status(super::nt::status_from_errno(errno), FALSE),
    };
    if files.dup_onto(taken, fd, false).is_err() {
        let _ = files.close(taken);
        return c.fail_status(Ntstatus::UNSUCCESSFUL, FALSE);
    }
    let _ = files.close(taken);
    // An overlapped connect that finished at once still reports through its
    // OVERLAPPED, which is where the caller reads the result from.
    if overlapped != 0 {
        c.write_u64(overlapped, 0);
        c.write_u64(overlapped + 8, 0);
    }
    // A connect that did not have to wait is reported as the failure
    // ERROR_PIPE_CONNECTED, which every caller reads as success.
    c.fail(ERROR_PIPE_CONNECTED, FALSE)
}

/// Open the client end of a pipe by name, which is what `CreateFileW` on a
/// pipe path does.
pub(super) fn open_client(c: &mut Call<'_>, path: &str) -> Dispatch {
    let (Some(name), Some(sockets)) = (name_of(path), c.host.sockets()) else {
        return c.fail(ERROR_PATH_NOT_FOUND, INVALID_HANDLE);
    };
    let Some(at) = address(name) else {
        return c.fail(super::ERROR_INVALID_PARAMETER, INVALID_HANDLE);
    };
    let Some(fd) = socket(c) else {
        return c.fail(super::ERROR_NOT_ENOUGH_MEMORY, INVALID_HANDLE);
    };
    if sockets.connect(fd, &at).is_err() {
        let _ = c.host.files().map(|files| files.close(fd));
        return c.fail(ERROR_FILE_NOT_FOUND, INVALID_HANDLE);
    }
    remember(c, fd);
    c.set_last_error(0);
    c.finish(Handle::from_slot(fd as usize).0 as usize)
}

/// SetNamedPipeHandleState(handle, mode, maxCollection, timeout): the mode a
/// pipe is read in.
///
/// The socket underneath keeps message boundaries whatever is asked for, so
/// the byte-stream mode is the one that cannot be given; asking for messages
/// is what the caller already has.
pub fn set_named_pipe_handle_state(c: &mut Call<'_>) -> Dispatch {
    /// `PIPE_READMODE_MESSAGE`.
    const READMODE_MESSAGE: u32 = 0x2;
    let (handle, mode_at) = (c.arg(0), c.arg(1));
    if super::file::descriptor(handle).is_err() {
        return c.fail_status(Ntstatus::INVALID_HANDLE, FALSE);
    }
    if mode_at != 0
        && let Some(mode) = c.read_u32(mode_at)
        && mode & READMODE_MESSAGE == 0
    {
        return c.fail(super::ERROR_INVALID_PARAMETER, FALSE);
    }
    c.set_last_error(0);
    c.finish(TRUE)
}

/// PeekNamedPipe(handle, buffer, size, read, available, left): what is
/// waiting, without taking it.
pub fn peek_named_pipe(c: &mut Call<'_>) -> Dispatch {
    let (handle, buffer, size) = (c.arg(0), c.arg(1), c.arg(2));
    let (read_out, available_out, left_out) = (c.arg(3), c.arg(4), c.arg(5));
    let (Ok(fd), Some(sockets)) = (super::file::descriptor(handle), c.host.sockets()) else {
        return c.fail_status(Ntstatus::INVALID_HANDLE, FALSE);
    };
    // What is there is read without taking it; a caller that gave no buffer
    // is only asking how much there is.
    let mut scratch: Vec<u8> = Vec::new();
    let (into, room) = if buffer != 0 && size != 0 {
        (buffer, size)
    } else {
        scratch.resize(1, 0);
        (0, 0)
    };
    // What is left of a message half read comes before what the socket has.
    let held = waiting(c, fd);
    let waiting = if held != 0 {
        held
    } else {
        match sockets.pending(fd) {
            Ok(waiting) => waiting,
            Err(errno) => return c.fail_status(super::nt::status_from_errno(errno), FALSE),
        }
    };
    let read = if room != 0 && waiting != 0 {
        match sockets.recv(fd, into, room.min(waiting), true) {
            Ok((read, _)) => read,
            Err(errno) => return c.fail_status(super::nt::status_from_errno(errno), FALSE),
        }
    } else {
        0
    };
    for (at, value) in [
        (read_out, read),
        (available_out, waiting),
        // One message is what is left of the one peeked at, which is all a
        // message-mode pipe reports.
        (left_out, waiting.saturating_sub(read)),
    ] {
        if at != 0 && !c.write_u32(at, value as u32) {
            return c.fail_status(Ntstatus::ACCESS_VIOLATION, FALSE);
        }
    }
    c.set_last_error(0);
    c.finish(TRUE)
}

/// DisconnectNamedPipe(handle): let go of the client, leaving the handle for
/// another connection. There is no listener to go back to here, so what it
/// does is shut the connection down.
pub fn disconnect_named_pipe(c: &mut Call<'_>) -> Dispatch {
    let handle = c.arg(0);
    let (Ok(fd), Some(sockets)) = (super::file::descriptor(handle), c.host.sockets()) else {
        return c.fail_status(Ntstatus::INVALID_HANDLE, FALSE);
    };
    match sockets.shutdown(fd, ax_abi_port::Shutdown::Both) {
        Ok(()) => {
            c.set_last_error(0);
            c.finish(TRUE)
        }
        Err(_) => c.fail(ERROR_BROKEN_PIPE, FALSE),
    }
}

/// WaitNamedPipeW(name, timeout): whether a pipe of that name is there to be
/// connected to. A name that exists is one a client can open, which is what
/// the caller goes on to do.
pub fn wait_named_pipe(c: &mut Call<'_>) -> Dispatch {
    let name_at = c.arg(0);
    let Some(path) = super::file::name_at_arg(c, name_at) else {
        return c.fail(super::ERROR_INVALID_PARAMETER, FALSE);
    };
    if name_of(&path).is_none() {
        return c.fail(ERROR_PATH_NOT_FOUND, FALSE);
    }
    c.set_last_error(0);
    c.finish(TRUE)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_pipe_path_carries_the_name_and_other_paths_do_not() {
        assert_eq!(name_of("\\\\.\\pipe\\pyc-42-0-abc"), Some("pyc-42-0-abc"));
        assert_eq!(name_of("\\\\?\\pipe\\name"), Some("name"));
        assert_eq!(name_of("\\\\.\\PIPE\\name"), Some("name"));
        assert_eq!(name_of("\\\\.\\pipe\\"), None, "a pipe needs a name");
        assert_eq!(name_of("Z:\\app\\file.txt"), None);
        assert_eq!(name_of("\\\\.\\NUL"), None, "a device is not a pipe");
    }
}
