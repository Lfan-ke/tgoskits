//! Completion ports, and the overlapped operations that report through them.
//!
//! Windows does its asynchronous work the other way round from the host: a
//! program hands the kernel a buffer and is told later that the transfer
//! happened, rather than being told the descriptor is ready and doing the
//! transfer itself. The host offers the second of those, so a completion port
//! here is a small queue and a poll: starting an operation tries it once, and
//! an operation that would block is remembered until the descriptor it waits
//! on says it can go through, at which point it is carried out and its
//! completion queued. That is the same shape Wine gives them, and it is what
//! lets `asyncio`'s proactor loop run unchanged.
//!
//! Everything lives in the program's own heap, like the synchronisation
//! objects next door: a port block holds the list of operations belonging to
//! it, and the registrations that say which port a descriptor reports to hang
//! off a word of the PEB.

use alloc::vec::Vec;

use ax_abi_port::Ready;
use ax_dispatch::Dispatch;

use super::{Call, FALSE, TRUE, heap, sock, sync};
use crate::{handle::Handle, teb_peb::PEB_PROCESS_HEAP};

/// "ARRYIOCP" and "ARRYIOOP": what tells a port or an operation from any
/// other block a handle or a pointer might name.
const PORT_MAGIC: u64 = 0x5043_4F49_5952_5241;
const OP_MAGIC: u64 = 0x504F_4F49_5952_5241;

/// A port: the head of its operation list, and the lock over that list.
const PORT_OPS: usize = 8;
const PORT_LOCK: usize = 16;
const PORT_SIZE: usize = 24;

/// An operation: what it is, what it is on, and what became of it.
const OP_NEXT: usize = 8;
const OP_OVERLAPPED: usize = 16;
const OP_PORT: usize = 24;
const OP_KEY: usize = 32;
const OP_FD: usize = 40;
const OP_KIND: usize = 44;
const OP_BUFFER: usize = 48;
const OP_LENGTH: usize = 56;
const OP_TRANSFERRED: usize = 64;
const OP_STATE: usize = 72;
const OP_ERROR: usize = 76;
const OP_ADDRESS: usize = 80;
const OP_ADDRESS_LEN: usize = 88;
/// What only an accept needs: the socket the connection becomes, and how much
/// of the output buffer the local address is given.
const OP_ACCEPT_FD: usize = 96;
const OP_LOCAL_LEN: usize = 100;
const OP_SIZE: usize = 112;

/// A registration: which port a descriptor reports to, under what key.
const REG_NEXT: usize = 0;
const REG_FD: usize = 8;
const REG_PORT: usize = 16;
const REG_KEY: usize = 24;
const REG_SIZE: usize = 32;

/// An operation's state.
const PENDING: u32 = 0;
const DONE: u32 = 1;

/// What an operation is.
const RECV: u32 = 1;
const SEND: u32 = 2;
const RECV_FROM: u32 = 3;
const SEND_TO: u32 = 4;
const READ: u32 = 5;
const WRITE: u32 = 6;
const ACCEPT: u32 = 7;
const CONNECT: u32 = 8;
/// A completion with nothing behind it, as `PostQueuedCompletionStatus`
/// leaves one.
const POSTED: u32 = 9;

/// `OVERLAPPED`: the status, the count, the offset and the event.
const OVERLAPPED_INTERNAL: usize = 0;
const OVERLAPPED_INTERNAL_HIGH: usize = 8;
const OVERLAPPED_EVENT: usize = 24;

/// `STATUS_PENDING`, which is what `OVERLAPPED.Internal` holds until the
/// operation finishes.
const STATUS_PENDING: u64 = 0x103;

/// `ERROR_IO_PENDING`, `ERROR_IO_INCOMPLETE`, `ERROR_OPERATION_ABORTED` and
/// `WAIT_TIMEOUT`, which is what a wait with nothing to hand back reports.
const ERROR_IO_PENDING: u32 = 997;
const ERROR_IO_INCOMPLETE: u32 = 996;
const ERROR_OPERATION_ABORTED: u32 = 995;
const ERROR_ABANDONED_WAIT_0: u32 = 735;
/// `ERROR_NOT_FOUND`, what a cancel with nothing outstanding reports.
const ERROR_NOT_FOUND: u32 = 1168;
/// `WAIT_TIMEOUT`, which is what a wait with nothing to hand back reports.
const WAIT_TIMEOUT: u32 = 258;

/// The longest a wait on a port stays inside one poll. A posted completion
/// is not something a descriptor can report, so the wait comes back this
/// often to look for one.
const POLL_MS: u32 = 50;

/// `INVALID_HANDLE_VALUE`, which is the handle a port is created without a
/// file for.
const INVALID_HANDLE: usize = usize::MAX;

/// Where the registrations hang: a word of the PEB's reserved area.
const PEB_PORT_FILES: usize = super::PEB_PORT_FILES;

fn heap_of(c: &Call<'_>) -> Option<usize> {
    c.peb()
        .and_then(|peb| c.read_u64(peb + PEB_PROCESS_HEAP))
        .map(|heap| heap as usize)
}

/// The port a handle names, if it names one.
fn port_at(c: &Call<'_>, handle: usize) -> Option<usize> {
    if handle == 0 || !handle.is_multiple_of(8) {
        return None;
    }
    (c.read_u64(handle)? == PORT_MAGIC).then_some(handle)
}

/// The descriptor a handle names, whether it is a socket or a file.
fn descriptor(handle: usize) -> Option<i32> {
    u32::try_from(handle)
        .ok()
        .and_then(|raw| Handle(raw).slot())
        .and_then(|slot| i32::try_from(slot).ok())
}

/// CreateIoCompletionPort(FileHandle, ExistingCompletionPort, CompletionKey,
/// NumberOfConcurrentThreads): a new port, or a descriptor added to one.
pub fn create_port(c: &mut Call<'_>) -> Dispatch {
    let (file, existing, key) = (c.arg(0), c.arg(1), c.arg(2));
    if existing == 0 {
        // A port of its own, which the caller then adds descriptors to.
        let Some(heap) = heap_of(c) else {
            return c.fail(super::ERROR_CALL_NOT_IMPLEMENTED, 0);
        };
        let Some(block) = heap::alloc(c, heap, PORT_SIZE) else {
            return c.fail(super::ERROR_NOT_ENOUGH_MEMORY, 0);
        };
        if !super::zero(c, block, PORT_SIZE) {
            return c.fail(super::ERROR_NOT_ENOUGH_MEMORY, 0);
        }
        c.write_u64(block, PORT_MAGIC);
        c.set_last_error(0);
        return c.finish(block);
    }
    let (Some(port), Some(fd)) = (port_at(c, existing), descriptor(file)) else {
        return c.fail(super::ERROR_INVALID_HANDLE, 0);
    };
    if file == INVALID_HANDLE {
        return c.fail(super::ERROR_INVALID_PARAMETER, 0);
    }
    match register(c, fd, port, key) {
        true => {
            c.set_last_error(0);
            c.finish(port)
        }
        false => c.fail(super::ERROR_NOT_ENOUGH_MEMORY, 0),
    }
}

/// Remember that `fd` reports to `port` under `key`, replacing what it
/// reported to before.
fn register(c: &mut Call<'_>, fd: i32, port: usize, key: usize) -> bool {
    let Some(peb) = c.peb() else { return false };
    let mut at = c.read_u64(peb + PEB_PORT_FILES).unwrap_or(0) as usize;
    while at != 0 {
        if c.read_u32(at + REG_FD) == Some(fd as u32) {
            c.write_u64(at + REG_PORT, port as u64);
            c.write_u64(at + REG_KEY, key as u64);
            return true;
        }
        at = c.read_u64(at + REG_NEXT).unwrap_or(0) as usize;
    }
    let Some(heap) = heap_of(c) else { return false };
    let Some(block) = heap::alloc(c, heap, REG_SIZE) else {
        return false;
    };
    if !super::zero(c, block, REG_SIZE) {
        return false;
    }
    let head = c.read_u64(peb + PEB_PORT_FILES).unwrap_or(0);
    c.write_u64(block + REG_NEXT, head);
    c.write_u32(block + REG_FD, fd as u32);
    c.write_u64(block + REG_PORT, port as u64);
    c.write_u64(block + REG_KEY, key as u64);
    c.write_u64(peb + PEB_PORT_FILES, block as u64);
    true
}

/// The port a descriptor reports to, and the key it reports under.
fn port_of(c: &Call<'_>, fd: i32) -> Option<(usize, usize)> {
    let peb = c.peb()?;
    let mut at = c.read_u64(peb + PEB_PORT_FILES).unwrap_or(0) as usize;
    while at != 0 {
        if c.read_u32(at + REG_FD) == Some(fd as u32) {
            return Some((
                c.read_u64(at + REG_PORT)? as usize,
                c.read_u64(at + REG_KEY)? as usize,
            ));
        }
        at = c.read_u64(at + REG_NEXT).unwrap_or(0) as usize;
    }
    None
}

/// Put an operation on its port's list.
fn attach(c: &mut Call<'_>, port: usize, op: usize) {
    sync::lock(c, port + PORT_LOCK, false);
    let head = c.read_u64(port + PORT_OPS).unwrap_or(0);
    c.write_u64(op + OP_NEXT, head);
    c.write_u64(port + PORT_OPS, op as u64);
    sync::unlock(c, port + PORT_LOCK, false);
}

/// Take an operation off its port's list.
fn detach(c: &mut Call<'_>, port: usize, op: usize) {
    sync::lock(c, port + PORT_LOCK, false);
    let mut at = c.read_u64(port + PORT_OPS).unwrap_or(0) as usize;
    let next = c.read_u64(op + OP_NEXT).unwrap_or(0);
    if at == op {
        c.write_u64(port + PORT_OPS, next);
    } else {
        while at != 0 {
            let following = c.read_u64(at + OP_NEXT).unwrap_or(0) as usize;
            if following == op {
                c.write_u64(at + OP_NEXT, next);
                break;
            }
            at = following;
        }
    }
    sync::unlock(c, port + PORT_LOCK, false);
}

/// Every operation on a port, oldest last, as the list holds them.
fn operations(c: &Call<'_>, port: usize) -> Vec<usize> {
    let mut found = Vec::new();
    let mut at = c.read_u64(port + PORT_OPS).unwrap_or(0) as usize;
    // A list that does not end is a corrupted one; stop rather than spin.
    while at != 0 && found.len() < 4096 {
        found.push(at);
        at = c.read_u64(at + OP_NEXT).unwrap_or(0) as usize;
    }
    found
}

/// Lay out an operation and put it on the port `fd` reports to.
#[allow(clippy::too_many_arguments)]
fn begin(
    c: &mut Call<'_>,
    kind: u32,
    fd: i32,
    overlapped: usize,
    buffer: usize,
    length: usize,
    address: usize,
    address_len: usize,
) -> Option<usize> {
    let (port, key) = port_of(c, fd)?;
    let heap = heap_of(c)?;
    let op = heap::alloc(c, heap, OP_SIZE)?;
    super::zero(c, op, OP_SIZE).then_some(())?;
    c.write_u64(op, OP_MAGIC);
    c.write_u64(op + OP_OVERLAPPED, overlapped as u64);
    c.write_u64(op + OP_PORT, port as u64);
    c.write_u64(op + OP_KEY, key as u64);
    c.write_u32(op + OP_FD, fd as u32);
    c.write_u32(op + OP_KIND, kind);
    c.write_u64(op + OP_BUFFER, buffer as u64);
    c.write_u64(op + OP_LENGTH, length as u64);
    c.write_u64(op + OP_ADDRESS, address as u64);
    c.write_u64(op + OP_ADDRESS_LEN, address_len as u64);
    if kind == ACCEPT {
        c.write_u32(op + OP_ACCEPT_FD, address as u32);
        c.write_u32(op + OP_LOCAL_LEN, address_len as u32);
    }
    c.write_u32(op + OP_STATE, PENDING);
    if overlapped != 0 {
        c.write_u64(overlapped + OVERLAPPED_INTERNAL, STATUS_PENDING);
        c.write_u64(overlapped + OVERLAPPED_INTERNAL_HIGH, 0);
    }
    attach(c, port, op);
    Some(op)
}

/// Carry an operation out, if the descriptor will take it now.
///
/// Whether it finished: an operation that would still block stays pending and
/// is tried again the next time its descriptor says it is ready.
fn attempt(c: &mut Call<'_>, op: usize) -> bool {
    let (Some(kind), Some(fd)) = (c.read_u32(op + OP_KIND), c.read_u32(op + OP_FD)) else {
        return false;
    };
    let fd = fd as i32;
    let buffer = c.read_u64(op + OP_BUFFER).unwrap_or(0) as usize;
    let length = c.read_u64(op + OP_LENGTH).unwrap_or(0) as usize;
    let outcome: Result<usize, i32> = match kind {
        RECV | RECV_FROM => match c.host.sockets() {
            Some(sockets) => match sockets.recv(fd, buffer, length, false) {
                Ok((read, from)) => {
                    let address = c.read_u64(op + OP_ADDRESS).unwrap_or(0) as usize;
                    let address_len = c.read_u64(op + OP_ADDRESS_LEN).unwrap_or(0) as usize;
                    if kind == RECV_FROM
                        && address != 0
                        && let Some(from) = from
                    {
                        sock::put_address(c, address, address_len, &from);
                    }
                    Ok(read)
                }
                Err(errno) => Err(errno),
            },
            None => Err(ax_abi_port::EAGAIN),
        },
        SEND | SEND_TO => match c.host.sockets() {
            Some(sockets) => {
                let to = (kind == SEND_TO)
                    .then(|| {
                        let at = c.read_u64(op + OP_ADDRESS).unwrap_or(0) as usize;
                        let len = c.read_u64(op + OP_ADDRESS_LEN).unwrap_or(0) as usize;
                        sock::take_address(c, at, len)
                    })
                    .flatten();
                sockets
                    .send(fd, buffer, length, to.as_ref())
                    .map(|sent| sent as usize)
            }
            None => Err(ax_abi_port::EAGAIN),
        },
        READ => match c.host.files() {
            Some(files) => files.read(fd, buffer, length).map(|read| read as usize),
            None => Err(ax_abi_port::EAGAIN),
        },
        WRITE => match c.host.files() {
            Some(files) => files.write(fd, buffer, length).map(|sent| sent as usize),
            None => Err(ax_abi_port::EAGAIN),
        },
        // A connection is under way; what is left is to find out whether it
        // arrived, which is what the error the socket kept says.
        CONNECT => match c.host.sockets() {
            Some(sockets) => match sockets.option(fd, ax_abi_port::SocketOption::Error) {
                Ok(0) => Ok(0),
                Ok(errno) => Err(errno as i32),
                Err(errno) => Err(errno),
            },
            None => Err(ax_abi_port::EAGAIN),
        },
        ACCEPT => match c.host.sockets() {
            Some(sockets) => match sockets.accept(fd) {
                Ok((taken, remote)) => {
                    // AcceptEx hands the connection to a socket the caller
                    // made, so the one the host made becomes that one.
                    let onto = c.read_u32(op + OP_ACCEPT_FD).unwrap_or(0) as i32;
                    let moved = match c.host.files() {
                        Some(files) => files.dup_onto(taken, onto, false).map(|_| {
                            let _ = files.close(taken);
                            0
                        }),
                        None => Err(ax_abi_port::ENOSYS),
                    };
                    match moved {
                        Ok(_) => {
                            let local = sockets.local(fd).ok();
                            if let Some(remote) = remote {
                                put_accept_addresses(c, op, local.as_ref(), &remote);
                            }
                            Ok(0)
                        }
                        Err(errno) => Err(errno),
                    }
                }
                Err(errno) => Err(errno),
            },
            None => Err(ax_abi_port::EAGAIN),
        },
        _ => return true,
    };
    match outcome {
        Ok(moved) => {
            complete(c, op, moved, 0);
            true
        }
        // The descriptor was not ready after all, which is not a failure.
        Err(errno) if errno == ax_abi_port::EAGAIN => false,
        Err(errno) => {
            complete(c, op, 0, sock::error_of(errno));
            true
        }
    }
}

/// Record what an operation ended with, in the operation and in the caller's
/// `OVERLAPPED`, and signal the event that block carries.
fn complete(c: &mut Call<'_>, op: usize, transferred: usize, error: u32) {
    c.write_u64(op + OP_TRANSFERRED, transferred as u64);
    c.write_u32(op + OP_ERROR, error);
    c.write_u32(op + OP_STATE, DONE);
    let overlapped = c.read_u64(op + OP_OVERLAPPED).unwrap_or(0) as usize;
    if overlapped != 0 {
        // Internal carries an NTSTATUS; the only distinction a caller of
        // these draws is success from failure.
        c.write_u64(
            overlapped + OVERLAPPED_INTERNAL,
            if error == 0 { 0 } else { u64::from(error) },
        );
        c.write_u64(overlapped + OVERLAPPED_INTERNAL_HIGH, transferred as u64);
        let event = c.read_u64(overlapped + OVERLAPPED_EVENT).unwrap_or(0) as usize;
        if event != 0 {
            sync::signal(c, event);
        }
    }
}

/// Lay the two addresses an accept reports into the buffer it was given:
/// the local one first, then the remote one, each in the room the caller
/// said to leave for it.
fn put_accept_addresses(
    c: &mut Call<'_>,
    op: usize,
    local: Option<&ax_abi_port::Address>,
    remote: &ax_abi_port::Address,
) {
    let buffer = c.read_u64(op + OP_BUFFER).unwrap_or(0) as usize;
    let data = c.read_u64(op + OP_LENGTH).unwrap_or(0) as usize;
    let room = c.read_u32(op + OP_LOCAL_LEN).unwrap_or(0) as usize;
    if buffer == 0 || room == 0 {
        return;
    }
    if let Some(local) = local {
        sock::put_address(c, buffer + data, 0, local);
    }
    sock::put_address(c, buffer + data + room, 0, remote);
}

/// What a descriptor has to be ready for before an operation can go through.
fn interest(kind: u32) -> Ready {
    match kind {
        SEND | SEND_TO | WRITE | CONNECT => Ready {
            write: true,
            error: true,
            ..Ready::default()
        },
        _ => Ready {
            read: true,
            error: true,
            ..Ready::default()
        },
    }
}

/// Start an overlapped transfer: `WSARecv`, `WSASend`, `ReadFile` and
/// `WriteFile` all come here once their own arguments are read.
///
/// Windows answers such a call three ways, and so does this one: the transfer
/// happened (TRUE, with a completion queued as well), it is under way
/// (FALSE with ERROR_IO_PENDING), or it failed outright.
#[allow(clippy::too_many_arguments)]
pub(super) fn start(
    c: &mut Call<'_>,
    kind: u32,
    fd: i32,
    overlapped: usize,
    buffer: usize,
    length: usize,
    address: usize,
    address_len: usize,
    transferred_out: usize,
    winsock: bool,
) -> Dispatch {
    // Winsock reports these as zero and SOCKET_ERROR; the Win32 forms report
    // them as TRUE and FALSE.
    let (ok, bad) = if winsock {
        (0, -1i32 as u32 as usize)
    } else {
        (TRUE, FALSE)
    };
    let Some(op) = begin(
        c,
        kind,
        fd,
        overlapped,
        buffer,
        length,
        address,
        address_len,
    ) else {
        // Nothing to report a completion to: the caller waits on the event
        // its OVERLAPPED carries instead, which is what a named pipe is read
        // this way. Windows is free to finish an overlapped call before it
        // returns, and here it always does - the descriptor itself waits.
        return inline(
            c,
            kind,
            fd,
            buffer,
            length,
            overlapped,
            transferred_out,
            ok,
            bad,
        );
    };
    if !attempt(c, op) {
        // WSA_IO_PENDING and ERROR_IO_PENDING are the same number.
        c.set_last_error(ERROR_IO_PENDING);
        return c.finish(bad);
    }
    let error = c.read_u32(op + OP_ERROR).unwrap_or(0);
    let moved = c.read_u64(op + OP_TRANSFERRED).unwrap_or(0) as usize;
    if error != 0 {
        // The failure is the caller's answer; the completion is not queued
        // as well, which is what Windows does for a call that fails at once.
        forget(c, op);
        return c.fail(error, bad);
    }
    if transferred_out != 0 {
        c.write_u32(transferred_out, moved as u32);
    }
    c.set_last_error(0);
    c.finish(ok)
}

/// Carry a transfer out here and now, reporting it in the caller's
/// `OVERLAPPED` as a completed one.
#[allow(clippy::too_many_arguments)]
fn inline(
    c: &mut Call<'_>,
    kind: u32,
    fd: i32,
    buffer: usize,
    length: usize,
    overlapped: usize,
    transferred_out: usize,
    ok: usize,
    bad: usize,
) -> Dispatch {
    // A pipe keeps message boundaries, and says so when a message did not
    // fit; every other descriptor is a plain read.
    if kind == READ && sock::is_pipe(c, fd) {
        return match super::pipe::read(c, fd, buffer, length) {
            Ok((moved, whole)) => {
                if overlapped != 0 {
                    let status = if whole {
                        0
                    } else {
                        u64::from(super::pipe::ERROR_MORE_DATA)
                    };
                    c.write_u64(overlapped + OVERLAPPED_INTERNAL, status);
                    c.write_u64(overlapped + OVERLAPPED_INTERNAL_HIGH, moved as u64);
                    wake(c, overlapped);
                }
                if transferred_out != 0 {
                    c.write_u32(transferred_out, moved as u32);
                }
                if whole {
                    c.set_last_error(0);
                    c.finish(ok)
                } else {
                    c.fail(super::pipe::ERROR_MORE_DATA, bad)
                }
            }
            Err(errno) => {
                let error = super::nt::status_from_errno(errno).dos_error();
                if overlapped != 0 {
                    c.write_u64(overlapped + OVERLAPPED_INTERNAL, u64::from(error));
                    c.write_u64(overlapped + OVERLAPPED_INTERNAL_HIGH, 0);
                    wake(c, overlapped);
                }
                c.fail(error, bad)
            }
        };
    }
    let moved = match kind {
        READ => c.host.files().map(|files| files.read(fd, buffer, length)),
        WRITE => c.host.files().map(|files| files.write(fd, buffer, length)),
        RECV => c.host.sockets().map(|sockets| {
            sockets
                .recv(fd, buffer, length, false)
                .map(|(n, _)| n as isize)
        }),
        SEND => c
            .host
            .sockets()
            .map(|sockets| sockets.send(fd, buffer, length, None)),
        _ => None,
    };
    let moved = match moved {
        Some(Ok(moved)) => moved as usize,
        Some(Err(errno)) => {
            let error = if winsock_kind(kind) {
                sock::error_of(errno)
            } else {
                super::nt::status_from_errno(errno).dos_error()
            };
            if overlapped != 0 {
                c.write_u64(overlapped + OVERLAPPED_INTERNAL, u64::from(error));
                c.write_u64(overlapped + OVERLAPPED_INTERNAL_HIGH, 0);
                wake(c, overlapped);
            }
            return c.fail(error, bad);
        }
        None => return c.fail(super::ERROR_CALL_NOT_IMPLEMENTED, bad),
    };
    if overlapped != 0 {
        c.write_u64(overlapped + OVERLAPPED_INTERNAL, 0);
        c.write_u64(overlapped + OVERLAPPED_INTERNAL_HIGH, moved as u64);
        wake(c, overlapped);
    }
    if transferred_out != 0 {
        c.write_u32(transferred_out, moved as u32);
    }
    c.set_last_error(0);
    c.finish(ok)
}

/// Whether a kind is one of the Winsock calls, whose failures are numbered
/// the Winsock way.
fn winsock_kind(kind: u32) -> bool {
    matches!(kind, RECV | SEND | RECV_FROM | SEND_TO | ACCEPT | CONNECT)
}

/// Signal the event an `OVERLAPPED` carries, which is what a caller with no
/// completion port waits on.
fn wake(c: &mut Call<'_>, overlapped: usize) {
    let event = c.read_u64(overlapped + OVERLAPPED_EVENT).unwrap_or(0) as usize;
    if event != 0 {
        sync::signal(c, event);
    }
}

/// Take an operation off its port and give its block back.
fn forget(c: &mut Call<'_>, op: usize) {
    let port = c.read_u64(op + OP_PORT).unwrap_or(0) as usize;
    if port != 0 {
        detach(c, port, op);
    }
    c.write_u64(op, 0);
    if let Some(heap) = heap_of(c) {
        heap::mark_free(c, heap, op);
    }
}

/// GetQueuedCompletionStatus(port, bytes out, key out, overlapped out, ms):
/// the next operation to have finished, waiting for one if none has.
pub fn queued(c: &mut Call<'_>) -> Dispatch {
    let (handle, bytes_out, key_out, overlapped_out, timeout) =
        (c.arg(0), c.arg(1), c.arg(2), c.arg(3), c.arg(4) as u32);
    let Some(port) = port_at(c, handle) else {
        return c.fail(super::ERROR_INVALID_HANDLE, FALSE);
    };
    let deadline = sync::deadline_for(c, timeout);
    // A wait that hands nothing back says so by leaving no operation behind:
    // a caller tells the wait failing from an operation failing by whether
    // there is an OVERLAPPED with it.
    let nothing = |c: &mut Call<'_>, error: u32| {
        if bytes_out != 0 {
            c.write_u32(bytes_out, 0);
        }
        if key_out != 0 {
            c.write_u64(key_out, 0);
        }
        if overlapped_out != 0 {
            c.write_u64(overlapped_out, 0);
        }
        c.fail(error, FALSE)
    };
    loop {
        // Anything already finished is handed over before anything is waited
        // for, which is the order a port answers in.
        if let Some(op) = operations(c, port)
            .into_iter()
            .find(|op| c.read_u32(op + OP_STATE) == Some(DONE))
        {
            let moved = c.read_u64(op + OP_TRANSFERRED).unwrap_or(0) as usize;
            let key = c.read_u64(op + OP_KEY).unwrap_or(0) as usize;
            let overlapped = c.read_u64(op + OP_OVERLAPPED).unwrap_or(0) as usize;
            let error = c.read_u32(op + OP_ERROR).unwrap_or(0);
            forget(c, op);
            if bytes_out != 0 {
                c.write_u32(bytes_out, moved as u32);
            }
            if key_out != 0 {
                c.write_u64(key_out, key as u64);
            }
            if overlapped_out != 0 {
                c.write_u64(overlapped_out, overlapped as u64);
            }
            // A failed operation is reported with its OVERLAPPED, which is
            // how the caller tells it from a wait that timed out.
            if error != 0 {
                return c.fail(error, FALSE);
            }
            c.set_last_error(0);
            return c.finish(TRUE);
        }
        let pending: Vec<(usize, i32, u32)> = operations(c, port)
            .into_iter()
            .filter_map(|op| {
                let fd = c.read_u32(op + OP_FD)? as i32;
                let kind = c.read_u32(op + OP_KIND)?;
                (kind != POSTED).then_some((op, fd, kind))
            })
            .collect();
        let left = sync::left_of(c, deadline);
        if pending.is_empty() {
            // Nothing to watch: the only thing that can arrive is a posted
            // completion, so wait for one to be announced.
            let Some(left) = left else {
                return nothing(c, WAIT_TIMEOUT);
            };
            let seen = sync::signal_count(c).unwrap_or(0);
            sync::wait_for_signal(c, seen, left);
            if left == 0 {
                return nothing(c, WAIT_TIMEOUT);
            }
            continue;
        }
        let Some(left) = left else {
            return nothing(c, WAIT_TIMEOUT);
        };
        let Some(files) = c.host.files() else {
            return nothing(c, super::ERROR_CALL_NOT_IMPLEMENTED);
        };
        let mut watch: Vec<(i32, Ready)> = pending
            .iter()
            .map(|(_, fd, kind)| (*fd, interest(*kind)))
            .collect();
        // A completion posted by another thread moves no descriptor, so the
        // poll is only ever left waiting for a slice at a time; whoever
        // posted one is then seen on the way round.
        let slice = left.min(POLL_MS);
        if slice == 0 {
            // Less than a millisecond of the deadline is left, which is none
            // to wait for.
            return nothing(c, WAIT_TIMEOUT);
        }
        let waited = files.poll(&mut watch, Some(u64::from(slice) * 1_000_000));
        if waited.is_err() {
            return nothing(c, super::ERROR_INVALID_PARAMETER);
        }
        for ((op, ..), (_, ready)) in pending.iter().zip(watch.iter()) {
            if ready.read || ready.write || ready.error {
                attempt(c, *op);
            }
        }
    }
}

/// PostQueuedCompletionStatus(port, bytes, key, overlapped): a completion
/// with no transfer behind it, which is how one thread wakes another's wait.
pub fn post(c: &mut Call<'_>) -> Dispatch {
    let (handle, bytes, key, overlapped) = (c.arg(0), c.arg(1), c.arg(2), c.arg(3));
    let Some(port) = port_at(c, handle) else {
        return c.fail(super::ERROR_INVALID_HANDLE, FALSE);
    };
    let Some(heap) = heap_of(c) else {
        return c.fail(super::ERROR_CALL_NOT_IMPLEMENTED, FALSE);
    };
    let Some(op) = heap::alloc(c, heap, OP_SIZE) else {
        return c.fail(super::ERROR_NOT_ENOUGH_MEMORY, FALSE);
    };
    if !super::zero(c, op, OP_SIZE) {
        return c.fail(super::ERROR_NOT_ENOUGH_MEMORY, FALSE);
    }
    c.write_u64(op, OP_MAGIC);
    c.write_u32(op + OP_KIND, POSTED);
    c.write_u64(op + OP_PORT, port as u64);
    c.write_u64(op + OP_KEY, key as u64);
    c.write_u64(op + OP_OVERLAPPED, overlapped as u64);
    c.write_u64(op + OP_TRANSFERRED, bytes as u64);
    c.write_u32(op + OP_STATE, DONE);
    attach(c, port, op);
    // A thread already waiting on the port is parked on the signal counter,
    // since a posted completion moves no descriptor.
    sync::announce_signal(c);
    c.set_last_error(0);
    c.finish(TRUE)
}

/// CancelIoEx(hFile, lpOverlapped): give up on what is outstanding for a
/// descriptor - one operation, or all of them when no `OVERLAPPED` is named.
pub fn cancel(c: &mut Call<'_>) -> Dispatch {
    let (handle, overlapped) = (c.arg(0), c.arg(1));
    let Some(fd) = descriptor(handle) else {
        return c.fail(super::ERROR_INVALID_HANDLE, FALSE);
    };
    let Some((port, _)) = port_of(c, fd) else {
        return c.fail(ERROR_NOT_FOUND, FALSE);
    };
    let mut found = false;
    for op in operations(c, port) {
        if c.read_u32(op + OP_FD) != Some(fd as u32) || c.read_u32(op + OP_STATE) != Some(PENDING) {
            continue;
        }
        if overlapped != 0 && c.read_u64(op + OP_OVERLAPPED) != Some(overlapped as u64) {
            continue;
        }
        complete(c, op, 0, ERROR_OPERATION_ABORTED);
        found = true;
    }
    if !found {
        return c.fail(ERROR_NOT_FOUND, FALSE);
    }
    sync::announce_signal(c);
    c.set_last_error(0);
    c.finish(TRUE)
}

/// GetOverlappedResult(hFile, lpOverlapped, lpNumberOfBytesTransferred,
/// bWait): what an operation ended with, once it has.
pub fn result(c: &mut Call<'_>) -> Dispatch {
    let (overlapped, out, wait) = (c.arg(1), c.arg(2), c.arg(3) != 0);
    if overlapped == 0 {
        return c.fail(super::ERROR_INVALID_PARAMETER, FALSE);
    }
    if wait {
        let event = c.read_u64(overlapped + OVERLAPPED_EVENT).unwrap_or(0) as usize;
        while c.read_u64(overlapped + OVERLAPPED_INTERNAL) == Some(STATUS_PENDING) {
            if event == 0 {
                return c.fail(ERROR_ABANDONED_WAIT_0, FALSE);
            }
            sync::wait_object(c, event, sync::INFINITE);
        }
    }
    let status = c.read_u64(overlapped + OVERLAPPED_INTERNAL).unwrap_or(0);
    if status == STATUS_PENDING {
        return c.fail(ERROR_IO_INCOMPLETE, FALSE);
    }
    let moved = c
        .read_u64(overlapped + OVERLAPPED_INTERNAL_HIGH)
        .unwrap_or(0);
    if out != 0 {
        c.write_u32(out, moved as u32);
    }
    if status != 0 {
        return c.fail(status as u32, FALSE);
    }
    c.set_last_error(0);
    c.finish(TRUE)
}

/// Close a port, if that is what the handle names. Whatever was outstanding
/// on it is dropped, since nothing can report through it any more.
pub(super) fn close(c: &mut Call<'_>, handle: usize) -> bool {
    let Some(port) = port_at(c, handle) else {
        return false;
    };
    for op in operations(c, port) {
        forget(c, op);
    }
    // The registrations naming it go too, so a descriptor that outlives the
    // port does not report to a block that has been handed out again.
    if let Some(peb) = c.peb() {
        let mut at = c.read_u64(peb + PEB_PORT_FILES).unwrap_or(0) as usize;
        let mut previous = 0usize;
        while at != 0 {
            let next = c.read_u64(at + REG_NEXT).unwrap_or(0) as usize;
            if c.read_u64(at + REG_PORT) == Some(port as u64) {
                if previous == 0 {
                    c.write_u64(peb + PEB_PORT_FILES, next as u64);
                } else {
                    c.write_u64(previous + REG_NEXT, next as u64);
                }
                if let Some(heap) = heap_of(c) {
                    heap::mark_free(c, heap, at);
                }
            } else {
                previous = at;
            }
            at = next;
        }
    }
    c.write_u64(port, 0);
    if let Some(heap) = heap_of(c) {
        heap::mark_free(c, heap, port);
    }
    true
}

/// Forget that a descriptor reports to a port, which closing it does: the
/// number is handed out again, and the next socket to have it is not the one
/// that was registered.
pub(super) fn unregister(c: &mut Call<'_>, fd: i32) {
    let Some(peb) = c.peb() else { return };
    let mut at = c.read_u64(peb + PEB_PORT_FILES).unwrap_or(0) as usize;
    let mut previous = 0usize;
    while at != 0 {
        let next = c.read_u64(at + REG_NEXT).unwrap_or(0) as usize;
        if c.read_u32(at + REG_FD) == Some(fd as u32) {
            if previous == 0 {
                c.write_u64(peb + PEB_PORT_FILES, next as u64);
            } else {
                c.write_u64(previous + REG_NEXT, next as u64);
            }
            // Whatever was outstanding on it can never be reported now.
            let port = c.read_u64(at + REG_PORT).unwrap_or(0) as usize;
            if port != 0 && port_at(c, port).is_some() {
                for op in operations(c, port) {
                    if c.read_u32(op + OP_FD) == Some(fd as u32) {
                        forget(c, op);
                    }
                }
            }
            if let Some(heap) = heap_of(c) {
                heap::mark_free(c, heap, at);
            }
        } else {
            previous = at;
        }
        at = next;
    }
}

/// The kinds a caller of [`start`] names.
pub(super) const OP_RECV: u32 = RECV;
pub(super) const OP_SEND: u32 = SEND;
pub(super) const OP_RECV_FROM: u32 = RECV_FROM;
pub(super) const OP_SEND_TO: u32 = SEND_TO;
pub(super) const OP_READ: u32 = READ;
pub(super) const OP_WRITE: u32 = WRITE;
pub(super) const OP_ACCEPT: u32 = ACCEPT;
pub(super) const OP_CONNECT: u32 = CONNECT;
