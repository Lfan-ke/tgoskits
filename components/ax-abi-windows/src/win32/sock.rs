//! Sockets, as Winsock presents them.
//!
//! A `SOCKET` is a handle like any other here, so the file ports close and
//! poll one the same way. What this module owns is Winsock's own vocabulary:
//! its address structures, its address families - `AF_INET6` is 23 on Windows
//! and 10 on Linux - its port and address byte order, and the `WSAE*` numbers
//! it reports failures with. The host is asked only for the socket itself.

use ax_abi_port::{Address, Shutdown, SocketKind, SocketOption};
use ax_dispatch::Dispatch;

use super::Call;
use crate::handle::Handle;

/// Winsock's address families. The numbers are Windows's own.
const AF_INET: u16 = 2;
const AF_INET6: u16 = 23;

/// `SOCK_STREAM` and `SOCK_DGRAM`, which happen to agree with Linux's.
const SOCK_STREAM: u32 = 1;
const SOCK_DGRAM: u32 = 2;

/// `INVALID_SOCKET`, which is `(SOCKET)(~0)`, and `SOCKET_ERROR`.
const INVALID_SOCKET: usize = usize::MAX;
const SOCKET_ERROR: usize = -1i32 as u32 as usize;

/// The `WSAE*` numbers, which are the Berkeley errors plus 10000.
const WSA_BASE: u32 = 10000;
const WSAEWOULDBLOCK: u32 = WSA_BASE + 35;
const WSAEINVAL: u32 = WSA_BASE + 22;
const WSAENOTSOCK: u32 = WSA_BASE + 38;
const WSAEOPNOTSUPP: u32 = WSA_BASE + 45;
const WSAEAFNOSUPPORT: u32 = WSA_BASE + 47;
const WSAECONNREFUSED: u32 = WSA_BASE + 61;
const WSAETIMEDOUT: u32 = WSA_BASE + 60;
const WSAECONNRESET: u32 = WSA_BASE + 54;
const WSAEADDRINUSE: u32 = WSA_BASE + 48;
const WSAENOTCONN: u32 = WSA_BASE + 57;
const WSAEFAULT: u32 = WSA_BASE + 14;
const WSAEINTR: u32 = WSA_BASE + 4;
const WSAEACCES: u32 = WSA_BASE + 13;
const WSAEMFILE: u32 = WSA_BASE + 24;
const WSAENOBUFS: u32 = WSA_BASE + 55;
const WSAEISCONN: u32 = WSA_BASE + 56;
const WSAEALREADY: u32 = WSA_BASE + 37;
const WSAEHOSTUNREACH: u32 = WSA_BASE + 65;
const WSAENETUNREACH: u32 = WSA_BASE + 51;
const WSAEPIPE: u32 = WSA_BASE + 32;
/// `WSAHOST_NOT_FOUND`, which is its own number rather than a Berkeley one.
const WSAHOST_NOT_FOUND: u32 = 11001;

/// `FIONBIO` and `FIONREAD` as Winsock numbers them.
const FIONBIO: u32 = 0x8004_667E;
const FIONREAD: u32 = 0x4004_667F;

/// `MSG_PEEK`.
const MSG_PEEK: u32 = 0x2;

/// The `WSAE*` number a host errno reports as. The two spaces agree below 10000
/// only by accident, so the ones a socket call actually returns are named.
fn wsa_error(errno: i32) -> u32 {
    match errno {
        11 => WSAEWOULDBLOCK,
        22 => WSAEINVAL,
        88 => WSAENOTSOCK,
        95 => WSAEOPNOTSUPP,
        97 => WSAEAFNOSUPPORT,
        111 => WSAECONNREFUSED,
        110 => WSAETIMEDOUT,
        104 => WSAECONNRESET,
        98 => WSAEADDRINUSE,
        107 => WSAENOTCONN,
        14 => WSAEFAULT,
        4 => WSAEINTR,
        13 => WSAEACCES,
        24 => WSAEMFILE,
        105 => WSAENOBUFS,
        106 => WSAEISCONN,
        114 => WSAEALREADY,
        115 => WSAEWOULDBLOCK,
        113 => WSAEHOSTUNREACH,
        101 => WSAENETUNREACH,
        32 => WSAEPIPE,
        other => WSA_BASE + other as u32,
    }
}

/// A block of the process heap, for the structures a lookup hands back and
/// the caller keeps.
fn heap_block(c: &Call<'_>, size: usize) -> Option<usize> {
    let heap = c
        .peb()
        .and_then(|peb| c.read_u64(peb + crate::teb_peb::PEB_PROCESS_HEAP))
        .map(|heap| heap as usize)?;
    let block = super::heap::alloc(c, heap, size)?;
    super::zero(c, block, size).then_some(block)
}

/// The socket a `SOCKET` names.
fn descriptor(handle: usize) -> Option<i32> {
    u32::try_from(handle)
        .ok()
        .and_then(|raw| Handle(raw).slot())
        .and_then(|slot| i32::try_from(slot).ok())
}

/// The `SOCKET` a descriptor is named by.
fn socket_handle(fd: i32) -> usize {
    Handle::from_slot(fd as usize).0 as usize
}

/// Read a `SOCKADDR` of `len` bytes. The family, the port and the address are
/// each in Winsock's own layout and order.
fn read_address(c: &Call<'_>, at: usize, len: usize) -> Option<Address> {
    if at == 0 {
        return None;
    }
    let family = u16::from_le_bytes(c.read::<2>(at)?);
    // The port is in network order wherever it appears.
    let port = u16::from_be_bytes(c.read::<2>(at + 2)?);
    match family {
        AF_INET if len >= 16 => Some(Address::V4(c.read::<4>(at + 4)?, port)),
        AF_INET6 if len >= 28 => {
            let scope = u32::from_le_bytes(c.read::<4>(at + 24)?);
            Some(Address::V6(c.read::<16>(at + 8)?, port, scope))
        }
        _ => None,
    }
}

/// Write a `SOCKADDR` and the length it took, as the out parameter pair every
/// call that reports an address uses.
fn write_address(c: &Call<'_>, at: usize, len_at: usize, address: &Address) -> bool {
    if at == 0 {
        return true;
    }
    let room = if len_at == 0 {
        usize::MAX
    } else {
        c.read_u32(len_at).unwrap_or(0) as usize
    };
    let (bytes, wrote): (alloc::vec::Vec<u8>, usize) = match address {
        Address::V4(ip, port) => {
            let mut out = alloc::vec![0u8; 16];
            out[0..2].copy_from_slice(&AF_INET.to_le_bytes());
            out[2..4].copy_from_slice(&port.to_be_bytes());
            out[4..8].copy_from_slice(ip);
            (out, 16)
        }
        Address::V6(ip, port, scope) => {
            let mut out = alloc::vec![0u8; 28];
            out[0..2].copy_from_slice(&AF_INET6.to_le_bytes());
            out[2..4].copy_from_slice(&port.to_be_bytes());
            out[8..24].copy_from_slice(ip);
            out[24..28].copy_from_slice(&scope.to_le_bytes());
            (out, 28)
        }
    };
    if room < wrote {
        return false;
    }
    if len_at != 0 {
        c.write_u32(len_at, wrote as u32);
    }
    c.write(at, &bytes)
}

/// Report a failure the way Winsock does: the error is fetched separately, so
/// the call itself only says that it failed.
fn failed(c: &mut Call<'_>, errno: i32, result: usize) -> Dispatch {
    c.set_last_error(wsa_error(errno));
    c.finish(result)
}

/// WSAStartup(wVersionRequested, lpWSAData): there is nothing to start, but
/// the caller reads the block it is given.
pub fn startup(c: &mut Call<'_>) -> Dispatch {
    let (version, data) = (c.arg(0) as u16, c.arg(1));
    if data != 0 {
        // WSADATA: the version in use, the highest supported, then two
        // descriptions the caller may print.
        let mut block = [0u8; 408];
        block[0..2].copy_from_slice(&version.to_le_bytes());
        block[2..4].copy_from_slice(&version.to_le_bytes());
        let description = b"Starry sockets\0";
        block[4..4 + description.len()].copy_from_slice(description);
        if !c.write(data, &block) {
            return c.finish(WSAEFAULT as usize);
        }
    }
    c.set_last_error(0);
    c.finish(0)
}

/// WSACleanup(): nothing was started, so nothing is torn down.
pub fn cleanup(c: &mut Call<'_>) -> Dispatch {
    c.set_last_error(0);
    c.finish(0)
}

/// socket(af, type, protocol) and the WSASocket forms.
pub fn socket(c: &mut Call<'_>) -> Dispatch {
    let (family, kind) = (c.arg(0) as u16, c.arg(1) as u32);
    let Some(sockets) = c.host.sockets() else {
        return failed(c, 95, INVALID_SOCKET);
    };
    let kind = match kind {
        SOCK_STREAM => SocketKind::Stream,
        SOCK_DGRAM => SocketKind::Datagram,
        _ => return failed(c, 95, INVALID_SOCKET),
    };
    let v6 = match family {
        AF_INET => false,
        AF_INET6 => true,
        _ => return failed(c, 97, INVALID_SOCKET),
    };
    match sockets.open(kind, v6) {
        Ok(fd) => {
            c.set_last_error(0);
            c.finish(socket_handle(fd))
        }
        Err(errno) => failed(c, errno, INVALID_SOCKET),
    }
}

/// closesocket(s): a socket is a descriptor, so this is a close.
pub fn close(c: &mut Call<'_>) -> Dispatch {
    let Some(fd) = descriptor(c.arg(0)) else {
        return failed(c, 88, SOCKET_ERROR);
    };
    match c.host.files().map(|files| files.close(fd)) {
        Some(Ok(_)) => {
            c.set_last_error(0);
            c.finish(0)
        }
        Some(Err(errno)) => failed(c, errno, SOCKET_ERROR),
        None => failed(c, 95, SOCKET_ERROR),
    }
}

/// bind(s, name, namelen) and connect(s, name, namelen).
pub fn bind(c: &mut Call<'_>, connecting: bool) -> Dispatch {
    let (handle, at, len) = (c.arg(0), c.arg(1), c.arg(2));
    let (Some(fd), Some(sockets)) = (descriptor(handle), c.host.sockets()) else {
        return failed(c, 88, SOCKET_ERROR);
    };
    let Some(address) = read_address(c, at, len) else {
        return failed(c, 22, SOCKET_ERROR);
    };
    let done = if connecting {
        sockets.connect(fd, &address)
    } else {
        sockets.bind(fd, &address)
    };
    match done {
        Ok(()) => {
            c.set_last_error(0);
            c.finish(0)
        }
        Err(errno) => failed(c, errno, SOCKET_ERROR),
    }
}

/// listen(s, backlog).
pub fn listen(c: &mut Call<'_>) -> Dispatch {
    let (handle, backlog) = (c.arg(0), c.arg(1) as u32);
    let (Some(fd), Some(sockets)) = (descriptor(handle), c.host.sockets()) else {
        return failed(c, 88, SOCKET_ERROR);
    };
    match sockets.listen(fd, backlog) {
        Ok(()) => {
            c.set_last_error(0);
            c.finish(0)
        }
        Err(errno) => failed(c, errno, SOCKET_ERROR),
    }
}

/// accept(s, addr, addrlen).
pub fn accept(c: &mut Call<'_>) -> Dispatch {
    let (handle, at, len_at) = (c.arg(0), c.arg(1), c.arg(2));
    let (Some(fd), Some(sockets)) = (descriptor(handle), c.host.sockets()) else {
        return failed(c, 88, INVALID_SOCKET);
    };
    match sockets.accept(fd) {
        Ok((taken, peer)) => {
            if !write_address(c, at, len_at, &peer) {
                return failed(c, 14, INVALID_SOCKET);
            }
            c.set_last_error(0);
            c.finish(socket_handle(taken))
        }
        Err(errno) => failed(c, errno, INVALID_SOCKET),
    }
}

/// send(s, buf, len, flags) and sendto(s, buf, len, flags, to, tolen).
pub fn send(c: &mut Call<'_>, to_address: bool) -> Dispatch {
    let (handle, buf, len) = (c.arg(0), c.arg(1), c.arg(2));
    let (Some(fd), Some(sockets)) = (descriptor(handle), c.host.sockets()) else {
        return failed(c, 88, SOCKET_ERROR);
    };
    let to = if to_address {
        read_address(c, c.arg(4), c.arg(5))
    } else {
        None
    };
    match sockets.send(fd, buf, len, to.as_ref()) {
        Ok(sent) => {
            c.set_last_error(0);
            c.finish(sent as usize)
        }
        Err(errno) => failed(c, errno, SOCKET_ERROR),
    }
}

/// recv(s, buf, len, flags) and recvfrom(s, buf, len, flags, from, fromlen).
pub fn recv(c: &mut Call<'_>, from_address: bool) -> Dispatch {
    let (handle, buf, len, flags) = (c.arg(0), c.arg(1), c.arg(2), c.arg(3) as u32);
    let (Some(fd), Some(sockets)) = (descriptor(handle), c.host.sockets()) else {
        return failed(c, 88, SOCKET_ERROR);
    };
    match sockets.recv(fd, buf, len, flags & MSG_PEEK != 0) {
        Ok((read, from)) => {
            if from_address
                && let Some(from) = from
                && !write_address(c, c.arg(4), c.arg(5), &from)
            {
                return failed(c, 14, SOCKET_ERROR);
            }
            c.set_last_error(0);
            c.finish(read)
        }
        Err(errno) => failed(c, errno, SOCKET_ERROR),
    }
}

/// shutdown(s, how): SD_RECEIVE, SD_SEND, SD_BOTH.
pub fn shutdown(c: &mut Call<'_>) -> Dispatch {
    let (handle, how) = (c.arg(0), c.arg(1) as u32);
    let (Some(fd), Some(sockets)) = (descriptor(handle), c.host.sockets()) else {
        return failed(c, 88, SOCKET_ERROR);
    };
    let how = match how {
        0 => Shutdown::Read,
        1 => Shutdown::Write,
        2 => Shutdown::Both,
        _ => return failed(c, 22, SOCKET_ERROR),
    };
    match sockets.shutdown(fd, how) {
        Ok(()) => {
            c.set_last_error(0);
            c.finish(0)
        }
        Err(errno) => failed(c, errno, SOCKET_ERROR),
    }
}

/// getsockname(s, name, namelen) and getpeername.
pub fn name_of(c: &mut Call<'_>, peer: bool) -> Dispatch {
    let (handle, at, len_at) = (c.arg(0), c.arg(1), c.arg(2));
    let (Some(fd), Some(sockets)) = (descriptor(handle), c.host.sockets()) else {
        return failed(c, 88, SOCKET_ERROR);
    };
    let found = if peer {
        sockets.peer(fd)
    } else {
        sockets.local(fd)
    };
    match found {
        Ok(address) => {
            if !write_address(c, at, len_at, &address) {
                return failed(c, 14, SOCKET_ERROR);
            }
            c.set_last_error(0);
            c.finish(0)
        }
        Err(errno) => failed(c, errno, SOCKET_ERROR),
    }
}

/// ioctlsocket(s, cmd, argp): the two commands a socket answers.
pub fn ioctl(c: &mut Call<'_>) -> Dispatch {
    let (handle, command, arg) = (c.arg(0), c.arg(1) as u32, c.arg(2));
    let (Some(fd), Some(sockets)) = (descriptor(handle), c.host.sockets()) else {
        return failed(c, 88, SOCKET_ERROR);
    };
    let done = match command {
        FIONBIO => sockets
            .set_blocking(fd, c.read_u32(arg).unwrap_or(0) == 0)
            .map(|()| 0usize),
        FIONREAD => sockets.pending(fd).map(|ready| {
            c.write_u32(arg, ready as u32);
            0usize
        }),
        _ => return failed(c, 22, SOCKET_ERROR),
    };
    match done {
        Ok(_) => {
            c.set_last_error(0);
            c.finish(0)
        }
        Err(errno) => failed(c, errno, SOCKET_ERROR),
    }
}

/// setsockopt / getsockopt for the settings both sides name the same way.
/// `SOL_SOCKET` is 0xFFFF on Windows and `IPPROTO_TCP` is 6.
pub fn option(c: &mut Call<'_>, setting: bool) -> Dispatch {
    const SOL_SOCKET: u32 = 0xFFFF;
    const IPPROTO_TCP: u32 = 6;
    let (handle, level, name) = (c.arg(0), c.arg(1) as u32, c.arg(2) as u32);
    let (Some(fd), Some(sockets)) = (descriptor(handle), c.host.sockets()) else {
        return failed(c, 88, SOCKET_ERROR);
    };
    let option = match (level, name) {
        (SOL_SOCKET, 0x0004) => SocketOption::ReuseAddress,
        (SOL_SOCKET, 0x0008) => SocketOption::KeepAlive,
        (SOL_SOCKET, 0x0020) => SocketOption::Broadcast,
        (SOL_SOCKET, 0x1001) => SocketOption::SendBuffer,
        (SOL_SOCKET, 0x1002) => SocketOption::ReceiveBuffer,
        (SOL_SOCKET, 0x1007) => SocketOption::Error,
        (SOL_SOCKET, 0x1008) => SocketOption::Kind,
        (IPPROTO_TCP, 0x0001) => SocketOption::NoDelay,
        // An option this layer does not model is accepted and ignored when
        // set, and reported as zero when read, rather than failing a caller
        // that only wanted to express a preference.
        _ => {
            if !setting {
                let (value, len) = (c.arg(3), c.arg(4));
                if value != 0 {
                    c.write_u32(value, 0);
                }
                if len != 0 {
                    c.write_u32(len, 4);
                }
            }
            c.set_last_error(0);
            return c.finish(0);
        }
    };
    let done = if setting {
        let value = c.read_u32(c.arg(3)).unwrap_or(0);
        sockets.set_option(fd, option, value).map(|()| 0)
    } else {
        sockets.option(fd, option).map(|value| {
            // A pending error is reported in Winsock's numbering, not the
            // host's: a caller passes it straight to the code that turns a
            // number into an exception, and 111 there means something else
            // entirely.
            let value = if option == SocketOption::Error && value != 0 {
                wsa_error(value as i32)
            } else {
                value
            };
            let (at, len) = (c.arg(3), c.arg(4));
            if at != 0 {
                c.write_u32(at, value);
            }
            if len != 0 {
                c.write_u32(len, 4);
            }
            0
        })
    };
    match done {
        Ok(_) => {
            c.set_last_error(0);
            c.finish(0)
        }
        Err(errno) => failed(c, errno, SOCKET_ERROR),
    }
}

/// WSAGetLastError / WSASetLastError, which are the thread's last error under
/// another name.
pub fn last_error(c: &mut Call<'_>) -> Dispatch {
    let error = c.last_error() as usize;
    c.finish(error)
}

pub fn set_last_error(c: &mut Call<'_>) -> Dispatch {
    c.set_last_error(c.arg(0) as u32);
    c.finish(0)
}

/// A NUL-terminated string in user memory, as text.
fn read_text(c: &Call<'_>, at: usize) -> Option<alloc::string::String> {
    if at == 0 {
        return None;
    }
    let mut bytes = c.read_cstr(at)?;
    bytes.pop();
    alloc::string::String::from_utf8(bytes).ok()
}

/// The address a text form names, for the family asked about.
fn parse_address(family: u16, text: &str) -> Option<Address> {
    use core::{
        net::{Ipv4Addr, Ipv6Addr},
        str::FromStr,
    };
    match family {
        AF_INET => Ipv4Addr::from_str(text)
            .ok()
            .map(|ip| Address::V4(ip.octets(), 0)),
        AF_INET6 => Ipv6Addr::from_str(text)
            .ok()
            .map(|ip| Address::V6(ip.octets(), 0, 0)),
        _ => None,
    }
}

/// inet_pton(family, src, dst): text to bytes, in network order.
pub fn inet_pton(c: &mut Call<'_>) -> Dispatch {
    let (family, src, dst) = (c.arg(0) as u16, c.arg(1), c.arg(2));
    let Some(text) = read_text(c, src) else {
        return c.finish(-1i32 as u32 as usize);
    };
    match parse_address(family, &text) {
        // Zero says the text was not an address of that family, which is not
        // an error - the caller asked a question and got an answer.
        None if family == AF_INET || family == AF_INET6 => c.finish(0),
        None => {
            c.set_last_error(WSAEAFNOSUPPORT);
            c.finish(-1i32 as u32 as usize)
        }
        Some(Address::V4(bytes, _)) => {
            c.write(dst, &bytes);
            c.finish(1)
        }
        Some(Address::V6(bytes, ..)) => {
            c.write(dst, &bytes);
            c.finish(1)
        }
    }
}

/// inet_ntop(family, src, dst, size): bytes to text.
pub fn inet_ntop(c: &mut Call<'_>) -> Dispatch {
    use core::net::{Ipv4Addr, Ipv6Addr};
    let (family, src, dst, size) = (c.arg(0) as u16, c.arg(1), c.arg(2), c.arg(3));
    let text = match family {
        AF_INET => c
            .read::<4>(src)
            .map(|b| alloc::format!("{}", Ipv4Addr::from(b))),
        AF_INET6 => c
            .read::<16>(src)
            .map(|b| alloc::format!("{}", Ipv6Addr::from(b))),
        _ => {
            c.set_last_error(WSAEAFNOSUPPORT);
            return c.finish(0);
        }
    };
    let Some(text) = text else {
        c.set_last_error(WSAEFAULT);
        return c.finish(0);
    };
    if text.len() + 1 > size {
        c.set_last_error(WSAENOBUFS);
        return c.finish(0);
    }
    let mut bytes = text.into_bytes();
    bytes.push(0);
    if !c.write(dst, &bytes) {
        c.set_last_error(WSAEFAULT);
        return c.finish(0);
    }
    c.finish(dst)
}

/// inet_addr(cp): the address a dotted quad names, in network order, or
/// `INADDR_NONE` for text that is not one.
pub fn inet_addr(c: &mut Call<'_>) -> Dispatch {
    const INADDR_NONE: usize = 0xFFFF_FFFF;
    let Some(text) = read_text(c, c.arg(0)) else {
        return c.finish(INADDR_NONE);
    };
    match parse_address(AF_INET, &text) {
        Some(Address::V4(bytes, _)) => c.finish(u32::from_le_bytes(bytes) as usize),
        _ => c.finish(INADDR_NONE),
    }
}

/// inet_ntoa(in): the dotted quad for an address, in a buffer of the calling
/// thread's, which is where Windows keeps it too.
pub fn inet_ntoa(c: &mut Call<'_>) -> Dispatch {
    use core::net::Ipv4Addr;
    let raw = (c.arg(0) as u32).to_le_bytes();
    let text = alloc::format!("{}\0", Ipv4Addr::from(raw));
    let at = c.teb + crate::teb_peb::TEB_ADDRESS_TEXT;
    if !c.write(at, text.as_bytes()) {
        c.set_last_error(WSAEFAULT);
        return c.finish(0);
    }
    c.finish(at)
}

/// The well-known services a program looks up by name. Windows reads these
/// from a services file; there is none here, so the assignments that matter
/// are named directly.
const SERVICES: &[(&str, u16, bool)] = &[
    ("echo", 7, true),
    ("ftp-data", 20, true),
    ("ftp", 21, true),
    ("ssh", 22, true),
    ("telnet", 23, true),
    ("smtp", 25, true),
    ("time", 37, true),
    ("domain", 53, true),
    ("tftp", 69, false),
    ("http", 80, true),
    ("pop3", 110, true),
    ("ntp", 123, false),
    ("imap", 143, true),
    ("snmp", 161, false),
    ("https", 443, true),
    ("syslog", 514, false),
];

/// The port a service name is assigned, for the protocol asked about.
fn service_port(name: &str, protocol: Option<&str>) -> Option<u16> {
    let tcp = match protocol {
        None => None,
        Some("tcp") => Some(true),
        Some("udp") => Some(false),
        Some(_) => return None,
    };
    SERVICES
        .iter()
        .find(|(service, _, is_tcp)| *service == name && tcp.is_none_or(|want| want == *is_tcp))
        .map(|(_, port, _)| *port)
}

/// getservbyname(name, proto): the entry is built in the process heap, since
/// the caller keeps the pointer until its next lookup.
pub fn getservbyname(c: &mut Call<'_>) -> Dispatch {
    let (name_at, proto_at) = (c.arg(0), c.arg(1));
    let (Some(name), protocol) = (read_text(c, name_at), read_text(c, proto_at)) else {
        c.set_last_error(WSAEFAULT);
        return c.finish(0);
    };
    let Some(port) = service_port(&name, protocol.as_deref()) else {
        c.set_last_error(WSAHOST_NOT_FOUND);
        return c.finish(0);
    };
    // servent, in the order the 64-bit headers declare: the name, the alias
    // list, the protocol, and only then the port - which is a short, in
    // network order. The 32-bit headers put the port before the protocol, and
    // reading them in that order here gives a caller nonsense.
    let Some(block) = heap_block(c, 64) else {
        c.set_last_error(WSAENOBUFS);
        return c.finish(0);
    };
    let name_bytes = alloc::format!("{name}\0").into_bytes();
    let proto_bytes = alloc::format!("{}\0", protocol.as_deref().unwrap_or("tcp")).into_bytes();
    let (name_at, proto_at) = (block + 32, block + 48);
    c.write(name_at, &name_bytes);
    c.write(proto_at, &proto_bytes);
    c.write_u64(block, name_at as u64);
    c.write_u64(block + 8, 0);
    c.write_u64(block + 16, proto_at as u64);
    c.write(block + 24, &port.to_be_bytes());
    c.set_last_error(0);
    c.finish(block)
}

/// `ADDRINFOA` on x64: flags, family, socktype and protocol, then the address
/// length, the canonical name, the address and the next entry.
const AI_FAMILY: usize = 4;
const AI_SOCKTYPE: usize = 8;
const AI_PROTOCOL: usize = 12;
const AI_ADDRLEN: usize = 16;
const AI_ADDR: usize = 32;
const AI_NEXT: usize = 40;
const AI_SIZE: usize = 48;

/// `AI_PASSIVE`: the address is for binding, so an absent node means "any".
const AI_PASSIVE: u32 = 0x1;

/// getaddrinfo(node, service, hints, result).
///
/// There is no resolver behind this: a numeric address is answered, and so is
/// `localhost`, which every system resolves without asking anyone. A name
/// that would need a lookup is reported as not found rather than guessed at.
pub fn getaddrinfo(c: &mut Call<'_>) -> Dispatch {
    let (node_at, service_at, hints, result_at) = (c.arg(0), c.arg(1), c.arg(2), c.arg(3));
    let (family, socktype, protocol, flags) = if hints != 0 {
        (
            c.read_u32(hints + AI_FAMILY).unwrap_or(0) as u16,
            c.read_u32(hints + AI_SOCKTYPE).unwrap_or(0),
            c.read_u32(hints + AI_PROTOCOL).unwrap_or(0),
            c.read_u32(hints).unwrap_or(0),
        )
    } else {
        (0, 0, 0, 0)
    };
    // AF_UNSPEC asks for whatever the address turns out to be.
    let wanted = match family {
        0 => None,
        AF_INET => Some(AF_INET),
        AF_INET6 => Some(AF_INET6),
        _ => return c.finish(WSAEAFNOSUPPORT as usize),
    };

    let port = match read_text(c, service_at) {
        None => 0,
        Some(text) => match text.parse::<u16>() {
            Ok(port) => port,
            Err(_) => match service_port(&text, None) {
                Some(port) => port,
                None => return c.finish(WSAHOST_NOT_FOUND as usize),
            },
        },
    };

    let node = read_text(c, node_at);
    let address = match node.as_deref() {
        None => {
            // No node: the wildcard for binding, the loopback for connecting.
            let passive = flags & AI_PASSIVE != 0;
            match wanted {
                Some(AF_INET6) => Address::V6(
                    if passive {
                        [0; 16]
                    } else {
                        core::net::Ipv6Addr::LOCALHOST.octets()
                    },
                    port,
                    0,
                ),
                _ => Address::V4(if passive { [0; 4] } else { [127, 0, 0, 1] }, port),
            }
        }
        Some("localhost") => match wanted {
            Some(AF_INET6) => Address::V6(core::net::Ipv6Addr::LOCALHOST.octets(), port, 0),
            _ => Address::V4([127, 0, 0, 1], port),
        },
        Some(text) => {
            let found = [AF_INET, AF_INET6]
                .into_iter()
                .filter(|family| wanted.is_none_or(|want| want == *family))
                .find_map(|family| parse_address(family, text));
            match found {
                Some(Address::V4(ip, _)) => Address::V4(ip, port),
                Some(Address::V6(ip, _, scope)) => Address::V6(ip, port, scope),
                None => return c.finish(WSAHOST_NOT_FOUND as usize),
            }
        }
    };

    // One entry, holding its own address: the caller frees the pair together.
    let Some(block) = heap_block(c, AI_SIZE + 32) else {
        return c.finish(WSA_BASE as usize + 55);
    };
    let address_at = block + AI_SIZE;
    if !write_address(c, address_at, 0, &address) {
        return c.finish(WSAEFAULT as usize);
    }
    let (declared_family, length) = match address {
        Address::V4(..) => (AF_INET, 16u32),
        Address::V6(..) => (AF_INET6, 28u32),
    };
    c.write_u32(block, flags);
    c.write_u32(block + AI_FAMILY, declared_family as u32);
    c.write_u32(
        block + AI_SOCKTYPE,
        if socktype == 0 { SOCK_STREAM } else { socktype },
    );
    c.write_u32(block + AI_PROTOCOL, protocol);
    c.write_u64(block + AI_ADDRLEN, length as u64);
    c.write_u64(block + AI_ADDR, address_at as u64);
    c.write_u64(block + AI_NEXT, 0);
    if result_at != 0 {
        c.write_u64(result_at, block as u64);
    }
    c.set_last_error(0);
    c.finish(0)
}

/// freeaddrinfo(info): give the chain back to the heap it came from.
pub fn freeaddrinfo(c: &mut Call<'_>) -> Dispatch {
    let heap = c
        .peb()
        .and_then(|peb| c.read_u64(peb + crate::teb_peb::PEB_PROCESS_HEAP))
        .map(|heap| heap as usize);
    let mut entry = c.arg(0);
    while entry != 0 {
        let next = c.read_u64(entry + AI_NEXT).unwrap_or(0) as usize;
        if let Some(heap) = heap {
            super::heap::mark_free(c, heap, entry);
        }
        entry = next;
    }
    c.finish(0)
}

/// gethostname(name, len): the host's own node name.
pub fn gethostname(c: &mut Call<'_>) -> Dispatch {
    let (at, len) = (c.arg(0), c.arg(1));
    let mut name = alloc::string::String::new();
    if let Some(system) = c.host.system() {
        system.uname(&mut |field, value| {
            if field == ax_abi_port::UtsField::NodeName {
                name = alloc::string::String::from(value);
            }
        });
    }
    let text = name.as_bytes();
    if text.len() + 1 > len {
        c.set_last_error(WSAEFAULT);
        return c.finish(SOCKET_ERROR);
    }
    let mut bytes = text.to_vec();
    bytes.push(0);
    if !c.write(at, &bytes) {
        c.set_last_error(WSAEFAULT);
        return c.finish(SOCKET_ERROR);
    }
    c.set_last_error(0);
    c.finish(0)
}

/// A Winsock `fd_set`: a count followed by the sockets themselves, which is
/// an array rather than the bitmask the other ABIs use.
const FD_SETSIZE: usize = 64;

/// Read the sockets a set names.
fn read_set(c: &Call<'_>, at: usize) -> alloc::vec::Vec<usize> {
    if at == 0 {
        return alloc::vec::Vec::new();
    }
    let count = c.read_u32(at).unwrap_or(0) as usize;
    (0..count.min(FD_SETSIZE))
        .filter_map(|i| c.read_u64(at + 8 + i * 8).map(|handle| handle as usize))
        .collect()
}

/// Write back the sockets that are ready, which is what select leaves behind.
fn write_set(c: &Call<'_>, at: usize, ready: &[usize]) {
    if at == 0 {
        return;
    }
    c.write_u32(at, ready.len() as u32);
    for (i, handle) in ready.iter().enumerate() {
        c.write_u64(at + 8 + i * 8, *handle as u64);
    }
}

/// select(nfds, readfds, writefds, exceptfds, timeout).
///
/// `nfds` is ignored, as it is on Windows, where the sets carry their own
/// count. The timeout is a `timeval` of two 32-bit fields here, because
/// Windows keeps `long` at 32 bits even on x64; a null one waits forever.
pub fn select(c: &mut Call<'_>) -> Dispatch {
    use ax_abi_port::Ready;
    let (read_at, write_at, except_at, timeout_at) = (c.arg(1), c.arg(2), c.arg(3), c.arg(4));
    let Some(files) = c.host.files() else {
        c.set_last_error(WSAEOPNOTSUPP);
        return c.finish(SOCKET_ERROR);
    };
    let (readers, writers, excepts) = (
        read_set(c, read_at),
        read_set(c, write_at),
        read_set(c, except_at),
    );
    if readers.len() + writers.len() + excepts.len() > FD_SETSIZE * 3 {
        c.set_last_error(WSAEINVAL);
        return c.finish(SOCKET_ERROR);
    }

    // One entry per socket, carrying everything asked about it.
    let mut handles: alloc::vec::Vec<usize> = alloc::vec::Vec::new();
    let mut interest: alloc::vec::Vec<(i32, Ready)> = alloc::vec::Vec::new();
    for (list, want) in [
        (
            &readers,
            Ready {
                read: true,
                write: false,
                error: false,
            },
        ),
        (
            &writers,
            Ready {
                read: false,
                write: true,
                error: false,
            },
        ),
        (
            &excepts,
            Ready {
                read: false,
                write: false,
                error: true,
            },
        ),
    ] {
        for handle in list {
            let Some(fd) = descriptor(*handle) else {
                c.set_last_error(WSAENOTSOCK);
                return c.finish(SOCKET_ERROR);
            };
            match handles.iter().position(|seen| seen == handle) {
                Some(at) => {
                    interest[at].1.read |= want.read;
                    interest[at].1.write |= want.write;
                    interest[at].1.error |= want.error;
                }
                None => {
                    handles.push(*handle);
                    interest.push((fd, want));
                }
            }
        }
    }

    let timeout = (timeout_at != 0).then(|| {
        let seconds = c.read_u32(timeout_at).unwrap_or(0) as u64;
        let micros = c.read_u32(timeout_at + 4).unwrap_or(0) as u64;
        seconds * 1_000_000_000 + micros * 1_000
    });
    if let Err(errno) = files.poll(&mut interest, timeout) {
        return failed(c, errno, SOCKET_ERROR);
    }

    // Each set keeps only the sockets that came back ready for it.
    let ready_for = |pick: fn(&Ready) -> bool, from: &[usize]| -> alloc::vec::Vec<usize> {
        from.iter()
            .copied()
            .filter(|handle| {
                handles
                    .iter()
                    .position(|seen| seen == handle)
                    .is_some_and(|at| pick(&interest[at].1))
            })
            .collect()
    };
    let ready_read = ready_for(|ready| ready.read, &readers);
    let ready_write = ready_for(|ready| ready.write, &writers);
    let ready_except = ready_for(|ready| ready.error, &excepts);
    write_set(c, read_at, &ready_read);
    write_set(c, write_at, &ready_write);
    write_set(c, except_at, &ready_except);
    c.set_last_error(0);
    c.finish(ready_read.len() + ready_write.len() + ready_except.len())
}

/// __WSAFDIsSet(s, set): whether a socket is in a set, which is what the
/// `FD_ISSET` macro expands to.
pub fn fd_is_set(c: &mut Call<'_>) -> Dispatch {
    let (handle, at) = (c.arg(0), c.arg(1));
    let found = read_set(c, at).contains(&handle);
    c.finish(usize::from(found))
}

/// htons / htonl / ntohs / ntohl: the host is little-endian, so each is a
/// byte swap of the width it names.
pub fn swap16(c: &mut Call<'_>) -> Dispatch {
    let value = c.arg(0) as u16;
    c.finish(value.swap_bytes() as usize)
}

pub fn swap32(c: &mut Call<'_>) -> Dispatch {
    let value = c.arg(0) as u32;
    c.finish(value.swap_bytes() as usize)
}
