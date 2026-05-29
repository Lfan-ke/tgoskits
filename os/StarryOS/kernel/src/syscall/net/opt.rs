use ax_errno::{AxError, AxResult, LinuxError};
use axnet::options::{Configurable, GetSocketOption, SetSocketOption};
use linux_raw_sys::net::{IPPROTO_IPV6, IPV6_V6ONLY, socklen_t};

use crate::{
    file::{FileLike, Socket, netlink::NetlinkSocket},
    mm::{UserConstPtr, UserPtr},
};

const PROTO_TCP: u32 = linux_raw_sys::net::IPPROTO_TCP as u32;

const PROTO_IP: u32 = linux_raw_sys::net::IPPROTO_IP as u32;

fn read_int_sockopt(optval: UserConstPtr<u8>, optlen: socklen_t) -> AxResult<i32> {
    if (optlen as usize) < size_of::<i32>() {
        return Err(AxError::InvalidInput);
    }
    Ok(*optval.cast::<i32>().get_as_ref()?)
}

mod conv {
    use ax_errno::{AxError, AxResult};
    use axnet::options::UnixCredentials;
    use linux_raw_sys::{general::timeval, net::ucred};

    use crate::time::TimeValueLike;

    pub struct Int<T>(T);

    impl<T: TryFrom<i32> + TryInto<i32>> Int<T> {
        pub fn sys_to_rust(val: i32) -> AxResult<T> {
            T::try_from(val).map_err(|_| AxError::InvalidInput)
        }

        pub fn rust_to_sys(val: T) -> AxResult<i32> {
            val.try_into().map_err(|_| AxError::InvalidInput)
        }
    }

    pub struct IntBool;

    impl IntBool {
        pub fn sys_to_rust(val: i32) -> AxResult<bool> {
            Ok(val != 0)
        }

        pub fn rust_to_sys(val: bool) -> AxResult<i32> {
            Ok(val as _)
        }
    }

    pub struct Duration;

    impl Duration {
        pub fn sys_to_rust(val: timeval) -> AxResult<core::time::Duration> {
            val.try_into_time_value()
        }

        pub fn rust_to_sys(val: core::time::Duration) -> AxResult<timeval> {
            Ok(timeval::from_time_value(val))
        }
    }

    pub struct Ucred;

    impl Ucred {
        pub fn sys_to_rust(val: ucred) -> AxResult<UnixCredentials> {
            Ok(UnixCredentials {
                pid: val.pid,
                uid: val.uid,
                gid: val.gid,
            })
        }

        pub fn rust_to_sys(val: UnixCredentials) -> AxResult<ucred> {
            Ok(ucred {
                pid: val.pid,
                uid: val.uid,
                gid: val.gid,
            })
        }
    }
}

macro_rules! call_dispatch {
    ($dispatch:ident, $pat:expr) => {{
        use conv::*;
        use linux_raw_sys::net::*;

        call_dispatch! {
            $dispatch, $pat,
            (SOL_SOCKET, SO_REUSEADDR) => ReuseAddress as IntBool,
            (SOL_SOCKET, SO_ERROR) => Error,
            (SOL_SOCKET, SO_DONTROUTE) => DontRoute as IntBool,
            (SOL_SOCKET, SO_SNDBUF) => SendBuffer as Int<usize>,
            (SOL_SOCKET, SO_RCVBUF) => ReceiveBuffer as Int<usize>,
            (SOL_SOCKET, SO_KEEPALIVE) => KeepAlive as IntBool,
            (SOL_SOCKET, SO_RCVTIMEO) => ReceiveTimeout as Duration,
            (SOL_SOCKET, SO_SNDTIMEO) => SendTimeout as Duration,
            (SOL_SOCKET, SO_PASSCRED) => PassCredentials as IntBool,
            (SOL_SOCKET, SO_PEERCRED) => PeerCredentials as Ucred,

            (PROTO_TCP, TCP_NODELAY) => NoDelay as IntBool,
            (PROTO_TCP, TCP_MAXSEG) => MaxSegment as Int<usize>,
            (PROTO_TCP, TCP_KEEPIDLE) => TcpKeepIdle as Int<u32>,
            (PROTO_TCP, TCP_KEEPINTVL) => TcpKeepInterval as Int<u32>,
            (PROTO_TCP, TCP_KEEPCNT) => TcpKeepCount as Int<u32>,
            (PROTO_TCP, TCP_USER_TIMEOUT) => TcpUserTimeout as Int<u32>,
            (PROTO_TCP, TCP_INFO) => TcpInfo,

            (PROTO_IP, IP_TTL) => Ttl as Int<u8>,
            (PROTO_IP, IP_RECVERR) => RecvErr as IntBool,
        }
    }};
    ($dispatch:ident, $in:expr, $($pat:pat => $which:ident $(as $conv:ty)?),* $(,)?) => {
        match $in {
            $(
                $pat => {
                    dispatch!($which $(as $conv)?);
                }
            )*
            _ => return Err(AxError::from(LinuxError::ENOPROTOOPT)),
        }
    }
}

pub fn sys_getsockopt(
    fd: i32,
    level: u32,
    optname: u32,
    optval: UserPtr<u8>,
    optlen: UserPtr<socklen_t>,
) -> AxResult<isize> {
    let optlen = optlen.get_as_mut()?;
    debug!(
        "sys_getsockopt <= fd: {}, level: {}, optname: {}, optval: {:?}, optlen: {}",
        fd,
        level,
        optname,
        optval.address(),
        optlen,
    );

    fn get<'a, T: 'static>(val: UserPtr<u8>, len: &mut socklen_t) -> AxResult<&'a mut T> {
        if (*len as usize) < size_of::<T>() {
            return Err(AxError::InvalidInput);
        }
        *len = size_of::<T>() as socklen_t;
        val.cast().get_as_mut()
    }

    let socket = Socket::from_fd(fd)?;
    if level == IPPROTO_IPV6 as u32 && optname == IPV6_V6ONLY {
        // TODO: Store and enforce IPV6_V6ONLY once native IPv6 sockets exist.
        *get::<i32>(optval, optlen)? = 0;
        return Ok(0);
    }

    macro_rules! dispatch {
        ($which:ident) => {
            socket.get_option(GetSocketOption::$which(get(optval, optlen)?))?;
        };
        ($which:ident as $conv:ty) => {
            let mut val = Default::default();
            socket.get_option(GetSocketOption::$which(&mut val))?;
            *get(optval, optlen)? = <$conv>::rust_to_sys(val)?;
        };
    }
    call_dispatch!(dispatch, (level, optname));

    Ok(0)
}

pub fn sys_setsockopt(
    fd: i32,
    level: u32,
    optname: u32,
    optval: UserConstPtr<u8>,
    optlen: socklen_t,
) -> AxResult<isize> {
    debug!(
        "sys_setsockopt <= fd: {}, level: {}, optname: {}, optval: {:?}, optlen: {}",
        fd,
        level,
        optname,
        optval.address(),
        optlen
    );

    if let Ok(socket) = NetlinkSocket::from_fd(fd) {
        use linux_raw_sys::net::{
            SO_ATTACH_FILTER, SO_LOCK_FILTER, SO_PASSCRED, SO_RCVBUF, SO_RCVBUFFORCE, SOL_SOCKET,
        };

        match (level, optname) {
            (SOL_SOCKET, SO_ATTACH_FILTER | SO_LOCK_FILTER) => {
                return Ok(0);
            }
            (SOL_SOCKET, SO_RCVBUF | SO_RCVBUFFORCE) => {
                let value = read_int_sockopt(optval, optlen)?;
                socket.set_receive_buffer_size(value.max(0) as usize);
                return Ok(0);
            }
            (SOL_SOCKET, SO_PASSCRED) => {
                let value = read_int_sockopt(optval, optlen)?;
                socket.set_passcred(value != 0);
                return Ok(0);
            }
            _ => return Err(AxError::from(LinuxError::ENOPROTOOPT)),
        }
    }

    {
        use linux_raw_sys::net::{SO_BROADCAST, SOL_SOCKET};

        if (level, optname) == (SOL_SOCKET, SO_BROADCAST) {
            let _ = read_int_sockopt(optval, optlen)?;
            return Ok(0);
        }
    }

    {
        // Options Tomcat/Spring's NioEndpoint sets that the smoltcp stack cannot
        // act on but must accept (Linux accepts them). Returning ENOPROTOOPT here
        // broke the Tomcat acceptor with "Error setting socket options: Protocol
        // not available". Accept + ignore: SO_LINGER (struct linger; default close),
        // SO_OOBINLINE (urgent-data inline), IP_TOS (QoS hint).
        use linux_raw_sys::net::{
            IP_MTU_DISCOVER, IP_PKTINFO, IP_RECVTOS, IP_TOS, SOL_SOCKET, SO_LINGER, SO_OOBINLINE,
            SO_REUSEPORT,
        };

        // Advisory options a minimal (smoltcp) stack cannot act on but that Linux
        // accepts; returning ENOPROTOOPT aborts servers that set them and treat
        // failure as fatal. SO_LINGER/SO_OOBINLINE/IP_TOS were for Tomcat. Added
        // for Go servers: IP_PKTINFO (consul's DNS via miekg/dns asks for the
        // packet dest-IP control message — on single-homed loopback ignoring is
        // correct, the app falls back to the bound address), IP_RECVTOS, the
        // path-MTU-discovery hint IP_MTU_DISCOVER, and SO_REUSEPORT (single
        // process → one socket gets all traffic, which is the intended effect).
        if matches!(
            (level, optname),
            (SOL_SOCKET, SO_LINGER)
                | (SOL_SOCKET, SO_OOBINLINE)
                | (SOL_SOCKET, SO_REUSEPORT)
                | (PROTO_IP, IP_TOS)
                | (PROTO_IP, IP_PKTINFO)
                | (PROTO_IP, IP_RECVTOS)
                | (PROTO_IP, IP_MTU_DISCOVER)
        ) {
            return Ok(0);
        }
    }

    fn get<'a, T: 'static>(val: UserConstPtr<u8>, len: socklen_t) -> AxResult<&'a T> {
        if len as usize != size_of::<T>() {
            return Err(AxError::InvalidInput);
        }
        val.cast().get_as_ref()
    }

    let socket = Socket::from_fd(fd)?;
    if level == IPPROTO_IPV6 as u32 && optname == IPV6_V6ONLY {
        // TODO: Store and enforce IPV6_V6ONLY once native IPv6 sockets exist.
        let _ = *get::<i32>(optval, optlen)?;
        return Ok(0);
    }

    macro_rules! dispatch {
        ($which:ident) => {
            socket.set_option(SetSocketOption::$which(get(optval, optlen)?))?;
        };
        ($which:ident as $conv:ty) => {
            let mut val = <$conv>::sys_to_rust(*get(optval, optlen)?)?;
            socket.set_option(SetSocketOption::$which(&mut val))?;
        };
    }
    call_dispatch!(dispatch, (level, optname));

    Ok(0)
}
