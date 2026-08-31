#!/usr/bin/env python3
"""Sockets and character devices — carpet coverage for StarryOS python-lang (#764)."""
import sys
_ok = True
def chk(name, cond, info=""):
    global _ok
    print(("  ok " if cond else "  FAIL ") + name + ((" " + info) if info else ""))
    if not cond:
        _ok = False


import errno
import os
import select
import socket
import stat as statmod
import struct
import threading

# Everything below stays on the loopback interface and on this machine's own
# device nodes: the suite has to give the same answer with no network.
HOST = "127.0.0.1"


# ============================================================================
# socket — addressing and the descriptor itself (docs: "socket — Low-level
# networking interface"). how: create sockets and read back what was asked
# for; expected: the documented family/type/proto and address forms.
# ============================================================================

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
chk("sock_family", s.family == socket.AF_INET)
chk("sock_type", s.type == socket.SOCK_STREAM)
chk("sock_fileno", s.fileno() >= 0)
# SO_TYPE reads back the type the socket was created with.
chk("sock_so_type",
    s.getsockopt(socket.SOL_SOCKET, socket.SO_TYPE) == socket.SOCK_STREAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
chk("sock_so_reuseaddr",
    s.getsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR) != 0)
s.bind((HOST, 0))
bound = s.getsockname()
chk("sock_bind_host", bound[0] == HOST)
chk("sock_bind_port_assigned", bound[1] != 0, "port=%d" % bound[1])
s.close()
chk("sock_fileno_after_close", s.fileno() == -1)
# Operating on a closed socket raises rather than reporting success.
try:
    s.getsockname()
    chk("sock_closed_raises", False)
except OSError:
    chk("sock_closed_raises", True)

# Address conversion is pure arithmetic on the string form.
chk("inet_aton", socket.inet_aton("127.0.0.1") == b"\x7f\x00\x00\x01")
chk("inet_ntoa", socket.inet_ntoa(b"\x7f\x00\x00\x01") == "127.0.0.1")
chk("htons", socket.htons(0x1234) in (0x1234, 0x3412))
chk("ntohl_roundtrip", socket.ntohl(socket.htonl(0xDEADBEEF)) == 0xDEADBEEF)
try:
    socket.inet_aton("not.an.address")
    chk("inet_aton_rejects_garbage", False)
except OSError:
    chk("inet_aton_rejects_garbage", True)


# ============================================================================
# TCP over loopback — the full connect/accept/transfer/close sequence, which
# is what a program doing anything over a network performs.
# ============================================================================

srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
srv.bind((HOST, 0))
srv.listen(4)
port = srv.getsockname()[1]

accepted = {}
def serve():
    conn, peer = srv.accept()
    accepted["peer"] = peer
    data = conn.recv(64)
    accepted["got"] = data
    conn.sendall(data[::-1])
    # A half-close is visible to the other end as an empty read.
    conn.shutdown(socket.SHUT_WR)
    conn.close()

t = threading.Thread(target=serve)
t.start()

cli = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
cli.settimeout(10.0)
cli.connect((HOST, port))
chk("tcp_getpeername", cli.getpeername() == (HOST, port))
cli.sendall(b"starry")
echoed = cli.recv(64)
chk("tcp_roundtrip", echoed == b"yrrats", repr(echoed))
chk("tcp_eof_after_peer_shutdown", cli.recv(64) == b"")
cli.close()
t.join(10.0)
chk("tcp_thread_finished", not t.is_alive())
chk("tcp_server_saw_payload", accepted.get("got") == b"starry")
chk("tcp_peer_is_loopback", accepted.get("peer", (None,))[0] == HOST)
srv.close()

# Connecting where nothing listens is refused, not silently accepted.
dead = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
dead.settimeout(10.0)
dead.bind((HOST, 0))
dead_port = dead.getsockname()[1]
dead.close()
probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
probe.settimeout(10.0)
try:
    probe.connect((HOST, dead_port))
    chk("tcp_connect_refused", False, "connected to a closed port")
except ConnectionRefusedError:
    chk("tcp_connect_refused", True)
except OSError as e:
    chk("tcp_connect_refused", e.errno == errno.ECONNREFUSED, "errno=%s" % e.errno)
probe.close()


# ============================================================================
# UDP over loopback — datagrams keep their boundaries, which is the whole
# difference from the stream above.
# ============================================================================

a = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
b = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
a.bind((HOST, 0))
b.bind((HOST, 0))
a.settimeout(10.0)
b.settimeout(10.0)
b.sendto(b"one", a.getsockname())
b.sendto(b"two", a.getsockname())
d1, from1 = a.recvfrom(64)
d2, _ = a.recvfrom(64)
chk("udp_first_datagram", d1 == b"one", repr(d1))
chk("udp_second_datagram", d2 == b"two", repr(d2))
chk("udp_sender_address", from1 == b.getsockname())
# A short buffer truncates the datagram rather than splitting it across reads.
b.sendto(b"abcdefgh", a.getsockname())
chk("udp_truncates_not_splits", a.recv(3) == b"abc")
a.close()
b.close()


# ============================================================================
# AF_UNIX socketpair — a connected pair with no name, which is how the
# standard library builds its own wakeup channels.
# ============================================================================

p, q = socket.socketpair()
p.sendall(b"ping")
chk("socketpair_transfer", q.recv(16) == b"ping")
q.sendall(b"pong")
chk("socketpair_reverse", p.recv(16) == b"pong")
chk("socketpair_type", p.type == socket.SOCK_STREAM)
p.close()
q.close()


# ============================================================================
# Readiness — select and poll over real descriptors, which every event loop
# in the standard library is built on.
# ============================================================================

p, q = socket.socketpair()
p.setblocking(False)
# Nothing has been sent, so nothing is readable.
r, _, _ = select.select([p], [], [], 0)
chk("select_idle_not_readable", r == [])
try:
    p.recv(16)
    chk("nonblocking_recv_raises", False)
except BlockingIOError:
    chk("nonblocking_recv_raises", True)
q.sendall(b"x")
r, _, _ = select.select([p], [], [], 5.0)
chk("select_reports_readable", r == [p])
chk("select_read_after_ready", p.recv(16) == b"x")

if hasattr(select, "poll"):
    poller = select.poll()
    poller.register(p, select.POLLIN)
    chk("poll_idle_empty", poller.poll(0) == [])
    q.sendall(b"y")
    events = poller.poll(5000)
    chk("poll_reports_readable", len(events) == 1 and events[0][0] == p.fileno())
    chk("poll_in_flag", bool(events[0][1] & select.POLLIN))
    poller.unregister(p)
    chk("poll_after_unregister", poller.poll(0) == [])
    p.recv(16)
p.close()
q.close()


# ============================================================================
# Name resolution — the numeric forms, which resolve with no resolver
# configured and therefore give the same answer anywhere.
# ============================================================================

info = socket.getaddrinfo(HOST, 80, socket.AF_INET, socket.SOCK_STREAM)
chk("getaddrinfo_returns_entries", len(info) >= 1)
chk("getaddrinfo_address", info[0][4] == (HOST, 80), repr(info[0][4]))
chk("getaddrinfo_family", info[0][0] == socket.AF_INET)
chk("getservbyname_http", socket.getservbyname("http", "tcp") == 80)
chk("hostname_is_a_string", isinstance(socket.gethostname(), str))


# ============================================================================
# Character devices (docs: null(4), zero(4), random(4)). how: read and write
# the standard nodes; expected: the documented behaviour of each; why: the
# standard library reaches for them for entropy and for a sink.
# ============================================================================

chk("dev_null_exists", os.path.exists("/dev/null"))
st = os.stat("/dev/null")
chk("dev_null_is_chardev", statmod.S_ISCHR(st.st_mode), oct(st.st_mode))
with open("/dev/null", "wb") as f:
    # A sink accepts everything and keeps nothing.
    chk("dev_null_write", f.write(b"discarded") == 9)
with open("/dev/null", "rb") as f:
    chk("dev_null_reads_eof", f.read(16) == b"")

if os.path.exists("/dev/zero"):
    with open("/dev/zero", "rb") as f:
        z = f.read(64)
    chk("dev_zero_length", len(z) == 64, "got %d" % len(z))
    chk("dev_zero_content", z == b"\x00" * 64)
    chk("dev_zero_is_chardev", statmod.S_ISCHR(os.stat("/dev/zero").st_mode))

if os.path.exists("/dev/urandom"):
    with open("/dev/urandom", "rb") as f:
        r1 = f.read(32)
        r2 = f.read(32)
    chk("dev_urandom_length", len(r1) == 32, "got %d" % len(r1))
    # Two reads returning the same 32 bytes would mean it is not a source of
    # entropy at all; the chance of a false failure is 2**-256.
    chk("dev_urandom_differs", r1 != r2)

# os.urandom is the same entropy through the interpreter's own path.
u1 = os.urandom(32)
chk("os_urandom_length", len(u1) == 32)
chk("os_urandom_differs", u1 != os.urandom(32))
chk("os_urandom_zero", os.urandom(0) == b"")

# The descriptors a process starts with are open and answer isatty either way.
for name, fd in (("stdin", 0), ("stdout", 1), ("stderr", 2)):
    chk("isatty_%s_answers" % name, isinstance(os.isatty(fd), bool))
chk("isatty_bad_fd", os.isatty(9999) is False)

# A device is opened by name like any other file, and a missing one reports
# ENOENT rather than an empty read.
try:
    open("/dev/definitely-not-a-device", "rb")
    chk("missing_device_raises", False)
except FileNotFoundError:
    chk("missing_device_raises", True)
except OSError as e:
    chk("missing_device_raises", e.errno == errno.ENOENT, "errno=%s" % e.errno)


# ============================================================================
# fcntl/ioctl on a real descriptor — the other way a program talks to a
# device, when the module is present.
# ============================================================================

try:
    import fcntl
except ImportError:
    fcntl = None
if fcntl is not None:
    p, q = socket.socketpair()
    flags = fcntl.fcntl(p.fileno(), fcntl.F_GETFL)
    fcntl.fcntl(p.fileno(), fcntl.F_SETFL, flags | os.O_NONBLOCK)
    chk("fcntl_setfl_sticks",
        fcntl.fcntl(p.fileno(), fcntl.F_GETFL) & os.O_NONBLOCK != 0)
    # FIONREAD reports what is waiting, which is how a device says how much
    # it has.
    def inq(sock):
        return struct.unpack("i", fcntl.ioctl(sock.fileno(), termios.FIONREAD,
                                              struct.pack("i", 0)))[0]

    import termios
    # A stream reports every byte queued, because a read is free to take them
    # all; nothing queued reports zero rather than failing.
    chk("ioctl_fionread_idle", inq(p) == 0)
    q.sendall(b"1234")
    chk("ioctl_fionread_stream", inq(p) == 4, "waiting=%d" % inq(p))
    q.sendall(b"56")
    chk("ioctl_fionread_stream_accumulates", inq(p) == 6, "waiting=%d" % inq(p))
    p.recv(4)
    chk("ioctl_fionread_after_read", inq(p) == 2, "waiting=%d" % inq(p))
    p.close()
    q.close()

    # A datagram socket reports the first datagram only: one receive returns
    # one datagram and discards what does not fit, so the total would mislead.
    da = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    db = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    da.bind((HOST, 0))
    da.settimeout(10.0)
    chk("ioctl_fionread_dgram_idle", inq(da) == 0)
    db.sendto(b"12345", da.getsockname())
    db.sendto(b"6789012345", da.getsockname())
    # Give the stack a moment to queue both before asking.
    select.select([da], [], [], 5.0)
    chk("ioctl_fionread_dgram_first_only", inq(da) == 5, "waiting=%d" % inq(da))
    chk("ioctl_fionread_dgram_read_matches", len(da.recv(64)) == 5)
    da.close()
    db.close()

    # A listening socket's queue holds connection requests, not bytes, so the
    # question means nothing and is refused rather than answered with zero.
    lis = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    lis.bind((HOST, 0))
    lis.listen(1)
    try:
        inq(lis)
        chk("ioctl_fionread_listening_refused", False, "answered instead")
    except OSError as e:
        chk("ioctl_fionread_listening_refused", e.errno == errno.EINVAL,
            "errno=%s" % e.errno)
    lis.close()


print(("PY_NETDEV_OK") if _ok else ("PY_NETDEV_FAIL"))
sys.exit(0 if _ok else 1)
