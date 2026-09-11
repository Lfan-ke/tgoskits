#!/usr/bin/env python3
"""Prove the page reached the screen by reading the guest's own scanout.

The guest asks the host's QEMU VNC server - reachable as 10.0.2.2 through
SLIRP - for a raw framebuffer and counts distinct colours on a 4-pixel grid.
On StarryOS and Linux alike the bare Weston desktop shows about 33 colours and
Firefox's window before the page paints 63 to 93, while a painted 4399 page
shows thousands. Navigation and cache entries only show the document was
fetched; this shows it was drawn.

Usage: render-check.py HOST PORT [MIN_COLOURS]
"""

import socket
import struct
import sys


def recv_exact(sock, size):
    data = bytearray()
    while len(data) < size:
        chunk = sock.recv(size - len(data))
        if not chunk:
            raise EOFError(f"server closed after {len(data)} of {size} bytes")
        data += chunk
    return bytes(data)


def handshake(sock):
    greeting = recv_exact(sock, 12)
    if not greeting.startswith(b"RFB 003."):
        raise ValueError(f"not an RFB greeting: {greeting!r}")
    sock.sendall(b"RFB 003.008\n")
    count = recv_exact(sock, 1)[0]
    if count == 0:
        (length,) = struct.unpack(">I", recv_exact(sock, 4))
        raise ValueError(f"server refused the connection: {recv_exact(sock, length)!r}")
    if 1 not in recv_exact(sock, count):
        raise ValueError("security type None not offered")
    sock.sendall(b"\x01")
    if struct.unpack(">I", recv_exact(sock, 4))[0] != 0:
        raise ValueError("security handshake failed")
    sock.sendall(b"\x01")
    width, height = struct.unpack(">HH", recv_exact(sock, 4))
    recv_exact(sock, 16)
    (name_length,) = struct.unpack(">I", recv_exact(sock, 4))
    recv_exact(sock, name_length)
    return width, height


def raw_frame(sock, width, height):
    # 32bpp little-endian true colour stores every pixel as B, G, R, padding.
    sock.sendall(struct.pack(">BxxxBBBBHHHBBBxxx", 0, 32, 24, 0, 1, 255, 255, 255, 16, 8, 0))
    sock.sendall(struct.pack(">BxHi", 2, 1, 0))
    sock.sendall(struct.pack(">BBHHHH", 3, 0, 0, 0, width, height))
    frame = bytearray(width * height * 4)
    while True:
        kind = recv_exact(sock, 1)[0]
        if kind == 0:
            recv_exact(sock, 1)
            (rects,) = struct.unpack(">H", recv_exact(sock, 2))
            for _ in range(rects):
                x, y, w, h, encoding = struct.unpack(">HHHHi", recv_exact(sock, 12))
                if encoding != 0:
                    raise ValueError(f"server answered with encoding {encoding}, not raw")
                data = recv_exact(sock, w * h * 4)
                for row in range(h):
                    start = ((y + row) * width + x) * 4
                    frame[start:start + w * 4] = data[row * w * 4:(row + 1) * w * 4]
            return frame
        if kind == 1:
            recv_exact(sock, 1)
            _, entries = struct.unpack(">HH", recv_exact(sock, 4))
            recv_exact(sock, entries * 6)
        elif kind == 3:
            recv_exact(sock, 3)
            (length,) = struct.unpack(">I", recv_exact(sock, 4))
            recv_exact(sock, length)
        elif kind != 2:
            raise ValueError(f"unexpected server message type {kind}")


def main():
    host, port = sys.argv[1], int(sys.argv[2])
    minimum = int(sys.argv[3]) if len(sys.argv) > 3 else 1000
    with socket.create_connection((host, port), timeout=60) as sock:
        width, height = handshake(sock)
        frame = raw_frame(sock, width, height)
    colours = {bytes(frame[i:i + 3]) for i in range(0, len(frame), 16)}
    print(f"WEB_BROWSER_RENDER scanout={width}x{height} colours={len(colours)} minimum={minimum}", flush=True)
    return 0 if len(colours) >= minimum else 1


if __name__ == "__main__":
    sys.exit(main())
