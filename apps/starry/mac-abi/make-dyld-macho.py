#!/usr/bin/env python3
"""Emit a Mach-O image that reaches the system through libSystem.

The other image in this case traps directly; this one is shaped the way a real
macOS program is - it names /usr/lib/libSystem.B.dylib, calls `write` through a
pointer a bind fills in, and returns from `main` rather than exiting itself.
Nothing of libSystem exists on disk: the personality synthesizes it, so what
this exercises is the whole loader path - place, bind, and the code that runs
before and after `main`.
"""
import struct
import sys

VM_BASE = 0x1_0000_0000
PAGE = 0x1000
MSG = b"MAC-DYLD-OK\n"

HEADER_LEN = 32
SEG_LEN = 72
MAIN_LEN = 24
LIB = b"/usr/lib/libSystem.B.dylib"
DYLIB_LEN = (24 + len(LIB) + 1 + 7) // 8 * 8
INFO_LEN = 48
CMDS_LEN = SEG_LEN * 4 + MAIN_LEN + DYLIB_LEN + INFO_LEN
CODE_OFF = HEADER_LEN + CMDS_LEN

# __DATA holds the one pointer a bind fills in: where `write` ended up.
GOT = VM_BASE + PAGE

code = bytearray()
code += b"\xbf" + struct.pack("<I", 1)          # mov edi, 1
lea_at = len(code)
code += b"\x48\x8d\x35" + b"\0\0\0\0"           # lea rsi, [rip+msg]
code += b"\xba" + struct.pack("<I", len(MSG))   # mov edx, length
call_at = len(code)
code += b"\xff\x15" + b"\0\0\0\0"               # call [rip+got]
code += b"\x31\xc0"                             # xor eax, eax
code += b"\xc3"                                 # ret
msg_at = len(code)
code += MSG
struct.pack_into("<i", code, lea_at + 3, msg_at - (lea_at + 7))
struct.pack_into(
    "<i", code, call_at + 2, GOT - (VM_BASE + CODE_OFF + call_at + 6)
)

# One bind: `_write`, from the first library named, into __DATA + 0.
bind = bytearray()
bind += b"\x11"                                 # dylib ordinal 1
bind += b"\x40" + b"_write\0"                   # symbol, no flags
bind += b"\x51"                                 # type: pointer
bind += b"\x72\x00"                             # segment 2 (__DATA), offset 0
bind += b"\x90"                                 # do bind
bind += b"\x00"                                 # done

text_end = CODE_OFF + len(code)
link_off = PAGE * 2

header = struct.pack(
    "<IiiIIIII",
    0xFEED_FACF, 0x0100_0007, 3, 2, 7, CMDS_LEN, 0x0020_0085, 0,
)


def segment(name, vmaddr, vmsize, fileoff, filesize, prot):
    return struct.pack(
        "<II16sQQQQiiII",
        0x19, SEG_LEN, name, vmaddr, vmsize, fileoff, filesize, 7, prot, 0, 0,
    )


cmds = b"".join([
    segment(b"__PAGEZERO", 0, VM_BASE, 0, 0, 0),
    segment(b"__TEXT", VM_BASE, PAGE, 0, PAGE, 5),
    segment(b"__DATA", VM_BASE + PAGE, PAGE, PAGE, PAGE, 3),
    segment(b"__LINKEDIT", VM_BASE + PAGE * 2, PAGE, link_off, len(bind), 1),
    struct.pack("<IIQQ", 0x8000_0028, MAIN_LEN, CODE_OFF, 0),
    struct.pack("<IIIIII", 0x0C, DYLIB_LEN, 24, 0, 0x1_0000, 0x1_0000)
    + LIB.ljust(DYLIB_LEN - 24, b"\0"),
    # rebase, bind, weak, lazy, export: only the bind stream is here.
    struct.pack(
        "<IIIIIIIIIIII",
        0x8000_0022, INFO_LEN, 0, 0, link_off, len(bind), 0, 0, 0, 0, 0, 0,
    ),
])
assert len(cmds) == CMDS_LEN, (len(cmds), CMDS_LEN)

image = bytearray(link_off + len(bind))
image[0:HEADER_LEN] = header
image[HEADER_LEN:CODE_OFF] = cmds
image[CODE_OFF:text_end] = code
image[link_off:link_off + len(bind)] = bind

with open(sys.argv[1], "wb") as f:
    f.write(image)
