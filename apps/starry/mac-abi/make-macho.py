#!/usr/bin/env python3
"""Emit a Mach-O image that issues Darwin system calls directly.

No dyld, no libSystem: the program traps into whatever services the BSD half of
the Darwin ABI, which on StarryOS is the Darwin personality package.
"""
import struct
import sys

VM_BASE = 0x1_0000_0000
PAGE = 0x1000
CLASS_UNIX = 2 << 24

MSG = b"MAC-ABI-OK\n"

HEADER_LEN = 32
SEG_LEN = 72
MAIN_LEN = 24
CODE_OFF = HEADER_LEN + SEG_LEN + MAIN_LEN

code = bytearray()
code += b"\xb8" + struct.pack("<I", CLASS_UNIX | 4)   # mov eax, write
code += b"\xbf" + struct.pack("<I", 1)                # mov edi, 1
lea_at = len(code)
code += b"\x48\x8d\x35" + b"\0\0\0\0"                 # lea rsi, [rip+msg]
code += b"\xba" + struct.pack("<I", len(MSG))         # mov edx, length
code += b"\x0f\x05"                                   # syscall
code += b"\xb8" + struct.pack("<I", CLASS_UNIX | 1)   # mov eax, exit
code += b"\x31\xff"                                   # xor edi, edi
code += b"\x0f\x05"                                   # syscall
code += b"\x0f\x0b"                                   # ud2
msg_at = len(code)
code += MSG
struct.pack_into("<i", code, lea_at + 3, msg_at - (lea_at + 7))

file_size = CODE_OFF + len(code)
vm_size = (file_size + PAGE - 1) // PAGE * PAGE

header = struct.pack(
    "<IiiIIIII",
    0xFEED_FACF, 0x0100_0007, 3, 2, 2, SEG_LEN + MAIN_LEN, 0x0000_0001, 0,
)
segment = struct.pack(
    "<II16sQQQQiiII",
    0x19, SEG_LEN, b"__TEXT", VM_BASE, vm_size, 0, file_size, 7, 5, 0, 0,
)
main = struct.pack("<IIQQ", 0x8000_0028, MAIN_LEN, CODE_OFF, 0)

with open(sys.argv[1], "wb") as f:
    f.write(header + segment + main + bytes(code))
