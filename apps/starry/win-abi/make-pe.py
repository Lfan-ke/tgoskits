#!/usr/bin/env python3
"""Emit a PE32+ image that issues NT system calls directly.

No Win32 layer is involved: the program traps straight into whatever services
the NT ABI, which on StarryOS is the Windows personality package. That is the
whole point of the case - the same kernel runs it because a package claims it.
"""
import struct
import sys

IMAGE_BASE = 0x1_4000_0000
TEXT_RVA = 0x1000
FILE_ALIGN = 0x200
SECT_ALIGN = 0x1000

MSG = b"WIN-ABI-OK\n"
STDOUT_HANDLE = 8  # handle value 8 is descriptor 1

# NtWriteFile(handle, buffer, length, io_status), then NtTerminateProcess(_, 0).
# A null io_status is accepted, so the image needs no writable data.
code = bytearray()
code += b"\xb8" + struct.pack("<I", 1)                 # mov eax, NtWriteFile
code += b"\xbf" + struct.pack("<I", STDOUT_HANDLE)     # mov edi, handle
lea_at = len(code)
code += b"\x48\x8d\x35" + b"\0\0\0\0"                  # lea rsi, [rip+msg]
code += b"\xba" + struct.pack("<I", len(MSG))          # mov edx, length
code += b"\x45\x31\xd2"                                # xor r10d, r10d
code += b"\x0f\x05"                                    # syscall
code += b"\xb8" + struct.pack("<I", 7)                 # mov eax, NtTerminateProcess
code += b"\x31\xff"                                    # xor edi, edi
code += b"\x31\xf6"                                    # xor esi, esi
code += b"\x0f\x05"                                    # syscall
code += b"\x0f\x0b"                                    # ud2
msg_at = len(code)
code += MSG
struct.pack_into("<i", code, lea_at + 3, msg_at - (lea_at + 7))

text = bytes(code)
raw = (len(text) + FILE_ALIGN - 1) // FILE_ALIGN * FILE_ALIGN
image = (TEXT_RVA + (len(text) + SECT_ALIGN - 1) // SECT_ALIGN * SECT_ALIGN)

dos = bytearray(0x40)
dos[0:2] = b"MZ"
struct.pack_into("<I", dos, 0x3C, 0x40)

coff = struct.pack("<HHIIIHH", 0x8664, 1, 0, 0, 0, 0xF0, 0x0022)

opt = struct.pack(
    "<HBBIIIII",
    0x20B, 14, 0, len(text), 0, 0, TEXT_RVA, TEXT_RVA,
)
opt += struct.pack("<Q", IMAGE_BASE)
opt += struct.pack("<IIHHHHHHIIIIHH", SECT_ALIGN, FILE_ALIGN,
                   6, 0, 0, 0, 6, 0, 0, image, FILE_ALIGN, 0, 3, 0)
opt += struct.pack("<QQQQ", 0x10_0000, 0x1000, 0x10_0000, 0x1000)
opt += struct.pack("<II", 0, 16)
opt += b"\0" * (16 * 8)
assert len(opt) == 0xF0, len(opt)

section = struct.pack(
    "<8sIIIIIIHHI", b".text\0\0\0", len(text), TEXT_RVA, raw,
    FILE_ALIGN, 0, 0, 0, 0, 0x6000_0020,
)

out = bytearray(FILE_ALIGN)
out[0:0x40] = dos
at = 0x40
out[at:at + 4] = b"PE\0\0"
out[at + 4:at + 4 + len(coff)] = coff
at += 4 + len(coff)
out[at:at + len(opt)] = opt
at += len(opt)
out[at:at + len(section)] = section
out += text.ljust(raw, b"\0")

with open(sys.argv[1], "wb") as f:
    f.write(out)
