#!/usr/bin/env python3
"""Emit a PE32+ image that calls the real C runtime.

The program imports `puts` and `exit` from `ucrtbase.dll` - the Universal CRT
Microsoft ships - and nothing else. Loading it makes the personality find the
library beside the program or in the system directory, map and relocate it,
bind its own imports (a hundred and more kernel32 functions), run its entry
point with DLL_PROCESS_ATTACH so it initializes itself, and then serve whatever
`puts` needs to reach standard output. Nothing about the runtime is special-
cased: it is a file, and the loader treats it like any other.
"""
import struct
import sys

IMAGE_BASE = 0x1_4000_0000
TEXT_RVA = 0x1000
RDATA_RVA = 0x2000
FILE_ALIGN = 0x200
SECT_ALIGN = 0x1000

MSG = b"WIN-CRT-OK\0"  # puts adds the newline

DESCRIPTORS = RDATA_RVA + 0x00
INT = RDATA_RVA + 0x40
IAT = RDATA_RVA + 0x80
NAMES = RDATA_RVA + 0xC0
LIBRARY = RDATA_RVA + 0x100
MESSAGE = RDATA_RVA + 0x140

FUNCTIONS = [b"puts", b"exit"]

code = bytearray()
patches = []


def emit(prefix, target_rva):
    code.extend(prefix)
    disp_at = len(code)
    code.extend(b"\0\0\0\0")
    patches.append((disp_at, TEXT_RVA + len(code), target_rva))


# Called by the startup sequence, so rsp is 8 mod 16 here; 0x28 makes it 0
# mod 16 for the calls and leaves the spill space a callee may use.
code += b"\x48\x83\xec\x28"          # sub rsp, 0x28
emit(b"\x48\x8d\x0d", MESSAGE)       # lea rcx, [message]
emit(b"\xff\x15", IAT + 0 * 8)       # call [puts]
code += b"\x31\xc9"                  # xor ecx, ecx
emit(b"\xff\x15", IAT + 1 * 8)       # call [exit]
code += b"\x0f\x0b"                  # ud2

for disp_at, end_rva, target in patches:
    struct.pack_into("<i", code, disp_at, target - end_rva)
text = bytes(code)

rdata = bytearray(0x200)
struct.pack_into("<IIIII", rdata, DESCRIPTORS - RDATA_RVA, INT, 0, 0, LIBRARY, IAT)
name_at = NAMES
for i, name in enumerate(FUNCTIONS):
    entry = name_at - RDATA_RVA
    rdata[entry + 2:entry + 2 + len(name) + 1] = name + b"\0"
    struct.pack_into("<Q", rdata, INT - RDATA_RVA + i * 8, name_at)
    struct.pack_into("<Q", rdata, IAT - RDATA_RVA + i * 8, name_at)
    name_at = (name_at + 2 + len(name) + 1 + 1) & ~1
rdata[LIBRARY - RDATA_RVA:LIBRARY - RDATA_RVA + 13] = b"ucrtbase.dll\0"
rdata[MESSAGE - RDATA_RVA:MESSAGE - RDATA_RVA + len(MSG)] = MSG
rdata = bytes(rdata)


def raw_size(data):
    return (len(data) + FILE_ALIGN - 1) // FILE_ALIGN * FILE_ALIGN


text_raw = FILE_ALIGN * 2
rdata_raw = text_raw + raw_size(text)
image = RDATA_RVA + (len(rdata) + SECT_ALIGN - 1) // SECT_ALIGN * SECT_ALIGN

dos = bytearray(0x40)
dos[0:2] = b"MZ"
struct.pack_into("<I", dos, 0x3C, 0x40)
coff = struct.pack("<HHIIIHH", 0x8664, 2, 0, 0, 0, 0xF0, 0x0022)
opt = struct.pack("<HBBIIIII", 0x20B, 14, 0, len(text), len(rdata), 0, TEXT_RVA, TEXT_RVA)
opt += struct.pack("<Q", IMAGE_BASE)
opt += struct.pack("<IIHHHHHHIIIIHH", SECT_ALIGN, FILE_ALIGN,
                   6, 0, 0, 0, 6, 0, 0, image, text_raw, 0, 3, 0)
opt += struct.pack("<QQQQ", 0x10_0000, 0x1000, 0x10_0000, 0x1000)
opt += struct.pack("<II", 0, 16)
dirs = bytearray(16 * 8)
struct.pack_into("<II", dirs, 1 * 8, DESCRIPTORS, 40)
struct.pack_into("<II", dirs, 12 * 8, IAT, 3 * 8)
opt += bytes(dirs)
assert len(opt) == 0xF0, len(opt)

sections = struct.pack("<8sIIIIIIHHI", b".text\0\0\0", len(text), TEXT_RVA, raw_size(text),
                       text_raw, 0, 0, 0, 0, 0x6000_0020)
sections += struct.pack("<8sIIIIIIHHI", b".rdata\0\0", len(rdata), RDATA_RVA, raw_size(rdata),
                        rdata_raw, 0, 0, 0, 0, 0x4000_0040)

out = bytearray(text_raw)
out[0:0x40] = dos
at = 0x40
out[at:at + 4] = b"PE\0\0"
out[at + 4:at + 4 + len(coff)] = coff
at += 4 + len(coff)
out[at:at + len(opt)] = opt
at += len(opt)
out[at:at + len(sections)] = sections
out += text.ljust(raw_size(text), b"\0")
out += rdata.ljust(raw_size(rdata), b"\0")

with open(sys.argv[1], "wb") as f:
    f.write(out)
