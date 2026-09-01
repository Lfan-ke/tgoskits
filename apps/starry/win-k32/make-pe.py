#!/usr/bin/env python3
"""Emit a PE32+ image that reaches the system through kernel32.

Unlike the win-abi case, nothing here traps directly: the program imports
GetStdHandle, WriteFile and ExitProcess from KERNEL32.dll and calls them through
its import address table, exactly as a compiler-built Windows program does. The
personality has to bind those imports to something callable, start the process
the way ntdll would, and serve the calls with Win32 conventions - a handle from
GetStdHandle, a BOOL and a byte count from WriteFile, no return from
ExitProcess. That whole path is what the case checks.
"""
import struct
import sys

IMAGE_BASE = 0x1_4000_0000
TEXT_RVA = 0x1000
RDATA_RVA = 0x2000
FILE_ALIGN = 0x200
SECT_ALIGN = 0x1000

MSG = b"WIN32-OK\n"
STD_OUTPUT_HANDLE = -11

# .rdata layout, as RVAs.
DESCRIPTORS = RDATA_RVA + 0x00   # two IMAGE_IMPORT_DESCRIPTORs, the second all zero
INT = RDATA_RVA + 0x40           # three name pointers and a terminator
IAT = RDATA_RVA + 0x80           # the same, rewritten by the loader
NAMES = RDATA_RVA + 0xC0         # hint/name entries
LIBRARY = RDATA_RVA + 0x100      # "KERNEL32.dll"
MESSAGE = RDATA_RVA + 0x140

FUNCTIONS = [b"GetStdHandle", b"WriteFile", b"ExitProcess"]


code = bytearray()
patches = []  # (offset of the disp32, rva of the instruction end, target rva)

def emit(prefix, target_rva, suffix=b""):
    """An instruction with a rip-relative disp32: prefix, disp32, suffix."""
    start = len(code)
    code.extend(prefix)
    disp_at = len(code)
    code.extend(b"\0\0\0\0")
    code.extend(suffix)
    patches.append((disp_at, TEXT_RVA + len(code), target_rva))

# The entry is called by the startup sequence, so rsp is 8 mod 16 here; taking
# 0x38 makes it 0 mod 16 for the calls below and leaves spill space, a fifth
# argument slot at [rsp+0x20], and a local at [rsp+0x30].
code += b"\x48\x83\xec\x38"                       # sub rsp, 0x38
code += b"\xb9" + struct.pack("<i", STD_OUTPUT_HANDLE)  # mov ecx, STD_OUTPUT_HANDLE
emit(b"\xff\x15", IAT + 0 * 8)                    # call [GetStdHandle]
code += b"\x48\x89\xc1"                           # mov rcx, rax
emit(b"\x48\x8d\x15", MESSAGE)                    # lea rdx, [message]
code += b"\x41\xb8" + struct.pack("<I", len(MSG)) # mov r8d, len
code += b"\x4c\x8d\x4c\x24\x30"                   # lea r9, [rsp+0x30]  (bytes written)
code += b"\x48\xc7\x44\x24\x20\0\0\0\0"           # mov qword [rsp+0x20], 0  (lpOverlapped)
emit(b"\xff\x15", IAT + 1 * 8)                    # call [WriteFile]
code += b"\x31\xc9"                               # xor ecx, ecx
emit(b"\xff\x15", IAT + 2 * 8)                    # call [ExitProcess]
code += b"\x0f\x0b"                               # ud2

for disp_at, end_rva, target in patches:
    struct.pack_into("<i", code, disp_at, target - end_rva)
text = bytes(code)

rdata = bytearray(0x200)
# IMAGE_IMPORT_DESCRIPTOR: OriginalFirstThunk, TimeDateStamp, ForwarderChain,
# Name, FirstThunk. The second descriptor stays zero and ends the table.
struct.pack_into("<IIIII", rdata, DESCRIPTORS - RDATA_RVA, INT, 0, 0, LIBRARY, IAT)
name_at = NAMES
for i, name in enumerate(FUNCTIONS):
    # IMAGE_IMPORT_BY_NAME: a two-byte hint, then the name.
    entry = name_at - RDATA_RVA
    rdata[entry:entry + 2] = b"\0\0"
    rdata[entry + 2:entry + 2 + len(name) + 1] = name + b"\0"
    struct.pack_into("<Q", rdata, INT - RDATA_RVA + i * 8, name_at)
    struct.pack_into("<Q", rdata, IAT - RDATA_RVA + i * 8, name_at)
    name_at += 2 + len(name) + 1
    name_at = (name_at + 1) & ~1
rdata[LIBRARY - RDATA_RVA:LIBRARY - RDATA_RVA + 13] = b"KERNEL32.dll\0"
rdata[MESSAGE - RDATA_RVA:MESSAGE - RDATA_RVA + len(MSG)] = MSG
rdata = bytes(rdata)


def raw_size(data):
    return (len(data) + FILE_ALIGN - 1) // FILE_ALIGN * FILE_ALIGN


text_raw = FILE_ALIGN * 2  # headers take one file-aligned block; .text follows
rdata_raw = text_raw + raw_size(text)
image = RDATA_RVA + (len(rdata) + SECT_ALIGN - 1) // SECT_ALIGN * SECT_ALIGN

dos = bytearray(0x40)
dos[0:2] = b"MZ"
struct.pack_into("<I", dos, 0x3C, 0x40)

coff = struct.pack("<HHIIIHH", 0x8664, 2, 0, 0, 0, 0xF0, 0x0022)

opt = struct.pack("<HBBIIIII", 0x20B, 14, 0, len(text), len(rdata), 0, TEXT_RVA, TEXT_RVA)
opt += struct.pack("<Q", IMAGE_BASE)
opt += struct.pack("<IIHHHHHHIIIIHH", SECT_ALIGN, FILE_ALIGN,
                   6, 0, 0, 0, 6, 0, 0, image, text_raw, 0, 3, 0)  # console subsystem
opt += struct.pack("<QQQQ", 0x10_0000, 0x1000, 0x10_0000, 0x1000)
opt += struct.pack("<II", 0, 16)
dirs = bytearray(16 * 8)
struct.pack_into("<II", dirs, 1 * 8, DESCRIPTORS, 40)      # import directory
struct.pack_into("<II", dirs, 12 * 8, IAT, 4 * 8)           # import address table
opt += bytes(dirs)
assert len(opt) == 0xF0, len(opt)

sections = struct.pack(
    "<8sIIIIIIHHI", b".text\0\0\0", len(text), TEXT_RVA, raw_size(text),
    text_raw, 0, 0, 0, 0, 0x6000_0020,
)
sections += struct.pack(
    "<8sIIIIIIHHI", b".rdata\0\0", len(rdata), RDATA_RVA, raw_size(rdata),
    rdata_raw, 0, 0, 0, 0, 0x4000_0040,
)

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
