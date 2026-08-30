#!/usr/bin/env python3
"""Emit a PE32+ image that issues NT system calls directly.

No Win32 layer is involved: the program traps straight into whatever services
the NT ABI, which on StarryOS is the Windows personality package. That is the
whole point of the case - the same kernel runs it because a package claims it.

The calls are made the way the real ones are: `NtWriteFile` takes its nine
documented arguments, the first four in registers and the rest on the stack.
"""
import struct
import sys

IMAGE_BASE = 0x1_4000_0000
TEXT_RVA = 0x1000
FILE_ALIGN = 0x200
SECT_ALIGN = 0x1000

MSG = b"WIN-ABI-OK\n"
STDOUT_HANDLE = 8  # handle value 8 is descriptor 1

NT_WRITE_FILE = 1
NT_TERMINATE_PROCESS = 7


def trap(number):
    """Move the first four arguments where this kernel reads them, then trap.

    A Windows program passes its first four arguments in rcx, rdx, r8 and r9;
    this kernel reads a trap frame the way its host does, from rdi, rsi, rdx
    and r10. Arguments past the fourth stay on the stack, which is where both a
    Windows kernel and this one read them. A real ntdll stub does the same move
    for the same reason: the trap frame's shape belongs to the host, not to
    every ABI running on it.
    """
    out = bytearray()
    out += b"\x48\x89\xcf"                    # mov rdi, rcx
    out += b"\x48\x89\xd6"                    # mov rsi, rdx
    out += b"\x4c\x89\xc2"                    # mov rdx, r8
    out += b"\x4d\x89\xca"                    # mov r10, r9
    out += b"\xb8" + struct.pack("<I", number)
    out += b"\x0f\x05"                        # syscall
    return bytes(out)


# NtWriteFile(FileHandle, Event, ApcRoutine, ApcContext, IoStatusBlock, Buffer,
# Length, ByteOffset, Key). The four completion arguments this program does not
# use are null; the payload starts at the fifth and so lives on the stack.
code = bytearray()
code += b"\x48\x83\xec\x40"                                  # sub rsp, 0x40
code += b"\x48\xc7\xc1" + struct.pack("<i", STDOUT_HANDLE)   # mov rcx, handle
code += b"\x48\x31\xd2"                                      # xor rdx, rdx  Event
code += b"\x4d\x31\xc0"                                      # xor r8, r8    ApcRoutine
code += b"\x4d\x31\xc9"                                      # xor r9, r9    ApcContext
code += b"\x48\xc7\x04\x24" + struct.pack("<i", 0)           # [rsp+0x00] IoStatusBlock
lea_at = len(code)
code += b"\x48\x8d\x05" + b"\0\0\0\0"                        # lea rax, [rip+msg]
code += b"\x48\x89\x44\x24\x08"                              # [rsp+0x08] Buffer
code += b"\x48\xc7\x44\x24\x10" + struct.pack("<i", len(MSG))  # [rsp+0x10] Length
code += b"\x48\xc7\x44\x24\x18" + struct.pack("<i", 0)       # [rsp+0x18] ByteOffset
code += b"\x48\xc7\x44\x24\x20" + struct.pack("<i", 0)       # [rsp+0x20] Key
code += trap(NT_WRITE_FILE)

# NtTerminateProcess(ProcessHandle, ExitStatus).
code += b"\x48\x31\xc9"                                      # xor rcx, rcx
code += b"\x48\x31\xd2"                                      # xor rdx, rdx
code += trap(NT_TERMINATE_PROCESS)
code += b"\x0f\x0b"                                          # ud2
msg_at = len(code)
code += MSG
struct.pack_into("<i", code, lea_at + 3, msg_at - (lea_at + 7))

text = bytes(code)
raw = (len(text) + FILE_ALIGN - 1) // FILE_ALIGN * FILE_ALIGN
image = TEXT_RVA + (len(text) + SECT_ALIGN - 1) // SECT_ALIGN * SECT_ALIGN

dos = bytearray(0x40)
dos[0:2] = b"MZ"
struct.pack_into("<I", dos, 0x3C, 0x40)

coff = struct.pack("<HHIIIHH", 0x8664, 1, 0, 0, 0, 0xF0, 0x0022)

opt = struct.pack("<HBBIIIII", 0x20B, 14, 0, len(text), 0, 0, TEXT_RVA, TEXT_RVA)
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
