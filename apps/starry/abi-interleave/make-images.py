#!/usr/bin/env python3
"""Emit three images, one per ABI, that each print their own letter.

The point is what happens when all three run at once: they are three ordinary
processes on one kernel, and the kernel services each one's traps through the
package that ABI belongs to. Interleaved output is that working under a
scheduler rather than one program at a time.

The ELF is the odd one out - the case runs an ordinary shell loop for it, since
a shell is already an ELF served by the Linux package.
"""
import struct
import sys

REPEATS = 40

# --- PE32+, printing W through NT calls ------------------------------------

PE_BASE = 0x1_4000_0000
NT_WRITE_FILE = 1
NT_TERMINATE_PROCESS = 7
NT_YIELD_EXECUTION = 9
NT_QUERY_INFORMATION_PROCESS = 8
STDOUT_HANDLE = 8


def nt_trap(number):
    """Windows passes its first four in rcx/rdx/r8/r9; this kernel reads a trap
    frame from rdi/rsi/rdx/r10, and arguments past the fourth stay on the stack
    where both read them. The move is what a real ntdll stub does."""
    out = bytearray()
    out += b"\x48\x89\xcf\x48\x89\xd6\x4c\x89\xc2\x4d\x89\xca"
    out += b"\xb8" + struct.pack("<I", number)
    out += b"\x0f\x05"
    return bytes(out)


def build_pe():
    code = bytearray()
    # The imm8 form sign-extends, so 0x80 would be -128 and move the stack the
    # wrong way; this is the imm32 form.
    code += b"\x48\x81\xec" + struct.pack("<I", 0x80)            # sub rsp, 0x80
    # NtQueryInformationProcess(handle, ProcessBasicInformation, buf, len, NULL)
    # leaves the process id at buf+32, which the case reads back out.
    code += b"\x48\xc7\xc1" + struct.pack("<i", -1)              # current process
    code += b"\x48\x31\xd2"                                      # class 0
    code += b"\x4c\x8d\x44\x24\x40"                             # r8 = rsp+0x40
    code += b"\x41\xb9" + struct.pack("<I", 48)                   # r9 = 48
    code += b"\x48\xc7\x04\x24" + struct.pack("<i", 0)          # ReturnLength NULL
    code += nt_trap(NT_QUERY_INFORMATION_PROCESS)
    # Make the query load-bearing: if it did not answer, print nothing, so the
    # case's letter check catches it rather than it passing unnoticed.
    code += b"\x85\xc0"                                           # test eax, eax
    bail_at = len(code)
    code += b"\x0f\x85" + b"\0\0\0\0"                           # jnz done
    code += b"\x41\xbc" + struct.pack("<I", REPEATS)              # mov r12d, REPEATS
    loop = len(code)
    code += b"\x48\xc7\xc1" + struct.pack("<i", STDOUT_HANDLE)    # mov rcx, handle
    code += b"\x48\x31\xd2\x4d\x31\xc0\x4d\x31\xc9"               # Event/Apc null
    code += b"\x48\xc7\x04\x24" + struct.pack("<i", 0)            # IoStatusBlock
    lea_at = len(code)
    code += b"\x48\x8d\x05" + b"\0\0\0\0"                         # lea rax, [rip+msg]
    code += b"\x48\x89\x44\x24\x08"                               # Buffer
    code += b"\x48\xc7\x44\x24\x10" + struct.pack("<i", 1)        # Length
    code += b"\x48\xc7\x44\x24\x18" + struct.pack("<i", 0)        # ByteOffset
    code += b"\x48\xc7\x44\x24\x20" + struct.pack("<i", 0)        # Key
    code += nt_trap(NT_WRITE_FILE)
    code += nt_trap(NT_YIELD_EXECUTION)   # give the others a turn
    code += b"\x41\xff\xcc"                                       # dec r12d
    back = loop - (len(code) + 2)
    code += b"\x75" + struct.pack("<b", back)                     # jnz loop
    done_at = len(code)
    struct.pack_into("<i", code, bail_at + 2, done_at - (bail_at + 6))
    code += b"\x48\x31\xc9\x48\x31\xd2"                           # handle/status 0
    code += nt_trap(NT_TERMINATE_PROCESS)
    code += b"\x0f\x0b"
    msg_at = len(code)
    code += b"W"
    struct.pack_into("<i", code, lea_at + 3, msg_at - (lea_at + 7))
    return pe_wrap(bytes(code))


def pe_wrap(text):
    file_align, sect_align, text_rva = 0x200, 0x1000, 0x1000
    raw = (len(text) + file_align - 1) // file_align * file_align
    image = text_rva + (len(text) + sect_align - 1) // sect_align * sect_align
    dos = bytearray(0x40)
    dos[0:2] = b"MZ"
    struct.pack_into("<I", dos, 0x3C, 0x40)
    coff = struct.pack("<HHIIIHH", 0x8664, 1, 0, 0, 0, 0xF0, 0x0022)
    opt = struct.pack("<HBBIIIII", 0x20B, 14, 0, len(text), 0, 0, text_rva, text_rva)
    opt += struct.pack("<Q", PE_BASE)
    opt += struct.pack("<IIHHHHHHIIIIHH", sect_align, file_align,
                       6, 0, 0, 0, 6, 0, 0, image, file_align, 0, 3, 0)
    opt += struct.pack("<QQQQ", 0x10_0000, 0x1000, 0x10_0000, 0x1000)
    opt += struct.pack("<II", 0, 16) + b"\0" * (16 * 8)
    section = struct.pack("<8sIIIIIIHHI", b".text\0\0\0", len(text), text_rva, raw,
                          file_align, 0, 0, 0, 0, 0x6000_0020)
    out = bytearray(file_align)
    out[0:0x40] = dos
    at = 0x40
    out[at:at + 4] = b"PE\0\0"
    out[at + 4:at + 4 + len(coff)] = coff
    at += 4 + len(coff)
    out[at:at + len(opt)] = opt
    out[at + len(opt):at + len(opt) + len(section)] = section
    out += text.ljust(raw, b"\0")
    return bytes(out)


# --- Mach-O, printing M through Darwin calls -------------------------------

MACHO_BASE = 0x1_0000_0000
CLASS_UNIX = 2 << 24
CLASS_MACH = 1 << 24
SWTCH_PRI = 59   # what libc's sched_yield issues


def build_macho():
    header_len, seg_len, main_len = 32, 72, 24
    code_off = header_len + seg_len + main_len

    code = bytearray()
    code += b"\x41\xbc" + struct.pack("<I", REPEATS)   # mov r12d, REPEATS
    loop = len(code)
    code += b"\xb8" + struct.pack("<I", CLASS_UNIX | 4)  # write
    code += b"\xbf" + struct.pack("<I", 1)               # fd 1
    lea_at = len(code)
    code += b"\x48\x8d\x35" + b"\0\0\0\0"                # lea rsi, [rip+msg]
    code += b"\xba" + struct.pack("<I", 1)               # length 1
    code += b"\x0f\x05"
    code += b"\xb8" + struct.pack("<I", CLASS_MACH | SWTCH_PRI)  # sched_yield
    code += b"\x31\xff"                                 # arg 0
    code += b"\x0f\x05"
    code += b"\x41\xff\xcc"                              # dec r12d
    back = loop - (len(code) + 2)
    code += b"\x75" + struct.pack("<b", back)
    code += b"\xb8" + struct.pack("<I", CLASS_UNIX | 1)  # exit
    code += b"\x31\xff\x0f\x05\x0f\x0b"
    msg_at = len(code)
    code += b"M"
    struct.pack_into("<i", code, lea_at + 3, msg_at - (lea_at + 7))

    file_size = code_off + len(code)
    vm_size = (file_size + 0xFFF) // 0x1000 * 0x1000
    header = struct.pack("<IiiIIIII", 0xFEED_FACF, 0x0100_0007, 3, 2, 2,
                         seg_len + main_len, 0x0000_0001, 0)
    segment = struct.pack("<II16sQQQQiiII", 0x19, seg_len, b"__TEXT",
                          MACHO_BASE, vm_size, 0, file_size, 7, 5, 0, 0)
    main = struct.pack("<IIQQ", 0x8000_0028, main_len, code_off, 0)
    return header + segment + main + bytes(code)


out = sys.argv[1]
with open(f"{out}/interleave.exe", "wb") as f:
    f.write(build_pe())
with open(f"{out}/interleave.macho", "wb") as f:
    f.write(build_macho())
