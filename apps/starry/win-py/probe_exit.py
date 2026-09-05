"""Why the C runtime's exit does not flush what was written before it.

`exit()` in ucrtbase runs one table of registered handlers and then ends the
process with TerminateProcess - which, unlike ExitProcess, runs no
DLL_PROCESS_DETACH, so whatever flushing happens has to be in that table. This
reads the table and then watches the behaviour either way.

Offsets are RVAs in the ucrtbase.dll this image ships, from disassembling
common_exit (0xa074c), its worker (0x48f14) and the table walker (0x49be0):
the pointer cookie is at 0x138480, the hook the worker calls before the table
at 0x139b18, and the two tables at 0x139e08 (quick) and 0x139e20 (full). A
stored pointer is `ror(value ^ cookie, cookie & 0x3f)`.
"""
import ctypes
import os
import subprocess
import sys

k32 = ctypes.CDLL("kernel32.dll")
k32.GetModuleHandleW.restype = ctypes.c_void_p
base = k32.GetModuleHandleW("ucrtbase.dll")
print("ucrtbase base = %#x" % (base or 0), flush=True)

MASK = (1 << 64) - 1


def read(rva, size=8):
    kind = {1: ctypes.c_uint8, 4: ctypes.c_uint32, 8: ctypes.c_uint64}[size]
    return ctypes.cast(ctypes.c_void_p(base + rva), ctypes.POINTER(kind))[0]


def at(address, size=8):
    kind = {1: ctypes.c_uint8, 4: ctypes.c_uint32, 8: ctypes.c_uint64}[size]
    return ctypes.cast(ctypes.c_void_p(address), ctypes.POINTER(kind))[0]


cookie = read(0x138480)
turn = cookie & 0x3F


def decode(value):
    value = (value ^ cookie) & MASK
    return ((value >> turn) | (value << (64 - turn))) & MASK


def named(value):
    return "%#x (ucrtbase+%#x)" % (value, value - base) if base <= value < base + (2 << 20) else "%#x" % value


print("cookie = %#x, rotate = %d" % (cookie, turn), flush=True)
print("hook = %s" % named(decode(read(0x139B18))), flush=True)
print("exit_complete = %d, in_progress = %d" % (read(0x139E00, 1), read(0x139E04, 4)), flush=True)

for name, table in (("quick", 0x139E08), ("full", 0x139E20)):
    first, last, end = (decode(read(table + i * 8)) for i in range(3))
    print("%s table: first=%#x last=%#x end=%#x entries=%d"
          % (name, first, last, end, (last - first) // 8 if last >= first else -1), flush=True)
    if first and last > first:
        for i in range((last - first) // 8):
            print("   [%d] %s" % (i, named(decode(at(first + i * 8)))), flush=True)

# And what actually happens to output written before exit, three ways: the
# runtime's own exit, the same with an explicit flush first, and the exit
# Python does. Whichever keeps the text says where the loss is.
WAYS = {
    "crt exit": "c.puts(b'MARK'); c.exit(0)",
    "crt exit after flushall": "c.puts(b'MARK'); c._flushall(); c.exit(0)",
    "crt exit after fflush(NULL)": "c.puts(b'MARK'); c.fflush(None); c.exit(0)",
    "sys.exit": "c.puts(b'MARK'); import sys; sys.exit(0)",
    "python print then crt exit": "print('MARK'); c.exit(0)",
}
for name, body in WAYS.items():
    code = "import ctypes; c = ctypes.CDLL('ucrtbase.dll'); " + body
    p = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True)
    print("%-30s rc=%d out=%r err=%r" % (name, p.returncode, p.stdout, p.stderr[-120:]), flush=True)

# The hypothesis: with no AppModel API to ask, common_exit takes the
# ExitProcess branch, and on Windows ExitProcess is what runs every loaded
# module's DllMain(DLL_PROCESS_DETACH) - which is where ucrtbase flushes. We
# do not run those, so nothing flushes. Calling ucrtbase's own entry point by
# hand should therefore make the text appear.
DETACH = (
    "import ctypes;"
    "k = ctypes.CDLL('kernel32.dll');"
    "k.GetModuleHandleW.restype = ctypes.c_void_p;"
    "b = k.GetModuleHandleW('ucrtbase.dll');"
    "c = ctypes.CDLL('ucrtbase.dll');"
    "c.puts(b'MARK');"
    "f = ctypes.CFUNCTYPE(ctypes.c_int, ctypes.c_void_p, ctypes.c_uint, ctypes.c_void_p)(b + 0x63c80);"
    "f(b, 0, None);"
    "c._exit(0)"
)
p = subprocess.run([sys.executable, "-c", DETACH], capture_output=True, text=True)
print("%-30s rc=%d out=%r err=%r" % ("detach by hand then _exit", p.returncode, p.stdout, p.stderr[-200:]), flush=True)

print("EXIT PROBE DONE", flush=True)
