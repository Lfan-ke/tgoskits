"""Why the C runtime's exit does not flush what was written before it.

`exit()` in ucrtbase runs the atexit table and then ends the process. If the
output written before it is lost, either the table is empty or the flush hook
it would call was never registered - both of which are readable, so this reads
them rather than guessing.

Offsets are RVAs in the ucrtbase.dll this image ships; they come from
disassembling common_exit (0xa074c) and the worker it calls (0x48f14).
"""
import ctypes

k32 = ctypes.CDLL("kernel32.dll")
k32.GetModuleHandleW.restype = ctypes.c_void_p
base = k32.GetModuleHandleW("ucrtbase.dll")
print("ucrtbase base = %#x" % (base or 0), flush=True)

# Where common_exit's worker looks: the encoded hook it calls before the table,
# the cookie it decodes with, the "exit is done" and "exit is running" flags,
# and the two onexit tables (quick and full), each three pointers.
FIELDS = [
    ("hook (encoded)", 0x138480, 8),
    ("cookie", 0x139B18, 8),
    ("exit_complete", 0x139E00, 1),
    ("exit_in_progress", 0x139E04, 4),
    ("quick table first", 0x139E08, 8),
    ("quick table last", 0x139E10, 8),
    ("quick table end", 0x139E18, 8),
    ("atexit table first", 0x139E20, 8),
    ("atexit table last", 0x139E28, 8),
    ("atexit table end", 0x139E30, 8),
]


def read(rva, size):
    at = base + rva
    kind = {1: ctypes.c_uint8, 4: ctypes.c_uint32, 8: ctypes.c_uint64}[size]
    return ctypes.cast(ctypes.c_void_p(at), ctypes.POINTER(kind))[0]


for name, rva, size in FIELDS:
    try:
        print("%-20s @%#x = %#x" % (name, rva, read(rva, size)), flush=True)
    except BaseException as e:
        print("%-20s @%#x !! %s" % (name, rva, e), flush=True)

hook, cookie = read(0x138480, 8), read(0x139B18, 8)
print("hook is null: %s" % (hook == cookie), flush=True)
first, last = read(0x139E20, 8), read(0x139E28, 8)
print("atexit table is empty: %s" % (first == last), flush=True)

# What the table holds, if anything: each entry is one encoded function
# pointer, decoded the way the worker decodes the hook.
if first not in (0, cookie) and last not in (0, cookie):
    put = ctypes.cast(ctypes.c_void_p(first), ctypes.POINTER(ctypes.c_uint64))
    count = max(0, min(32, (last - first) // 8))
    print("atexit entries = %d" % count, flush=True)
    for i in range(count):
        raw = put[i]
        turn = cookie & 0x3F
        value = (raw ^ cookie) & 0xFFFFFFFFFFFFFFFF
        value = ((value >> turn) | (value << (64 - turn))) & 0xFFFFFFFFFFFFFFFF
        print("  [%d] raw=%#x decoded=%#x rva=%#x" % (i, raw, value, value - base), flush=True)

print("PROBE DONE", flush=True)
