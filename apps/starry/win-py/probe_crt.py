"""Where a child's version line goes: to a file, and to a pipe."""
import os
import subprocess
import sys

PY = sys.executable
WORK = "Z:\\tmp"
os.makedirs(WORK, exist_ok=True)


def to_file(label, args):
    path = os.path.join(WORK, "out.txt")
    with open(path, "wb") as fh:
        r = subprocess.run([PY] + args, stdout=fh, stderr=subprocess.DEVNULL)
    with open(path, "rb") as fh:
        print("  %s rc=%r file=%r" % (label, r.returncode, fh.read()), flush=True)


def to_pipe(label, args):
    r = subprocess.run([PY] + args, capture_output=True, text=True)
    print("  %s rc=%r out=%r err=%r" % (label, r.returncode, r.stdout, r.stderr), flush=True)


# The C runtime's own buffered stdout, reached through ctypes.
print("=== the C runtime's own stdout", flush=True)
CRT = r"""
import ctypes, sys
crt = ctypes.CDLL("ucrtbase.dll")
crt.puts(b"crt-puts")
if %s:
    crt.fflush(None)
sys.stdout.write("py-write\n")
"""
for label, flush in (("with an explicit flush", "True"), ("with no flush", "False")):
    r = subprocess.run([PY, "-c", CRT % flush], capture_output=True, text=True)
    print("  %s rc=%r out=%r err=%r" % (label, r.returncode, r.stdout, r.stderr[-200:]), flush=True)

print("=== into a file", flush=True)
to_file("-V", ["-V"])
to_file("-h", ["-h"])
to_file("-c print", ["-c", "print('printed')"])
print("=== into a pipe", flush=True)
to_pipe("-V", ["-V"])
to_pipe("-c print", ["-c", "print('printed')"])
print("PROBE-CRT-DONE", flush=True)
