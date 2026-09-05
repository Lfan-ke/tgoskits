"""Whether a section is really shared memory, and a semaphore really counts.

Two processes are the point: the child is given the handle number and has to
find the same page and the same count behind it. Every step prints before and
after itself, so the last line says which one did not come back.
"""
import ctypes
import os
import subprocess
import sys

k32 = ctypes.WinDLL("kernel32") if hasattr(ctypes, "WinDLL") else ctypes.CDLL("kernel32.dll")

INVALID = ctypes.c_void_p(-1)
PAGE_READWRITE = 0x04
FILE_MAP_ALL_ACCESS = 0x000F001F
WAIT_OBJECT_0 = 0
WAIT_TIMEOUT = 0x102
ERROR_TOO_MANY_POSTS = 298
PATTERN = 0xABCD1234


def say(name, value):
    print("   %s = %r" % (name, value), flush=True)


def section(size=4096):
    k32.CreateFileMappingW.restype = ctypes.c_void_p
    return k32.CreateFileMappingW(INVALID, None, PAGE_READWRITE, 0, size, None)


def view(handle, size=4096):
    k32.MapViewOfFile.restype = ctypes.c_void_p
    return k32.MapViewOfFile(ctypes.c_void_p(handle), FILE_MAP_ALL_ACCESS, 0, 0, size)


def word_at(at):
    return ctypes.cast(ctypes.c_void_p(at), ctypes.POINTER(ctypes.c_uint32))


def child():
    handle = int(os.environ["PROBE_SECTION"])
    semaphore = int(os.environ["PROBE_SEMAPHORE"])
    at = view(handle)
    print("child view = %#x" % (at or 0), flush=True)
    print("child sees %#x" % (word_at(at)[0] if at else 0), flush=True)
    if at:
        word_at(at)[1] = PATTERN ^ 0xFFFF
    print("child wait = %d" % k32.WaitForSingleObject(ctypes.c_void_p(semaphore), 0), flush=True)
    print("CHILD DONE", flush=True)


def parent():
    print("-> section", flush=True)
    handle = section()
    say("handle", handle)
    print("-> view", flush=True)
    at = view(handle)
    say("at", hex(at or 0))
    word_at(at)[0] = PATTERN
    say("read back", hex(word_at(at)[0]))

    print("-> semaphore", flush=True)
    k32.CreateSemaphoreW.restype = ctypes.c_void_p
    sem = k32.CreateSemaphoreW(None, 2, 2, None)
    say("semaphore", sem)
    wait = lambda: k32.WaitForSingleObject(ctypes.c_void_p(sem), 0)
    say("first", wait())
    say("second", wait())
    say("third (want 258)", wait())
    say("release past the top (want 0)", k32.ReleaseSemaphore(ctypes.c_void_p(sem), 3, None))
    say("last error (want 298)", k32.GetLastError())
    say("release one (want 1)", k32.ReleaseSemaphore(ctypes.c_void_p(sem), 1, None))

    print("-> child", flush=True)
    env = dict(os.environ, PROBE_SECTION=str(handle), PROBE_SEMAPHORE=str(sem), PROBE_CHILD="1")
    out = subprocess.run([sys.executable, __file__], env=env, capture_output=True, text=True)
    print(out.stdout, flush=True)
    print(out.stderr, flush=True)
    say("child rc", out.returncode)
    say("what the child wrote (want %#x)" % (PATTERN ^ 0xFFFF), hex(word_at(at)[1]))
    say("count after the child took one (want 258)", wait())
    print("PROBE DONE", flush=True)


if os.environ.get("PROBE_CHILD"):
    child()
else:
    parent()
