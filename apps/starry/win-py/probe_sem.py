"""Two questions this answers: are two semaphores really separate objects, and
which call inside multiprocessing's Pipe() ends the process.

Each step prints before and after itself. A step that never prints its result
is the one that did not come back.
"""
import ctypes
import os

k32 = ctypes.CDLL("kernel32.dll")
k32.CreateSemaphoreW.restype = ctypes.c_void_p
WAIT_OBJECT_0 = 0
WAIT_TIMEOUT = 0x102


def sem(initial, maximum):
    return k32.CreateSemaphoreW(None, initial, maximum, None)


def take(handle):
    return k32.WaitForSingleObject(ctypes.c_void_p(handle), 0)


print("== semaphores are their own objects", flush=True)
SHAPES = [(1, 1), (0, 0x7FFFFFFF), (0, 0x7FFFFFFF), (2, 5), (0, 1)]
made = []
for i, (initial, maximum) in enumerate(SHAPES):
    handle = sem(initial, maximum)
    made.append((handle, initial))
    print("  sem%d handle=%#x initial=%d" % (i, handle or 0, initial), flush=True)
for i, (handle, initial) in enumerate(made):
    # Exactly `initial` takes succeed and the next one times out - unless the
    # handle names something other than the semaphore it was made as.
    got = [take(handle) for _ in range(initial + 1)]
    want = [WAIT_OBJECT_0] * initial + [WAIT_TIMEOUT]
    print("  sem%d takes=%r want=%r %s"
          % (i, got, want, "ok" if got == want else "WRONG"), flush=True)

print("== what multiprocessing sees, on the same objects", flush=True)
import multiprocessing as mp

ctx = mp.get_context("spawn")
s0 = ctx.Semaphore(0)
print("  Semaphore(0) handle=%#x" % s0._semlock.handle, flush=True)
print("  its own acquire(False) = %r (want False)" % s0.acquire(False), flush=True)
print("  a raw wait on the same handle = %d (want 258)"
      % take(s0._semlock.handle), flush=True)
ev = ctx.Event()
print("  Event() flag handle=%#x raw wait=%d (want 258)"
      % (ev._flag._semlock.handle, take(ev._flag._semlock.handle)), flush=True)
print("  Event().is_set() = %r (want False)" % ev.is_set(), flush=True)

print("== the same pipe through ctypes, no _winapi in the way", flush=True)
PIPE_ACCESS_DUPLEX = 0x00000003
FILE_FLAG_OVERLAPPED = 0x40000000
FILE_FLAG_FIRST_PIPE_INSTANCE = 0x00080000
PIPE_TYPE_MESSAGE = 0x0004
PIPE_READMODE_MESSAGE = 0x0002
NMPWAIT_WAIT_FOREVER = 0xFFFFFFFF

raw_name = r"\\.\pipe\pyc-raw-%d" % os.getpid()
k32.CreateNamedPipeW.restype = ctypes.c_void_p
print("  calling CreateNamedPipeW", flush=True)
raw = k32.CreateNamedPipeW(
    ctypes.c_wchar_p(raw_name),
    PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED | FILE_FLAG_FIRST_PIPE_INSTANCE,
    PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE,
    1, 8192, 8192, NMPWAIT_WAIT_FOREVER, None)
print("  CreateNamedPipeW -> %#x last_error=%d" % (raw or 0, k32.GetLastError()), flush=True)

print("== Pipe(), one _winapi call at a time", flush=True)
import _winapi
print("  _winapi imported", flush=True)
from multiprocessing.connection import BUFSIZE, Pipe
print("  connection imported", flush=True)


def step(name, fn):
    print("-> " + name, flush=True)
    try:
        value = fn()
    except BaseException as e:
        print("   !! %s: %s" % (type(e).__name__, e), flush=True)
        return None
    print("   ok %r" % (value,), flush=True)
    return value


address = r"\\.\pipe\pyc-probe-%d" % os.getpid()
h1 = step("CreateNamedPipe", lambda: _winapi.CreateNamedPipe(
    address,
    _winapi.PIPE_ACCESS_DUPLEX | _winapi.FILE_FLAG_OVERLAPPED
    | _winapi.FILE_FLAG_FIRST_PIPE_INSTANCE,
    _winapi.PIPE_TYPE_MESSAGE | _winapi.PIPE_READMODE_MESSAGE | _winapi.PIPE_WAIT,
    1, BUFSIZE, BUFSIZE, _winapi.NMPWAIT_WAIT_FOREVER, _winapi.NULL))
h2 = step("CreateFile", lambda: _winapi.CreateFile(
    address, _winapi.GENERIC_READ | _winapi.GENERIC_WRITE, 0, _winapi.NULL,
    _winapi.OPEN_EXISTING, _winapi.FILE_FLAG_OVERLAPPED, _winapi.NULL))
step("SetNamedPipeHandleState", lambda: _winapi.SetNamedPipeHandleState(
    h2, _winapi.PIPE_READMODE_MESSAGE, None, None))
ov = step("ConnectNamedPipe(overlapped)",
          lambda: _winapi.ConnectNamedPipe(h1, overlapped=True))
if ov is not None:
    step("GetOverlappedResult(True)", lambda: ov.GetOverlappedResult(True))
step("connection.Pipe()", Pipe)
print("SEM PROBE DONE", flush=True)
