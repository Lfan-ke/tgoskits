"""Where multiprocessing's spawn falls over, one step at a time.

Each step prints before and after itself, so the last line printed names the
call that did not come back - which is what a process that ends by abort()
leaves behind, since it says nothing on the way out.
"""
import multiprocessing as mp
import os
import sys


def step(name, fn):
    print("-> " + name, flush=True)
    try:
        value = fn()
    except BaseException as e:
        print("   !! %s: %s" % (type(e).__name__, e), flush=True)
        return None
    print("   ok %r" % (value,), flush=True)
    return value


def target(q, value):
    q.put((os.getpid(), value * 2))


def main():
    mp.freeze_support()
    ctx = step("get_context('spawn')", lambda: mp.get_context("spawn"))
    if ctx is None:
        return
    lock = step("Lock()", ctx.Lock)
    if lock is not None:
        step("lock.acquire()", lock.acquire)
        step("lock.release()", lock.release)
        step("lock.acquire(block=False)", lambda: lock.acquire(False))
        step("lock.release() again", lock.release)
    step("BoundedSemaphore(1)", lambda: ctx.BoundedSemaphore(1))
    step("Event()", ctx.Event)
    pipe = step("Pipe()", ctx.Pipe)
    if pipe is not None:
        step("pipe send/recv", lambda: (pipe[0].send("x"), pipe[1].recv())[1])
    q = step("Queue()", ctx.Queue)
    if q is None:
        return
    step("queue put/get in one process", lambda: (q.put("x"), q.get(timeout=5))[1])
    p = step("Process(...)", lambda: ctx.Process(target=target, args=(q, 21)))
    if p is None:
        return
    step("p.start()", p.start)
    step("q.get(timeout=20)", lambda: q.get(timeout=20))
    step("p.join(timeout=20)", lambda: p.join(timeout=20))
    step("p.exitcode", lambda: p.exitcode)
    print("MP PROBE DONE", flush=True)


if __name__ == "__main__":
    main()
