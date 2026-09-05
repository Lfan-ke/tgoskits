"""Where a multi-writer multiprocessing.Queue stops delivering."""
import os
import sys
import time
import multiprocessing as mp


def say(*a):
    print(*a, flush=True)


def chatty(q, val, tag):
    say("  child", tag, "up", os.getpid())
    sl = q._sem._semlock
    try:
        say("  child", tag, "sem value", sl._get_value())
    except Exception as e:
        say("  child", tag, "sem value failed", repr(e))
    t = time.monotonic()
    q.put((os.getpid(), val * 2))
    say("  child", tag, "put returned %.2fs" % (time.monotonic() - t))
    q.close()
    q.join_thread()
    say("  child", tag, "feeder joined")


def semkid(sem, tag):
    say("  sem child", tag, "up")
    got = sem.acquire(timeout=8)
    say("  sem child", tag, "acquired", got)
    if got:
        sem.release()
    say("  sem child", tag, "released")


def drain(q, n, secs=8):
    out = []
    for i in range(n):
        try:
            out.append(q.get(timeout=secs))
        except Exception as e:
            out.append(repr(e))
            break
    return out


def main():
    ctx = mp.get_context("spawn")

    sem = ctx.BoundedSemaphore(2 ** 31 - 1)
    say("parent sem value", sem._semlock._get_value())
    ps = [ctx.Process(target=semkid, args=(sem, i)) for i in range(3)]
    for p in ps:
        p.start()
    for p in ps:
        p.join(timeout=10)
    say("sem children exitcodes", [p.exitcode for p in ps])
    say("parent sem value after", sem._semlock._get_value())

    for n in (1, 2, 3):
        q = ctx.Queue()
        say("queue with", n, "writers; parent sem value", q._sem._semlock._get_value())
        ps = [ctx.Process(target=chatty, args=(q, i, i)) for i in range(n)]
        for p in ps:
            p.start()
        say("  drained", drain(q, n))
        for p in ps:
            p.join(timeout=8)
        say("  exitcodes", [p.exitcode for p in ps])

    say("PROBE-QUEUE-DONE")


if __name__ == "__main__":
    main()
