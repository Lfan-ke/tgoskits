"""Whether a message survives the pipe whole, at every size that matters."""
import multiprocessing as mp


# Both ends of the pipe are held here, so a message only crosses while it fits
# in the pipe's own buffer - hence nothing past sixteen kilobytes. What matters
# is the sizes either side of 128: that is how much a first read asks for, and
# anything longer is what `_get_more_data` exists to finish.
SIZES = [1, 64, 127, 128, 129, 200, 511, 512, 1000, 4096, 16384]


def say(*a):
    print(*a, flush=True)


def sender(w):
    for n in SIZES:
        w.send_bytes(b"z" * n)
    w.close()


def main():
    ctx = mp.get_context("spawn")

    # Same process, both ends held here: the pipe itself, with no spawn in the
    # way. A message longer than the 128 bytes a first read asks for is the
    # case `_get_more_data` exists for, so the sizes straddle it.
    r, w = ctx.Pipe(duplex=False)
    for n in SIZES:
        w.send_bytes(b"y" * n)
        got = r.recv_bytes()
        ok = len(got) == n and got == b"y" * n
        say("pipe %7d %s%s" % (n, "ok" if ok else "WRONG", "" if ok else " got %d" % len(got)))
        if not ok:
            break

    # The same sizes again, but written by another process. A pool's result
    # comes back this way, and the difference between the two is the whole
    # question: same-process worked above.
    r2, w2 = ctx.Pipe(duplex=False)
    p = ctx.Process(target=sender, args=(w2,))
    p.start()
    w2.close()
    for n in SIZES:
        got = r2.recv_bytes()
        ok = len(got) == n and got == b"z" * n
        say("child %7d %s%s" % (n, "ok" if ok else "WRONG", "" if ok else " got %d" % len(got)))
        if not ok:
            break
    p.join(timeout=120)

    # An exception with a traceback is what a pool sends back when its work
    # raises, and it is far bigger than any result above.
    try:
        raise ValueError("x" * 200)
    except ValueError as e:
        import pickle
        blob = pickle.dumps(e)
        say("a pickled exception is %d bytes" % len(blob))
    say("PROBE-MSGSIZE-DONE")


if __name__ == "__main__":
    main()
