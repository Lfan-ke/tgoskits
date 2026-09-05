"""Where a pool stops when the work it was given raises."""
import multiprocessing as mp
import sys
import threading
import time


def say(*a):
    print(*a, flush=True)


def ident(x):
    return x


def boom():
    raise ValueError("boom-in-worker")


def main():
    # multiprocessing says why its own threads give up, but only when asked.
    # The result handler exits quietly on EOFError/OSError and dies silently
    # on anything else, so its reason is the whole question here.
    import logging
    mp.log_to_stderr(logging.DEBUG)
    ctx = mp.get_context("spawn")
    say("start", sys.platform)

    pool = ctx.Pool(processes=2)
    say("pool up")
    say("plain map", pool.map(ident, range(3)))

    ar = pool.apply_async(boom)
    say("submitted")
    # A watchdog thread, so a get() that never returns still says so instead
    # of taking the whole run down with it in silence.
    stop = threading.Event()

    def tick():
        for i in range(1, 40):
            if stop.wait(5):
                return
            say("  still waiting %ds" % (i * 5))

    threading.Thread(target=tick, daemon=True).start()
    t = time.monotonic()
    try:
        say("got", ar.get(timeout=30))
    except Exception as e:  # noqa: BLE001 - which one it is is the answer
        say("raised %s: %s after %.1fs" % (type(e).__name__, e, time.monotonic() - t))
    stop.set()
    say("successful?", ar.successful() if ar.ready() else "not ready")
    say("workers", [(w.pid, w.is_alive()) for w in pool._pool])
    say("result handler alive?", pool._result_handler.is_alive())
    say("task handler alive?", pool._task_handler.is_alive())

    pool.terminate()
    say("terminated")
    pool.join()
    say("PROBE-POOL-DONE")


if __name__ == "__main__":
    main()
