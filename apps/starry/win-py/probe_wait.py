"""Where a child that is waited for with a deadline goes wrong.

Each step prints before and after itself, so the last line printed says which
one did not come back.
"""
import subprocess
import sys
import threading
import time

PY = sys.executable


def step(name, fn):
    print("-> " + name, flush=True)
    try:
        print("   %s = %r" % (name, fn()), flush=True)
    except BaseException as e:
        print("   %s !! %s: %s" % (name, type(e).__name__, e), flush=True)


step("thread join with a deadline", lambda: (
    lambda t: (t.start(), t.join(2.0), t.is_alive())[-1]
)(threading.Thread(target=lambda: time.sleep(0.1))))

step("thread join that times out", lambda: (
    lambda t: (t.start(), t.join(0.2), t.is_alive())[-1]
)(threading.Thread(target=lambda: time.sleep(3))))

step("child, no pipes, no deadline", lambda: subprocess.run(
    [PY, "-c", "print('a')"]).returncode)

step("child with pipes, no deadline", lambda: subprocess.run(
    [PY, "-c", "print('b')"], capture_output=True, text=True).stdout.strip())

step("child with a deadline, no pipes", lambda: subprocess.run(
    [PY, "-c", "print('c')"], timeout=30).returncode)

step("child with pipes and a deadline", lambda: subprocess.run(
    [PY, "-c", "print('d')"], capture_output=True, text=True, timeout=30).stdout.strip())

step("child that outlives its deadline", lambda: subprocess.run(
    [PY, "-c", "import time; time.sleep(5)"], timeout=0.5).returncode)

step("ten children with pipes and a deadline", lambda: [
    subprocess.run([PY, "-c", "import sys; print(sys.argv[1])", str(i)],
                   capture_output=True, text=True, timeout=30).stdout.strip()
    for i in range(10)
])

print("PROBE-WAIT-DONE", flush=True)
