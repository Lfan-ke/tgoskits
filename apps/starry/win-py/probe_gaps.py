"""What the suite still fails on, each with the error it actually raises.

Run with the interpreter under test; every section prints what happened rather
than stopping at the first failure.
"""
import os
import pathlib
import stat
import subprocess
import sys
import traceback

PY = sys.executable


def section(name):
    print("=== " + name, flush=True)


def show(label, fn):
    try:
        print("  %s -> %r" % (label, fn()), flush=True)
    except BaseException as e:
        print("  %s !! %s: %s" % (label, type(e).__name__, e), flush=True)
        traceback.print_exc()
        sys.stdout.flush()


section("chmod")
_f = os.path.join(os.getcwd(), "probe_chmod.txt")
with open(_f, "w") as fh:
    fh.write("x")
show("stat before", lambda: oct(stat.S_IMODE(os.stat(_f).st_mode)))
show("os.chmod 0o640", lambda: os.chmod(_f, 0o640))
show("stat after", lambda: oct(stat.S_IMODE(os.stat(_f).st_mode)))
show("Path.chmod 0o644", lambda: pathlib.Path(_f).chmod(0o644))
show("stat after path", lambda: oct(stat.S_IMODE(os.stat(_f).st_mode)))
show("os.chmod follow=False", lambda: os.chmod(_f, 0o600, follow_symlinks=False))
show("os.access W_OK", lambda: os.access(_f, os.W_OK))

section("devnull")
show("open nul", lambda: open("nul", "w").close())
show("subprocess DEVNULL", lambda: subprocess.run(
    [PY, "-c", "print('noisy')"], stdout=subprocess.DEVNULL).returncode)

section("cwd and timeout")
show("run cwd=/tmp", lambda: subprocess.run(
    [PY, "-c", "import os; print(os.getcwd())"],
    capture_output=True, text=True, cwd="/tmp").stdout.strip())
show("run timeout", lambda: subprocess.run(
    [PY, "-c", "import time; time.sleep(5)"], timeout=0.5))

section("dash m")
for mod in ("platform", "venv"):
    show("-m " + mod, lambda mod=mod: subprocess.run(
        [PY, "-m", mod] + (["Z:\\tmp\\venvprobe"] if mod == "venv" else []),
        capture_output=True, text=True, timeout=120))

_case = os.path.join(os.getcwd(), "probe_case.py")
with open(_case, "w") as fh:
    fh.write("import unittest\n"
             "class T(unittest.TestCase):\n"
             "    def test_ok(self):\n"
             "        self.assertEqual(1, 1)\n")
show("-m unittest", lambda: subprocess.run(
    [PY, "-m", "unittest", "-v", "probe_case"],
    capture_output=True, text=True, cwd=os.getcwd(), timeout=120))

section("multiprocessing")
show("start methods", lambda: __import__("multiprocessing").get_all_start_methods())


def _child(q):
    q.put(42)


def _mp():
    import multiprocessing as mp
    ctx = mp.get_context("spawn")
    q = ctx.Queue()
    p = ctx.Process(target=_child, args=(q,))
    p.start()
    got = q.get(timeout=30)
    p.join(timeout=30)
    return (got, p.exitcode)


if __name__ == "__main__":
    show("spawn round trip", _mp)

    section("asyncio")
    show("event loop", lambda: __import__("asyncio").new_event_loop())

    print("PROBE-DONE", flush=True)
