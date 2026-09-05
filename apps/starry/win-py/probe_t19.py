"""The three t19 checks that come back with nothing, run where the output shows."""
import os
import subprocess
import sys

PY = sys.executable


def show(label, args, env=None):
    p = subprocess.run([PY] + args, capture_output=True, text=True, timeout=60, env=env)
    print("== %s rc=%r" % (label, p.returncode), flush=True)
    print("   out=%r" % p.stdout[:400], flush=True)
    print("   err=%r" % p.stderr[:400], flush=True)


def main():
    # The same three, captured.
    show("m-timeit-help", ["-m", "timeit", "--help"])
    show("X-tracemalloc", ["-X", "tracemalloc=1", "-c",
                           "import tracemalloc; print(tracemalloc.is_tracing())"])
    env = {k: v for k, v in os.environ.items() if not k.startswith("PYTHON")}
    env["PYTHONTRACEMALLOC"] = "1"
    show("env-tracemalloc", ["-c", "import tracemalloc; print(tracemalloc.is_tracing())"], env)

    # The same three again, this time letting the child write to the console
    # instead of a pipe: if the output only goes missing when captured, the
    # fault is in the pipe and not in the interpreter.
    for label, args in (
        ("timeit-direct", ["-m", "timeit", "--help"]),
        ("tracemalloc-direct", ["-X", "tracemalloc=1", "-c",
                                "import tracemalloc; print('tracing', tracemalloc.is_tracing())"]),
    ):
        print("== %s (straight to the console)" % label, flush=True)
        rc = subprocess.run([PY] + args).returncode
        print("   rc=%r" % rc, flush=True)

    # Narrow it down: does importing tracemalloc alone work, and does the
    # -X switch alone survive?
    show("import-tracemalloc", ["-c", "import tracemalloc; print('imported')"])
    show("X-alone", ["-X", "tracemalloc=1", "-c", "print('alive')"])
    show("X-showopts", ["-X", "tracemalloc=1", "-c",
                        "import sys; print(sys._xoptions)"])
    show("import-timeit", ["-c", "import timeit; print('timeit ok')"])
    print("PROBE-T19-DONE", flush=True)


if __name__ == "__main__":
    main()
