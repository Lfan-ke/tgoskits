#!/usr/bin/env python3
"""Aggregate runner for the StarryOS python-lang carpet suite (#764).

Runs every t<NN>_*.py carpet module (plus test_lang.py) as a child interpreter,
reports per-file PASS/FAIL with the failing tail, and prints `TEST PASSED` on the
final line iff every module exits 0 (the qemu harness success_regex keys on it).
"""
import glob
import os
import subprocess
import sys
import tempfile

BIN = "/usr/bin"
here = os.path.dirname(os.path.abspath(__file__))
base = BIN if os.path.exists(os.path.join(BIN, "t01_syntax.py")) else here

files = sorted(glob.glob(os.path.join(base, "t[0-9][0-9]_*.py")))
smoke = os.path.join(base, "test_lang.py")
if os.path.exists(smoke):
    files.append(smoke)
# Modules whose output goes straight to the console instead of into a file.
# Both of these run for many minutes and drive dozens of child interpreters, so
# a run that stops inside one has to say where it stopped - a captured file is
# never read if the machine is killed first.
streamed_modules = {"t10_multiprocessing.py", "t19_cli.py"}

print(
    "PYLANG-SUITE python %d.%d.%d (%s) on %s — %d modules"
    % (
        sys.version_info[0], sys.version_info[1], sys.version_info[2],
        sys.implementation.name, sys.platform, len(files),
    )
)

fails = []
for index, f in enumerate(files):
    name = os.path.basename(f)
    print("  [RUN ] %-28s" % name, flush=True)
    out = ""
    if name in streamed_modules:
        try:
            r = subprocess.run([sys.executable, "-u", f], timeout=1800)
            rc = r.returncode
        except Exception as e:  # noqa: BLE001 — runner must never crash on one file
            out, rc = ("runner exception: %r" % e), 99
    else:
        fd, output_path = tempfile.mkstemp(
            prefix="pylang_%02d_" % index, suffix="_" + name + ".log"
        )
        try:
            with os.fdopen(fd, "wb") as output:
                r = subprocess.run(
                    [sys.executable, "-u", f],
                    stdout=output, stderr=subprocess.STDOUT, timeout=1800,
                )
                rc = r.returncode
            with open(output_path, "rb") as output:
                out = output.read().decode("utf-8", "replace")
        except Exception as e:  # noqa: BLE001 — runner must never crash on one file
            try:
                os.close(fd)
            except OSError:
                pass
            try:
                with open(output_path, "rb") as output:
                    out = output.read().decode("utf-8", "replace")
            except OSError:
                out = ""
            out = (out + "\n" if out else "") + "runner exception: %r" % e
            rc = 99
        finally:
            try:
                os.unlink(output_path)
            except OSError:
                pass
    ok = rc == 0
    lines = out.strip().splitlines()
    tail = lines[-1] if lines else "(no output)"
    print("  [%s] %-28s rc=%s | %s" % ("PASS" if ok else "FAIL", name, rc, tail))
    if not ok:
        fails.append(name)
        # The failing checks first, wherever in the run they were, then the
        # tail. A module that ends in a wall of skips would otherwise push the
        # one line that says why off the top.
        why = [ln for ln in lines if "FAIL" in ln][:20]
        rest = [ln for ln in lines[-15:] if ln not in why]
        for ln in why + rest:
            print("    | " + ln)

passed = len(files) - len(fails)
print("PYLANG-SUITE: %d/%d modules passed" % (passed, len(files)))
if fails:
    print("PYLANG-SUITE FAILURES: " + ", ".join(fails))
    print("TEST FAILED")
    sys.exit(1)
print("TEST PASSED")
sys.exit(0)
