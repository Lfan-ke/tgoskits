"""Run the modules that still fail, one after another, with their own output.

The suite's runner only keeps the last thirty lines of a failing module, which
is not where the failure is. This runs each of them in this interpreter and
lets everything they print reach the console.
"""
import runpy
import sys
import traceback

SUITE = "Z:\\suite"

for name in sys.argv[1:]:
    print("=== " + name, flush=True)
    saved = sys.argv
    sys.argv = [SUITE + "\\" + name]
    try:
        runpy.run_path(SUITE + "\\" + name, run_name="__main__")
    except SystemExit:
        pass
    except BaseException:
        traceback.print_exc()
    finally:
        sys.argv = saved
    sys.stdout.flush()

print("PROBE-FAILING-DONE", flush=True)
