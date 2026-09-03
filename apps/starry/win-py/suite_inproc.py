"""Run the extended python-lang suite in-process, one module after another.

The suite's own runner starts a child interpreter per module; here each module
is executed in this interpreter instead, so the suite runs where spawning a
process is not available yet. Modules that need threads, subprocesses or the
network are listed separately and skipped until those arrive.
"""
import os
import runpy
import sys
import traceback

SUITE = "Z:\\suite"
DEFERRED = {"t08_async", "t09_threads", "t10_multiprocessing", "t19_cli", "t20_dash_m", "t22_net_devices"}
SKIP = {"run_all", "test_lang"}

results = {}
for name in sorted(n[:-3] for n in os.listdir(SUITE) if n.endswith(".py")):
    if name in SKIP or name in DEFERRED:
        continue
    path = os.path.join(SUITE, name + ".py")
    print(f"MOD-START {name}")
    sys.stdout.flush()
    saved = sys.argv
    sys.argv = [path]
    try:
        runpy.run_path(path, run_name="__main__")
        rc = 0
    except SystemExit as e:
        rc = e.code if isinstance(e.code, int) else (0 if e.code is None else 1)
    except BaseException:
        traceback.print_exc()
        rc = 99
    finally:
        sys.argv = saved
    results[name] = rc
    print(f"MOD-END {name} rc={rc}")
    sys.stdout.flush()

passed = sum(1 for rc in results.values() if rc == 0)
for name, rc in results.items():
    if rc:
        print(f"  FAILED {name} rc={rc}")
print(f"SUITE-SUMMARY passed={passed} total={len(results)} deferred={len(DEFERRED)}")
sys.stdout.flush()
