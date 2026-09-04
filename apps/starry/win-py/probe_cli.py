"""What a child that only prints its version does, with and without a pipe."""
import subprocess
import sys

PY = sys.executable


def show(label, args, capture):
    try:
        r = subprocess.run([PY] + args, capture_output=capture, text=capture)
        print("  %s rc=%r out=%r err=%r" % (label, r.returncode,
                                            r.stdout if capture else None,
                                            r.stderr if capture else None),
              flush=True)
    except BaseException as e:
        print("  %s !! %s: %s" % (label, type(e).__name__, e), flush=True)


print("=== straight to the console (watch for a version line)", flush=True)
show("-V console", ["-V"], False)
print("=== through a pipe", flush=True)
show("-V piped", ["-V"], True)
show("--version piped", ["--version"], True)
show("-h piped", ["-h"], True)
show("-c print piped", ["-c", "print('printed')"], True)
show("-c write piped", ["-c", "import sys; sys.stdout.write('written\\n')"], True)
show("-c exit piped", ["-c", "import sys; print('before exit'); sys.exit(3)"], True)
show("-c os_exit piped", ["-c", "import os,sys; print('before _exit'); sys.stdout.flush(); os._exit(4)"], True)
print("PROBE-CLI-DONE", flush=True)
