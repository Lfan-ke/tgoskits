"""Compare what reaches a child's redirected stdout, module by module.

A module that passes on the console but fails as a child with its output in a
temporary file points at the redirection rather than the module, so this runs
three children the same way - a one-line program, a module known to report,
and the one in question - and says how many bytes each landed.
"""
import os
import subprocess
import sys
import tempfile


def capture(argv):
    fd, log = tempfile.mkstemp(suffix=".log")
    handle = None
    try:
        import msvcrt

        handle = msvcrt.get_osfhandle(fd)
    except Exception:
        pass
    out = os.fdopen(fd, "wb")
    result = subprocess.run(argv, stdout=out, stderr=subprocess.STDOUT)
    # What the file holds while the parent's own descriptor is still open,
    # which separates "the child never wrote" from "the bytes went away".
    inner = os.fstat(fd).st_size
    out.close()
    size = os.path.getsize(log) if os.path.exists(log) else -1
    # A second look after a pause tells a write that never happened from one
    # that had not yet become visible.
    import time

    time.sleep(0.5)
    later = os.path.getsize(log) if os.path.exists(log) else -1
    with open(log, "rb") as reader:
        data = reader.read()
    os.unlink(log)
    return result.returncode, data, fd, inner, (size, later)


for name, argv in [
    ("exit7a", [sys.executable, "-c", "import sys; print('MARKER-A'); sys.exit(7)"]),
    ("exit7b", [sys.executable, "-c", "import sys; print('MARKER-B'); sys.exit(7)"]),
    ("exit7c", [sys.executable, "-c", "import sys; print('MARKER-C'); sys.exit(7)"]),
    ("exit7d", [sys.executable, "-c", "import sys; print('MARKER-D'); sys.exit(7)"]),
]:
    rc, data, fd, inner, size = capture(argv)
    tail = data.decode("utf-8", "replace").splitlines()[-1:] or [""]
    print(
        "CHILD %-8s rc=%s fd=%s while_open=%s after_close=%s bytes=%d last=%r"
        % (name, rc, fd, inner, size, len(data), tail[0][:40])
    )
print("CAPTURE-DONE")
