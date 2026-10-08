#!/usr/bin/env bash
# Install python.org's macOS CPython at the path its own load commands name.
# Nothing is checked in; point STARRY_MAC_PY_DIR at the Python.framework
# payload of python-3.14.x-macos11.pkg (the directory holding Versions/3.14).
set -euo pipefail

app_dir="${STARRY_APP_DIR:-$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)}"
overlay_dir="${STARRY_OVERLAY_DIR:-}"
fw_dir="${STARRY_MAC_PY_DIR:-$HOME/rcore/macpkg/fw}"

if [[ -z "$overlay_dir" ]]; then
    echo "ERROR: STARRY_OVERLAY_DIR is required" >&2
    exit 1
fi
if [[ "$STARRY_ARCH" != "x86_64" ]]; then
    echo "ERROR: this case covers x86-64 only" >&2
    exit 1
fi
src="$fw_dir/Versions/3.14"
for f in Python Resources/Python.app/Contents/MacOS/Python lib/python3.14/os.py; do
    if [[ ! -f "$src/$f" ]]; then
        echo "ERROR: $src/$f not found; set STARRY_MAC_PY_DIR" >&2
        exit 1
    fi
done

dst="$overlay_dir/Library/Frameworks/Python.framework/Versions/3.14"
install -d "$dst/Resources/Python.app/Contents/MacOS" "$dst/lib"
install -m 0755 "$src/Python" "$dst/Python"
install -m 0755 "$src/Resources/Python.app/Contents/MacOS/Python" \
    "$dst/Resources/Python.app/Contents/MacOS/Python"

# The standard library with its timestamps, so the shipped bytecode stays
# valid and nothing is recompiled at import. What no test here imports - the
# test suite, the GUI toolkits, the installer - stays behind.
cp -a "$src/lib/python3.14" "$dst/lib/python3.14"
for d in test idlelib tkinter turtledemo ensurepip site-packages lib2to3; do
    rm -rf "$dst/lib/python3.14/$d"
done

# readline is built against libedit, which is not among the system libraries
# here. Left in place, the interactive prompt would try to load it and fail on
# every start; without it the interpreter uses its plain line reader.
rm -f "$dst/lib/python3.14/lib-dynload/readline.cpython-314-darwin.so"

install -d "$overlay_dir/usr/bin"
ln -sf /Library/Frameworks/Python.framework/Versions/3.14/Resources/Python.app/Contents/MacOS/Python \
    "$overlay_dir/usr/bin/python3-mac"
install -m 0644 "$app_dir/probe.py" "$overlay_dir/probe.py"
