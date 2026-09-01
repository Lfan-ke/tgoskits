#!/usr/bin/env bash
# Generate the program and install the C runtime it calls. The runtime is
# Microsoft's ucrtbase.dll, taken from a local directory rather than checked
# in; point STARRY_WIN_DLL_DIR at a copy of it.
set -euo pipefail

app_dir="${STARRY_APP_DIR:-$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)}"
overlay_dir="${STARRY_OVERLAY_DIR:-}"
dll_dir="${STARRY_WIN_DLL_DIR:-$HOME/rcore/wt-personality/tmp/win}"

if [[ -z "$overlay_dir" ]]; then
    echo "ERROR: STARRY_OVERLAY_DIR is required" >&2
    exit 1
fi
if [[ "$STARRY_ARCH" != "x86_64" ]]; then
    echo "ERROR: this case covers x86-64 only" >&2
    exit 1
fi
if [[ ! -f "$dll_dir/ucrtbase.dll" ]]; then
    echo "ERROR: $dll_dir/ucrtbase.dll not found; set STARRY_WIN_DLL_DIR to a directory holding it" >&2
    exit 1
fi

install -d "$overlay_dir/usr/bin" "$overlay_dir/windows/system32"
python3 "$app_dir/make-pe.py" "$overlay_dir/usr/bin/hello-crt.exe"
chmod 0755 "$overlay_dir/usr/bin/hello-crt.exe"
# The loader compares library names lowered, and the filesystem is exact.
install -m 0644 "$dll_dir/ucrtbase.dll" "$overlay_dir/windows/system32/ucrtbase.dll"
