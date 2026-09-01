#!/usr/bin/env bash
# Install Microsoft's real CPython and the libraries it needs. Nothing is
# checked in; point STARRY_WIN_DLL_DIR at a directory holding python.exe,
# python313.dll, python3.dll, ucrtbase.dll and vcruntime140*.dll.
set -euo pipefail

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
for f in python.exe python313.dll ucrtbase.dll vcruntime140.dll; do
    if [[ ! -f "$dll_dir/$f" ]]; then
        echo "ERROR: $dll_dir/$f not found; set STARRY_WIN_DLL_DIR" >&2
        exit 1
    fi
done

# python.exe searches its own directory for python313.dll first, so both go in
# /python; the C runtime goes where the loader looks for the system, and the
# program directory too so either search finds it.
install -d "$overlay_dir/python" "$overlay_dir/windows/system32"
for f in python.exe python313.dll; do
    install -m 0755 "$dll_dir/$f" "$overlay_dir/python/$f"
done
for f in ucrtbase.dll vcruntime140.dll vcruntime140_1.dll python3.dll; do
    [[ -f "$dll_dir/$f" ]] || continue
    install -m 0644 "$dll_dir/$f" "$overlay_dir/windows/system32/$f"
    install -m 0644 "$dll_dir/$f" "$overlay_dir/python/$f"
done
