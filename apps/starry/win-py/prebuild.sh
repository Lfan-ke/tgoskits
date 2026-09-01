#!/usr/bin/env bash
# Install Microsoft's real CPython, the libraries it needs, and its standard
# library as a zip beside the executable. Nothing is checked in; point
# STARRY_WIN_DLL_DIR at a directory holding python.exe, python313.dll,
# python313.zip, ucrtbase.dll and vcruntime140*.dll.
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
for f in python.exe python313.dll python313.zip ucrtbase.dll vcruntime140.dll; do
    if [[ ! -f "$dll_dir/$f" ]]; then
        echo "ERROR: $dll_dir/$f not found; set STARRY_WIN_DLL_DIR" >&2
        exit 1
    fi
done

install -d "$overlay_dir/python" "$overlay_dir/windows/system32"
for f in python.exe python313.dll python313.zip; do
    install -m 0644 "$dll_dir/$f" "$overlay_dir/python/$f"
done
chmod 0755 "$overlay_dir/python/python.exe"
for f in ucrtbase.dll vcruntime140.dll vcruntime140_1.dll python3.dll; do
    [[ -f "$dll_dir/$f" ]] || continue
    install -m 0644 "$dll_dir/$f" "$overlay_dir/windows/system32/$f"
    install -m 0644 "$dll_dir/$f" "$overlay_dir/python/$f"
done

# An isolated path file next to the executable: the standard library zip and
# the program directory, and no site processing. CPython reads python._pth
# beside python.exe and, finding it, runs isolated from any registry or
# user paths - which is what this image is.
cat > "$overlay_dir/python/python._pth" <<'PTH'
Z:\python\python313.zip
Z:\python
PTH
