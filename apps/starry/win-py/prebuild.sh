#!/usr/bin/env bash
# Install Microsoft's real CPython, the libraries it needs, and its standard
# library as a directory tree beside the executable. Nothing is checked in;
# point STARRY_WIN_DLL_DIR at a directory holding python.exe, python313.dll,
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
install -m 0755 "$dll_dir/python.exe" "$overlay_dir/python/python.exe"
install -m 0644 "$dll_dir/python313.dll" "$overlay_dir/python/python313.dll"
for f in ucrtbase.dll vcruntime140.dll vcruntime140_1.dll python3.dll; do
    [[ -f "$dll_dir/$f" ]] || continue
    install -m 0644 "$dll_dir/$f" "$overlay_dir/windows/system32/$f"
    install -m 0644 "$dll_dir/$f" "$overlay_dir/python/$f"
done

# The standard library as a directory tree the file finder walks, rather than
# a zip: encodings and the rest are read as plain files. The archive built on
# the host is expanded into Lib.
install -d "$overlay_dir/python/Lib"
unzip -qo "$dll_dir/python313.zip" -d "$overlay_dir/python/Lib"

# An absolute isolated path file next to the executable and beside the DLL:
# the standard library directory and the program directory, no site.
for pth in "$overlay_dir/python/python._pth" "$overlay_dir/python/python313._pth"; do
    cat > "$pth" <<'PTH'
Z:\python\Lib
Z:\python
PTH
done
