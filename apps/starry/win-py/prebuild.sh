#!/usr/bin/env bash
# Install Microsoft's real CPython, the libraries it needs, and its standard
# library as a directory tree beside the executable. Nothing is checked in;
# point STARRY_WIN_DLL_DIR at a directory holding python.exe, python314.dll,
# python314.zip, ucrtbase.dll and vcruntime140*.dll.
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
for f in python.exe python314.dll python314.zip ucrtbase.dll vcruntime140.dll; do
    if [[ ! -f "$dll_dir/$f" ]]; then
        echo "ERROR: $dll_dir/$f not found; set STARRY_WIN_DLL_DIR" >&2
        exit 1
    fi
done

install -d "$overlay_dir/python" "$overlay_dir/windows/system32"
install -m 0755 "$dll_dir/python.exe" "$overlay_dir/python/python.exe"
install -m 0644 "$dll_dir/python314.dll" "$overlay_dir/python/python314.dll"
for f in ucrtbase.dll vcruntime140.dll vcruntime140_1.dll python3.dll; do
    [[ -f "$dll_dir/$f" ]] || continue
    install -m 0644 "$dll_dir/$f" "$overlay_dir/windows/system32/$f"
    install -m 0644 "$dll_dir/$f" "$overlay_dir/python/$f"
done

# The standard library as a directory tree the file finder walks, rather than
# a zip: encodings and the rest are read as plain files. The archive built on
# the host is expanded into Lib.
install -d "$overlay_dir/python/Lib"
unzip -qo "$dll_dir/python314.zip" -d "$overlay_dir/python/Lib"

# A python._pth beside the executable pins sys.path to exactly these entries
# (each resolved relative to the executable's directory) and disables the
# prefix landmark / realpath search that fails on this host. Lib holds the
# expanded stdlib, so `encodings` resolves during interpreter startup.
cat > "$overlay_dir/python/python._pth" <<'PTH'
Lib
.
python314.zip
PTH

# Stage the extended python-lang suite (shared with the Linux personality)
# so the Windows python.exe runs the same t01..t22 modules.
suite_src="$HOME/rcore/wt-personality/apps/starry/python-lang/python"
install -d "$overlay_dir/suite"
for f in "$suite_src"/*.py; do
    install -m 0644 "$f" "$overlay_dir/suite/$(basename "$f")"
done

# A small import smoke: exercises the C-runtime heap and directory
# enumeration by importing real stdlib modules, then prints IMPORT-OK.
install -m 0644 "$HOME/rcore/wt-personality/apps/starry/win-py/probe.py" "$overlay_dir/python/probe.py"

# The C extension modules shipped beside the interpreter (unicodedata,
# _socket, _decimal, ...): LoadLibraryExW brings each in on first import.
for f in "$dll_dir"/*.pyd; do
    [[ -f "$f" ]] || continue
    install -m 0644 "$f" "$overlay_dir/python/$(basename "$f")"
done
