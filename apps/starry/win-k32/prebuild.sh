#!/usr/bin/env bash
# Generate the case's PE image: a program that imports from kernel32 and calls
# through its import address table, as a compiler-built one does.
set -euo pipefail

app_dir="${STARRY_APP_DIR:-$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)}"
overlay_dir="${STARRY_OVERLAY_DIR:-}"

if [[ -z "$overlay_dir" ]]; then
    echo "ERROR: STARRY_OVERLAY_DIR is required" >&2
    exit 1
fi

if [[ "$STARRY_ARCH" != "x86_64" ]]; then
    echo "ERROR: this case covers x86-64 only" >&2
    exit 1
fi

install -d "$overlay_dir/usr/bin"
python3 "$app_dir/make-pe.py" "$overlay_dir/usr/bin/hello32.exe"
chmod 0755 "$overlay_dir/usr/bin/hello32.exe"
