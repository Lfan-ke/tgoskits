#!/usr/bin/env bash
# Generate the two foreign images and install the runner. No toolchain is
# involved: each image is a few dozen bytes that trap straight into its ABI.
set -euo pipefail

app_dir="${STARRY_APP_DIR:-$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)}"
overlay_dir="${STARRY_OVERLAY_DIR:-}"

if [[ -z "$overlay_dir" ]]; then
    echo "ERROR: STARRY_OVERLAY_DIR is required" >&2
    exit 1
fi

if [[ "$STARRY_ARCH" != "x86_64" ]]; then
    echo "ERROR: PE and Mach-O images exist for x86-64 and aarch64 only" >&2
    exit 1
fi

install -d "$overlay_dir/usr/bin"
python3 "$app_dir/make-images.py" "$overlay_dir/usr/bin"
install -m0755 "$app_dir/interleave.sh" "$overlay_dir/usr/bin/interleave.sh"
chmod 0755 "$overlay_dir/usr/bin/interleave.exe" "$overlay_dir/usr/bin/interleave.macho"
