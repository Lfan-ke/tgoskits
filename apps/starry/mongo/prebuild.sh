#!/usr/bin/env bash
# Stage the official MongoDB server (mongod) plus its glibc runtime closure into the
# app overlay. MongoDB publishes prebuilt servers for x86_64 and aarch64 only (glibc,
# ubuntu2404); riscv64/loongarch64 have no upstream build and the 8.x source tree does
# not compile for them (no mozjs/ninja-python for those arches) - see README. So mongo
# is a two-architecture app; the other apps in this tree stay four-arch.
#
# mongod is a dynamically linked glibc PIE (interp /lib64/ld-linux-x86-64.so.2 etc.),
# not a static musl binary. StarryOS runs glibc-dynamic binaries (see glibc-dynamic-smoke),
# so we stage the real glibc closure (ld-linux + libc/libssl/libcrypto/libcurl + their
# transitive deps) next to mongod - NOT the thin gcompat shim - so the server actually
# starts instead of failing loader resolution.
set -euo pipefail

app_dir="${STARRY_APP_DIR:-$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)}"
overlay_dir="${STARRY_OVERLAY_DIR:-}"
arch="${STARRY_ARCH:-x86_64}"
[[ -n "$overlay_dir" ]] || { echo "error: STARRY_OVERLAY_DIR is required" >&2; exit 1; }

MONGO_VER=8.0.23
case "$arch" in
    x86_64)  RELARCH=x86_64  ;;
    aarch64) RELARCH=aarch64 ;;
    riscv64|loongarch64)
        echo "error: mongo has no upstream prebuilt for $arch (x86_64/aarch64 only); see README" >&2
        exit 1 ;;
    *) echo "error: unsupported arch: $arch" >&2; exit 1 ;;
esac

for t in curl tar readelf ldd install; do
    command -v "$t" >/dev/null 2>&1 || { echo "error: need host tool '$t'" >&2; exit 1; }
done

cache="${STARRY_WORKSPACE:-$(cd "$app_dir/../../.." && pwd)}/target/mongo-cache"
mkdir -p "$cache"
TGZ="mongodb-linux-${RELARCH}-ubuntu2404-${MONGO_VER}.tgz"
# provenance: mongodb.com official release (URL + sha256 pinned in SOURCES.md)
declare -A SHA=(
  [x86_64]=0037bc07dc0a2f943c3d6f680dc8ee06029f6394e35449b0cfec2ed9b48d701c
  [aarch64]=af456e7a702db89899fd7a343dc622b061509d29be8d5f5f978d6fb71be7dcfe
)
if [[ ! -f "$cache/$TGZ" ]]; then
    echo "=== fetch $TGZ ==="
    curl -fL --retry 3 -o "$cache/$TGZ" "https://fastdl.mongodb.org/linux/$TGZ"
fi
echo "${SHA[$arch]}  $cache/$TGZ" | sha256sum -c - || { echo "error: mongod tarball sha256 mismatch" >&2; exit 1; }

# --- extract mongod ----------------------------------------------------------
stage="$cache/stage-$arch"; rm -rf "$stage"; mkdir -p "$stage"
top="mongodb-linux-${RELARCH}-ubuntu2404-${MONGO_VER}"
tar xzf "$cache/$TGZ" -C "$stage" "$top/bin/mongod"
mongod="$stage/$top/bin/mongod"
[[ -x "$mongod" ]] || { echo "error: mongod not extracted" >&2; exit 1; }

install -Dm0755 "$mongod" "$overlay_dir/usr/bin/mongod"

# --- stage the glibc runtime closure -----------------------------------------
# Build host is ubuntu2404 (glibc 2.39) - the same base mongod was built on, so ldd
# resolves the exact NEEDED closure. Copy every resolved .so by SONAME plus the PT_INTERP.
mkdir -p "$overlay_dir/lib" "$overlay_dir/lib64"
INTERP=$(readelf -l "$mongod" | sed -n 's/.*program interpreter: \(.*\)]/\1/p')
[[ -n "$INTERP" ]] || { echo "error: no PT_INTERP in mongod" >&2; exit 1; }
if [[ "$arch" == "$(uname -m)" ]]; then
    # native arch: harvest exact closure from the running host loader
    cp -Lf "$INTERP" "$overlay_dir$INTERP"
    ldd "$mongod" | awk '/=>/ {print $3} /ld-linux|ld-musl/ {print $1}' | grep -E '^/' | sort -u \
      | while read -r so; do [[ -f "$so" ]] && install -Dm0644 "$so" "$overlay_dir/lib/$(basename "$so")"; done
else
    echo "error: cross-arch closure harvest not wired yet for $arch (run on matching host or add apt-get download)" >&2
    exit 1
fi

install -Dm0755 "$app_dir/programs/mongo-tests.sh" "$overlay_dir/usr/bin/mongo-tests.sh"

echo "=== staged mongod ($MONGO_VER/$RELARCH) + $(ls "$overlay_dir/lib" | wc -l) glibc closure libs + interp $INTERP ==="
