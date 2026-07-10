#!/usr/bin/env bash
# update-apk-lock.sh [BRANCH] - rewrite apk.lock from the live Alpine index.
#
# For every staged package on every arch it takes the version the index lists now, downloads
# that file, checks it with apk_verify.py and records its sha256. prebuild.sh never reads the
# index; it fetches exactly what the lock names. Run this when prebuild.sh reports that a
# locked file is gone from the mirrors or that the rootfs moved to another Alpine branch, and
# commit the result, so a version change is reviewed like any other change. BRANCH defaults
# to the branch apk.lock already names.
set -euo pipefail

app_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
lock="$app_dir/apk.lock"
branch="${1:-$(awk '$1 == "branch" { print $2; exit }' "$lock")}"
mirror="${DNSMASQ_APK_MIRROR:-https://dl-cdn.alpinelinux.org/alpine}"
packages=(dnsmasq tftp-hpa)
arches=(x86_64 aarch64 riscv64 loongarch64)

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

# indexed_version <APKINDEX> <package>
indexed_version() {
    awk -v p="$2" 'BEGIN { RS = ""; FS = "\n" }
        { n = ""; v = ""
          for (i = 1; i <= NF; i++) {
              if ($i ~ /^P:/) n = substr($i, 3)
              if ($i ~ /^V:/) v = substr($i, 3)
          }
          if (n == p) { print v; exit } }' "$1"
}

{
    echo "# Alpine packages staged by prebuild.sh, which fetches exactly these files and checks"
    echo "# each sha256. Written by update-apk-lock.sh; regenerate rather than edit."
    echo "branch $branch"
    echo "# arch       repo      package   version   sha256"
    for arch in "${arches[@]}"; do
        for repo in main community; do
            curl -fsSL --retry 3 --connect-timeout 20 "$mirror/$branch/$repo/$arch/APKINDEX.tar.gz" \
                | tar -xzO APKINDEX > "$work/$arch-$repo"
        done
        for pkg in "${packages[@]}"; do
            version=""
            for repo in main community; do
                version="$(indexed_version "$work/$arch-$repo" "$pkg")"
                [[ -n "$version" ]] && break
            done
            [[ -n "$version" ]] || { echo "update-apk-lock: $pkg is not in $branch for $arch" >&2; exit 1; }
            file="$work/$arch-$pkg-$version.apk"
            curl -fsSL --retry 3 --connect-timeout 20 "$mirror/$branch/$repo/$arch/$pkg-$version.apk" -o "$file"
            python3 "$app_dir/apk_verify.py" "$app_dir/keys" "$file"
            printf '%-12s %-9s %-9s %-9s %s\n' "$arch" "$repo" "$pkg" "$version" \
                "$(sha256sum "$file" | cut -d' ' -f1)"
        done
    done
} > "$work/apk.lock"

mv "$work/apk.lock" "$lock"
echo "update-apk-lock: wrote $lock for $branch" >&2
