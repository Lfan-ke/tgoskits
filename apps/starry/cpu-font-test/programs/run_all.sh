#!/bin/sh
# On-target runner for the cpu-font-test carpet - the "pyte for fonts". Each cell drives libfreetype
# (rasterization + metrics) or libharfbuzz (shaping) and asserts the output BYTE-EXACT / EXACT-INTEGER
# against goldens captured host-side with the same FreeType/HarfBuzz. Prints "TEST PASSED" only when every
# provisioned cell reports its "FONT_<CELL> OK <n>" marker (three-gate: fail==0 && total==EXPECTED==pass).
#
# Cells:
#   font_raster     - FreeType glyph -> pixels: exact w/h/pitch/top/left + SHA-256 of the ink buffer +
#                     ink count + known-position pixels, across sizes (16/32/48/64), MONO vs AA, hinting
#                     on/off, and a CJK glyph. No shaper needed.
#   font_metrics    - exact 26.6 metrics: monospace advance uniformity, per-glyph bearing/width/height,
#                     units_per_EM/ascender/descender/height, kerning (JBM has none -> AV==(0,0)); a
#                     proportional contrast face proves the monospace assertion is real.
#   font_shape      - HarfBuzz shaping: exact glyph-index + x_advance/x_offset/y_offset + cluster map for
#                     Latin "Hello", "AV", the "fi" ligature (HarmonyOS Sans -> 1 glyph), and Arabic RTL.
#   font_formats    - WOFF/WOFF2 wrappers decode to the identical outline (same 'A' SHA as the TTF); the
#                     wrappers are mandatory (prebuild hard-fails if it cannot stage them).
#   font_realassets - iterate every provided font: loads, sane num_glyphs/upm/family, renders a real
#                     glyph non-empty, HarfBuzz accepts it. A missing $ASSET_DIR fails the gate.
set -u
BIN=/opt/cpu-font-test
export PATH="/usr/bin:/usr/local/bin:$PATH"
# Font dir: the carpet stages render-assets/fonts here; on-target the media submodule may mount at
# ASSET_DIR. ASSET_DIR defaults to the staged FONT_DIR, so realassets always finds the prebuilt fonts.
export FONT_DIR="${FONT_DIR:-$BIN/fonts}"
export ASSET_DIR="${ASSET_DIR:-$FONT_DIR}"
ncpu=$(nproc 2>/dev/null || grep -c '^processor' /proc/cpuinfo 2>/dev/null || echo '?')
echo "cpu-font-test: detected CPU count = $ncpu; FONT_DIR=$FONT_DIR"

pass=0; total=0; fail=0
run() {
    name="$1"; prog="$2"
    [ -x "$prog" ] || { echo "cpu-font-test: $name in manifest but binary absent at runtime"; total=$((total + 1)); fail=$((fail + 1)); return 0; }
    total=$((total + 1))
    out="$(cd "$BIN" && "$prog" 2>&1 </dev/null)"; rc=$?
    if [ "$rc" -eq 0 ] && echo "$out" | grep -qE "OK [0-9]+$"; then
        echo "$out" | grep -E "OK [0-9]+$" | tail -1
        pass=$((pass + 1))
    else
        echo "$out" | tail -8
        echo "CARPET FAILED: $name (exit $rc)"
        fail=$((fail + 1))
    fi
}

cd "$BIN" || exit 1
MANIFEST="$BIN/expected_cells"
[ -f "$MANIFEST" ] || { echo "cpu-font-test: expected_cells manifest missing - prebuild provisioned no carpet"; echo "TEST FAILED"; exit 1; }
EXPECTED=$(grep -c . "$MANIFEST")
while IFS= read -r cell <&3; do
    [ -n "$cell" ] || continue
    run "$cell" "$BIN/$cell"
done 3< "$MANIFEST"

echo "cpu-font-test: $pass/$total font carpets OK on $(uname -m) (expected $EXPECTED: $(tr '\n' ' ' < "$MANIFEST"))"
if [ "$EXPECTED" -ge 1 ] && [ "$fail" -eq 0 ] && [ "$total" -eq "$EXPECTED" ] && [ "$pass" -eq "$EXPECTED" ]; then
    echo "TEST PASSED"; exit 0
else
    echo "cpu-font-test: GATE FAILED - need all $EXPECTED manifest carpets to pass (>=1 floor); got fail=$fail total=$total pass=$pass"
    echo "TEST FAILED"; exit 1
fi
