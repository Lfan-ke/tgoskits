#!/bin/sh
# On-target runner: set up the software Vulkan runtime (Mesa lavapipe) and run the egui/eframe GUI test
# carpet cells. Each cell drives the official egui_kittest harness, rendering an egui UI headlessly
# through egui_wgpu on the wgpu crate (which picks the CPU adapter = lavapipe), and asserts per-pixel
# closed-form / exact layout Rects / real event simulation with state+pixel checks. Prints "TEST PASSED"
# only when every cell reports its "GUI_EGUI_<NAME> OK <n>" marker and exits 0.
set -u
BIN=/opt/cpu-gui-egui-test
mkdir -p /tmp/vkrt
export XDG_RUNTIME_DIR=/tmp/vkrt
export LD_LIBRARY_PATH=/usr/lib
# lavapipe (software Vulkan) ICD - the wgpu backend egui_kittest renders through.
ICD=$(ls /usr/share/vulkan/icd.d/lvp_icd*.json 2>/dev/null | head -1)
export VK_DRIVER_FILES="$ICD"
export VK_ICD_FILENAMES="$ICD"
# StarryOS runs one vCPU; pin the LLVM JIT thread pool to 1. The carpets assert correctness, not
# throughput, so thread count does not affect results.
export LP_NUM_THREADS=1
ncpu=$(nproc 2>/dev/null || grep -c '^processor' /proc/cpuinfo 2>/dev/null || echo '?')
echo "cpu-gui-egui-test: detected CPU count = $ncpu; lavapipe pinned single-threaded; ICD=$ICD"

pass=0; total=0; fail=0
# run <name> <binary>. A pass requires BOTH a clean exit (rc==0) AND the exact "<name> OK <n>" marker:
# a cell that prints its marker then aborts in teardown must fail, not pass.
run() {
    name="$1"; prog="$2"
    [ -x "$prog" ] || { echo "cpu-gui-egui-test: $name in manifest but binary absent at runtime"; total=$((total + 1)); fail=$((fail + 1)); return 0; }
    total=$((total + 1))
    out="$(cd "$BIN" && "$prog" 2>&1)"; rc=$?
    if [ "$rc" -eq 0 ] && echo "$out" | grep -qE "OK [0-9]+$"; then
        echo "$out" | grep -E ": PASS=|OK [0-9]+$" | tail -1
        pass=$((pass + 1))
    else
        echo "$out" | tail -8
        echo "CARPET FAILED: $name (exit $rc)"
        fail=$((fail + 1))
    fi
}

cd "$BIN" || exit 1
# Capability manifest: prebuild lists the cells it provisioned on this arch. Each cell is a wgpu-crate
# cargo binary cross-compiled by prebuild (dynamic musl), and each build hard-fails in prebuild, so a
# listed cell genuinely built. Every cell prints its own "GUI_EGUI_<NAME> OK <n>" marker.
MANIFEST="$BIN/expected_cells"
[ -f "$MANIFEST" ] || { echo "cpu-gui-egui-test: expected_cells manifest missing - prebuild provisioned no carpet"; echo "TEST FAILED"; exit 1; }
NCELL=$(grep -c . "$MANIFEST")
EXPECTED="$NCELL"
while IFS= read -r cell; do
    [ -n "$cell" ] || continue
    run "$cell" "$BIN/$cell"
done < "$MANIFEST"

echo "cpu-gui-egui-test: $pass/$total cells OK on $(uname -m) (cells $NCELL: $(tr '\n' ' ' < "$MANIFEST"))"
if [ "$NCELL" -ge 1 ] && [ "$fail" -eq 0 ] && [ "$total" -eq "$EXPECTED" ] && [ "$pass" -eq "$EXPECTED" ]; then
    echo "TEST PASSED"; exit 0
else
    echo "cpu-gui-egui-test: GATE FAILED - need all $EXPECTED cells to pass (>=1 cell floor); got fail=$fail total=$total pass=$pass"
    echo "TEST FAILED"; exit 1
fi
