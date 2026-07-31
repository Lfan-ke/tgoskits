#!/bin/sh
# On-target runner: set up the software GPU compute runtime and run the wgpu (WebGPU) Rust compute
# carpet. Prints "TEST PASSED" only when the carpet reports its "WGPU_RUST_FULL_API OK <n>" marker AND
# exits 0.
set -u
BIN=/opt/cpu-wgpu-compute
mkdir -p /tmp/vkrt
export XDG_RUNTIME_DIR=/tmp/vkrt
export LD_LIBRARY_PATH=/usr/lib
# lavapipe (software Vulkan) ICD; the JSON carries an absolute library_path resolved against the root.
ICD=$(ls /usr/share/vulkan/icd.d/lvp_icd.*.json 2>/dev/null | head -1)
export VK_DRIVER_FILES="$ICD"
export VK_ICD_FILENAMES="$ICD"
# wgpu lands on the ash Vulkan backend; pin it so it does not probe a GL fallback that is not staged.
export WGPU_BACKEND=vulkan
# StarryOS runs one vCPU (SMP off), so lavapipe's llvmpipe JIT executes every workgroup on one thread.
# Pin the thread pool to 1 to make that explicit; the carpet asserts numerical correctness, not
# throughput, so the thread count does not change the results.
export LP_NUM_THREADS=1
ncpu=$(nproc 2>/dev/null || grep -c '^processor' /proc/cpuinfo 2>/dev/null || echo '?')
echo "cpu-wgpu-compute: detected CPU count = $ncpu; lavapipe pinned single-threaded (LP_NUM_THREADS=1); ICD=$ICD"

pass=0; total=0; fail=0
# run <name> <binary>. A pass requires BOTH a clean exit (rc==0) AND the exact "<name> OK <n>" marker:
# a carpet that prints its marker then aborts in teardown must fail, not pass.
run() {
    name="$1"; prog="$2"
    [ -x "$prog" ] || { echo "cpu-wgpu-compute: $name in manifest but binary absent at runtime"; total=$((total + 1)); fail=$((fail + 1)); return 0; }
    total=$((total + 1))
    out="$(cd "$BIN" && "$prog" 2>&1)"; rc=$?
    if [ "$rc" -eq 0 ] && echo "$out" | grep -qE "OK [0-9]+$"; then
        echo "$out" | grep -E ": PASS=|OK [0-9]+$" | tail -1
        pass=$((pass + 1))
    else
        echo "$out" | tail -12
        echo "CARPET FAILED: $name (exit $rc)"
        fail=$((fail + 1))
    fi
}

cd "$BIN" || exit 1
# Capability manifest: prebuild lists the cells it provisioned on this arch - wgpu_rust (wgpu crate,
# on-target every arch) and wgpu_c / wgpu_cpp (linked against libwgpu_native.so built from source for
# musl by the prebuild recipe); wgpu_py (wgpu-py + WGPU_LIB_PATH) appends once its provisioning lands.
# Each build hard-fails in prebuild, so a listed cell genuinely built and the manifest cannot silently
# under-count.
MANIFEST="$BIN/expected_cells"
[ -f "$MANIFEST" ] || { echo "cpu-wgpu-compute: expected_cells manifest missing - prebuild provisioned no carpet"; echo "TEST FAILED"; exit 1; }
# EXPECTED_CELLS is the hard-coded full cell set (wgpu_rust/c/cpp/py); a manifest with fewer than these 4
# means prebuild dropped a cell, so the gate fails rather than shrinking EXPECTED to a partial run.
EXPECTED_CELLS=4
EXPECTED=$(grep -c . "$MANIFEST")
while IFS= read -r cell; do
    [ -n "$cell" ] || continue
    run "$cell" "$BIN/$cell"
done < "$MANIFEST"

# The gate requires the full hard-coded cell set (not just a >=1 floor): a dropped cell shrinks the
# manifest and must FAIL, never a vacuous pass. Above that the gate is the canonical strict triple-check.
echo "cpu-wgpu-compute: $pass/$total carpets OK on $(uname -m) (expected $EXPECTED_CELLS: $(tr '\n' ' ' < "$MANIFEST"))"
if [ "$EXPECTED" -eq "$EXPECTED_CELLS" ] && [ "$fail" -eq 0 ] && [ "$total" -eq "$EXPECTED_CELLS" ] && [ "$pass" -eq "$EXPECTED_CELLS" ]; then
    echo "TEST PASSED"; exit 0
else
    echo "cpu-wgpu-compute: GATE FAILED - need all $EXPECTED_CELLS cells to pass; got cells=$EXPECTED fail=$fail total=$total pass=$pass"
    echo "TEST FAILED"; exit 1
fi
