# cpu-font-test - the "pyte for fonts"

An industrial-grade font test carpet for StarryOS. Where `pyte` gives a headless terminal you can assert
against cell-by-cell, this gives a headless font-rendering + text-shaping pipeline you can assert against
**per pixel and per glyph**: every cell drives FreeType (glyph rasterization + metrics) or HarfBuzz (text
shaping) and checks the output BYTE-EXACT against a golden - a per-pixel SHA-256 of the rendered ink
buffer, exact-integer 26.6 metrics, exact glyph-index + position shaping - never a smoke test. "Font
loaded" alone is not a test here.

Runtime dependency is only the Alpine musl `freetype` + `harfbuzz` shared libraries. No TrueType
interpreter, rasterizer or shaper is reinvented - the whole point is to TEST freetype/harfbuzz. Only the
SHA-256, the comparison logic and the golden constants are self-written in the cells, so each assertion is
an independent check against a captured golden, not a self-comparison.

## Fonts

54 flattened TTFs from `render-assets/fonts` (staged into the image under `/opt/cpu-font-test/fonts`, with
their LICENSE files kept): JetBrains Mono (Apache/OFL) Regular/Medium/Bold + the HarmonyOS Sans family
(SC/TC/Arabic/Naskh-Arabic-UI/Condensed/Italic, each licensed). JetBrains Mono is monospace (upm 1000,
every glyph advances 600 font units); the HarmonyOS Arabic Naskh face carries no Latin `A` and is used for
the RTL shaping leg; HarmonyOS SC supplies the CJK glyph; HarmonyOS Sans (proportional, with `fi/ffi/fl`
ligatures) is the contrast face.

## Cells

Each cell prints `FONT_<CELL> OK <n>` only when `fail==0 && total==pass==<n>` (three-gate). `run_all.sh`
gates on the capability manifest: `fail==0 && total==EXPECTED==pass`, EXPECTED>=1 floor.

### `font_raster` - FreeType glyph -> pixels, deterministic per-pixel golden - 68 assertions
Render specific glyphs at fixed pixel sizes and assert the rasterizer output byte-exact:

- exact bitmap `width / height / pitch / bitmap_top / bitmap_left`, the **SHA-256 of the full ink buffer**
  (pitch*rows bytes, incl. row padding), and the ink pixel count, for JetBrains Mono `A g 0 l` and the CJK
  `中` (HarmonyOS SC), plus JetBrains Mono Bold `A` (a genuinely different outline).
- matrix: sizes 16 / 32 / 48 / 64 px, `FT_RENDER_MODE_MONO` vs `NORMAL` (AA), hinting on (`FT_LOAD_DEFAULT`)
  vs off (`FT_LOAD_NO_HINTING`) - each combination has its own golden because each is a different rasterizer
  output.
- known-position pixels: the `l` stem inks its center column continuously (>= h/2) while the top-right
  corner stays blank; `space` is a valid glyph index but an empty 0x0 bitmap with zero ink; the AA `A`
  buffer carries partial-coverage (anti-aliased) pixels, the MONO one does not.

### `font_metrics` - exact numeric metric assertions - 71 assertions
FreeType metrics in the 26.6 fixed-point domain vs golden, no tolerance:

- **monospace uniformity**: every glyph in `AglW0i·xz` shares one advance at 16 / 32 / 64 px
  (`640 / 1216 / 2432` in 26.6, i.e. upm-scaled 600).
- per-glyph `advance / horiBearingX / horiBearingY / width / height` for `A g l 0 W space` at 32px.
- face constants: `units_per_EM == 1000`, `ascender == 1020`, `descender == -300`, line `height == 1320`,
  `num_glyphs == 1754`, family `"JetBrains Mono"`.
- kerning: JetBrains Mono ships none, so `FT_HAS_KERNING == 0` and `FT_Get_Kerning('A','V') == (0,0)` (an
  honest golden - monospace fonts do not kern).
- contrast: HarmonyOS Sans (proportional) advances `A/V == 1344` but `i == 512`, `l == 448`, proving the
  monospace assertion above is a real discriminator, not a tautology.

### `font_shape` - HarfBuzz shaping, exact glyph-index + position golden - 52 assertions
Shape known strings and assert the output glyph sequence + per-glyph `x_advance/x_offset/y_offset` +
cluster map + auto-detected direction/script:

- Latin `"Hello"` (JetBrains Mono): 5 glyphs, gids `65,234,287,287,302`, clusters `0..4`, every
  `x_advance == 1229` (monospace), LTR, script Latin.
- `"AV"` (JBM): 2 glyphs (gids `1,170`), advances unchanged (no ligature/kern).
- **ligature**: HarmonyOS Sans `"fi"` maps to a **single** ligature glyph (gid `397`, cluster 0,
  advance `1176`), while JetBrains Mono keeps `"fi"` as two glyphs (`254,265`) - both asserted, so the
  ligature test is real.
- proportional contrast: HarmonyOS Sans `"AV"` shapes to gids `3,169` with **different** advances
  (`1186 != 1348`).
- **RTL complex script**: Arabic "سلام" (salam) with HarmonyOS Naskh Arabic -> 3 shaped glyphs, direction
  auto-detected `RTL`, script `Arab`, exact gids/advances (`255,368,137`), and clusters in descending
  (RTL-reordered) order.

### `font_formats` - format matrix: WOFF/WOFF2 wrappers decode to the identical outline - 18 assertions
The sources are TTF. The prebuild converts JetBrains Mono Regular to WOFF and WOFF2 host-side (fontTools,
brotli for WOFF2) and stages them next to the TTF. WOFF/WOFF2 are container compressions of the same sfnt
tables, so FreeType must decode them to the byte-identical outline:

- TTF baseline: `FT_Get_Font_Format == "TrueType"`, `num_glyphs == 1754`, `units_per_EM == 1000`,
  `num_faces == 1`, family `"JetBrains Mono"`, `A@32px` SHA `== font_raster`'s golden.
- each staged WOFF / WOFF2 wrapper: loads, reports the same TrueType format / num_glyphs / upm, and renders
  `A@32px` to the **same per-pixel SHA** as the TTF (format must not change the outline).
- both wrappers are mandatory: `prebuild.sh` stages them host-side (fontTools + brotli) and hard-fails if it
  cannot, and the cell fails the gate if a wrapper is missing, so the format-identity matrix cannot silently
  collapse to the TTF baseline. OTF (glyf->CFF outline re-encoding) is a genuine re-encode, not a lossless
  wrapper, so it is documented as a follow-up rather than pixel-asserted.

### `font_realassets` - iterate every provided font - 380 assertions with assets present
Walk all `.ttf` under `$ASSET_DIR` and assert each is a real, usable face: `FT_New_Face` ok, `num_glyphs > 0`,
`units_per_EM == 1000`, non-empty `family_name`, `FT_Get_Font_Format == "TrueType"`, at least one
representative glyph (`A`, else Arabic sheen `U+0633`, else CJK `U+4E2D`) renders NON-EMPTY at 32px, and
HarfBuzz accepts the file with a matching glyph count. The 12 Arabic Naskh faces have no Latin `A`
(glyph index 0), so the probe falls back to the Arabic/CJK codepoints - every provided font inks at least
one. `ASSET_DIR` defaults to the staged `/opt/cpu-font-test/fonts`, which `prebuild.sh` always populates
(it exit-5s if it stages zero TTFs); an absent asset dir is a real staging failure and fails the gate.

## Build / run

`prebuild.sh` extracts the base Alpine rootfs and `apk add`s `freetype freetype-dev harfbuzz harfbuzz-dev`
for the target arch via qemu-user (apk runs fine under qemu-user), then cross-compiles the five cells **on
the host** with a musl cross-gcc, `--sysroot` at the staged rootfs so the target headers and `.so` link.
The cross-toolchain musl and Alpine musl are ABI-compatible for C, so linking the target `.so` from the
staging root with the host cross-gcc works. The compiler is resolved reproducibly - `${triple}-gcc` on PATH,
then `/opt/${triple}-cross/bin/${triple}-gcc`, then `zig cc -target ${triple}`, then `musl-gcc` for a native
x86_64 build - and the include/link closure (`-lfreetype -lharfbuzz` plus transitive `-lz -lbz2 -lpng16
-lbrotlidec ...`) is resolved by a host `pkgconf` run against the staged `freetype2.pc`/`harfbuzz.pc` with
`PKG_CONFIG_SYSROOT_DIR` pointed at the staging root. The staging gcc is deliberately not used: gcc spawns
`cc1` via `posix_spawn`, which qemu-user cannot exec (`cc1: posix_spawn`), so no cell would ever compile.

Alpine edge ships `libfreetype`/`libharfbuzz` with `DT_RELR` (`.relr.dyn`, section type `0x13`) relocations,
which the GNU ld 2.37 bundled in the musl-cross toolchains cannot parse (`unknown type [0x13] section
'.relr.dyn'` -> `cannot find -lfreetype`). The link therefore goes through a RELR-aware linker: when a
standalone `ld.lld` is reachable (LLD is a cross-linker and reads RELR on every arch) it is used as
`${triple}-gcc -fuse-ld=lld`; otherwise the build switches to `zig cc -target ${triple}`, which links with its
own bundled LLD. Any LLVM `ld.lld` (Debian/Ubuntu `lld` package, or `/usr/lib/llvm-*/bin/ld.lld`) or a `zig`
on PATH satisfies this - no pinned versions.

It then stages the TTF fonts + LICENSE files (and the WOFF/WOFF2 wrappers, converted host-side) under
`/opt/cpu-font-test/fonts`, and writes the `expected_cells` manifest. `programs/run_all.sh` is the on-target
three-gate runner. Four `build-*.toml` + `qemu-*.toml` cover x86_64 / aarch64 / riscv64 / loongarch64 (nvme
rootfs + virtio-net; loong/riscv carry `ax-driver/serial`; loong uses the dynamic platform raw-binary boot
path). Run on each architecture (single vCPU):

```
cargo xtask starry app qemu -t cpu-font-test --arch x86_64
cargo xtask starry app qemu -t cpu-font-test --arch aarch64
cargo xtask starry app qemu -t cpu-font-test --arch riscv64
cargo xtask starry app qemu -t cpu-font-test --arch loongarch64
```

### Font assets

The fonts are provided by the per-app `assets` git submodule (same `fonts/` layout as `render-assets`,
tracked with git-LFS). `prebuild.sh` inits and LFS-pulls it automatically when the marker font
`assets/fonts/root__JetBrainsMono-Regular.ttf` is a bare gitlink or an LFS pointer, but you can also do it by
hand before the first run:

```
git submodule update --init apps/starry/cpu-font-test/assets
git -C apps/starry/cpu-font-test/assets lfs pull --include='fonts/*'
```

Set `FONT_ASSET_SRC=<path>` to stage from a different `fonts/` tree instead of the submodule; if it is unset
and the submodule is absent, `prebuild.sh` walks up to a sibling `render-assets/fonts`. With no font source at
all it exits 5 (a font source is required - the golden cells assert real glyphs).

## Host validation

Goldens are pinned to the FreeType/HarfBuzz the image ships. Alpine edge currently packages **FreeType
2.14.3** and **HarfBuzz 14.2.1** (musl); the goldens were captured and re-verified by staging those exact
`.so` + `-dev` packages into a rootfs (fetched from the Alpine edge repo), cross-compiling each cell against
that staging root with the host musl cross-gcc exactly as `prebuild.sh` does, and running the resulting
target binaries under the Alpine musl loader with the staged libraries. All five cells green, `TEST PASSED`:

```
FONT_RASTER OK 68
FONT_METRICS OK 71
FONT_SHAPE OK 52
FONT_FORMATS OK 18
FONT_REALASSETS OK 380
cpu-font-test: 5/5 font carpets OK on x86_64 (expected 5: font_raster font_metrics font_shape font_formats font_realassets )
TEST PASSED
```

Metrics, shaping (glyph indices/advances, Arabic RTL) and every AA-render SHA are identical from FreeType
2.13 through 2.14; the one value that moved across the 2.14 bump is the 1-bit `A@32 MONO` packing SHA, and
the golden tracks the shipped 2.14.3 value.

Non-vacuity (mutation-tested against the on-target Alpine libs): flipping one byte of the `A@32` render SHA,
changing an expected glyph index in `font_shape` (Hello / Arabic), and perturbing a golden metric advance
or a golden bitmap geometry each turn the respective cell into a real FAIL (exit 1, `fail>0`), proving the
per-pixel / per-glyph assertions are load-bearing.

Tool availability on the build host: fontTools 4.63.0 + brotli produce both the WOFF and WOFF2 wrappers.
Both are required - `prebuild.sh` aborts (exit 6) if either wrapper cannot be generated, so a host missing
fontTools/brotli fails the build rather than silently degrading `font_formats` to the TTF baseline. OTF
(glyf->CFF) conversion needs fontforge/cu2qu-reverse (not required and not a lossless-identity test) -
documented as a follow-up.
