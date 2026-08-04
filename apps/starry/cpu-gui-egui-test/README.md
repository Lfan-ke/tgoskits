# cpu-gui-egui-test - egui/eframe GUI test carpet (egui_kittest, wgpu-on-lavapipe)

An industrial-grade GUI test carpet for the **egui** immediate-mode toolkit, driven by egui's official
test harness **egui_kittest**. Each cell renders an egui UI **headlessly** through `egui_wgpu` on the
`wgpu` crate; wgpu's adapter selector prefers a CPU adapter, so on StarryOS this rides the same Mesa
**lavapipe** (software Vulkan) path `cpu-wgpu-render` proved on musl - no GPU, no window/surface, single
vCPU (`-smp 1`). egui is deterministic given fixed input, so pixels and layout Rects are closed-form.

This is also the browser GUI-stack path (campaign #392, egui/eframe). No smoke: every cell hard-asserts
per-pixel closed forms, exact layout Rects, or real event simulation with state+pixel checks, and gates
on a calibrated `EXPECTED` assertion count.

## Cells (Rust `egui` / `egui_kittest` 0.32.3, dynamic musl)

| cell | file | marker | assertions (host) | what it proves |
|------|------|--------|------:|----------------|
| egui_render | `programs/carpets/egui_render/` | `GUI_EGUI_RENDER OK 31` | 31 | per-pixel closed-form render |
| egui_layout | `programs/carpets/egui_layout/` | `GUI_EGUI_LAYOUT OK 33` | 33 | exact layout Rects |
| egui_interact | `programs/carpets/egui_interact/` | `GUI_EGUI_INTERACT OK 24` | 24 | real event simulation + state/pixel |
| egui_snapshot | `programs/carpets/egui_snapshot/` | `GUI_EGUI_SNAPSHOT OK 7` | 7 | robust downscaled golden signature |

Each cell prints `GUI_EGUI_<NAME> OK <n>` only when every assertion passes and the count equals its
pinned `EXPECTED`; `run_all.sh` requires every listed cell to pass (gate = cells, `>=1` floor). egui and
egui_kittest are pinned to `=0.32.3` and each cell commits its `Cargo.lock`.

## Coverage

### egui_render - per-pixel closed form
Builds a UI with a colored `ui.painter().rect_filled(rect, 0.0, color)`, a `Label`, a `Button` and a
`Checkbox` in a 96x96 Dark-theme Harness at `pixels_per_point = 1.0` (widget coords = physical pixels),
renders to an RGBA8 image and asserts:

- The painter rect is **exactly** its color across its whole interior (an opaque axis-aligned rect has
  no AA): every pixel in `[RX..RX+RW) x [RY..RY+RH)` equals `(0,200,80,255)`, its four corners land on the
  analytic min/max, and one pixel outside each edge is background.
- The background is **exactly** the Dark-theme panel fill `#1B1B1B` (`(27,27,27,255)`), read back as the
  ground truth for egui 0.32.3; the top-margin strip is uniform panel fill.
- **Determinism**: two further renders are byte-identical to each other and to the first.
- The whole framebuffer alpha is 255 (opaque offscreen target).
- Where pixels depend on **font anti-aliasing** (the "Hello" label), it asserts the ink **bounding box**
  and non-background content, not exact glyph pixels.
- Negative controls: a background pixel is not the rect color; the rect color differs from the background.

### egui_layout - exact layout Rects
Drives vertical, horizontal and 2x2 grid layouts of fixed-size (`ui.add_sized([80,24], ...)`) widgets and
asserts each widget's `Response.rect` against the **closed-form** position derived from the live style
constants (CentralPanel inner margin = 8, `item_spacing = (8, 3)`, read back from the Context):

- Vertical: `btn[i].min == (8, 8 + i*(24+3))`, consecutive vertical gap == `spacing.y`, left-aligned.
- Horizontal: `btn[i].min.x == 8 + i*(80+8)`, gap == `spacing.x`, top-aligned.
- Grid: two columns at `x = 8` and `x = 8+80+8`, two rows with row gap == `spacing.y`, col gap ==
  `spacing.x`.
- **Resize -> re-layout**: a wider harness leaves the top/left-anchored stack unchanged; the layout is
  deterministic across independent builds. A negative control confirms a spacing-ignoring closed form does
  not match.

### egui_interact - real egui_kittest event simulation
Every interaction goes through egui_kittest / kittest and asserts **both** application state **and**
re-rendered pixels:

- A `Button` with a click counter: `harness.get_by_label("Increment").click(); harness.run();` -> counter
  incremented **and** the frame pixels changed (label repainted); a second click increments again.
- A `Checkbox`: click -> bool toggled **and** the indicator pixels changed; toggle back changes them again.
- A `Slider`: focus + `ArrowRight` key events raise the value from 0; `ArrowLeft` lowers it (deterministic
  keyboard stepping via the harness).
- A `TextEdit`: `focus()` + `type_text("egui")` -> the backing `String` equals the typed text **and** the
  frame changed; a second `type_text("42")` appends.
- **Negative controls**: clicking a **disabled** button does not change the counter; an idle re-run with no
  event leaves the frame byte-identical; a fresh harness reproduces the same one-click state.

### egui_snapshot - robust golden signature
Renders a fixed composite UI (heading, button, checkbox, two closed-form colored rects) into a 128x128
frame and asserts a robust **8x8 average-luminance pooled signature** against a committed golden
(calibrated to egui 0.32.3 on lavapipe), each pooled cell within a tolerance that absorbs sub-pixel AA
jitter, plus a SHA-256 fingerprint of the quantized grid. Exact-pixel golden PNGs are brittle across
font-AA and egui point releases, so the pooled signature + pinned version is the robust form; setting
`UPDATE_SNAPSHOT_GRID=1` prints the observed grid for deliberate recalibration. Determinism is asserted
(byte-identical raw frames + identical pooled grid across renders); a negative control perturbs one cell
and confirms the golden match fails.

## Bring-up on StarryOS

`prebuild.sh` extracts the base Alpine rootfs, `apk add`s the software Vulkan stack (`mesa-vulkan-swrast`
= lavapipe, `vulkan-loader`) via qemu-user, and cross-compiles each cell to `<arch>-unknown-linux-musl`
(dynamic musl, `-C target-feature=-crt-static`, `--release --locked`), staging each as its own binary. A
capability manifest lists the cells provisioned on this arch; `run_all.sh` sets the lavapipe ICD
(`VK_DRIVER_FILES` / `VK_ICD_FILENAMES`), pins `LP_NUM_THREADS=1`, runs every cell and gates on
`fail==0 && total==cells==pass` (`>=1` cell floor), never emitting a 0-carpet pass.

## Run

```
cargo xtask starry app qemu -t cpu-gui-egui-test --arch x86_64
cargo xtask starry app qemu -t cpu-gui-egui-test --arch aarch64
cargo xtask starry app qemu -t cpu-gui-egui-test --arch riscv64
cargo xtask starry app qemu -t cpu-gui-egui-test --arch loongarch64
```

## Host validation (Mesa lavapipe)

Build each cell for the host target and run under lavapipe:

```
VK_ICD_FILENAMES=$(ls /usr/share/vulkan/icd.d/lvp_icd*.json | head -1) LP_NUM_THREADS=1 \
  cargo run --release --manifest-path programs/carpets/egui_render/Cargo.toml
```

egui_render 31/31, egui_layout 33/33, egui_interact 24/24, egui_snapshot 7/7, and `run_all.sh` reports
`TEST PASSED` with all four cells green (egui/egui_kittest 0.32.3, wgpu backend on lavapipe, CPU adapter).
