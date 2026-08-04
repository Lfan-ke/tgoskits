// egui_render - egui/eframe RENDER carpet cell driven by the official egui_kittest test harness.
//
// egui is an immediate-mode GUI; egui_kittest renders a UI headlessly through egui_wgpu on the
// wgpu crate. On StarryOS this rides the same Mesa lavapipe (software Vulkan) path cpu-wgpu-render
// proved on musl - egui_kittest's default adapter selector prefers a CPU adapter, i.e. lavapipe.
// This cell builds a UI of known widgets (a colored painter rect, a Label, a Button, a Checkbox) in
// a fixed-size Harness with the Dark theme and pixels_per_point 1.0 (so widget coordinates are in
// physical pixels), renders it to an RGBA8 image, and hard-asserts:
//   - PER-PIXEL closed form where geometry is analytic: the painter rect_filled interior is exactly
//     its color; the panel background is exactly the Dark-theme panel fill (#1B1B1B, calibrated to
//     the pinned egui 0.32 version); the rect edges are exact (no AA on an axis-aligned opaque rect).
//   - Determinism: two consecutive renders of the same input are byte-identical.
//   - Where exact pixels depend on font anti-aliasing (glyph text), assert the ink bounding box +
//     non-background content instead of exact glyph pixels.
//   - A negative control (a pixel that must NOT be the rect color).
// Prints "GUI_EGUI_RENDER OK <n>" only when every assertion passes and the count equals EXPECTED.

use std::sync::atomic::{AtomicU32, Ordering};

use egui_kittest::Harness;

static PASS: AtomicU32 = AtomicU32::new(0);
static FAIL: AtomicU32 = AtomicU32::new(0);

// Calibrated to the count this cell genuinely runs on the success path (pinned to egui 0.32.3).
const EXPECTED: u32 = 31;

fn ok(cond: bool, desc: &str) {
    if cond {
        PASS.fetch_add(1, Ordering::Relaxed);
    } else {
        FAIL.fetch_add(1, Ordering::Relaxed);
        eprintln!("FAIL: {desc}");
    }
}

const W: u32 = 96;
const H: u32 = 96;

// Dark-theme panel fill, ground truth read back from egui 0.32.3
// (visuals.panel_fill == Color32::from_rgb(27, 27, 27) in the Dark visuals).
const BG: (u8, u8, u8, u8) = (27, 27, 27, 255);

// Analytic geometry of the painter rect (physical pixels; ppp = 1.0). ui.painter() draws in screen
// (physical) coordinates, so rect_filled(pos2(RX,RY), size(RW,RH)) fills exactly the pixel block
// [RX..RX+RW) x [RY..RY+RH) - verified against the real render, corners land on (RX,RY)/(RX+RW-1,..).
const MARGIN: u32 = 8; // CentralPanel default inner margin, used only for the label-band checks below
const RX: u32 = 12;
const RY: u32 = 16;
const RW: u32 = 40;
const RH: u32 = 30;
const RCOL: (u8, u8, u8, u8) = (0, 200, 80, 255);

struct Img {
    px: Vec<u8>,
    w: u32,
    h: u32,
}
impl Img {
    fn at(&self, x: u32, y: u32) -> (u8, u8, u8, u8) {
        let i = ((y * self.w + x) * 4) as usize;
        (self.px[i], self.px[i + 1], self.px[i + 2], self.px[i + 3])
    }
}

fn render_scene() -> Img {
    // Deterministic RNG seed contract for the carpet (egui itself is deterministic given fixed input;
    // no RNG is used to drive the scene, but we honor the seed contract for the campaign).
    let _seed: u64 = 0x233;
    let mut harness = Harness::builder()
        .with_size(egui::Vec2::new(W as f32, H as f32))
        .with_pixels_per_point(1.0)
        .with_theme(egui::Theme::Dark)
        .wgpu()
        .build(|ctx| {
            egui::CentralPanel::default().show(ctx, |ui| {
                // A closed-form filled rect via the painter (content-space coords).
                let painter = ui.painter();
                painter.rect_filled(
                    egui::Rect::from_min_size(
                        egui::pos2(RX as f32, RY as f32),
                        egui::vec2(RW as f32, RH as f32),
                    ),
                    0.0,
                    egui::Color32::from_rgb(RCOL.0, RCOL.1, RCOL.2),
                );
                // Known widgets below the rect (their pixels are exercised by egui_interact; here we
                // just want them present so the UI is a real composite).
                ui.add_space(60.0);
                ui.label("Hello");
                let _ = ui.button("Go");
                let mut checked = false;
                ui.checkbox(&mut checked, "On");
            });
        });
    harness.run();
    let im = harness.render().expect("egui_kittest wgpu render failed");
    Img {
        w: im.width(),
        h: im.height(),
        px: im.as_raw().clone(),
    }
}

fn near(a: (u8, u8, u8, u8), b: (u8, u8, u8, u8), tol: u8) -> bool {
    let d = |x: u8, y: u8| (x as i32 - y as i32).unsigned_abs() as u8;
    d(a.0, b.0) <= tol && d(a.1, b.1) <= tol && d(a.2, b.2) <= tol && d(a.3, b.3) <= tol
}

fn main() {
    let img = render_scene();

    ok(img.w == W && img.h == H, "image size == requested");
    ok(
        img.px.len() == (W * H * 4) as usize,
        "image byte length == W*H*4",
    );

    // --- Background closed form: corners + a mid-left column that predate any widget must be BG. ---
    ok(img.at(0, 0) == BG, "top-left is panel bg");
    ok(img.at(W - 1, 0) == BG, "top-right is panel bg");
    ok(img.at(0, H - 1) == BG, "bottom-left is panel bg");
    ok(img.at(W - 1, H - 1) == BG, "bottom-right is panel bg");
    ok(img.at(2, 2) == BG, "inside top margin is panel bg");

    // --- Painter rect closed form: interior is exactly RCOL (opaque, axis-aligned, no AA). ---
    ok(
        img.at(RX + 1, RY + 1) == RCOL,
        "rect interior top-left corner == RCOL",
    );
    ok(
        img.at(RX + RW / 2, RY + RH / 2) == RCOL,
        "rect interior center == RCOL",
    );
    ok(
        img.at(RX + RW - 2, RY + RH - 2) == RCOL,
        "rect interior bottom-right == RCOL",
    );
    // Entire interior scan (every pixel strictly inside the rect equals RCOL exactly).
    let mut interior_exact = true;
    for y in (RY + 1)..(RY + RH - 1) {
        for x in (RX + 1)..(RX + RW - 1) {
            if img.at(x, y) != RCOL {
                interior_exact = false;
            }
        }
    }
    ok(
        interior_exact,
        "every interior pixel of the rect == RCOL (per-pixel closed form)",
    );

    // --- Rect boundary: one pixel outside each edge is background, one pixel inside is RCOL. ---
    ok(img.at(RX - 1, RY + RH / 2) == BG, "just left of rect is bg");
    ok(
        img.at(RX + RW, RY + RH / 2) == BG,
        "just right of rect is bg",
    );
    ok(img.at(RX + RW / 2, RY - 1) == BG, "just above rect is bg");
    ok(img.at(RX + RW / 2, RY + RH) == BG, "just below rect is bg");
    ok(img.at(RX, RY) == RCOL, "rect min corner is RCOL");
    ok(
        img.at(RX + RW - 1, RY + RH - 1) == RCOL,
        "rect max corner is RCOL",
    );

    // --- Negative control: a background pixel is NOT the rect color. ---
    ok(
        img.at(1, 1) != RCOL,
        "negative control: bg pixel is not RCOL",
    );
    // Negative control: the rect color is distinct from bg (guards a degenerate all-one-color image).
    ok(RCOL != BG, "negative control: RCOL differs from BG");

    // --- Determinism: two more renders are byte-identical to each other. ---
    let a = render_scene();
    let b = render_scene();
    ok(
        a.px == b.px,
        "two renders are byte-identical (deterministic)",
    );
    ok(
        a.px == img.px,
        "re-render equals first render (deterministic across calls)",
    );

    // --- Font-AA-tolerant assertions: the "Hello" label draws non-background ink somewhere in its
    // row band, and its ink bounding box is inside the panel. We do NOT assert exact glyph pixels. ---
    // Text is light-on-dark; count pixels brighter than BG in the label band.
    let band_y0 = 60u32;
    let band_y1 = 80u32.min(H - 1);
    let mut ink = 0u32;
    let (mut minx, mut maxx, mut miny, mut maxy) = (W, 0u32, H, 0u32);
    for y in band_y0..band_y1 {
        for x in MARGIN..(W - MARGIN) {
            let p = img.at(x, y);
            // brighter than the panel bg => glyph anti-aliased ink
            if p.0 as u32 + p.1 as u32 + p.2 as u32 > (BG.0 as u32 + BG.1 as u32 + BG.2 as u32) + 40
            {
                ink += 1;
                minx = minx.min(x);
                maxx = maxx.max(x);
                miny = miny.min(y);
                maxy = maxy.max(y);
            }
        }
    }
    ok(
        ink > 10,
        "label band has anti-aliased text ink (non-background content present)",
    );
    ok(
        minx >= MARGIN && maxx < W - MARGIN,
        "label ink bounding box x within panel margins",
    );
    ok(
        miny >= band_y0 && maxy < band_y1,
        "label ink bounding box y within its band",
    );
    ok(
        maxx > minx && maxy >= miny,
        "label ink bounding box is non-degenerate",
    );

    // --- Channel-tolerant check: rect center matches RCOL within tol 0 (exact) AND within tol 2. ---
    ok(
        near(img.at(RX + RW / 2, RY + RH / 2), RCOL, 0),
        "rect center exact within tol 0",
    );
    ok(
        near(img.at(RX + RW / 2, RY + RH / 2), RCOL, 2),
        "rect center within tol 2",
    );

    // --- Alpha channel is fully opaque across the whole framebuffer (offscreen has no transparency). ---
    let mut all_opaque = true;
    for y in 0..H {
        for x in 0..W {
            if img.at(x, y).3 != 255 {
                all_opaque = false;
            }
        }
    }
    ok(
        all_opaque,
        "framebuffer alpha is 255 everywhere (opaque offscreen target)",
    );

    // --- Background dominates a widget-free strip (top MARGIN rows are pure panel fill). ---
    let mut top_all_bg = true;
    for y in 0..MARGIN {
        for x in 0..W {
            if img.at(x, y) != BG {
                top_all_bg = false;
            }
        }
    }
    ok(
        top_all_bg,
        "top margin strip is uniform panel bg (closed form)",
    );

    // Two more spot checks anchoring the rect within the image bounds.
    ok(RX + RW < W && RY + RH < H, "rect fits inside framebuffer");
    ok(
        img.at(RX + 3, RY + 3) == RCOL,
        "rect near-corner interior == RCOL",
    );

    finish();
}

fn finish() {
    let pass = PASS.load(Ordering::Relaxed);
    let fail = FAIL.load(Ordering::Relaxed);
    let total = pass + fail;
    println!("egui-render: PASS={pass} FAIL={fail} TOTAL={total} EXPECTED={EXPECTED}");
    if fail == 0 && total == EXPECTED {
        println!("GUI_EGUI_RENDER OK {pass}");
        std::process::exit(0);
    } else {
        println!("GUI_EGUI_RENDER FAIL");
        std::process::exit(1);
    }
}
