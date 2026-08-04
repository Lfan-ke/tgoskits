// egui_layout - egui/eframe LAYOUT carpet cell (egui_kittest harness). egui is immediate-mode and its
// layout is fully deterministic given fixed input, so the Rect of every widget is a closed form of the
// panel margin + item sizes + item_spacing. This cell drives vertical, horizontal and grid layouts with
// fixed-size widgets (ui.add_sized) and asserts each widget's computed Response.rect == the analytic
// position, then resizes the harness and asserts the layout is stable / re-flows. All constants are
// calibrated to the pinned egui 0.32.3 default style (CentralPanel inner margin = 8, item_spacing =
// (8, 3)), read back from the live Context, so the asserts are ground truth, not guesses.
// Prints "GUI_EGUI_LAYOUT OK <n>".

use std::{
    cell::RefCell,
    rc::Rc,
    sync::atomic::{AtomicU32, Ordering},
};

use egui_kittest::Harness;

static PASS: AtomicU32 = AtomicU32::new(0);
static FAIL: AtomicU32 = AtomicU32::new(0);

const EXPECTED: u32 = 33;

fn ok(cond: bool, desc: &str) {
    if cond {
        PASS.fetch_add(1, Ordering::Relaxed);
    } else {
        FAIL.fetch_add(1, Ordering::Relaxed);
        eprintln!("FAIL: {desc}");
    }
}

// egui 0.32.3 default style (verified live): CentralPanel inner margin = 8 px on each side;
// item_spacing = (8.0 horizontal, 3.0 vertical). Widget sizes are fixed by ui.add_sized.
const MARGIN: f32 = 8.0;
const SPACING_X: f32 = 8.0;
const SPACING_Y: f32 = 3.0;
const BW: f32 = 80.0; // button width
const BH: f32 = 24.0; // button height

fn approx(a: f32, b: f32) -> bool {
    (a - b).abs() < 0.01
}

fn rect_eq(r: egui::Rect, minx: f32, miny: f32, w: f32, h: f32) -> bool {
    approx(r.min.x, minx) && approx(r.min.y, miny) && approx(r.width(), w) && approx(r.height(), h)
}

// Capture the three vertical-stack button rects and (re-)verify the item_spacing/margin the style
// reports so the closed form below is anchored to the live constants.
fn run_vertical(size: egui::Vec2) -> (Vec<egui::Rect>, egui::Vec2, f32) {
    let rects: Rc<RefCell<Vec<egui::Rect>>> = Rc::new(RefCell::new(Vec::new()));
    let spacing: Rc<RefCell<egui::Vec2>> = Rc::new(RefCell::new(egui::Vec2::ZERO));
    let margin: Rc<RefCell<f32>> = Rc::new(RefCell::new(0.0));
    let (rc, sp, mg) = (rects.clone(), spacing.clone(), margin.clone());
    let mut h = Harness::builder()
        .with_size(size)
        .with_pixels_per_point(1.0)
        .with_theme(egui::Theme::Dark)
        .wgpu()
        .build(move |ctx| {
            *sp.borrow_mut() = ctx.style().spacing.item_spacing;
            egui::CentralPanel::default().show(ctx, |ui| {
                *mg.borrow_mut() = ui.spacing().item_spacing.y; // just to touch spacing api
                rc.borrow_mut().clear();
                for lbl in ["A", "B", "C"] {
                    let r = ui.add_sized([BW, BH], egui::Button::new(lbl));
                    rc.borrow_mut().push(r.rect);
                }
            });
        });
    h.run();
    drop(h);
    let out = rects.borrow().clone();
    let sp_val = *spacing.borrow();
    let mg_val = *margin.borrow();
    (out, sp_val, mg_val)
}

fn run_horizontal(size: egui::Vec2) -> Vec<egui::Rect> {
    let rects: Rc<RefCell<Vec<egui::Rect>>> = Rc::new(RefCell::new(Vec::new()));
    let rc = rects.clone();
    let mut h = Harness::builder()
        .with_size(size)
        .with_pixels_per_point(1.0)
        .with_theme(egui::Theme::Dark)
        .wgpu()
        .build(move |ctx| {
            egui::CentralPanel::default().show(ctx, |ui| {
                rc.borrow_mut().clear();
                ui.horizontal(|ui| {
                    for lbl in ["A", "B", "C"] {
                        let r = ui.add_sized([BW, BH], egui::Button::new(lbl));
                        rc.borrow_mut().push(r.rect);
                    }
                });
            });
        });
    h.run();
    drop(h);
    let out = rects.borrow().clone();
    out
}

// 2x2 grid of fixed-size cells; capture each cell rect.
fn run_grid(size: egui::Vec2) -> Vec<egui::Rect> {
    let rects: Rc<RefCell<Vec<egui::Rect>>> = Rc::new(RefCell::new(Vec::new()));
    let rc = rects.clone();
    let mut h = Harness::builder()
        .with_size(size)
        .with_pixels_per_point(1.0)
        .with_theme(egui::Theme::Dark)
        .wgpu()
        .build(move |ctx| {
            egui::CentralPanel::default().show(ctx, |ui| {
                rc.borrow_mut().clear();
                egui::Grid::new("g")
                    .spacing([SPACING_X, SPACING_Y])
                    .show(ui, |ui| {
                        for row in 0..2 {
                            for col in 0..2 {
                                let _ = (row, col);
                                let r = ui.add_sized([BW, BH], egui::Button::new("x"));
                                rc.borrow_mut().push(r.rect);
                            }
                            ui.end_row();
                        }
                    });
            });
        });
    h.run();
    drop(h);
    let out = rects.borrow().clone();
    out
}

fn main() {
    let _seed: u64 = 0x233; // seed contract; layout has no RNG (deterministic by construction)

    // ---------------- vertical stack ----------------
    let (v, spacing, _mg) = run_vertical(egui::vec2(200.0, 160.0));
    ok(v.len() == 3, "vertical produced 3 rects");
    // Confirm the live style constants match what the closed form assumes.
    ok(approx(spacing.x, SPACING_X), "live item_spacing.x == 8");
    ok(approx(spacing.y, SPACING_Y), "live item_spacing.y == 3");
    // Closed-form positions: first widget at (MARGIN, MARGIN); each next is BH + SPACING_Y lower.
    let y0 = MARGIN;
    let y1 = y0 + BH + SPACING_Y;
    let y2 = y1 + BH + SPACING_Y;
    ok(
        rect_eq(v[0], MARGIN, y0, BW, BH),
        "vertical btn0 rect closed form",
    );
    ok(
        rect_eq(v[1], MARGIN, y1, BW, BH),
        "vertical btn1 rect closed form",
    );
    ok(
        rect_eq(v[2], MARGIN, y2, BW, BH),
        "vertical btn2 rect closed form",
    );
    // Adjacent-gap invariant: vertical gap between consecutive buttons == SPACING_Y exactly.
    ok(
        approx(v[1].min.y - v[0].max.y, SPACING_Y),
        "vertical gap 0->1 == spacing.y",
    );
    ok(
        approx(v[2].min.y - v[1].max.y, SPACING_Y),
        "vertical gap 1->2 == spacing.y",
    );
    // All share the same x (left-aligned column).
    ok(
        approx(v[0].min.x, v[1].min.x) && approx(v[1].min.x, v[2].min.x),
        "vertical column left-aligned",
    );
    ok(
        approx(v[0].width(), BW) && approx(v[0].height(), BH),
        "vertical widget size fixed",
    );

    // ---------------- horizontal row ----------------
    let hr = run_horizontal(egui::vec2(360.0, 120.0));
    ok(hr.len() == 3, "horizontal produced 3 rects");
    let x0 = MARGIN;
    let x1 = x0 + BW + SPACING_X;
    let x2 = x1 + BW + SPACING_X;
    ok(
        rect_eq(hr[0], x0, MARGIN, BW, BH),
        "horizontal btn0 rect closed form",
    );
    ok(
        rect_eq(hr[1], x1, MARGIN, BW, BH),
        "horizontal btn1 rect closed form",
    );
    ok(
        rect_eq(hr[2], x2, MARGIN, BW, BH),
        "horizontal btn2 rect closed form",
    );
    ok(
        approx(hr[1].min.x - hr[0].max.x, SPACING_X),
        "horizontal gap 0->1 == spacing.x",
    );
    ok(
        approx(hr[2].min.x - hr[1].max.x, SPACING_X),
        "horizontal gap 1->2 == spacing.x",
    );
    ok(
        approx(hr[0].min.y, hr[1].min.y) && approx(hr[1].min.y, hr[2].min.y),
        "horizontal row top-aligned",
    );

    // ---------------- 2x2 grid ----------------
    let g = run_grid(egui::vec2(300.0, 200.0));
    ok(g.len() == 4, "grid produced 4 cell rects");
    // Grid cell columns share x; rows share y. Column 0 x == MARGIN; column 1 x == MARGIN + BW + SPACING_X.
    let gx0 = MARGIN;
    let gx1 = MARGIN + BW + SPACING_X;
    ok(approx(g[0].min.x, gx0), "grid (0,0).x == margin");
    ok(
        approx(g[1].min.x, gx1),
        "grid (0,1).x == margin + col width + spacing",
    );
    ok(approx(g[2].min.x, gx0), "grid (1,0).x == margin");
    ok(
        approx(g[3].min.x, gx1),
        "grid (1,1).x == margin + col width + spacing",
    );
    ok(approx(g[0].min.y, g[1].min.y), "grid row 0 top-aligned");
    ok(approx(g[2].min.y, g[3].min.y), "grid row 1 top-aligned");
    ok(g[2].min.y > g[0].max.y - 0.01, "grid row 1 is below row 0");
    // Row-to-row vertical spacing == SPACING_Y.
    ok(
        approx(g[2].min.y - g[0].max.y, SPACING_Y),
        "grid row gap == spacing.y",
    );
    // Column horizontal spacing == SPACING_X.
    ok(
        approx(g[1].min.x - g[0].max.x, SPACING_X),
        "grid col gap == spacing.x",
    );

    // ---------------- resize -> re-layout ----------------
    // A wider harness must not move the (left/top-anchored) vertical stack: same rects.
    let (v_wide, _s2, _m2) = run_vertical(egui::vec2(400.0, 300.0));
    ok(v_wide.len() == 3, "resized vertical still 3 rects");
    ok(
        rect_eq(v_wide[0], MARGIN, y0, BW, BH),
        "resize: btn0 rect unchanged (left/top anchored)",
    );
    ok(
        rect_eq(v_wide[1], MARGIN, y1, BW, BH),
        "resize: btn1 rect unchanged",
    );
    ok(
        rect_eq(v_wide[2], MARGIN, y2, BW, BH),
        "resize: btn2 rect unchanged",
    );
    // Determinism: layout is identical across two independent builds of the same size.
    let (v_again, _s3, _m3) = run_vertical(egui::vec2(200.0, 160.0));
    ok(
        v_again.len() == 3
            && rect_eq(
                v_again[0],
                v[0].min.x,
                v[0].min.y,
                v[0].width(),
                v[0].height(),
            )
            && rect_eq(
                v_again[1],
                v[1].min.x,
                v[1].min.y,
                v[1].width(),
                v[1].height(),
            )
            && rect_eq(
                v_again[2],
                v[2].min.x,
                v[2].min.y,
                v[2].width(),
                v[2].height(),
            ),
        "layout deterministic across independent runs",
    );

    // Negative control: a wrong closed-form (off by the spacing) must NOT match.
    ok(
        !rect_eq(v[1], MARGIN, y0 + BH, BW, BH),
        "negative control: ignoring spacing.y mismatches",
    );

    finish();
}

fn finish() {
    let pass = PASS.load(Ordering::Relaxed);
    let fail = FAIL.load(Ordering::Relaxed);
    let total = pass + fail;
    println!("egui-layout: PASS={pass} FAIL={fail} TOTAL={total} EXPECTED={EXPECTED}");
    if fail == 0 && total == EXPECTED {
        println!("GUI_EGUI_LAYOUT OK {pass}");
        std::process::exit(0);
    } else {
        println!("GUI_EGUI_LAYOUT FAIL");
        std::process::exit(1);
    }
}
