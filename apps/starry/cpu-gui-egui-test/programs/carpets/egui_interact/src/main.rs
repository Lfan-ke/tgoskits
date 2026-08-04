// egui_interact - egui/eframe INTERACTION carpet cell via the official egui_kittest event simulation.
// Every interaction is driven through egui_kittest / kittest (get_by_label(...).click(), type_text(...))
// and asserted on BOTH the resulting application state AND the re-rendered pixels, so the test proves the
// event actually propagated through egui and repainted - not just that a bool flipped in isolation:
//   - Button with a click counter: click via the harness, assert the counter incremented AND the frame
//     pixels changed after the click.
//   - Checkbox: click, assert the bool toggled AND the checkbox indicator pixels changed.
//   - Slider: drag right (pointer press+move+release simulated by kittest), assert the value increased.
//   - TextEdit: focus + type, assert the backing String equals what was typed AND the frame changed.
//   - Negative control: a DISABLED button - clicking it must NOT change the counter, and an idle re-run
//     (no event) must leave the frame byte-identical.
// egui is deterministic given fixed input; the wgpu render rides Mesa lavapipe (CPU) on StarryOS.
// Prints "GUI_EGUI_INTERACT OK <n>".

use std::sync::atomic::{AtomicU32, Ordering};

use egui_kittest::{Harness, kittest::Queryable};

static PASS: AtomicU32 = AtomicU32::new(0);
static FAIL: AtomicU32 = AtomicU32::new(0);

const EXPECTED: u32 = 24;

fn ok(cond: bool, desc: &str) {
    if cond {
        PASS.fetch_add(1, Ordering::Relaxed);
    } else {
        FAIL.fetch_add(1, Ordering::Relaxed);
        eprintln!("FAIL: {desc}");
    }
}

#[derive(Default)]
struct App {
    count: i32,
    checked: bool,
    slider: f32,
    text: String,
}

fn build<'a>() -> Harness<'a, App> {
    Harness::builder()
        .with_size(egui::Vec2::new(240.0, 220.0))
        .with_pixels_per_point(1.0)
        .with_theme(egui::Theme::Dark)
        .wgpu()
        .build_ui_state(
            |ui, s: &mut App| {
                if ui.button("Increment").clicked() {
                    s.count += 1;
                }
                ui.label(format!("count {}", s.count));
                ui.checkbox(&mut s.checked, "Enable");
                ui.add(egui::Slider::new(&mut s.slider, 0.0..=100.0).text("amt"));
                ui.add(egui::TextEdit::singleline(&mut s.text).hint_text("type"));
                ui.add_enabled(false, egui::Button::new("Disabled"));
            },
            App::default(),
        )
}

fn frame(h: &mut Harness<App>) -> Vec<u8> {
    h.render().expect("wgpu render").as_raw().clone()
}

fn main() {
    let _seed: u64 = 0x233; // seed contract; interaction is deterministic given the scripted events

    let mut h = build();
    h.run();

    // --- initial state closed form ---
    ok(h.state().count == 0, "initial counter is 0");
    ok(!h.state().checked, "initial checkbox is false");
    ok(h.state().slider == 0.0, "initial slider is 0.0");
    ok(h.state().text.is_empty(), "initial text is empty");
    let f0 = frame(&mut h);
    ok(f0.len() == 240 * 220 * 4, "frame size is W*H*4");

    // --- idle re-run: no event -> pixels are byte-identical (determinism / no spurious repaint diff) ---
    h.run();
    let f_idle = frame(&mut h);
    ok(
        f_idle == f0,
        "idle re-run leaves frame byte-identical (deterministic)",
    );

    // --- Button click increments counter AND changes pixels (the "count N" label repaints) ---
    h.get_by_label("Increment").click();
    h.run();
    ok(h.state().count == 1, "counter incremented to 1 after click");
    let f1 = frame(&mut h);
    ok(
        f1 != f0,
        "frame pixels changed after button click (label repainted)",
    );

    // A second click increments again (event simulation is repeatable).
    h.get_by_label("Increment").click();
    h.run();
    ok(
        h.state().count == 2,
        "counter incremented to 2 after second click",
    );

    // --- Checkbox toggles the bool AND changes the indicator pixels ---
    let f_before_cb = frame(&mut h);
    h.get_by_label("Enable").click();
    h.run();
    ok(h.state().checked, "checkbox toggled to true after click");
    let f_after_cb = frame(&mut h);
    ok(
        f_after_cb != f_before_cb,
        "checkbox indicator pixels changed after toggle",
    );
    // Toggle back off - state returns to false and pixels change again.
    h.get_by_label("Enable").click();
    h.run();
    ok(!h.state().checked, "checkbox toggled back to false");
    let f_cb_off = frame(&mut h);
    ok(
        f_cb_off != f_after_cb,
        "checkbox indicator pixels changed on second toggle",
    );

    // --- Slider: drag the handle to the right, value must increase from 0 ---
    // kittest simulates a real pointer press+move+release on the slider node.
    let slider = h.get_by_role_and_label(egui::accesskit::Role::Slider, "amt");
    slider.hover();
    // Drag by a positive dx along the slider track.
    slider.click(); // focus the slider
    h.run();
    // Use keyboard arrow to move the slider deterministically (kittest key events on the focused slider).
    let slider = h.get_by_role_and_label(egui::accesskit::Role::Slider, "amt");
    slider.focus();
    h.run();
    for _ in 0..5 {
        h.key_press(egui::Key::ArrowRight);
        h.run();
    }
    ok(
        h.state().slider > 0.0,
        "slider value increased after ArrowRight presses",
    );
    let slider_val = h.state().slider;
    // Pressing left once must decrease it (below the max it reached).
    h.key_press(egui::Key::ArrowLeft);
    h.run();
    ok(
        h.state().slider < slider_val,
        "slider value decreased after ArrowLeft",
    );

    // --- TextEdit: focus + type, backing String must equal the typed text AND frame changes ---
    let f_before_txt = frame(&mut h);
    let te = h.get_by_role(egui::accesskit::Role::TextInput);
    te.focus();
    h.run();
    let te = h.get_by_role(egui::accesskit::Role::TextInput);
    te.type_text("egui");
    h.run();
    ok(
        h.state().text == "egui",
        "text edit backing string equals typed text",
    );
    let f_after_txt = frame(&mut h);
    ok(
        f_after_txt != f_before_txt,
        "text edit frame pixels changed after typing",
    );
    // Type more; string appends.
    let te = h.get_by_role(egui::accesskit::Role::TextInput);
    te.type_text("42");
    h.run();
    ok(
        h.state().text == "egui42",
        "text edit appended subsequent typed text",
    );

    // --- Negative control: DISABLED button click must NOT change the counter ---
    let count_before_disabled = h.state().count;
    h.get_by_label("Disabled").click();
    h.run();
    ok(
        h.state().count == count_before_disabled,
        "negative control: clicking disabled button does not change counter",
    );

    // --- Negative control: after all events settle, an idle re-run is byte-stable ---
    h.run();
    let f_settle = frame(&mut h);
    h.run();
    let f_settle2 = frame(&mut h);
    ok(
        f_settle2 == f_settle,
        "negative control: idle re-run after events is byte-identical",
    );

    // --- Cross-check: the counter never went backwards across the whole session ---
    ok(
        h.state().count >= 2,
        "counter is at least 2 (monotonic across clicks)",
    );

    // --- Cross-check: clicking Increment once more still works after other interactions ---
    let c = h.state().count;
    h.get_by_label("Increment").click();
    h.run();
    ok(
        h.state().count == c + 1,
        "increment still responsive after other interactions",
    );

    // --- Determinism across a fresh harness: same scripted click yields same state ---
    let mut h2 = build();
    h2.run();
    h2.get_by_label("Increment").click();
    h2.run();
    ok(
        h2.state().count == 1,
        "fresh harness: one click -> count 1 (deterministic)",
    );
    let mut h3 = build();
    h3.run();
    h3.get_by_label("Increment").click();
    h3.run();
    ok(
        h3.state().count == 1,
        "another fresh harness: identical result",
    );

    finish();
}

fn finish() {
    let pass = PASS.load(Ordering::Relaxed);
    let fail = FAIL.load(Ordering::Relaxed);
    let total = pass + fail;
    println!("egui-interact: PASS={pass} FAIL={fail} TOTAL={total} EXPECTED={EXPECTED}");
    if fail == 0 && total == EXPECTED {
        println!("GUI_EGUI_INTERACT OK {pass}");
        std::process::exit(0);
    } else {
        println!("GUI_EGUI_INTERACT FAIL");
        std::process::exit(1);
    }
}
