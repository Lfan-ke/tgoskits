/* font_shape - HarfBuzz text shaping, exact glyph-index + position golden (cell 3).
 *
 * Shape known strings and assert HarfBuzz's output glyph-index sequence + per-glyph x_advance/x_offset/
 * y_offset + cluster map against goldens captured host-side (HarfBuzz 8.3.0). Legs:
 *   - simple Latin "Hello" in JetBrains Mono: 5 glyphs, monospace so every x_advance == 1229 (26.6),
 *     exact gids 65,234,287,287,302, clusters 0..4, script auto-detected Latin, direction LTR.
 *   - "AV" in JBM: 2 glyphs, no ligature/kern -> advances stay 1229 each (contrast with a kerning font).
 *   - ligature "fi": HarmonyOS Sans maps f+i -> a SINGLE ligature glyph (gid397, cluster 0), while
 *     JetBrains Mono keeps them as 2 separate glyphs. Both are asserted so the ligature test is real.
 *   - RTL complex script: Arabic "سلام" (salam) with HarmonyOS Naskh Arabic ->
 *     3 shaped glyphs, direction auto-detected RTL, script Arab, descending cluster order (RTL reorder).
 *   - buffer property detection: hb_buffer_guess_segment_properties sets direction/script from the text.
 * All glyph indices and 26.6 positions are exact vs golden - no tolerance. HarfBuzz shaping is
 * deterministic for a fixed font + feature set.
 */
#include "font_common.h"

static hb_font_t *load_hb(const char *dir_name, int px) {
    char path[512]; snprintf(path, sizeof path, "%s/%s", font_dir(), dir_name);
    hb_blob_t *blob = hb_blob_create_from_file(path);
    if (!blob || hb_blob_get_length(blob) == 0) return NULL;
    hb_face_t *face = hb_face_create(blob, 0);
    hb_font_t *font = hb_font_create(face);
    hb_font_set_scale(font, px << 6, px << 6);
    hb_face_destroy(face); hb_blob_destroy(blob);
    return font;
}

typedef struct { unsigned gid, cluster; int xadv, xoff, yoff; } shaped;

/* shape text with auto-detected properties; fill out[] (cap) and return glyph count, dir, script */
static unsigned shape(hb_font_t *font, const char *text, shaped *out, unsigned cap,
                      hb_direction_t *dir, hb_script_t *script) {
    hb_buffer_t *b = hb_buffer_create();
    hb_buffer_add_utf8(b, text, -1, 0, -1);
    hb_buffer_guess_segment_properties(b);
    hb_shape(font, b, NULL, 0);
    unsigned gc; hb_glyph_info_t *gi = hb_buffer_get_glyph_infos(b, &gc);
    hb_glyph_position_t *gp = hb_buffer_get_glyph_positions(b, &gc);
    if (dir) *dir = hb_buffer_get_direction(b);
    if (script) *script = hb_buffer_get_script(b);
    unsigned n = gc < cap ? gc : cap;
    for (unsigned i = 0; i < n; i++) {
        out[i].gid = gi[i].codepoint; out[i].cluster = gi[i].cluster;
        out[i].xadv = gp[i].x_advance; out[i].xoff = gp[i].x_offset; out[i].yoff = gp[i].y_offset;
    }
    hb_buffer_destroy(b);
    return gc;
}

int main(void) {
    gate g; gate_init(&g, "FONT_SHAPE");

    hb_font_t *jbm = load_hb(FONT_JBM_REGULAR, 32);
    gate_check(&g, jbm != NULL, "load JetBrains Mono for HarfBuzz");
    hb_font_t *hos = load_hb("HarmonyOS_Sans__HarmonyOS_Sans_Regular.ttf", 32);
    gate_check(&g, hos != NULL, "load HarmonyOS Sans for HarfBuzz");
    hb_font_t *ara = load_hb(FONT_ARABIC, 32);
    gate_check(&g, ara != NULL, "load HarmonyOS Naskh Arabic for HarfBuzz");
    if (g.fail) return gate_finish(&g);

    shaped out[16]; hb_direction_t dir; hb_script_t script;

    /* ---- "Hello" in JBM: exact gid sequence + uniform monospace advance ---- */
    {
        static const shaped GHELLO[] = {
            {65,0,1229,0,0},{234,1,1229,0,0},{287,2,1229,0,0},{287,3,1229,0,0},{302,4,1229,0,0} };
        unsigned n = shape(jbm, "Hello", out, 16, &dir, &script);
        gate_check(&g, n == 5, "Hello: glyph count != 5");
        gate_check(&g, dir == HB_DIRECTION_LTR, "Hello: not LTR");
        gate_check(&g, script == HB_SCRIPT_LATIN, "Hello: script not Latin");
        for (unsigned i = 0; i < n && i < 5; i++) {
            gate_check(&g, out[i].gid == GHELLO[i].gid, "Hello: glyph index != golden");
            gate_check(&g, out[i].cluster == GHELLO[i].cluster, "Hello: cluster != golden");
            gate_check(&g, out[i].xadv == GHELLO[i].xadv, "Hello: x_advance != golden");
            gate_check(&g, out[i].xoff == 0 && out[i].yoff == 0, "Hello: unexpected offset");
        }
    }

    /* ---- "AV" in JBM: 2 glyphs, no ligature/kern, advances unchanged ---- */
    {
        unsigned n = shape(jbm, "AV", out, 16, &dir, &script);
        gate_check(&g, n == 2, "AV(JBM): glyph count != 2");
        gate_check(&g, out[0].gid == 1 && out[1].gid == 170, "AV(JBM): gids != golden 1,170");
        gate_check(&g, out[0].xadv == 1229 && out[1].xadv == 1229, "AV(JBM): advances kerned?");
    }

    /* ---- ligature: HarmonyOS Sans "fi" -> single ligature glyph; JBM "fi" -> two glyphs ---- */
    {
        unsigned n = shape(hos, "fi", out, 16, &dir, &script);
        gate_check(&g, n == 1, "fi(HOS): not a single ligature glyph");
        gate_check(&g, out[0].gid == 397, "fi(HOS): ligature gid != golden 397");
        gate_check(&g, out[0].cluster == 0, "fi(HOS): ligature cluster != 0");
        gate_check(&g, out[0].xadv == 1176, "fi(HOS): ligature advance != golden 1176");

        unsigned n2 = shape(jbm, "fi", out, 16, &dir, &script);
        gate_check(&g, n2 == 2, "fi(JBM): expected 2 separate glyphs (no ligature)");
        gate_check(&g, out[0].gid == 254 && out[1].gid == 265, "fi(JBM): gids != golden 254,265");
    }

    /* ---- HarmonyOS Sans "AV": proportional advances differ from JBM's uniform 1229 ---- */
    {
        unsigned n = shape(hos, "AV", out, 16, &dir, &script);
        gate_check(&g, n == 2, "AV(HOS): glyph count != 2");
        gate_check(&g, out[0].gid == 3 && out[1].gid == 169, "AV(HOS): gids != golden 3,169");
        gate_check(&g, out[0].xadv == 1186 && out[1].xadv == 1348, "AV(HOS): advances != golden");
        gate_check(&g, out[0].xadv != out[1].xadv, "AV(HOS): proportional advances collapsed");
    }

    /* ---- Arabic RTL complex script: salam -> 3 glyphs, auto RTL/Arab, RTL cluster reorder ---- */
    {
        /* U+0633 U+0644 U+0627 U+0645 */
        const char *salam = "\xd8\xb3\xd9\x84\xd8\xa7\xd9\x85";
        static const shaped GARA[] = { {255,6,1004,0,0},{368,2,1434,0,0},{137,0,1288,0,0} };
        unsigned n = shape(ara, salam, out, 16, &dir, &script);
        gate_check(&g, n == 3, "arabic: shaped glyph count != 3");
        gate_check(&g, dir == HB_DIRECTION_RTL, "arabic: direction not auto-detected RTL");
        gate_check(&g, script == HB_SCRIPT_ARABIC, "arabic: script not auto-detected Arab");
        for (unsigned i = 0; i < n && i < 3; i++) {
            gate_check(&g, out[i].gid == GARA[i].gid, "arabic: glyph index != golden");
            gate_check(&g, out[i].cluster == GARA[i].cluster, "arabic: cluster != golden");
            gate_check(&g, out[i].xadv == GARA[i].xadv, "arabic: x_advance != golden");
        }
        /* RTL reorder: visual glyph order runs from the last logical cluster to the first */
        gate_check(&g, out[0].cluster > out[n-1].cluster, "arabic: clusters not in RTL (descending) order");
    }

    hb_font_destroy(jbm); hb_font_destroy(hos); hb_font_destroy(ara);
    return gate_finish(&g);
}
