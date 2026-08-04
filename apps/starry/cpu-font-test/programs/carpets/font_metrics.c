/* font_metrics - exact numeric metric assertions (cell 2).
 *
 * FreeType exposes glyph metrics in 26.6 fixed point (font-unit metrics scaled by the pixel size). For a
 * MONOSPACE face every glyph shares one advance width; JetBrains Mono @32px advances 1216 (26.6) for A,
 * g, l, 0, W and space alike. We assert:
 *   - the shared monospace advance at 16/32/64 px (1000 upm -> advance == 640/1216/2432 in 26.6),
 *   - per-glyph horiBearingX/Y, width, height against golden font-unit-scaled values,
 *   - face-level units_per_EM (1000), ascender (1020), descender (-300), height (1320),
 *   - FT_HAS_KERNING: JetBrains Mono ships no 'kern'/GPOS-kern, so FT_Get_Kerning('A','V') == (0,0);
 *     HarmonyOS Sans (proportional) has genuinely different advances for A/V vs i/l, proving the
 *     monospace assertion is a real property, not a tautology.
 * All values are exact integers in FreeType's fixed-point domain vs golden - no tolerance.
 */
#include "font_common.h"

/* golden per-glyph metrics at 32px (26.6), captured host-side (FreeType 2.14.3, JetBrains Mono; per
 * README these metrics are identical from 2.13 through 2.14, so the goldens match the shipped 2.14.3) */
typedef struct { uint32_t cp; long adv, bx, by, w, h; } glyph_metric;
static const glyph_metric M32[] = {
  {'A', 1216,   64, 1472, 1088, 1472},
  {'g', 1216,  128, 1152,  960, 1536},
  {'l', 1216,    0, 1472, 1152, 1472},
  {'0', 1216,  128, 1472,  960, 1472},
  {'W', 1216,    0, 1472, 1216, 1472},
  {' ', 1216,    0,    0,    0,    0},
};
#define NM ((int)(sizeof(M32)/sizeof(M32[0])))

int main(void) {
    gate g; gate_init(&g, "FONT_METRICS");
    FT_Library lib;
    gate_check(&g, FT_Init_FreeType(&lib) == 0, "FT_Init_FreeType failed");
    if (g.fail) return gate_finish(&g);

    char path[512];
    FT_Face jbm;
    gate_check(&g, ft_open(lib, font_path(path, sizeof path, FONT_JBM_REGULAR), &jbm) == 0,
               "open JetBrains Mono");
    if (g.fail) return gate_finish(&g);

    /* face-level constants (font-unit domain, size-independent) */
    gate_check(&g, jbm->units_per_EM == 1000, "JBM units_per_EM != 1000");
    gate_check(&g, jbm->ascender == 1020, "JBM ascender != 1020");
    gate_check(&g, jbm->descender == -300, "JBM descender != -300");
    gate_check(&g, jbm->height == 1320, "JBM line height != 1320");
    gate_check(&g, jbm->num_glyphs == 1754, "JBM num_glyphs != 1754");
    gate_check(&g, strcmp(jbm->family_name, "JetBrains Mono") == 0, "JBM family_name mismatch");

    /* monospace advance at three sizes. JetBrains Mono's advance is 600 font units at 1000 upm; the
     * unhinted scale would be px*600/1000 = px*38.4 in 26.6 (32px -> 1228.8), but FT_LOAD_DEFAULT
     * grid-fits the advance to a whole pixel, so 32px rounds to 19px == 1216 (19*64) in 26.6. The
     * goldens are these hinted, rounded advances: 10px/640, 19px/1216, 38px/2432. */
    struct { int px; long adv; } sizes[] = { {16,640}, {32,1216}, {64,2432} };
    for (int s = 0; s < 3; s++) {
        FT_Set_Pixel_Sizes(jbm, sizes[s].px, sizes[s].px);
        const char *probe = "AglW0i xz";   /* mix of wide/narrow glyphs + space */
        for (const char *c = probe; *c; c++) {
            FT_Load_Glyph(jbm, FT_Get_Char_Index(jbm, *c), FT_LOAD_DEFAULT);
            gate_check(&g, jbm->glyph->advance.x == sizes[s].adv,
                       "monospace advance not uniform across glyphs/size");
        }
    }

    /* exact per-glyph metrics at 32px */
    FT_Set_Pixel_Sizes(jbm, 32, 32);
    for (int i = 0; i < NM; i++) {
        FT_Load_Glyph(jbm, FT_Get_Char_Index(jbm, M32[i].cp), FT_LOAD_DEFAULT);
        FT_Glyph_Metrics *m = &jbm->glyph->metrics;
        gate_check(&g, jbm->glyph->advance.x == M32[i].adv, "advance != golden");
        gate_check(&g, m->horiBearingX == M32[i].bx, "horiBearingX != golden");
        gate_check(&g, m->horiBearingY == M32[i].by, "horiBearingY != golden");
        gate_check(&g, m->width  == M32[i].w, "glyph width != golden");
        gate_check(&g, m->height == M32[i].h, "glyph height != golden");
    }

    /* kerning: JetBrains Mono has none - assert FT_HAS_KERNING is false and the AV pair is (0,0).
     * Honest golden: monospace fonts do not kern (every advance is already fixed). */
    gate_check(&g, FT_HAS_KERNING(jbm) == 0, "JBM unexpectedly reports kerning");
    FT_UInt a = FT_Get_Char_Index(jbm, 'A'), v = FT_Get_Char_Index(jbm, 'V');
    FT_Vector kv; FT_Get_Kerning(jbm, a, v, FT_KERNING_DEFAULT, &kv);
    gate_check(&g, kv.x == 0 && kv.y == 0, "JBM AV kerning nonzero");

    /* contrast face: HarmonyOS Sans is proportional - A/V share 1344 but i/l are narrower, so the
     * monospace property above is a real discriminator, not vacuous. */
    FT_Face hos;
    if (ft_open(lib, font_path(path, sizeof path,
                "HarmonyOS_Sans__HarmonyOS_Sans_Regular.ttf"), &hos) == 0) {
        FT_Set_Pixel_Sizes(hos, 32, 32);
        FT_Load_Glyph(hos, FT_Get_Char_Index(hos, 'A'), FT_LOAD_DEFAULT); long aA = hos->glyph->advance.x;
        FT_Load_Glyph(hos, FT_Get_Char_Index(hos, 'V'), FT_LOAD_DEFAULT); long aV = hos->glyph->advance.x;
        FT_Load_Glyph(hos, FT_Get_Char_Index(hos, 'i'), FT_LOAD_DEFAULT); long ai = hos->glyph->advance.x;
        FT_Load_Glyph(hos, FT_Get_Char_Index(hos, 'l'), FT_LOAD_DEFAULT); long al = hos->glyph->advance.x;
        gate_check(&g, aA == 1344 && aV == 1344, "HOS A/V advance != golden 1344");
        gate_check(&g, ai == 512 && al == 448, "HOS i/l advance != golden");
        gate_check(&g, ai != aA && al != aA, "HOS Sans is not proportional (i/l == A)?");
        gate_check(&g, hos->units_per_EM == 1000, "HOS units_per_EM != 1000");
        FT_Done_Face(hos);
    } else gate_check(&g, 0, "open HarmonyOS Sans contrast face");

    FT_Done_Face(jbm);
    FT_Done_FreeType(lib);
    return gate_finish(&g);
}
