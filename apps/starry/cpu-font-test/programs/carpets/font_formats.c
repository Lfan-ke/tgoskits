/* font_formats - format matrix: WOFF / WOFF2 wrappers decode to the identical outline (cell 4).
 *
 * The source fonts are TTF. The prebuild converts JetBrains Mono Regular to WOFF and WOFF2 host-side
 * (fontTools, brotli for WOFF2) and stages them next to the TTF. WOFF/WOFF2 are container compressions
 * of the same sfnt tables, so FreeType must decode them to the byte-identical glyph outline. This cell
 * asserts:
 *   - FreeType loads the TTF and reports FT_Get_Font_Format == "TrueType", with the expected
 *     num_glyphs (1754) / units_per_EM (1000) / family_name,
 *   - FreeType loads each of the WOFF/WOFF2 wrappers, reports the same TrueType format, num_glyphs and
 *     upm, and renders 'A' @32px to the SAME per-pixel SHA as the TTF (format must not change the
 *     outline). prebuild.sh stages both wrappers host-side (fontTools + brotli) and hard-fails if it
 *     cannot, so on-target both legs are mandatory: a missing wrapper fails the gate rather than letting
 *     the format-identity matrix silently collapse to the TTF baseline.
 *
 * OTF (glyf->CFF outline reflow) is a genuine outline re-encoding, not a lossless wrapper, so it is not
 * asserted for pixel-identity here; the wrapper matrix (WOFF/WOFF2) is the lossless-identity test and
 * the OTF leg is documented as a follow-up (honest).
 */
#include "font_common.h"

/* golden SHA of JetBrains Mono 'A' @32px AA (same as font_raster's A@32 AA hint) */
static const char *A32_SHA = "b3e1b83fb1f1fe09aa91f5a260065d8ba8c954b38209fad01478394e39396487";

/* render 'A' @32px and hash; returns 0 on success */
static int hash_A(FT_Face f, char hex[65]) {
    unsigned char *buf; int w,h,pitch,top,left; FT_UInt gi;
    if (ft_render_char(f, 'A', 32, FT_LOAD_DEFAULT, FT_RENDER_MODE_NORMAL,
                       &buf, &w, &h, &pitch, &top, &left, &gi)) return -1;
    size_t n = (size_t)(pitch < 0 ? -pitch : pitch) * h;
    sha256_buf(buf, n ? n : 1, hex);
    free(buf);
    return 0;
}

/* Assert a wrapper loads, is TrueType, and renders A identically to the TTF golden. prebuild.sh stages
 * both wrappers host-side (fontTools + brotli) and hard-fails if it cannot, so on-target the wrapper is
 * MANDATORY: a missing wrapper is a real staging failure, not a skip - it fails the gate rather than
 * silently collapsing the format-identity matrix to the TTF baseline. */
static void check_wrapper(gate *g, FT_Library lib, const char *dir, const char *name, const char *label) {
    char path[512]; snprintf(path, sizeof path, "%s/%s", dir, name);
    FT_Face f;
    FT_Error err = FT_New_Face(lib, path, 0, &f);
    gate_check(g, err == 0, label); /* wrapper MUST be staged and openable */
    if (err) return;
    gate_check(g, strcmp(FT_Get_Font_Format(f), "TrueType") == 0, label);
    gate_check(g, f->num_glyphs == 1754, label);
    gate_check(g, f->units_per_EM == 1000, label);
    char hex[65];
    gate_check(g, hash_A(f, hex) == 0 && strcmp(hex, A32_SHA) == 0, label); /* identical outline */
    FT_Done_Face(f);
}

int main(void) {
    gate g; gate_init(&g, "FONT_FORMATS");
    FT_Library lib;
    gate_check(&g, FT_Init_FreeType(&lib) == 0, "FT_Init_FreeType failed");
    if (g.fail) return gate_finish(&g);

    const char *dir = font_dir();
    char path[512];

    /* baseline TTF leg (always present) */
    {
        FT_Face f;
        gate_check(&g, ft_open(lib, font_path(path, sizeof path, FONT_JBM_REGULAR), &f) == 0,
                   "open JBM TTF");
        if (!g.fail) {
            gate_check(&g, strcmp(FT_Get_Font_Format(f), "TrueType") == 0, "TTF format != TrueType");
            gate_check(&g, f->num_glyphs == 1754, "TTF num_glyphs != 1754");
            gate_check(&g, f->units_per_EM == 1000, "TTF units_per_EM != 1000");
            gate_check(&g, strcmp(f->family_name, "JetBrains Mono") == 0, "TTF family_name mismatch");
            /* enumerate faces: a single-face TTF reports num_faces == 1 */
            gate_check(&g, f->num_faces == 1, "TTF num_faces != 1");
            char hex[65];
            gate_check(&g, hash_A(f, hex) == 0 && strcmp(hex, A32_SHA) == 0, "TTF 'A' SHA != golden");
            FT_Done_Face(f);
        }
    }

    /* wrapper matrix: WOFF + WOFF2 staged next to the TTF (mandatory - prebuild hard-fails if unstaged) */
    check_wrapper(&g, lib, dir, "jbm-format.woff",  "WOFF wrapper 'A' identical to TTF");
    check_wrapper(&g, lib, dir, "jbm-format.woff2", "WOFF2 wrapper 'A' identical to TTF");

    FT_Done_FreeType(lib);
    return gate_finish(&g);
}
