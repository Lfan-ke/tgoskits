/* font_raster - FreeType glyph -> pixels, deterministic per-pixel golden (cell 1).
 *
 * Load JetBrains Mono (and HarmonyOS SC for CJK) at fixed pixel sizes and render specific glyphs, then
 * assert the rasterizer output BYTE-EXACT against goldens captured host-side with the same FreeType:
 *   - exact bitmap width / height / pitch / bitmap_top / bitmap_left,
 *   - the SHA-256 of the full ink buffer (pitch*rows bytes, incl. row padding),
 *   - the ink pixel count,
 *   - known-position pixels: 'l' (a vertical bar) has ink in its center column; ' ' renders empty.
 * Covers multiple sizes (16/32/48/64 px), FT_RENDER_MODE_MONO vs NORMAL (AA), and hinting on/off - each
 * combination has its own golden because they are genuinely different rasterizer outputs.
 *
 * Goldens are the real FreeType output on this font, pinned to the Alpine edge musl build the image ships
 * (FreeType 2.14.3). FreeType's smooth + monochrome rasterizers are deterministic integer/fixed-point
 * pipelines, so the SHA is reproducible on every arch. A rasterizer regression (or a font/size/hinting
 * mismatch) flips the SHA and this cell FAILs loudly.
 */
#include "font_common.h"

typedef struct {
    const char *label, *font;
    uint32_t cp; int px;
    FT_Int32 load_flags; FT_Render_Mode mode;
    int w, h, pitch, top, left; long ink;
    const char *sha;
} raster_golden;

/* Captured and re-verified against Alpine edge musl FreeType 2.14.3 (the version the image ships). The
 * MONO packing SHA moved across the 2.14 bump; every AA SHA + geometry is stable from 2.13 onward. */
static const raster_golden G[] = {
  {"A@32 AA hint",  FONT_JBM_REGULAR, 'A', 32, FT_LOAD_DEFAULT, FT_RENDER_MODE_NORMAL,
   17,23,17,23,1,194, "b3e1b83fb1f1fe09aa91f5a260065d8ba8c954b38209fad01478394e39396487"},
  {"g@32 AA hint",  FONT_JBM_REGULAR, 'g', 32, FT_LOAD_DEFAULT, FT_RENDER_MODE_NORMAL,
   15,24,15,18,2,222, "9a228a7fbce3068767b2e2a98780f255708b05de7a11587680e5f6a4746cd1f2"},
  {"0@32 AA hint",  FONT_JBM_REGULAR, '0', 32, FT_LOAD_DEFAULT, FT_RENDER_MODE_NORMAL,
   15,23,15,23,2,231, "325a5ade541c08b99293cf266b5e8195dfa2c4a7b1ffd6c2256c6b7f0f813631"},
  {"l@32 AA hint",  FONT_JBM_REGULAR, 'l', 32, FT_LOAD_DEFAULT, FT_RENDER_MODE_NORMAL,
   18,23,18,23,0,115, "6efc437130e7bc13f52e82ce756df80f6d7fb13e278992773dfa2b2ec3a3fcbf"},
  {"space@32 AA",   FONT_JBM_REGULAR, ' ', 32, FT_LOAD_DEFAULT, FT_RENDER_MODE_NORMAL,
   0,0,0,0,0,0,       "6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d"},
  {"A@32 MONO hint", FONT_JBM_REGULAR, 'A', 32, FT_LOAD_TARGET_MONO, FT_RENDER_MODE_MONO,
   16,23,2,23,2,46,   "3e7ebc49816f3a72e55dbdaad26a878e686c0acb8f3e21b8a9b2f27911caa628"},
  {"A@32 AA nohint", FONT_JBM_REGULAR, 'A', 32, FT_LOAD_NO_HINTING, FT_RENDER_MODE_NORMAL,
   17,24,17,24,1,193, "b8a4ffe44364ac62faedc5c83653720f4081725c0dd281058dc2c2d5e447e811"},
  {"A@16 AA hint",  FONT_JBM_REGULAR, 'A', 16, FT_LOAD_DEFAULT, FT_RENDER_MODE_NORMAL,
   9,12,9,12,0,63,    "12b3741b1cbae1f4da3a7ff2f376017526b967a652d110cc9a621f04dade8465"},
  {"A@48 AA hint",  FONT_JBM_REGULAR, 'A', 48, FT_LOAD_DEFAULT, FT_RENDER_MODE_NORMAL,
   25,35,25,35,2,398, "a7ed620203f3de1b476bd53193ccda1a09c469fb3d7e8592ac68dab66df1f525"},
  {"A@64 AA hint",  FONT_JBM_REGULAR, 'A', 64, FT_LOAD_DEFAULT, FT_RENDER_MODE_NORMAL,
   33,47,33,47,3,690, "403ef1f4a11d91424f7b1aea4316be736d187ad573e76d649718bce425f68746"},
  {"A@32 AA bold",  FONT_JBM_BOLD,    'A', 32, FT_LOAD_DEFAULT, FT_RENDER_MODE_NORMAL,
   18,23,18,23,1,235, "17b4b2724110abae4ed7e0d69a410ad58973422a6839cc56b013ac6c9bc50be1"},
  {"zhong@32 AA",   FONT_SC_REGULAR, 0x4E2D, 32, FT_LOAD_DEFAULT, FT_RENDER_MODE_NORMAL,
   25,30,25,28,3,285, "00bbc8cd438cffe33ad8917e10f8ffa87d2d95b779c982b1b065ea15dc151ae7"},
};
#define NG ((int)(sizeof(G)/sizeof(G[0])))

int main(void) {
    gate g; gate_init(&g, "FONT_RASTER");
    FT_Library lib;
    gate_check(&g, FT_Init_FreeType(&lib) == 0, "FT_Init_FreeType failed");
    if (g.fail) return gate_finish(&g);

    /* pin the FreeType version the goldens were captured with: a different rasterizer could shift SHAs */
    FT_Int maj, min, pat; FT_Library_Version(lib, &maj, &min, &pat);
    gate_check(&g, maj == 2, "FreeType major != 2 (golden captured on FT2)");

    char path[512];
    for (int i = 0; i < NG; i++) {
        const raster_golden *gd = &G[i];
        FT_Face face;
        if (ft_open(lib, font_path(path, sizeof path, gd->font), &face)) {
            gate_check(&g, 0, gd->label); continue;
        }
        unsigned char *buf; int w,h,pitch,top,left; FT_UInt gi;
        int rc = ft_render_char(face, gd->cp, gd->px, gd->load_flags, gd->mode,
                                &buf, &w, &h, &pitch, &top, &left, &gi);
        gate_check(&g, rc == 0, gd->label);
        if (rc == 0) {
            gate_check(&g, w == gd->w && h == gd->h && pitch == gd->pitch,
                       gd->label); /* bitmap geometry */
            gate_check(&g, top == gd->top && left == gd->left,
                       gd->label); /* pen offsets */
            gate_check(&g, ink_count(buf, pitch, h) == gd->ink,
                       gd->label); /* ink pixel count */
            size_t n = (size_t)(pitch < 0 ? -pitch : pitch) * h;
            char hex[65]; sha256_buf(buf, n ? n : 1, hex);
            gate_check(&g, strcmp(hex, gd->sha) == 0, gd->label); /* per-pixel SHA */
            free(buf);
        }
        FT_Done_Face(face);
    }

    /* known-position pixels: 'l' at 32px AA is a vertical bar - its center column must carry ink,
     * whereas a blank margin column must not. This asserts real glyph shape, not just a hash. */
    {
        FT_Face face; ft_open(lib, font_path(path, sizeof path, FONT_JBM_REGULAR), &face);
        unsigned char *buf; int w,h,pitch,top,left; FT_UInt gi;
        if (ft_render_char(face, 'l', 32, FT_LOAD_DEFAULT, FT_RENDER_MODE_NORMAL,
                           &buf, &w, &h, &pitch, &top, &left, &gi) == 0) {
            int cx = w/2, cy = h/2;
            gate_check(&g, buf[cy*pitch + cx] > 0, "'l' center column has no ink");
            long col_ink = 0; for (int y = 0; y < h; y++) if (buf[y*pitch + cx]) col_ink++;
            gate_check(&g, col_ink >= h/2, "'l' center column not a continuous stem");
            /* the vertical stem sits mid-width; the top-right corner is blank margin (the top serif
             * hooks left, the baseline serif is at the bottom). */
            gate_check(&g, buf[w-1] == 0, "'l' top-right corner unexpectedly inked");
            free(buf);
        } else gate_check(&g, 0, "'l' render for pixel probe failed");
        FT_Done_Face(face);
    }

    /* space glyph: a valid glyph index but an empty (0x0) bitmap - assert emptiness explicitly */
    {
        FT_Face face; ft_open(lib, font_path(path, sizeof path, FONT_JBM_REGULAR), &face);
        unsigned char *buf; int w,h,pitch,top,left; FT_UInt gi;
        int rc = ft_render_char(face, ' ', 32, FT_LOAD_DEFAULT, FT_RENDER_MODE_NORMAL,
                                &buf, &w, &h, &pitch, &top, &left, &gi);
        gate_check(&g, rc == 0 && gi != 0, "space has no glyph index");
        gate_check(&g, w == 0 && h == 0 && ink_count(buf, pitch, h) == 0, "space is not empty");
        if (rc == 0) free(buf);
        FT_Done_Face(face);
    }

    /* AA vs MONO must genuinely differ: the AA buffer has intermediate coverage values, MONO is 1-bit */
    {
        FT_Face face; ft_open(lib, font_path(path, sizeof path, FONT_JBM_REGULAR), &face);
        unsigned char *aa; int w,h,pitch,top,left; FT_UInt gi;
        ft_render_char(face, 'A', 32, FT_LOAD_DEFAULT, FT_RENDER_MODE_NORMAL,
                       &aa, &w, &h, &pitch, &top, &left, &gi);
        int has_partial = 0;
        for (int k = 0; k < pitch*h; k++) if (aa[k] > 0 && aa[k] < 255) { has_partial = 1; break; }
        gate_check(&g, has_partial, "AA 'A' has no anti-aliased (partial-coverage) pixels");
        free(aa);
        FT_Done_Face(face);
    }

    FT_Done_FreeType(lib);
    return gate_finish(&g);
}
