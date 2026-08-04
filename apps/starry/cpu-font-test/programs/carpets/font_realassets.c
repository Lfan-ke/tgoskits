/* font_realassets - iterate every provided font in ASSET_DIR (cell 5).
 *
 * Walk all .ttf files under $ASSET_DIR (the render-assets/fonts submodule mount, staged by prebuild) and
 * assert each one is a real, usable face:
 *   - FT_New_Face succeeds,
 *   - num_glyphs > 0 and units_per_EM is sane (a power-of-two or 1000; these fonts are all 1000),
 *   - family_name is non-empty,
 *   - FT_Get_Font_Format == "TrueType",
 *   - at least one representative glyph renders NON-EMPTY at 32px. The Latin fonts carry 'A'; the
 *     Arabic Naskh faces have no Latin 'A' (glyph index 0), so the probe falls back to Arabic sheen
 *     U+0633, then CJK U+4E2D - every provided font inks at least one of these.
 *   - HarfBuzz can create a face+font from the same file (the shaper accepts it).
 * prebuild.sh exit-5s if it stages zero TTFs, so on-target $ASSET_DIR is guaranteed present. An absent
 * asset dir is therefore a real staging failure and fails the gate loudly rather than skipping. When the
 * assets are present, every font is asserted; a per-font failure fails the cell.
 */
#include "font_common.h"
#include <dirent.h>
#include <sys/stat.h>

static long ink_of_cp(FT_Face f, uint32_t cp) {
    FT_UInt gi = FT_Get_Char_Index(f, cp);
    if (!gi) return -1;
    if (FT_Set_Pixel_Sizes(f, 32, 32)) return -1;
    if (FT_Load_Glyph(f, gi, FT_LOAD_DEFAULT)) return -1;
    if (FT_Render_Glyph(f->glyph, FT_RENDER_MODE_NORMAL)) return -1;
    return ink_count(f->glyph->bitmap.buffer, f->glyph->bitmap.pitch, f->glyph->bitmap.rows);
}

int main(void) {
    gate g; gate_init(&g, "FONT_REALASSETS");

    const char *base = font_dir();
    /* If FONT_DIR/ASSET_DIR points at a tree with a fonts/ subdir, descend into it. */
    char dir[512]; snprintf(dir, sizeof dir, "%s", base);
    struct stat st;
    char sub[512]; snprintf(sub, sizeof sub, "%s/fonts", base);
    if (stat(sub, &st) == 0 && S_ISDIR(st.st_mode)) snprintf(dir, sizeof dir, "%s", sub);

    DIR *d = opendir(dir);
    if (!d) {
        /* prebuild.sh exit-5s if it stages zero TTFs, so on-target the asset dir is guaranteed present.
         * An absent dir here is a real staging failure, not a skip - fail the gate loudly. */
        fprintf(stderr, "  FAIL: ASSET_DIR '%s' absent - fonts must be staged on-target\n", dir);
        gate_check(&g, 0, "asset dir absent");
        return gate_finish(&g);
    }

    FT_Library lib;
    gate_check(&g, FT_Init_FreeType(&lib) == 0, "FT_Init_FreeType failed");
    if (g.fail) { closedir(d); return gate_finish(&g); }

    int nfonts = 0;
    struct dirent *e;
    while ((e = readdir(d)) != NULL) {
        const char *nm = e->d_name; size_t L = strlen(nm);
        if (L < 4 || strcmp(nm + L - 4, ".ttf") != 0) continue;
        char path[1024]; snprintf(path, sizeof path, "%s/%s", dir, nm);

        FT_Face f;
        if (FT_New_Face(lib, path, 0, &f) != 0) { gate_check(&g, 0, nm); continue; }
        nfonts++;
        gate_check(&g, f->num_glyphs > 0, nm);                       /* has glyphs */
        gate_check(&g, f->units_per_EM == 1000, nm);                 /* sane upm (these are all 1000) */
        gate_check(&g, f->family_name && f->family_name[0], nm);     /* named family */
        gate_check(&g, strcmp(FT_Get_Font_Format(f), "TrueType") == 0, nm); /* TrueType */

        long a = ink_of_cp(f, 'A'), s = ink_of_cp(f, 0x0633), c = ink_of_cp(f, 0x4E2D);
        long best = a; if (s > best) best = s; if (c > best) best = c;
        gate_check(&g, best > 0, nm);                                /* renders a real glyph */

        /* HarfBuzz accepts the same file */
        hb_blob_t *blob = hb_blob_create_from_file(path);
        gate_check(&g, blob && hb_blob_get_length(blob) > 0, nm);
        hb_face_t *hf = hb_face_create(blob, 0);
        gate_check(&g, hb_face_get_glyph_count(hf) == (unsigned)f->num_glyphs, nm);
        hb_face_destroy(hf); hb_blob_destroy(blob);

        FT_Done_Face(f);
    }
    closedir(d);

    gate_check(&g, nfonts >= 1, "no .ttf fonts found under asset dir");
    fprintf(stderr, "  font_realassets: iterated %d fonts under %s\n", nfonts, dir);

    FT_Done_FreeType(lib);
    return gate_finish(&g);
}
