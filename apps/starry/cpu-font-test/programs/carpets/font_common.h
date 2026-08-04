/* font_common.h - shared primitives for the cpu-font-test carpet ("pyte for fonts").
 *
 * Everything the cells assert against is either a closed-form property (monospace advance is a single
 * fixed value; a space glyph rasterizes to an empty bitmap) or a golden value calibrated once host-side
 * with the SAME FreeType/HarfBuzz the image ships (Alpine musl freetype/harfbuzz). The cells REUSE
 * libfreetype (rasterization + metrics) and libharfbuzz (shaping) - only the comparison logic, the
 * SHA-256 over the rendered ink buffer, and the golden constants are self-written. "Font loaded" is not
 * a test: every cell asserts per-pixel bitmaps, exact-integer metrics, or exact glyph-index/position
 * shaping output against the golden.
 *
 * FreeType rasterization is bit-exact deterministic for a fixed (font, pixel size, hinting, render
 * mode, FreeType version): the smooth (AA) rasterizer and the monochrome rasterizer are pure integer/
 * fixed-point pipelines with no float rounding divergence across the arches Alpine builds for. So the
 * SHA-256 of the ink buffer is a reproducible golden. HarfBuzz shaping (glyph indices + 26.6 advances)
 * is likewise deterministic for a fixed font+features. Goldens are pinned to the FreeType/HarfBuzz the
 * image actually ships: Alpine edge musl FreeType 2.14.3 + HarfBuzz 14.2.1 (verified by rebuilding the
 * goldens against those exact .so files). AA/mono geometry, ink counts, all AA SHAs and every metric/
 * shaping value are identical from FreeType 2.13 through 2.14; the one value that moved across the 2.14
 * bump is the 1-bit MONO packing SHA, which the golden tracks. A further version skew that changed a
 * glyph outline would flip the SHA and the cell would FAIL loudly rather than silently pass.
 */
#ifndef FONT_COMMON_H
#define FONT_COMMON_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include <ft2build.h>
#include FT_FREETYPE_H
#include FT_MODULE_H
#include FT_FONT_FORMATS_H

#include <hb.h>
#include <hb-ft.h>

/* -------- font locations -------- */
/* On-target these come from the staged overlay (prebuild copies render-assets/fonts here) or from the
 * ASSET_DIR submodule mount. Host validation points FONT_DIR at the render-assets tree directly. */
static const char *font_dir(void) {
    const char *d = getenv("FONT_DIR");
    if (d && *d) return d;
    d = getenv("ASSET_DIR");
    if (d && *d) return d;          /* ASSET_DIR/fonts appended by callers when needed */
    return "/opt/cpu-font-test/fonts";
}

/* Build "<font_dir>/<name>" into a static-ish caller buffer. */
static const char *font_path(char *buf, size_t n, const char *name) {
    snprintf(buf, n, "%s/%s", font_dir(), name);
    return buf;
}

/* Canonical faces used by the golden cells (flattened names in render-assets/fonts). */
#define FONT_JBM_REGULAR "root__JetBrainsMono-Regular.ttf"
#define FONT_JBM_MEDIUM  "root__JetBrainsMono-Medium.ttf"
#define FONT_JBM_BOLD    "root__JetBrainsMono-Bold.ttf"
#define FONT_SC_REGULAR  "root__HarmonyOS_Sans_SC_Regular.ttf"
#define FONT_ARABIC      "HarmonyOS_Sans_Naskh_Arabic__HarmonyOS_Sans_Naskh_Arabic_Regular.ttf"

/* -------- self-written SHA-256 over the rendered ink buffer -------- */
typedef struct { uint32_t h[8]; uint64_t len; unsigned char buf[64]; size_t n; } sha256_ctx;
static const uint32_t SHA_K[64] = {
    0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
    0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
    0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
    0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
    0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
    0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
    0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
    0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2 };
static uint32_t sha_ror(uint32_t x, int n) { return (x >> n) | (x << (32 - n)); }
static void sha256_init(sha256_ctx *c) {
    c->h[0]=0x6a09e667; c->h[1]=0xbb67ae85; c->h[2]=0x3c6ef372; c->h[3]=0xa54ff53a;
    c->h[4]=0x510e527f; c->h[5]=0x9b05688c; c->h[6]=0x1f83d9ab; c->h[7]=0x5be0cd19;
    c->len = 0; c->n = 0;
}
static void sha256_block(sha256_ctx *c, const unsigned char *p) {
    uint32_t w[64];
    for (int i = 0; i < 16; i++)
        w[i] = (p[i*4]<<24)|(p[i*4+1]<<16)|(p[i*4+2]<<8)|p[i*4+3];
    for (int i = 16; i < 64; i++) {
        uint32_t s0 = sha_ror(w[i-15],7)^sha_ror(w[i-15],18)^(w[i-15]>>3);
        uint32_t s1 = sha_ror(w[i-2],17)^sha_ror(w[i-2],19)^(w[i-2]>>10);
        w[i] = w[i-16]+s0+w[i-7]+s1;
    }
    uint32_t a=c->h[0],b=c->h[1],cc=c->h[2],d=c->h[3],e=c->h[4],f=c->h[5],g=c->h[6],h=c->h[7];
    for (int i = 0; i < 64; i++) {
        uint32_t S1 = sha_ror(e,6)^sha_ror(e,11)^sha_ror(e,25);
        uint32_t ch = (e&f)^((~e)&g);
        uint32_t t1 = h+S1+ch+SHA_K[i]+w[i];
        uint32_t S0 = sha_ror(a,2)^sha_ror(a,13)^sha_ror(a,22);
        uint32_t maj = (a&b)^(a&cc)^(b&cc);
        uint32_t t2 = S0+maj;
        h=g; g=f; f=e; e=d+t1; d=cc; cc=b; b=a; a=t1+t2;
    }
    c->h[0]+=a; c->h[1]+=b; c->h[2]+=cc; c->h[3]+=d; c->h[4]+=e; c->h[5]+=f; c->h[6]+=g; c->h[7]+=h;
}
static void sha256_update(sha256_ctx *c, const void *data, size_t len) {
    const unsigned char *p = (const unsigned char *)data;
    c->len += len;
    while (len > 0) {
        size_t take = 64 - c->n; if (take > len) take = len;
        memcpy(c->buf + c->n, p, take);
        c->n += take; p += take; len -= take;
        if (c->n == 64) { sha256_block(c, c->buf); c->n = 0; }
    }
}
static void sha256_hex(sha256_ctx *c, char out[65]) {
    uint64_t bits = c->len * 8;
    unsigned char pad = 0x80;
    sha256_update(c, &pad, 1);
    unsigned char z = 0;
    while (c->n != 56) sha256_update(c, &z, 1);
    unsigned char lb[8];
    for (int i = 0; i < 8; i++) lb[i] = (bits >> (56 - i*8)) & 0xff;
    sha256_update(c, lb, 8);
    for (int i = 0; i < 8; i++) sprintf(out + i*8, "%08x", c->h[i]);
}
/* one-shot: hex SHA-256 of buf[0..len) */
static void sha256_buf(const void *buf, size_t len, char out[65]) {
    sha256_ctx c; sha256_init(&c); sha256_update(&c, buf, len); sha256_hex(&c, out);
}

/* -------- three-gate marker (identical semantics to the audio/render carpets) -------- */
typedef struct { int pass, total, fail; const char *name; } gate;
static void gate_init(gate *g, const char *name) { g->pass = g->total = g->fail = 0; g->name = name; }
static void gate_check(gate *g, int cond, const char *msg) {
    g->total++;
    if (cond) g->pass++;
    else { g->fail++; fprintf(stderr, "  FAIL: %s\n", msg); }
}
static int gate_finish(gate *g) {
    if (g->fail == 0 && g->total == g->pass && g->total > 0) {
        printf("%s OK %d\n", g->name, g->total);
        return 0;
    }
    printf("%s FAILED pass=%d total=%d fail=%d\n", g->name, g->pass, g->total, g->fail);
    return 1;
}

/* gate discipline: an OK line with 0 assertions is NOT allowed (gate_finish requires total>0). Every
 * cell must assert at least one real check; font_realassets emits its OK marker over the fonts it
 * iterated (assets are guaranteed staged on-target, so an absent asset dir is a FAIL, not a skip). */

/* -------- FreeType convenience -------- */
/* Load a face at a fixed pixel size; hinting/render mode chosen by the caller's FT_Load_Glyph flags. */
static int ft_open(FT_Library lib, const char *path, FT_Face *face) {
    return FT_New_Face(lib, path, 0, face);
}

/* Render a single character to an 8-bit coverage buffer via FreeType. Returns 0 on success and fills
 * *w,*h,*pitch,*top,*left plus a malloc'd copy of the bitmap (caller frees). mode is FT_RENDER_MODE_*
 * and load_flags is the FT_Load_Glyph flag set (hinting on/off). The returned buffer is exactly
 * pitch*h bytes so the SHA is over the true rasterizer output including row padding. */
static int ft_render_char(FT_Face face, uint32_t cp, int px, FT_Int32 load_flags, FT_Render_Mode mode,
                          unsigned char **buf, int *w, int *h, int *pitch, int *top, int *left,
                          FT_UInt *gindex_out) {
    if (FT_Set_Pixel_Sizes(face, px, px)) return -1;
    FT_UInt gi = FT_Get_Char_Index(face, cp);
    if (gindex_out) *gindex_out = gi;
    if (FT_Load_Glyph(face, gi, load_flags)) return -2;
    if (FT_Render_Glyph(face->glyph, mode)) return -3;
    FT_Bitmap *bm = &face->glyph->bitmap;
    *w = bm->width; *h = bm->rows; *pitch = bm->pitch;
    *top = face->glyph->bitmap_top; *left = face->glyph->bitmap_left;
    size_t n = (size_t)(*pitch < 0 ? -*pitch : *pitch) * (*h);
    unsigned char *out = (unsigned char *)malloc(n ? n : 1);
    if (n) memcpy(out, bm->buffer, n); else out[0] = 0;
    *buf = out;
    return 0;
}

/* count nonzero (ink) bytes in an 8-bit coverage buffer */
static long ink_count(const unsigned char *buf, int pitch, int h) {
    long n = 0; int ap = pitch < 0 ? -pitch : pitch;
    for (int y = 0; y < h; y++) for (int x = 0; x < ap; x++) if (buf[y*ap + x]) n++;
    return n;
}

#endif /* FONT_COMMON_H */
