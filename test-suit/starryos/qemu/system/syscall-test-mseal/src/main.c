/*
 * test_mseal.c - mseal(2) (Linux 6.10) man-exhaustive, deterministic semantics.
 *
 * mseal(unsigned long start, size_t len, unsigned long flags) seals the covered
 * VMAs so they can no longer be mprotect'd, munmap'd, mremap'd, mmap(MAP_FIXED)-
 * over, or (for read-only anonymous ranges) discarded via madvise. Sealing is
 * irreversible; re-sealing an already-sealed range is a no-op success.
 *
 * References (Linux v7.2 source):
 *   - do_mseal / SYSCALL_DEFINE3(mseal) : mm/mseal.c:143-195
 *       flags != 0                     -> -EINVAL      (mm/mseal.c:151)
 *       start not page-aligned         -> -EINVAL      (mm/mseal.c:155)
 *       len rounds small -ve up to 0   -> -EINVAL      (mm/mseal.c:160)
 *       start + len overflow (end<start)-> -EINVAL     (mm/mseal.c:164)
 *       end == start (len 0)           -> return 0     (mm/mseal.c:167)
 *       unmapped hole in [start,end)   -> -ENOMEM      (mm/mseal.c:173 / range_contains_unmapped)
 *       success                        -> 0
 *   - enforcement gates (all return -EPERM on a sealed VMA):
 *       mprotect : mm/mprotect.c:737  (vma_is_sealed -> -EPERM)
 *       munmap   : mm/vma.c:1422,1442 (vma_is_sealed -> -EPERM)
 *       mremap   : mm/mremap.c:1736   (vma_is_sealed -> -EPERM)
 *       MAP_FIXED-over: reuses the munmap gate via do_vmi_munmap
 *       madvise discard on RO anon: mm/madvise.c:1289-1324 can_madvise_modify -> -EPERM
 *           discard set (is_discard, mm/madvise.c:1267): MADV_FREE, MADV_DONTNEED,
 *           MADV_DONTNEED_LOCKED, MADV_REMOVE, MADV_DONTFORK, MADV_WIPEONFORK,
 *           MADV_GUARD_INSTALL. Non-discard advice (e.g. MADV_WILLNEED) stays allowed.
 *           A sealed but writable anon range is NOT blocked (vm_flags & VM_WRITE).
 *
 * mseal is number 462 on x86_64 (syscall_64.tbl) and on the asm-generic table
 * (aarch64 / riscv64 / loongarch64) alike - uniform, no per-arch quirk. The musl
 * cross sysroots predate 6.10 and provide neither SYS_mseal nor a libc wrapper,
 * so the number and the raw syscall are defined here to keep the test
 * self-contained. On a kernel that lacks mseal every call returns ENOSYS, so
 * this suite fails as a whole (test-first baseline).
 */

#include "test_framework.h"
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <stdint.h>

#ifndef SYS_mseal
#define SYS_mseal 462
#endif

#ifndef MADV_WIPEONFORK
#define MADV_WIPEONFORK 18
#endif

#ifndef MADV_REMOVE
#define MADV_REMOVE 9
#endif

static long raw_mseal(unsigned long start, size_t len, unsigned long flags)
{
    return syscall(SYS_mseal, start, len, flags);
}

static char *map_pages(size_t n, int prot)
{
    void *p = mmap(NULL, n, prot, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    return p == MAP_FAILED ? NULL : (char *)p;
}

int main(void)
{
    TEST_START("mseal");

    const size_t ps = (size_t)sysconf(_SC_PAGESIZE);

    /* ---- 0. implemented-not-ENOSYS probe ------------------------------
     * A length-0 mseal (end == start) is defined to return 0 without touching
     * any VMA (mm/mseal.c:167). On a kernel missing the syscall this is ENOSYS,
     * which fails the probe and, by design, the whole suite. */
    {
        char *probe = map_pages(ps, PROT_READ | PROT_WRITE);
        CHECK(probe != NULL, "mmap probe page");
        long r = raw_mseal((unsigned long)probe, 0, 0);
        CHECK(!(r == -1 && errno == ENOSYS), "mseal is implemented (not ENOSYS)");
        CHECK_RET(raw_mseal((unsigned long)probe, 0, 0), 0, "mseal(len=0) -> 0 (no-op)");
        munmap(probe, ps);
    }

    /* ---- 1. flags must be 0 -> EINVAL (mm/mseal.c:151) ---------------- */
    {
        char *p = map_pages(ps, PROT_READ | PROT_WRITE);
        CHECK(p != NULL, "mmap page for flags test");
        CHECK_ERR(raw_mseal((unsigned long)p, ps, 1), EINVAL, "mseal(flags=1) -> EINVAL");
        CHECK_ERR(raw_mseal((unsigned long)p, ps, 0x8000), EINVAL, "mseal(flags=0x8000) -> EINVAL");
        CHECK_ERR(raw_mseal((unsigned long)p, ps, ~0UL), EINVAL, "mseal(flags=~0) -> EINVAL");
        /* flags checked before alignment/range: a bad flag on an unaligned addr
         * still reports EINVAL, but so would alignment - assert flags wins on an
         * aligned, mapped range so the errno is unambiguous. */
        munmap(p, ps);
    }

    /* ---- 2. start not page-aligned -> EINVAL (mm/mseal.c:155) --------- */
    {
        char *p = map_pages(2 * ps, PROT_READ | PROT_WRITE);
        CHECK(p != NULL, "mmap 2 pages for alignment test");
        CHECK_ERR(raw_mseal((unsigned long)p + 1, ps, 0), EINVAL,
                  "mseal(start+1, unaligned) -> EINVAL");
        CHECK_ERR(raw_mseal((unsigned long)p + ps - 1, ps, 0), EINVAL,
                  "mseal(start+ps-1, unaligned) -> EINVAL");
        munmap(p, 2 * ps);
    }

    /* ---- 3. address+len overflow -> EINVAL (mm/mseal.c:160,164) ------- */
    {
        /* len rounds up to 0: len in (0 .. ) that page-aligns to 0 is only
         * possible when it wraps, which the overflow check below covers. Use a
         * near-max length so start+len wraps past the address space. */
        unsigned long near_max = (unsigned long)-1 & ~(ps - 1); /* page aligned */
        CHECK_ERR(raw_mseal(ps, near_max, 0), EINVAL,
                  "mseal(start=ps, len~=UINTMAX) overflow -> EINVAL");
        /* start=0 (page aligned) with the maximum length also wraps. */
        CHECK_ERR(raw_mseal(0, (unsigned long)-1, 0), EINVAL,
                  "mseal(start=0, len=UINTMAX) overflow -> EINVAL");
    }

    /* ---- 4. unmapped ranges -> ENOMEM (mm/mseal.c:173) ----------------
     * A hole at the start, in the middle, or at the end each fails. */
    {
        /* 4a. entirely unmapped range. */
        char *hole = map_pages(ps, PROT_READ | PROT_WRITE);
        CHECK(hole != NULL, "mmap page to derive an unmapped address");
        unsigned long gone = (unsigned long)hole;
        munmap(hole, ps);
        CHECK_ERR(raw_mseal(gone, ps, 0), ENOMEM, "mseal(fully unmapped) -> ENOMEM");

        /* 4b. [mapped][hole][mapped]: punch the middle page, seal all three. */
        char *tri = map_pages(3 * ps, PROT_READ | PROT_WRITE);
        CHECK(tri != NULL, "mmap 3 pages for middle-hole test");
        CHECK_RET(munmap(tri + ps, ps), 0, "punch middle page");
        CHECK_ERR(raw_mseal((unsigned long)tri, 3 * ps, 0), ENOMEM,
                  "mseal over a middle hole -> ENOMEM");
        /* The failed mseal must NOT have sealed the surviving fragments: prove
         * the first page is still mutable. */
        CHECK_RET(mprotect(tri, ps, PROT_READ), 0,
                  "first fragment still mprotect-able after failed mseal");
        munmap(tri, ps);
        munmap(tri + 2 * ps, ps);

        /* 4c. hole at the end: map one page, seal two pages worth. */
        char *tail = map_pages(ps, PROT_READ | PROT_WRITE);
        CHECK(tail != NULL, "mmap 1 page for tail-hole test");
        CHECK_ERR(raw_mseal((unsigned long)tail, 2 * ps, 0), ENOMEM,
                  "mseal past the end of the mapping -> ENOMEM");
        munmap(tail, ps);
    }

    /* ---- 5. success + irreversibility + re-seal no-op ----------------- */
    {
        char *p = map_pages(ps, PROT_READ | PROT_WRITE);
        CHECK(p != NULL, "mmap page to seal");
        CHECK_RET(raw_mseal((unsigned long)p, ps, 0), 0, "mseal(mapped RW page) -> 0");
        /* Re-sealing the same (already sealed) range is a no-op success. */
        CHECK_RET(raw_mseal((unsigned long)p, ps, 0), 0, "re-mseal already-sealed -> 0 (no-op)");
        /* Sealing is irreversible: there is no unseal, and the page stays sealed
         * (enforced below). Keep it mapped; teardown at process exit is allowed
         * (Linux tears sealed VMAs down on exit). */

        /* 5a. mprotect on a sealed VMA -> EPERM (mm/mprotect.c:737). */
        CHECK_ERR(mprotect(p, ps, PROT_READ), EPERM, "mprotect(sealed) -> EPERM");
        CHECK_ERR(mprotect(p, ps, PROT_READ | PROT_WRITE | PROT_EXEC), EPERM,
                  "mprotect(sealed, add EXEC) -> EPERM");

        /* 5b. munmap on a sealed VMA -> EPERM (mm/vma.c:1442). */
        CHECK_ERR(munmap(p, ps), EPERM, "munmap(sealed) -> EPERM");

        /* 5c. mremap of a sealed VMA -> EPERM (mm/mremap.c:1736). */
        CHECK_ERR(mremap(p, ps, 2 * ps, 0), EPERM, "mremap(sealed, grow in place) -> EPERM");
        CHECK_ERR(mremap(p, ps, 2 * ps, MREMAP_MAYMOVE), EPERM,
                  "mremap(sealed, MAYMOVE) -> EPERM");

        /* 5d. mmap(MAP_FIXED) over a sealed VMA -> EPERM (munmap gate reused). */
        void *fixed = mmap(p, ps, PROT_READ | PROT_WRITE,
                           MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
        CHECK(fixed == MAP_FAILED && errno == EPERM,
              "mmap(MAP_FIXED over sealed) -> EPERM");

        /* 5e. the seal must not have corrupted the mapping: it is still readable
         * and writable (permissions unchanged). */
        volatile char *vp = (volatile char *)p;
        vp[0] = 0x5a;
        CHECK(vp[0] == 0x5a, "sealed RW page still readable/writable");
    }

    /* ---- 6. madvise on a sealed range (mm/madvise.c can_madvise_modify) ----
     * Sealing blocks *discarding* advice only, and only for read-only anonymous
     * mappings. */
    {
        /* 6a. read-only anon sealed: discard advice -> EPERM. */
        char *ro = map_pages(ps, PROT_READ);
        CHECK(ro != NULL, "mmap RO anon page");
        CHECK_RET(raw_mseal((unsigned long)ro, ps, 0), 0, "mseal RO anon page -> 0");
        CHECK_ERR(madvise(ro, ps, MADV_DONTNEED), EPERM,
                  "madvise(MADV_DONTNEED) on sealed RO anon -> EPERM");
        CHECK_ERR(madvise(ro, ps, MADV_FREE), EPERM,
                  "madvise(MADV_FREE) on sealed RO anon -> EPERM");
        CHECK_ERR(madvise(ro, ps, MADV_DONTFORK), EPERM,
                  "madvise(MADV_DONTFORK) on sealed RO anon -> EPERM");
        /* Non-discard advice stays permitted even on a sealed VMA. */
        CHECK_RET(madvise(ro, ps, MADV_WILLNEED), 0,
                  "madvise(MADV_WILLNEED) on sealed RO anon -> 0 (not a discard)");

        /* 6b. writable anon sealed: discard advice is STILL allowed, because the
         * user could zero the range by writing anyway (vm_flags & VM_WRITE). */
        char *rw = map_pages(ps, PROT_READ | PROT_WRITE);
        CHECK(rw != NULL, "mmap RW anon page");
        rw[0] = 0x42;
        CHECK_RET(raw_mseal((unsigned long)rw, ps, 0), 0, "mseal RW anon page -> 0");
        CHECK_RET(madvise(rw, ps, MADV_DONTNEED), 0,
                  "madvise(MADV_DONTNEED) on sealed RW anon -> 0 (writable, allowed)");
        /* After DONTNEED the anon page re-faults to zero. */
        CHECK(rw[0] == 0, "sealed RW anon page zero-refaulted after DONTNEED");
    }

    /* ---- 7. partial-range seal splits the VMA correctly ---------------
     * Seal only the middle page of a 3-page mapping; the outer pages must stay
     * mutable while the middle is EPERM-locked. This exercises the VMA split
     * carrying the sealed bit to the correct fragment only. */
    {
        char *m = map_pages(3 * ps, PROT_READ | PROT_WRITE);
        CHECK(m != NULL, "mmap 3 pages for partial-seal test");
        CHECK_RET(raw_mseal((unsigned long)(m + ps), ps, 0), 0, "mseal middle page only -> 0");
        /* middle sealed */
        CHECK_ERR(mprotect(m + ps, ps, PROT_READ), EPERM,
                  "mprotect(middle, sealed) -> EPERM");
        /* first page NOT sealed */
        CHECK_RET(mprotect(m, ps, PROT_READ), 0, "mprotect(first, unsealed) -> 0");
        /* last page NOT sealed */
        CHECK_RET(mprotect(m + 2 * ps, ps, PROT_READ), 0, "mprotect(last, unsealed) -> 0");
        /* unmapping the unsealed tail page succeeds, sealed middle stays. */
        CHECK_RET(munmap(m + 2 * ps, ps), 0, "munmap(last, unsealed) -> 0");
        CHECK_ERR(munmap(m + ps, ps), EPERM, "munmap(middle, sealed) -> EPERM");
        munmap(m, ps); /* first page (unsealed) */
    }

    /* ---- 8. len rounds up to 0 -> EINVAL, a branch distinct from overflow ----
     * len_in in (SIZE_MAX-ps+1 .. SIZE_MAX] page-aligns to 0, so `len_in && !len`
     * (mm/mseal.c:160) fires BEFORE the end<start check (mm/mseal.c:164). Section
     * 3 only reaches line 164; this reaches line 160. */
    {
        char *p = map_pages(ps, PROT_READ | PROT_WRITE);
        CHECK(p != NULL, "mmap page for len-wrap test");
        CHECK_ERR(raw_mseal((unsigned long)p, (size_t)-16, 0), EINVAL,
                  "mseal(len rounds up to 0) -> EINVAL");
        munmap(p, ps);
    }

    /* ---- 9. sealed file-backed RO mapping: discard advice ALLOWED -----------
     * can_madvise_modify (mm/madvise.c:1314) only blocks discards on ANONYMOUS
     * sealed ranges; a sealed file-backed mapping permits MADV_DONTNEED. This is
     * the branch a kernel that keyed on "sealed+discard" without the anon check
     * would wrongly reject. */
    {
        int fd = open("/tmp/starry_mseal_file", O_RDWR | O_CREAT | O_TRUNC, 0644);
        CHECK(fd >= 0, "open backing file");
        CHECK_RET(ftruncate(fd, ps), 0, "size backing file to one page");
        char *fp = mmap(NULL, ps, PROT_READ, MAP_PRIVATE, fd, 0);
        CHECK(fp != MAP_FAILED, "mmap RO file-backed page");
        CHECK_RET(raw_mseal((unsigned long)fp, ps, 0), 0, "mseal RO file-backed -> 0");
        CHECK_RET(madvise(fp, ps, MADV_DONTNEED), 0,
                  "madvise(DONTNEED) on sealed RO file-backed -> 0 (non-anon allowed)");
        if (fp != MAP_FAILED) munmap(fp, ps);
        if (fd >= 0) close(fd);
        unlink("/tmp/starry_mseal_file");
    }

    /* ---- 10. MADV_REMOVE on sealed RO anon -> EPERM (is_discard, madvise.c:1273) --
     * MADV_REMOVE is in the is_discard set, so the seal gate refuses it before the
     * per-behavior handler runs. */
    {
        char *ro = map_pages(ps, PROT_READ);
        CHECK(ro != NULL, "mmap RO anon page for REMOVE test");
        CHECK_RET(raw_mseal((unsigned long)ro, ps, 0), 0, "mseal RO anon -> 0");
        CHECK_ERR(madvise(ro, ps, MADV_REMOVE), EPERM,
                  "madvise(MADV_REMOVE) on sealed RO anon -> EPERM");
        /* ro stays mapped and sealed; teardown at process exit is allowed. */
    }

    /* ---- 11. munmap straddling a sealed and an unsealed VMA -> EPERM ---------
     * Linux fails the whole call and unmaps nothing (the sealed gate runs during
     * the gather pass in mm/vma.c). The unsealed neighbor must survive intact. */
    {
        char *m = map_pages(2 * ps, PROT_READ | PROT_WRITE);
        CHECK(m != NULL, "mmap 2 pages for straddle-munmap");
        CHECK_RET(raw_mseal((unsigned long)m, ps, 0), 0, "seal first page only");
        CHECK_ERR(munmap(m, 2 * ps), EPERM, "munmap straddling sealed -> EPERM (nothing unmapped)");
        /* Prove the unsealed second page is untouched: still mprotect-able. */
        CHECK_RET(mprotect(m + ps, ps, PROT_READ), 0, "unsealed neighbor survived failed munmap");
        munmap(m + ps, ps); /* first page stays sealed until exit */
    }

    TEST_DONE();
}
