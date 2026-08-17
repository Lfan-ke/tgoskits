/*
 * mlockall(2) / munlockall(2) / munlock(2) conformance.
 *
 * Ground truth: mlockall(2)/munlock(2) man pages and Linux mm/mlock.c
 * (do_mlockall path via sys_mlockall, sys_munlockall, sys_munlock,
 * apply_mlockall_flags). Exercises the full MCL_* flag-validation matrix,
 * every documented EINVAL branch, page-rounding of munlock, success readback
 * (the locked pages stay resident and readable/writable), idempotency, and
 * negative controls. On a kernel lacking these syscalls each call returns
 * ENOSYS -> -1/EPERM-unrelated, so this whole suite fails there (test-first
 * baseline).
 *
 * Note: StarryOS runs privileged (CAP_IPC_LOCK effectively held) with an
 * effectively unlimited RLIMIT_MEMLOCK, so the EPERM (can_do_mlock) and the
 * ENOMEM (RLIMIT_MEMLOCK) branches are not reachable from userspace here and
 * are asserted as "succeeds" rather than as failures - matching a root caller
 * with memlock unlimited on Linux.
 */

#include "test_framework.h"

#include <sys/mman.h>
#include <unistd.h>

#ifndef MCL_CURRENT
#define MCL_CURRENT 1
#endif
#ifndef MCL_FUTURE
#define MCL_FUTURE 2
#endif
#ifndef MCL_ONFAULT
#define MCL_ONFAULT 4
#endif

static long page_size;

/* Touch every page so a fault-in path has observable, verifiable contents. */
static void fill(volatile unsigned char *p, size_t len, unsigned char v)
{
    for (size_t i = 0; i < len; i += (size_t)page_size)
        p[i] = v;
}

static int verify(volatile unsigned char *p, size_t len, unsigned char v)
{
    for (size_t i = 0; i < len; i += (size_t)page_size)
        if (p[i] != v)
            return 0;
    return 1;
}

/*
 * mlockall flag validation matrix. Linux mm/mlock.c sys_mlockall:
 *   if (!flags || (flags & ~(MCL_CURRENT|MCL_FUTURE|MCL_ONFAULT)) ||
 *       flags == MCL_ONFAULT)  return -EINVAL;
 */
static void test_mlockall_flag_validation(void)
{
    /* zero flags -> EINVAL */
    CHECK_ERR(mlockall(0), EINVAL, "mlockall(0) -> EINVAL");

    /* unknown high bit set -> EINVAL (even combined with a valid flag) */
    CHECK_ERR(mlockall(MCL_CURRENT | 0x8), EINVAL,
              "mlockall with unknown bit -> EINVAL");
    CHECK_ERR(mlockall(0x8), EINVAL, "mlockall(unknown-only) -> EINVAL");
    CHECK_ERR(mlockall(~0), EINVAL, "mlockall(all bits) -> EINVAL");

    /* MCL_ONFAULT alone (no CURRENT|FUTURE) -> EINVAL */
    CHECK_ERR(mlockall(MCL_ONFAULT), EINVAL,
              "mlockall(MCL_ONFAULT alone) -> EINVAL");

    /* Every accepted combination must succeed on a privileged/unlimited caller. */
    CHECK_RET(mlockall(MCL_CURRENT), 0, "mlockall(MCL_CURRENT) ok");
    CHECK_RET(mlockall(MCL_FUTURE), 0, "mlockall(MCL_FUTURE) ok");
    CHECK_RET(mlockall(MCL_CURRENT | MCL_FUTURE), 0,
              "mlockall(CURRENT|FUTURE) ok");
    CHECK_RET(mlockall(MCL_CURRENT | MCL_ONFAULT), 0,
              "mlockall(CURRENT|ONFAULT) ok");
    CHECK_RET(mlockall(MCL_FUTURE | MCL_ONFAULT), 0,
              "mlockall(FUTURE|ONFAULT) ok");
    CHECK_RET(mlockall(MCL_CURRENT | MCL_FUTURE | MCL_ONFAULT), 0,
              "mlockall(CURRENT|FUTURE|ONFAULT) ok");

    /* Clean up so MCL_FUTURE does not leak into later mappings. */
    CHECK_RET(munlockall(), 0, "munlockall() clears mlockall state");
}

/*
 * mlockall(MCL_CURRENT) must fault in and keep resident every current mapping;
 * verify contents survive and stay accessible.
 */
static void test_mlockall_current_readback(void)
{
    size_t len = (size_t)page_size * 8;
    unsigned char *p = mmap(NULL, len, PROT_READ | PROT_WRITE,
                            MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    CHECK(p != MAP_FAILED, "mmap 8 pages for MCL_CURRENT readback");

    fill(p, len, 0xA5);
    CHECK_RET(mlockall(MCL_CURRENT), 0, "mlockall(MCL_CURRENT) locks all current maps");
    CHECK(verify(p, len, 0xA5), "locked region retains contents");

    /* Writable after lock, and readback is consistent. */
    fill(p, len, 0x5A);
    CHECK(verify(p, len, 0x5A), "locked region remains writable/readable");

    CHECK_RET(munlockall(), 0, "munlockall() after MCL_CURRENT");
    CHECK(verify(p, len, 0x5A), "contents intact after munlockall");

    CHECK_RET(munmap(p, len), 0, "munmap MCL_CURRENT fixture");
}

/*
 * munlock(2): pages are rounded like mlock. munlock never eagerly populates
 * (Linux apply_vma_lock_flags with flags==0), so it is a validated no-op-on-
 * residency here; success on a mapped range, and errno matrix on bad ranges.
 */
static void test_munlock(void)
{
    size_t len = (size_t)page_size * 4;
    unsigned char *p = mmap(NULL, len, PROT_READ | PROT_WRITE,
                            MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    CHECK(p != MAP_FAILED, "mmap 4 pages for munlock");
    fill(p, len, 0x11);

    /* Lock then unlock a fully-mapped range. */
    CHECK_RET(mlock(p, len), 0, "mlock(range) succeeds");
    CHECK_RET(munlock(p, len), 0, "munlock(range) succeeds");
    CHECK(verify(p, len, 0x11), "contents intact after munlock");

    /* munlock is idempotent: unlocking an already-unlocked range is fine. */
    CHECK_RET(munlock(p, len), 0, "munlock(already unlocked) is a no-op success");

    /* len==0 is a success no-op (nothing to round up). */
    CHECK_RET(munlock(p, 0), 0, "munlock(len=0) success no-op");

    /* Unaligned addr+len still round to whole pages and succeed on a mapped range. */
    CHECK_RET(munlock(p + 1, (size_t)page_size - 2), 0,
              "munlock rounds unaligned range to pages");

    /* Sub-page tail: [p, p+1) rounds up to one page, still within mapping. */
    CHECK_RET(munlock(p, 1), 0, "munlock(len=1) rounds up to a page");

    CHECK_RET(munmap(p, len), 0, "munmap munlock fixture");

    /* munlock over a fully-unmapped range -> ENOMEM (apply_vma_lock_flags
     * walks the range and reports the hole). */
    CHECK_ERR(munlock(p, len), ENOMEM, "munlock over unmapped range -> ENOMEM");
}

/*
 * munlock ENOMEM on a partially-mapped range: [mapped][hole]. Linux
 * apply_vma_lock_flags validates the whole span, so a trailing hole fails.
 */
static void test_munlock_partial_hole(void)
{
    size_t span = (size_t)page_size * 4;
    /* Reserve a contiguous span, then punch a hole in the second half. */
    unsigned char *p = mmap(NULL, span, PROT_READ | PROT_WRITE,
                            MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    CHECK(p != MAP_FAILED, "mmap span for partial-hole munlock");
    /* Unmap the tail two pages, leaving [mapped 2p][hole 2p]. */
    CHECK_RET(munmap(p + (size_t)page_size * 2, (size_t)page_size * 2), 0,
              "punch trailing hole");

    CHECK_ERR(munlock(p, span), ENOMEM,
              "munlock over [mapped][hole] -> ENOMEM");

    /* The still-mapped head alone unlocks fine. */
    CHECK_RET(munlock(p, (size_t)page_size * 2), 0,
              "munlock of the mapped head succeeds");

    CHECK_RET(munmap(p, (size_t)page_size * 2), 0, "munmap partial-hole head");
}

/*
 * munlockall(2) takes no args and always returns 0 (Linux sys_munlockall ->
 * apply_mlockall_flags(0) which cannot fail). Idempotent.
 */
static void test_munlockall(void)
{
    CHECK_RET(munlockall(), 0, "munlockall() with nothing locked");
    CHECK_RET(mlockall(MCL_CURRENT | MCL_FUTURE), 0, "mlockall then munlockall");
    CHECK_RET(munlockall(), 0, "munlockall() clears lock state");
    CHECK_RET(munlockall(), 0, "munlockall() idempotent");
}

/*
 * MCL_FUTURE: after mlockall(MCL_FUTURE), a subsequently created mapping is
 * locked-on-creation. We cannot observe the VM_LOCKED flag from userspace, but
 * the new mapping must be fully usable (populated/accessible) and munlockall
 * must clear the future-lock default so later maps are lazy again.
 */
static void test_mcl_future(void)
{
    CHECK_RET(mlockall(MCL_FUTURE), 0, "mlockall(MCL_FUTURE) sets future default");

    size_t len = (size_t)page_size * 4;
    unsigned char *p = mmap(NULL, len, PROT_READ | PROT_WRITE,
                            MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    CHECK(p != MAP_FAILED, "mmap after MCL_FUTURE");
    fill(p, len, 0x77);
    CHECK(verify(p, len, 0x77), "future-locked mapping is usable");

    CHECK_RET(munlockall(), 0, "munlockall() clears MCL_FUTURE default");
    CHECK_RET(munmap(p, len), 0, "munmap MCL_FUTURE fixture");
}

int main(void)
{
    TEST_START("mlockall/munlockall/munlock");

    page_size = sysconf(_SC_PAGESIZE);
    if (page_size <= 0)
        page_size = 4096;

    test_mlockall_flag_validation();
    test_mlockall_current_readback();
    test_munlock();
    test_munlock_partial_hole();
    test_munlockall();
    test_mcl_future();

    TEST_DONE();
}
