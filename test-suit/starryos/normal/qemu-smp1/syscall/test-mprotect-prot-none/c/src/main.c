#define _GNU_SOURCE
#include "test_framework.h"
#include <signal.h>
#include <setjmp.h>
#include <unistd.h>
#include <sys/mman.h>

/*
 * mprotect(2) PROT_NONE enforcement test.
 *
 * man 2 mprotect: "PROT_NONE — The memory cannot be accessed at all."
 * Any access to a PROT_NONE region must raise SIGSEGV. This is what makes
 * guard pages work — e.g. the JVM protects each thread stack's guard page with
 * PROT_NONE so a stack overflow traps instead of silently corrupting memory.
 *
 * StarryOS bug this guards against (fixed): the MmapProt -> MappingFlags
 * conversion always set MappingFlags::USER, so PROT_NONE produced a non-empty
 * flag set; on x86_64 that left the PTE PRESENT (present implies readable on
 * x86), so reads of a PROT_NONE page did NOT fault and guard pages were
 * defeated. The fix only tags accessible mappings as USER, so PROT_NONE maps
 * to empty flags -> non-present PTE -> faults.
 */

static sigjmp_buf g_jb;
static volatile int g_faulted;
static void on_fault(int sig) { (void)sig; g_faulted = 1; siglongjmp(g_jb, 1); }

/* Returns 1 if the access faulted (SIGSEGV/SIGBUS), 0 if it completed. */
static int access_faults(volatile char *p, int do_write) {
    g_faulted = 0;
    if (sigsetjmp(g_jb, 1) == 0) {
        if (do_write) {
            *p = 'Z';
        } else {
            volatile char c = *p;
            (void)c;
        }
    }
    return g_faulted;
}

int main(void) {
    TEST_START("mprotect-prot-none");

    long ps = sysconf(_SC_PAGESIZE);
    struct sigaction sa = {0};
    sa.sa_handler = on_fault;
    sigaction(SIGSEGV, &sa, NULL);
    sigaction(SIGBUS, &sa, NULL);

    /* ============================================================
     * 1. mmap RW is accessible; mprotect PROT_NONE makes it fault.
     * ============================================================ */
    char *p = mmap(NULL, ps, PROT_READ | PROT_WRITE,
                   MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    CHECK(p != MAP_FAILED, "mmap(RW, anon) succeeds");
    CHECK(access_faults(p, 1) == 0, "RW page: write does NOT fault");
    CHECK(access_faults(p, 0) == 0, "RW page: read does NOT fault");

    CHECK_RET(mprotect(p, ps, PROT_NONE), 0, "mprotect(PROT_NONE) returns 0");
    CHECK(access_faults(p, 0) == 1, "PROT_NONE page: read FAULTS (guard works)");
    CHECK(access_faults(p, 1) == 1, "PROT_NONE page: write FAULTS");

    /* ============================================================
     * 2. Re-enabling access works again.
     * ============================================================ */
    CHECK_RET(mprotect(p, ps, PROT_READ | PROT_WRITE), 0, "mprotect back to RW");
    CHECK(access_faults(p, 1) == 0, "re-enabled page: write does NOT fault");

    /* ============================================================
     * 3. PROT_READ: read OK, write FAULTS.
     * ============================================================ */
    CHECK_RET(mprotect(p, ps, PROT_READ), 0, "mprotect(PROT_READ) returns 0");
    CHECK(access_faults(p, 0) == 0, "PROT_READ page: read does NOT fault");
    CHECK(access_faults(p, 1) == 1, "PROT_READ page: write FAULTS");
    munmap(p, ps);

    /* ============================================================
     * 4. mmap PROT_NONE (address reservation): access FAULTS.
     * ============================================================ */
    char *r = mmap(NULL, ps, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    CHECK(r != MAP_FAILED, "mmap(PROT_NONE, anon) succeeds (reservation)");
    CHECK(access_faults(r, 0) == 1, "reserved PROT_NONE page: read FAULTS");
    CHECK_RET(mprotect(r, ps, PROT_READ | PROT_WRITE), 0, "commit reservation to RW");
    CHECK(access_faults(r, 1) == 0, "committed page: write does NOT fault");
    munmap(r, ps);

    TEST_DONE();
}
