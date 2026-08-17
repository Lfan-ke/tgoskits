/*
 * clock_settime(2) / settimeofday(2) conformance.
 *
 * Ground truth: clock_settime(2)/settimeofday(2) man pages, Linux
 * kernel/time/posix-timers.c (SYSCALL_DEFINE2(clock_settime),
 * posix_clock_realtime_set) and kernel/time/time.c
 * (SYSCALL_DEFINE2(settimeofday), do_sys_settimeofday64) with
 * do_settimeofday64 / timespec64_valid_settod in timekeeping.c / time64.h.
 *
 * Only CLOCK_REALTIME is settable. Covered branches:
 *   - clock_settime: bad clockid -> EINVAL; non-settable clocks
 *     (MONOTONIC, MONOTONIC_RAW, BOOTTIME, *_COARSE, TAI, the cpu-time
 *     clocks) -> EINVAL; tv_nsec out of [0,1e9) -> EINVAL; tv_sec < 0 ->
 *     EINVAL; EFAULT for a bad pointer; EPERM without CAP_SYS_TIME;
 *     success sets CLOCK_REALTIME and clock_gettime reads it back, while
 *     CLOCK_MONOTONIC keeps advancing across the jump.
 *   - settimeofday: tv_usec out of [0,1e6) -> EINVAL; tv_sec < 0 ->
 *     EINVAL; tz_minuteswest out of +-15h -> EINVAL; EFAULT; EPERM;
 *     success readback via gettimeofday; NULL/NULL is a no-op success.
 *
 * On a kernel lacking these syscalls every call returns ENOSYS, so the
 * whole suite fails there (test-first baseline).
 */

#include "test_framework.h"

#include <sys/syscall.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#ifndef CLOCK_TAI
#define CLOCK_TAI 11
#endif
#ifndef CLOCK_MONOTONIC_RAW
#define CLOCK_MONOTONIC_RAW 4
#endif
#ifndef CLOCK_REALTIME_COARSE
#define CLOCK_REALTIME_COARSE 5
#endif
#ifndef CLOCK_MONOTONIC_COARSE
#define CLOCK_MONOTONIC_COARSE 6
#endif
#ifndef CLOCK_BOOTTIME
#define CLOCK_BOOTTIME 7
#endif

/*
 * Go through the raw syscall path so kernel-side argument validation is
 * exercised directly, independent of any libc range-checking that some
 * wrappers perform before trapping. glibc's settimeofday translates to
 * clock_settime; the raw path pins the __kernel_old_timeval ABI the
 * SYSCALL_DEFINE2(settimeofday) handler actually parses.
 */
static long sc_clock_settime(clockid_t id, const struct timespec *ts)
{
    return syscall(SYS_clock_settime, id, ts);
}

static long sc_clock_gettime(clockid_t id, struct timespec *ts)
{
    return syscall(SYS_clock_gettime, id, ts);
}

#ifdef SYS_settimeofday
static long sc_settimeofday(const struct timeval *tv, const struct timezone *tz)
{
    return syscall(SYS_settimeofday, tv, tz);
}
#else
static long sc_settimeofday(const struct timeval *tv, const struct timezone *tz)
{
    return settimeofday(tv, tz);
}
#endif

static int is_root(void) { return geteuid() == 0; }

/* Restore a sane wall clock after a test that moved it, best-effort. */
static void restore_realtime(void)
{
    /* Park realtime at a fixed known epoch so later reads are predictable. */
    struct timespec base = {1700000000, 0};
    (void)sc_clock_settime(CLOCK_REALTIME, &base);
}

/* clockid validity + settability: only CLOCK_REALTIME may be set. */
static void test_clock_settime_bad_clockid(void)
{
    struct timespec ts = {1700000000, 0};

    /* Non-settable but otherwise valid clocks -> EINVAL (no .clock_set). */
    CHECK_ERR(sc_clock_settime(CLOCK_MONOTONIC, &ts), EINVAL,
              "clock_settime(CLOCK_MONOTONIC) -> EINVAL");
    CHECK_ERR(sc_clock_settime(CLOCK_MONOTONIC_RAW, &ts), EINVAL,
              "clock_settime(CLOCK_MONOTONIC_RAW) -> EINVAL");
    CHECK_ERR(sc_clock_settime(CLOCK_BOOTTIME, &ts), EINVAL,
              "clock_settime(CLOCK_BOOTTIME) -> EINVAL");
    CHECK_ERR(sc_clock_settime(CLOCK_REALTIME_COARSE, &ts), EINVAL,
              "clock_settime(CLOCK_REALTIME_COARSE) -> EINVAL");
    CHECK_ERR(sc_clock_settime(CLOCK_MONOTONIC_COARSE, &ts), EINVAL,
              "clock_settime(CLOCK_MONOTONIC_COARSE) -> EINVAL");
    CHECK_ERR(sc_clock_settime(CLOCK_TAI, &ts), EINVAL,
              "clock_settime(CLOCK_TAI) -> EINVAL (no .clock_set)");
    CHECK_ERR(sc_clock_settime(CLOCK_PROCESS_CPUTIME_ID, &ts), EINVAL,
              "clock_settime(PROCESS_CPUTIME_ID) -> EINVAL");
    CHECK_ERR(sc_clock_settime(CLOCK_THREAD_CPUTIME_ID, &ts), EINVAL,
              "clock_settime(THREAD_CPUTIME_ID) -> EINVAL");

    /* Out-of-range clockid past the posix_clocks[] table -> EINVAL. */
    CHECK_ERR(sc_clock_settime(999, &ts), EINVAL,
              "clock_settime(999) unknown clockid -> EINVAL");
    CHECK_ERR(sc_clock_settime(-2, &ts), EINVAL,
              "clock_settime(-2) negative clockid -> EINVAL");
}

/* tv_nsec / tv_sec range validation on the settable clock. */
static void test_clock_settime_bad_time(void)
{
    struct timespec bad_ns_hi = {1700000000, 1000000000}; /* == 1e9 */
    CHECK_ERR(sc_clock_settime(CLOCK_REALTIME, &bad_ns_hi), EINVAL,
              "clock_settime nsec==1e9 -> EINVAL");

    struct timespec bad_ns_big = {1700000000, 2000000000};
    CHECK_ERR(sc_clock_settime(CLOCK_REALTIME, &bad_ns_big), EINVAL,
              "clock_settime nsec>1e9 -> EINVAL");

    struct timespec bad_ns_neg = {1700000000, -1};
    CHECK_ERR(sc_clock_settime(CLOCK_REALTIME, &bad_ns_neg), EINVAL,
              "clock_settime nsec<0 -> EINVAL");

    struct timespec bad_sec = {-1, 0};
    CHECK_ERR(sc_clock_settime(CLOCK_REALTIME, &bad_sec), EINVAL,
              "clock_settime sec<0 -> EINVAL");

    /* Upper nsec boundary that is still valid: 999_999_999. Only when
     * privileged do we expect success; unprivileged sees EPERM but the
     * point here is that the value is *not* rejected as EINVAL. */
    struct timespec edge = {1700000000, 999999999};
    errno = 0;
    long r = sc_clock_settime(CLOCK_REALTIME, &edge);
    if (is_root())
        CHECK(r == 0, "clock_settime nsec==999999999 boundary accepted");
    else
        CHECK(r == -1 && errno == EPERM,
              "clock_settime nsec==999999999 valid range, EPERM unprivileged");
}

/* Bad user pointer -> EFAULT (checked before permission for a valid clock). */
static void test_clock_settime_efault(void)
{
    CHECK_ERR(sc_clock_settime(CLOCK_REALTIME, (struct timespec *)(void *)0x1),
              EFAULT, "clock_settime bad tp pointer -> EFAULT");
}

/* Permission: without CAP_SYS_TIME the settable clock returns EPERM. */
static void test_clock_settime_eperm(void)
{
    if (is_root())
    {
        printf("  SKIP-note | running as root, EPERM path exercised in child\n");
        pid_t pid = fork();
        if (pid == 0)
        {
            /* Drop to a non-root uid so CAP_SYS_TIME is absent. */
            if (setuid(65534) != 0)
                _exit(2);
            struct timespec ts = {1700000000, 0};
            errno = 0;
            long r = sc_clock_settime(CLOCK_REALTIME, &ts);
            _exit(r == -1 && errno == EPERM ? 0 : 1);
        }
        int st = 0;
        (void)waitpid(pid, &st, 0);
        CHECK(WIFEXITED(st) && WEXITSTATUS(st) == 0,
              "clock_settime without CAP_SYS_TIME -> EPERM (child)");
    }
    else
    {
        struct timespec ts = {1700000000, 0};
        CHECK_ERR(sc_clock_settime(CLOCK_REALTIME, &ts), EPERM,
                  "clock_settime without CAP_SYS_TIME -> EPERM");
    }
}

/* Success + readback: setting CLOCK_REALTIME is visible via clock_gettime,
 * and CLOCK_MONOTONIC is unaffected by the wall-clock jump. */
static void test_clock_settime_success_readback(void)
{
    if (!is_root())
    {
        printf("  SKIP-note | not root: settable success covered under privilege only\n");
        return;
    }

    struct timespec mono_before;
    CHECK_RET(sc_clock_gettime(CLOCK_MONOTONIC, &mono_before), 0,
              "read CLOCK_MONOTONIC before jump");

    /* Jump the wall clock far forward to a distinctive epoch. */
    struct timespec target = {2000000000, 123456789};
    CHECK_RET(sc_clock_settime(CLOCK_REALTIME, &target), 0,
              "clock_settime(CLOCK_REALTIME) succeeds");

    struct timespec rt;
    CHECK_RET(sc_clock_gettime(CLOCK_REALTIME, &rt), 0, "read back CLOCK_REALTIME");
    /* Allow a few seconds of forward drift since the set. */
    CHECK(rt.tv_sec >= target.tv_sec && rt.tv_sec < target.tv_sec + 10,
          "CLOCK_REALTIME reflects the value that was set");

    /* Monotonic must not have leapt to the new epoch. */
    struct timespec mono_after;
    CHECK_RET(sc_clock_gettime(CLOCK_MONOTONIC, &mono_after), 0,
              "read CLOCK_MONOTONIC after jump");
    CHECK(mono_after.tv_sec < target.tv_sec / 2,
          "CLOCK_MONOTONIC unaffected by realtime jump");
    CHECK(mono_after.tv_sec >= mono_before.tv_sec,
          "CLOCK_MONOTONIC kept advancing across the jump");

    /* Set backwards too: realtime is freely settable in either direction. */
    struct timespec back = {1600000000, 0};
    CHECK_RET(sc_clock_settime(CLOCK_REALTIME, &back), 0,
              "clock_settime backwards succeeds");
    struct timespec rt2;
    CHECK_RET(sc_clock_gettime(CLOCK_REALTIME, &rt2), 0, "read back after backward set");
    CHECK(rt2.tv_sec >= back.tv_sec && rt2.tv_sec < back.tv_sec + 10,
          "CLOCK_REALTIME reflects the backward value");

    restore_realtime();
}

/* settimeofday: tv_usec / tv_sec range + timezone range. */
static void test_settimeofday_validation(void)
{
    struct timeval bad_us = {1700000000, 1000000}; /* usec == 1e6 */
    CHECK_ERR(sc_settimeofday(&bad_us, NULL), EINVAL,
              "settimeofday usec==1e6 -> EINVAL");

    struct timeval bad_us_neg = {1700000000, -1};
    CHECK_ERR(sc_settimeofday(&bad_us_neg, NULL), EINVAL,
              "settimeofday usec<0 -> EINVAL");

    struct timeval bad_sec = {-5, 0};
    CHECK_ERR(sc_settimeofday(&bad_sec, NULL), EINVAL,
              "settimeofday sec<0 -> EINVAL");

    /*
     * timezone range check |tz_minuteswest| <= 15*60 lives inside
     * do_sys_settimeofday64, AFTER security_settime64. With tv==NULL an
     * unprivileged caller therefore sees EPERM (from cap_settime) before
     * the tz range is examined; only a privileged caller reaches EINVAL.
     * (time.c:174-193 in the local Linux tree.)
     */
    struct timezone bad_tz = {15 * 60 + 1, 0};
    struct timezone bad_tz_neg = {-(15 * 60 + 1), 0};
    if (is_root())
    {
        CHECK_ERR(sc_settimeofday(NULL, &bad_tz), EINVAL,
                  "settimeofday tz_minuteswest>15h -> EINVAL (root)");
        CHECK_ERR(sc_settimeofday(NULL, &bad_tz_neg), EINVAL,
                  "settimeofday tz_minuteswest<-15h -> EINVAL (root)");
    }
    else
    {
        CHECK_ERR(sc_settimeofday(NULL, &bad_tz), EPERM,
                  "settimeofday bad tz unprivileged -> EPERM (cap before range)");
    }

    CHECK_ERR(sc_settimeofday((struct timeval *)(void *)0x1, NULL), EFAULT,
              "settimeofday bad tv pointer -> EFAULT");
    /*
     * A bad tz pointer: settimeofday copies tz in with copy_from_user
     * before do_sys_settimeofday64 / the security hook, so EFAULT wins
     * over EPERM for the tz copy (time.c:215-218).
     */
    CHECK_ERR(sc_settimeofday(NULL, (struct timezone *)(void *)0x1), EFAULT,
              "settimeofday bad tz pointer -> EFAULT");
}

/* settimeofday permission + success readback + NULL/NULL no-op. */
static void test_settimeofday_perm_and_success(void)
{
    if (!is_root())
    {
        struct timeval tv = {1700000000, 0};
        CHECK_ERR(sc_settimeofday(&tv, NULL), EPERM,
                  "settimeofday without CAP_SYS_TIME -> EPERM");
        /* NULL/NULL performs no clock change and requires no privilege. */
        CHECK_RET(sc_settimeofday(NULL, NULL), 0,
                  "settimeofday(NULL,NULL) no-op succeeds unprivileged");
        return;
    }

    /* NULL/NULL: nothing to set, must succeed. */
    CHECK_RET(sc_settimeofday(NULL, NULL), 0, "settimeofday(NULL,NULL) no-op");

    struct timeval tv = {1900000000, 500000};
    CHECK_RET(sc_settimeofday(&tv, NULL), 0, "settimeofday sets wall clock");

    struct timeval got;
    CHECK_RET(gettimeofday(&got, NULL), 0, "gettimeofday reads it back");
    CHECK(got.tv_sec >= tv.tv_sec && got.tv_sec < tv.tv_sec + 10,
          "gettimeofday reflects settimeofday value");

    /* usec upper boundary 999999 is valid and must be accepted. */
    struct timeval edge = {1900000001, 999999};
    CHECK_RET(sc_settimeofday(&edge, NULL), 0,
              "settimeofday usec==999999 boundary accepted");

    /* tz within +-15h alone is accepted (no time change). */
    struct timezone ok_tz = {8 * 60, 0};
    CHECK_RET(sc_settimeofday(NULL, &ok_tz), 0,
              "settimeofday tz within range accepted");

    restore_realtime();
}

int main(void)
{
    TEST_START("clock_settime / settimeofday");

    test_clock_settime_bad_clockid();
    test_clock_settime_bad_time();
    test_clock_settime_efault();
    test_clock_settime_eperm();
    test_clock_settime_success_readback();
    test_settimeofday_validation();
    test_settimeofday_perm_and_success();

    TEST_DONE();
}
