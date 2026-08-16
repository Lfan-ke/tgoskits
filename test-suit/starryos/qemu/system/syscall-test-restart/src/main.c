/*
 * test_restart.c - restart_syscall(2) / restart_block conformance.
 *
 * nanosleep(2)/clock_nanosleep(2) use ERESTART_RESTARTBLOCK, not ERESTARTSYS:
 * when a signal HANDLER runs they return EINTR (with the remaining time for a
 * relative sleep) even under SA_RESTART - they are never restarted by the plain
 * SA_RESTART path (which would re-run the original interval and over-sleep).
 * The restart_block auto-restart only applies when no handler runs. See
 * restart_syscall(2) and the nanosleep(2) NOTES on SA_RESTART.
 *
 * A kernel that wrongly treats nanosleep as SA_RESTART-restartable over-sleeps
 * (re-runs the full interval); that is caught by cases A/C below. Elapsed time
 * is measured with CLOCK_MONOTONIC, which advances across sleeps regardless of
 * the return value.
 */

#include "test_framework.h"

#include <time.h>
#include <signal.h>
#include <sys/time.h>
#include <sys/syscall.h>
#include <unistd.h>

static volatile sig_atomic_t sig_count;
static void on_alarm(int s) { (void)s; sig_count++; }

static double elapsed_s(const struct timespec *a, const struct timespec *b) {
    return (double)(b->tv_sec - a->tv_sec) + (double)(b->tv_nsec - a->tv_nsec) / 1e9;
}

/* Arm ITIMER_REAL to raise SIGALRM once after `ms` milliseconds. */
static void arm_once(long ms) {
    struct itimerval it;
    memset(&it, 0, sizeof(it));
    it.it_value.tv_sec = ms / 1000;
    it.it_value.tv_usec = (ms % 1000) * 1000;
    setitimer(ITIMER_REAL, &it, NULL);
}

static void install(int flags) {
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = on_alarm;
    sa.sa_flags = flags;
    sigaction(SIGALRM, &sa, NULL);
}

int main(void) {
    TEST_START("restart_syscall");

    /* A: SA_RESTART must NOT restart nanosleep - a handler causes EINTR, and the
     * sleep stops at the interruption (~half), it does not over-sleep by
     * re-running the full interval. */
    {
        install(SA_RESTART);
        sig_count = 0;
        struct timespec t0, t1, req = { 2, 0 };
        clock_gettime(CLOCK_MONOTONIC, &t0);
        arm_once(1000);
        errno = 0;
        int r = nanosleep(&req, NULL);
        clock_gettime(CLOCK_MONOTONIC, &t1);
        double e = elapsed_s(&t0, &t1);
        printf("  INFO | A: ret=%d errno=%d elapsed=%.3fs sig=%d\n", r, errno, e, (int)sig_count);
        CHECK(sig_count == 1, "A: SIGALRM handler ran once");
        CHECK(r == -1 && errno == EINTR, "A: nanosleep returns EINTR under SA_RESTART (not restarted)");
        CHECK(e >= 0.7 && e <= 1.6, "A: stopped at interruption, no over-sleep from a full re-run");
    }

    /* B: no SA_RESTART - nanosleep returns EINTR and reports the remaining time. */
    {
        install(0);
        sig_count = 0;
        struct timespec t0, t1, req = { 2, 0 }, rem = { 0, 0 };
        clock_gettime(CLOCK_MONOTONIC, &t0);
        arm_once(1000);
        errno = 0;
        int r = nanosleep(&req, &rem);
        clock_gettime(CLOCK_MONOTONIC, &t1);
        double e = elapsed_s(&t0, &t1);
        double rems = (double)rem.tv_sec + (double)rem.tv_nsec / 1e9;
        printf("  INFO | B: ret=%d errno=%d elapsed=%.3fs rem=%.3fs\n", r, errno, e, rems);
        CHECK(sig_count == 1, "B: SIGALRM handler ran once");
        CHECK(r == -1 && errno == EINTR, "B: nanosleep returns EINTR (no SA_RESTART)");
        CHECK(rems >= 0.4 && rems <= 1.6, "B: remaining ~= half the request");
        CHECK(e >= 0.7 && e <= 1.6, "B: slept ~= until interruption (~half)");
    }

    /* C: clock_nanosleep reports errors by return value (not errno). A handler
     * interrupting a TIMER_ABSTIME sleep returns EINTR (positive) under
     * SA_RESTART too, stopping at the interruption rather than over-sleeping. */
    {
        install(SA_RESTART);
        sig_count = 0;
        struct timespec now, abs, t1;
        clock_gettime(CLOCK_MONOTONIC, &now);
        abs = now;
        abs.tv_sec += 2;
        arm_once(1000);
        int r = clock_nanosleep(CLOCK_MONOTONIC, TIMER_ABSTIME, &abs, NULL);
        clock_gettime(CLOCK_MONOTONIC, &t1);
        double e = elapsed_s(&now, &t1);
        printf("  INFO | C: ret=%d elapsed=%.3fs sig=%d\n", r, e, (int)sig_count);
        CHECK(r == EINTR, "C: clock_nanosleep ABSTIME returns EINTR on handler (not restarted)");
        CHECK(e >= 0.7 && e <= 1.6, "C: stopped at interruption, no over-sleep");
    }

    /* D: bare restart_syscall with no pending restart block returns EINTR. */
    {
        errno = 0;
        long r = syscall(SYS_restart_syscall);
        printf("  INFO | D: ret=%ld errno=%d\n", r, errno);
        CHECK(r == -1 && errno == EINTR, "D: restart_syscall with no pending block -> EINTR");
    }

    TEST_DONE();
}
