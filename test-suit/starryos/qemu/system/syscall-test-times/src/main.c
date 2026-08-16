/*
 * test_times.c - comprehensive times(2) conformance test.
 *
 * times() reports process CPU time and returns elapsed wall time, both in
 * clock ticks of sysconf(_SC_CLK_TCK) (USER_HZ, fixed at 100 on Linux, so one
 * tick == 10 ms). See times(2).
 *
 *   struct tms {
 *     clock_t tms_utime;   // user CPU time of the whole thread group
 *     clock_t tms_stime;   // system CPU time of the whole thread group
 *     clock_t tms_cutime;  // tms_utime+tms_cutime of reaped children
 *     clock_t tms_cstime;  // tms_stime+tms_cstime of reaped children
 *   };
 *   clock_t times(struct tms *buf);   // returns wall ticks, or (clock_t)-1 + errno
 *
 * Unit pinning (A3, A4) is the core of this test: both the return value and the
 * struct fields must be CLK_TCK ticks. A microsecond field is 1e4x too large
 * and a hardware-timer-tick return is orders of magnitude too large; each is
 * caught below by comparing against an independent CLOCK_MONOTONIC reference.
 *
 * CPU-time magnitude is deliberately not asserted to be non-zero: the kernel
 * accounts CPU statistically at the timer tick, so sub-tick work rounds to 0
 * (matching what syscall-test-getrusage documents for RUSAGE_CHILDREN).
 */

#include "test_framework.h"

#include <sys/times.h>
#include <sys/wait.h>
#include <sys/syscall.h>
#include <sys/resource.h>
#include <unistd.h>
#include <time.h>
#include <pthread.h>
#include <stdint.h>
#include <stdlib.h>

#define TV_TO_US(tv) ((long)(tv).tv_sec * 1000000L + (long)(tv).tv_usec)

/* Consume CPU without being optimised away. */
static volatile uint64_t g_sink;
static void burn_cpu(uint64_t iters) {
    uint64_t s = g_sink;
    for (uint64_t i = 0; i < iters; i++) {
        s += i * 2654435761ULL + 1;
    }
    g_sink = s;
}

static double wall_seconds(const struct timespec *a, const struct timespec *b) {
    return (double)(b->tv_sec - a->tv_sec) + (double)(b->tv_nsec - a->tv_nsec) / 1e9;
}

static volatile int worker_stop;
static void *worker(void *arg) {
    (void)arg;
    /* Burn continuously so a concurrent sample charges this thread's CPU. */
    while (!worker_stop) {
        burn_cpu(20ULL * 1000 * 1000);
    }
    return NULL;
}

int main(void) {
    TEST_START("times");

    struct timespec t_start;
    clock_gettime(CLOCK_MONOTONIC, &t_start);
    long clk_tck = sysconf(_SC_CLK_TCK);
    struct tms buf;
    clock_t r;

    /* A1: basic success. */
    memset(&buf, 0xFF, sizeof(buf));
    errno = 0;
    r = times(&buf);
    CHECK(r != (clock_t)-1, "A1: times() succeeds");
    CHECK((long)r >= 0, "A1: return is non-negative");
    printf("  INFO | ret=%ld utime=%ld stime=%ld cutime=%ld cstime=%ld CLK_TCK=%ld\n",
           (long)r, (long)buf.tms_utime, (long)buf.tms_stime,
           (long)buf.tms_cutime, (long)buf.tms_cstime, clk_tck);

    /* A2: the tick unit is USER_HZ == 100. */
    CHECK(clk_tck == 100, "A2: sysconf(_SC_CLK_TCK) == 100 (USER_HZ)");

    /* A6: a fresh process has reaped no children. Check before forking. */
    CHECK(buf.tms_cutime == 0, "A6: cutime == 0 with no reaped children");
    CHECK(buf.tms_cstime == 0, "A6: cstime == 0 with no reaped children");

    /* A3: the return value advances in CLK_TCK ticks, not the hardware timer
     * tick. Over a 1 s sleep the delta must be ~clk_tck; a hardware-tick return
     * would be orders of magnitude larger. */
    clock_t r0 = times(&buf);
    struct timespec one_sec = { 1, 0 };
    nanosleep(&one_sec, NULL);
    clock_t r1 = times(&buf);
    long dret = (long)(r1 - r0);
    printf("  INFO | return delta over 1s sleep: %ld ticks\n", dret);
    CHECK(dret >= clk_tck / 2 && dret <= clk_tck * 50,
          "A3: return delta over 1s is CLK_TCK-scaled (not micros/hw-ticks)");

    /* A4: the CPU-time fields are CLK_TCK ticks. Consumed CPU can never exceed
     * the process's wall-clock lifetime; measure that lifetime independently
     * with CLOCK_MONOTONIC (advanced by the 1 s sleep above). A microsecond
     * field would be ~1e4x the tick value and blow past the uptime bound. */
    struct timespec t_now;
    clock_gettime(CLOCK_MONOTONIC, &t_now);
    times(&buf);
    long cpu_ticks = (long)(buf.tms_utime + buf.tms_stime);
    long uptime_ticks = (long)(wall_seconds(&t_start, &t_now) * (double)clk_tck);
    printf("  INFO | cpu=%ld ticks, uptime=%ld ticks\n", cpu_ticks, uptime_ticks);
    CHECK(cpu_ticks >= 0, "A4: CPU-time fields are non-negative");
    CHECK(cpu_ticks <= uptime_ticks + clk_tck,
          "A4: CPU-time fields are CLK_TCK ticks (cpu<=uptime; micros would be 1e4x)");

    /* A5: the return value is monotonic non-decreasing. */
    clock_t m0 = times(&buf);
    clock_t m1 = times(&buf);
    CHECK((long)m1 >= (long)m0, "A5: return value is monotonic");

    /* A7: a reaped child's CPU time lands in cutime/cstime as valid ticks.
     * Magnitude is not asserted (sub-tick work rounds to 0), but the values
     * must stay within the plausible tick range - microseconds would not. */
    clock_gettime(CLOCK_MONOTONIC, &t_now);
    uptime_ticks = (long)(wall_seconds(&t_start, &t_now) * (double)clk_tck);
    pid_t pid = fork();
    if (pid == 0) {
        burn_cpu(200ULL * 1000 * 1000);
        _exit(0);
    }
    CHECK(pid > 0, "A7: fork() succeeds");
    if (pid > 0) {
        int st;
        waitpid(pid, &st, 0);
        times(&buf);
        printf("  INFO | after child: cutime=%ld cstime=%ld uptime=%ld\n",
               (long)buf.tms_cutime, (long)buf.tms_cstime, uptime_ticks);
        CHECK(buf.tms_cutime >= 0 && buf.tms_cstime >= 0,
              "A7: child times are non-negative");
        CHECK((long)(buf.tms_cutime + buf.tms_cstime) <= uptime_ticks + 5 * clk_tck,
              "A7: cutime/cstime are CLK_TCK ticks (bounded by uptime, not micros)");
    }

    /* A8: times() reports whole-process (thread-group) CPU, and in the same
     * tick unit, as getrusage(RUSAGE_SELF) - both implement Linux
     * thread_group_cputime. A worker thread gives the process a second thread
     * with its own CPU, so a per-thread times() (calling thread only) would
     * disagree with the process-wide getrusage; matching units disagree by 1e4.
     * The two are sampled close together, so they agree within rounding. */
    pthread_t th;
    int pc = pthread_create(&th, NULL, worker, NULL);
    CHECK(pc == 0, "A8: pthread_create succeeds");
    if (pc == 0) {
        struct timespec quarter = { 0, 250 * 1000 * 1000 };
        nanosleep(&quarter, NULL);
        struct tms tt;
        struct rusage ru;
        times(&tt);
        getrusage(RUSAGE_SELF, &ru);
        worker_stop = 1;
        pthread_join(th, NULL);
        long times_ticks = (long)(tt.tms_utime + tt.tms_stime);
        long ru_ticks = (TV_TO_US(ru.ru_utime) + TV_TO_US(ru.ru_stime))
                        / (1000000L / clk_tck);
        printf("  INFO | times()=%ld ticks, getrusage(SELF)=%ld ticks\n",
               times_ticks, ru_ticks);
        CHECK(labs(times_ticks - ru_ticks) <= clk_tck / 10 + 2,
              "A8: times() process CPU matches getrusage(RUSAGE_SELF) (thread group, ticks)");
    }

    /* B1: the kernel accepts a NULL buf and still returns the tick count.
     * Use the raw syscall to bypass any libc-side pointer check. */
    errno = 0;
    long rn = syscall(SYS_times, (struct tms *)NULL);
    CHECK(rn >= 0, "B1: times(NULL) returns the tick count (kernel allows NULL)");

    /* B2: an invalid buf pointer faults with EFAULT (times(2) EFAULT). */
    errno = 0;
    long rf = syscall(SYS_times, (void *)-1);
    CHECK(rf == -1 && errno == EFAULT, "B2: times(bad pointer) -> EFAULT");

    TEST_DONE();
}
