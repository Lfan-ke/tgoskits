#define _GNU_SOURCE
/*
 * bug-times-clock-ticks — times(2) must report USER_HZ clock ticks, not raw
 * microseconds or hardware timer ticks.
 *
 * ground truth: Linux times(2) fills every struct tms field and returns the
 * elapsed real time in clock ticks of _SC_CLK_TCK (glibc/musl hardcode 100, so
 * one tick is 10 ms). The in-repo /proc/[pid]/stat writer already uses this
 * jiffies unit: utime = duration.as_millis() / 10 (USER_HZ = 100). StarryOS
 * sys_times wrote the tms fields in microseconds and returned the value in
 * hardware timer ticks (nanos_to_ticks), so a caller dividing by _SC_CLK_TCK
 * saw wildly wrong seconds.
 */
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <time.h>
#include <unistd.h>
#include <sys/times.h>

static int failed;
static void check(int cond, const char *msg)
{
    if (cond) {
        printf("  PASS | %s\n", msg);
    } else {
        printf("  FAIL | %s | errno=%d (%s)\n", msg, errno, strerror(errno));
        failed = 1;
    }
}

int main(void)
{
    long clk = sysconf(_SC_CLK_TCK);
    if (clk <= 0) {
        clk = 100;
    }
    printf("  _SC_CLK_TCK = %ld\n", clk);

    struct tms tb0, tb1;
    clock_t t0 = times(&tb0);
    check(t0 != (clock_t)-1, "times() 首次调用成功");

    /* Sleep a known monotonic interval; the return value advances in USER_HZ
     * ticks, so ~300 ms is a few tens of ticks, never the hardware frequency. */
    struct timespec req = { .tv_sec = 0, .tv_nsec = 300L * 1000 * 1000 };
    while (nanosleep(&req, &req) != 0 && errno == EINTR) {
    }

    clock_t t1 = times(&tb1);
    check(t1 != (clock_t)-1, "times() 二次调用成功");
    long delta = (long)(t1 - t0);
    long hi = 30 * clk; /* 3000 for clk=100: 30 s of monotonic for a 0.3 s sleep */
    printf("  return delta = %ld ticks over ~300ms sleep (allowed [1, %ld])\n", delta, hi);
    check(delta >= 1 && delta <= hi,
          "times() 返回值以 USER_HZ 节拍计(非硬件频率)");

    /* tms fields are clock_t ticks, never microseconds. Burn measurable CPU,
     * then the accumulated user+system time must stay within a tick budget the
     * microsecond bug (10000x larger) cannot satisfy. Skip if the kernel does
     * not account CPU time at all (both fields zero). */
    volatile unsigned long spin = 0;
    for (long i = 0; i < 200000000L; i++) {
        spin += (unsigned long)i;
    }
    (void)spin;
    struct tms tb2;
    clock_t t2 = times(&tb2);
    check(t2 != (clock_t)-1, "times() 三次调用成功");
    long cpu = (long)(tb2.tms_utime + tb2.tms_stime);
    printf("  tms_utime+tms_stime = %ld ticks after busy loop\n", cpu);
    if (cpu != 0) {
        long cpu_hi = 100 * clk; /* 10000 for clk=100; micros bug yields ~1e5+ */
        check(cpu <= cpu_hi, "tms 字段以节拍计(非微秒)");
    } else {
        printf("  SKIP | 内核未累计 CPU 时间, tms 单位判别跳过\n");
    }

    printf("=== bug-times-clock-ticks: %s ===\n", failed ? "FAIL" : "PASS");
    return failed;
}
