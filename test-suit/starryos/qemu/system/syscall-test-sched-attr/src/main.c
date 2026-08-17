/*
 * sched_setattr(2) / sched_getattr(2) conformance.
 *
 * Ground truth: sched_setattr(2)/sched_getattr(2) man pages and Linux
 * kernel/sched/syscalls.c (sys_sched_setattr, sys_sched_getattr,
 * sched_copy_attr, __sched_setscheduler) plus include/uapi/linux/sched/types.h
 * (struct sched_attr) and include/uapi/linux/sched.h (SCHED_* / SCHED_FLAG_*).
 *
 * Covers: the size-versioned struct ABI (size==0 quirk, size<VER0 -> EINVAL,
 * setattr trailing non-zero bytes -> E2BIG, getattr min(size,ksize) writeback),
 * every policy accept/reject, the RT-priority-vs-policy consistency rule,
 * nice clamping, RESET_ON_FORK round-trip, KEEP_POLICY/KEEP_PARAMS, unknown
 * sched_flags -> EINVAL, UTIL_CLAMP-without-VER1 -> EINVAL, ESRCH for a missing
 * pid, EINVAL for pid<0 and flags!=0, EFAULT for a bad pointer, and readback
 * assertions after every successful set. On a kernel lacking these syscalls
 * every call returns ENOSYS so the whole suite fails there.
 */

#include "test_framework.h"

#include <sched.h>
#include <stdint.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <sys/wait.h>

/* struct sched_attr and SCHED_* flags are kernel-uapi; musl's <sched.h> does
 * not expose sched_setattr/sched_getattr, so declare the kernel layout and
 * call through syscall(). Layout: include/uapi/linux/sched/types.h. */
struct sched_attr
{
    uint32_t size;
    uint32_t sched_policy;
    uint64_t sched_flags;
    int32_t sched_nice;
    uint32_t sched_priority;
    uint64_t sched_runtime;
    uint64_t sched_deadline;
    uint64_t sched_period;
    uint32_t sched_util_min;
    uint32_t sched_util_max;
};

#define SCHED_ATTR_SIZE_VER0 48 /* size without util_{min,max} */
#define SCHED_ATTR_SIZE_VER1 56 /* full struct with util clamp */

#ifndef SCHED_NORMAL
#define SCHED_NORMAL 0
#endif
#ifndef SCHED_FIFO
#define SCHED_FIFO 1
#endif
#ifndef SCHED_RR
#define SCHED_RR 2
#endif
#ifndef SCHED_BATCH
#define SCHED_BATCH 3
#endif
#ifndef SCHED_IDLE
#define SCHED_IDLE 5
#endif
#ifndef SCHED_DEADLINE
#define SCHED_DEADLINE 6
#endif

#define SCHED_FLAG_RESET_ON_FORK 0x01
#define SCHED_FLAG_RECLAIM 0x02
#define SCHED_FLAG_DL_OVERRUN 0x04
#define SCHED_FLAG_KEEP_POLICY 0x08
#define SCHED_FLAG_KEEP_PARAMS 0x10
#define SCHED_FLAG_UTIL_CLAMP_MIN 0x20
#define SCHED_FLAG_UTIL_CLAMP_MAX 0x40

static int sys_setattr(pid_t pid, struct sched_attr *attr, unsigned int flags)
{
    return (int)syscall(SYS_sched_setattr, pid, attr, flags);
}

static int sys_getattr(pid_t pid, struct sched_attr *attr, unsigned int size,
                       unsigned int flags)
{
    return (int)syscall(SYS_sched_getattr, pid, attr, size, flags);
}

/* musl stubs the sched_getscheduler wrapper to ENOSYS, so call the syscall
 * directly (the kernel implements it). */
static int sys_getscheduler(pid_t pid)
{
    return (int)syscall(SYS_sched_getscheduler, pid);
}

/* Confirm the syscall exists at all; if the kernel lacks it every call is
 * ENOSYS and the suite is meant to fail. This makes the baseline explicit. */
static void test_present(void)
{
    struct sched_attr a;
    memset(&a, 0, sizeof(a));
    errno = 0;
    int r = sys_getattr(0, &a, sizeof(a), 0);
    CHECK(!(r == -1 && errno == ENOSYS), "sched_getattr is implemented (not ENOSYS)");
}

/* getattr readback of the calling thread reflects its current policy/params. */
static void test_getattr_self(void)
{
    struct sched_attr a;
    memset(&a, 0xEE, sizeof(a));
    CHECK_RET(sys_getattr(0, &a, sizeof(a), 0), 0, "getattr(self) succeeds");
    CHECK(a.size == sizeof(a), "getattr writes size = min(usize, ksize)");
    CHECK(a.sched_policy == SCHED_NORMAL, "default policy is SCHED_NORMAL");
    CHECK(a.sched_priority == 0, "non-RT policy reports priority 0");
    /* sched_flags is masked to SCHED_FLAG_ALL; no stray bits. */
    CHECK((a.sched_flags & ~(uint64_t)(SCHED_FLAG_RESET_ON_FORK | SCHED_FLAG_RECLAIM |
                                       SCHED_FLAG_DL_OVERRUN | SCHED_FLAG_KEEP_POLICY |
                                       SCHED_FLAG_KEEP_PARAMS | SCHED_FLAG_UTIL_CLAMP_MIN |
                                       SCHED_FLAG_UTIL_CLAMP_MAX)) == 0,
          "getattr sched_flags is masked to known bits");
}

/* Set SCHED_FIFO and read the priority back; then reset to SCHED_NORMAL. */
static void test_setattr_fifo_roundtrip(void)
{
    struct sched_attr a;
    memset(&a, 0, sizeof(a));
    a.size = sizeof(a);
    a.sched_policy = SCHED_FIFO;
    a.sched_priority = 42;
    CHECK_RET(sys_setattr(0, &a, 0), 0, "setattr SCHED_FIFO prio 42");

    struct sched_attr b;
    memset(&b, 0, sizeof(b));
    CHECK_RET(sys_getattr(0, &b, sizeof(b), 0), 0, "getattr after FIFO");
    CHECK(b.sched_policy == SCHED_FIFO, "policy reads back SCHED_FIFO");
    CHECK(b.sched_priority == 42, "priority reads back 42");
    CHECK_RET(sys_getscheduler(0), SCHED_FIFO, "sched_getscheduler agrees FIFO");

    /* Boundary priorities for RT: 1 and 99 accepted, 0 and 100 rejected. */
    a.sched_priority = 1;
    CHECK_RET(sys_setattr(0, &a, 0), 0, "FIFO prio 1 (low boundary)");
    a.sched_priority = 99;
    CHECK_RET(sys_setattr(0, &a, 0), 0, "FIFO prio 99 (high boundary)");
    a.sched_priority = 100;
    CHECK_ERR(sys_setattr(0, &a, 0), EINVAL, "FIFO prio 100 -> EINVAL");
    a.sched_priority = 0;
    CHECK_ERR(sys_setattr(0, &a, 0), EINVAL, "FIFO prio 0 -> EINVAL (rt needs prio!=0)");

    /* SCHED_RR behaves like FIFO for the priority range. */
    a.sched_policy = SCHED_RR;
    a.sched_priority = 10;
    CHECK_RET(sys_setattr(0, &a, 0), 0, "setattr SCHED_RR prio 10");
    memset(&b, 0, sizeof(b));
    CHECK_RET(sys_getattr(0, &b, sizeof(b), 0), 0, "getattr after RR");
    CHECK(b.sched_policy == SCHED_RR && b.sched_priority == 10, "RR policy+prio readback");

    /* Back to SCHED_NORMAL: priority must be 0. */
    a.sched_policy = SCHED_NORMAL;
    a.sched_priority = 0;
    CHECK_RET(sys_setattr(0, &a, 0), 0, "setattr back to SCHED_NORMAL");
    CHECK_RET(sys_getscheduler(0), SCHED_NORMAL, "sched_getscheduler agrees NORMAL");
}

/* Non-RT policies require priority 0; nice is clamped to [-20,19]. */
static void test_setattr_normal_nice(void)
{
    struct sched_attr a;
    memset(&a, 0, sizeof(a));
    a.size = sizeof(a);

    /* SCHED_NORMAL/BATCH/IDLE all accepted with priority 0. */
    a.sched_policy = SCHED_BATCH;
    a.sched_priority = 0;
    CHECK_RET(sys_setattr(0, &a, 0), 0, "SCHED_BATCH prio 0 accepted");
    a.sched_policy = SCHED_IDLE;
    CHECK_RET(sys_setattr(0, &a, 0), 0, "SCHED_IDLE prio 0 accepted");

    /* Non-RT policy with non-zero priority -> EINVAL (rt_policy mismatch). */
    a.sched_policy = SCHED_NORMAL;
    a.sched_priority = 1;
    CHECK_ERR(sys_setattr(0, &a, 0), EINVAL, "SCHED_NORMAL prio 1 -> EINVAL");

    /* nice clamped rather than rejected: 100 -> 19, -100 -> -20. */
    a.sched_policy = SCHED_NORMAL;
    a.sched_priority = 0;
    a.sched_nice = 100;
    CHECK_RET(sys_setattr(0, &a, 0), 0, "SCHED_NORMAL nice=100 (clamped) accepted");
    struct sched_attr b;
    memset(&b, 0, sizeof(b));
    CHECK_RET(sys_getattr(0, &b, sizeof(b), 0), 0, "getattr after nice=100");
    CHECK(b.sched_nice == 19, "nice clamped to MAX_NICE=19");

    a.sched_nice = -100;
    CHECK_RET(sys_setattr(0, &a, 0), 0, "SCHED_NORMAL nice=-100 (clamped) accepted");
    memset(&b, 0, sizeof(b));
    CHECK_RET(sys_getattr(0, &b, sizeof(b), 0), 0, "getattr after nice=-100");
    CHECK(b.sched_nice == -20, "nice clamped to MIN_NICE=-20");

    a.sched_nice = 0;
    CHECK_RET(sys_setattr(0, &a, 0), 0, "restore nice=0");
}

/* Bad policy value -> EINVAL. */
static void test_bad_policy(void)
{
    struct sched_attr a;
    memset(&a, 0, sizeof(a));
    a.size = sizeof(a);
    a.sched_policy = 999;
    CHECK_ERR(sys_setattr(0, &a, 0), EINVAL, "policy 999 -> EINVAL");

    /* A negative policy (top bit set, read as int<0) is rejected. */
    a.sched_policy = 0x80000000u;
    CHECK_ERR(sys_setattr(0, &a, 0), EINVAL, "policy with sign bit -> EINVAL");
}

/* Size-versioned ABI: size==0 quirk, size<VER0 -> EINVAL, trailing bytes. */
static void test_size_abi(void)
{
    struct sched_attr a;
    memset(&a, 0, sizeof(a));

    /* size==0 is treated as SCHED_ATTR_SIZE_VER0 (ABI quirk). */
    a.size = 0;
    a.sched_policy = SCHED_NORMAL;
    a.sched_priority = 0;
    CHECK_RET(sys_setattr(0, &a, 0), 0, "setattr size==0 quirk accepted as VER0");

    /* size below VER0 -> E2BIG (sched_copy_attr err_size path). */
    a.size = SCHED_ATTR_SIZE_VER0 - 1;
    CHECK_ERR(sys_setattr(0, &a, 0), E2BIG, "size < VER0 -> E2BIG");

    /* Exactly VER0 is accepted. */
    a.size = SCHED_ATTR_SIZE_VER0;
    CHECK_RET(sys_setattr(0, &a, 0), 0, "size == VER0 accepted");

    /* An oversized struct whose trailing (unknown) bytes are all zero is fine:
     * declare a larger buffer, zero it, set size past our struct. */
    unsigned char big[128];
    memset(big, 0, sizeof(big));
    struct sched_attr *pa = (struct sched_attr *)big;
    pa->size = sizeof(big);
    pa->sched_policy = SCHED_NORMAL;
    CHECK_RET(sys_setattr(0, (struct sched_attr *)big, 0),
              0, "oversized size w/ zero trailing bytes accepted");

    /* Same oversized struct but with a non-zero trailing byte -> E2BIG. */
    big[sizeof(struct sched_attr) + 4] = 0x7F;
    CHECK_ERR(sys_setattr(0, (struct sched_attr *)big, 0),
              E2BIG, "oversized size w/ non-zero trailing byte -> E2BIG");
}

/* UTIL_CLAMP flags require a VER1-sized struct. */
static void test_util_clamp_size(void)
{
    struct sched_attr a;
    memset(&a, 0, sizeof(a));
    a.sched_policy = SCHED_NORMAL;
    a.sched_flags = SCHED_FLAG_UTIL_CLAMP_MIN;

    /* VER0 size + UTIL_CLAMP -> EINVAL. */
    a.size = SCHED_ATTR_SIZE_VER0;
    CHECK_ERR(sys_setattr(0, &a, 0), EINVAL, "UTIL_CLAMP with size<VER1 -> EINVAL");
}

/* Unknown sched_flags bits -> EINVAL. */
static void test_unknown_flags(void)
{
    struct sched_attr a;
    memset(&a, 0, sizeof(a));
    a.size = sizeof(a);
    a.sched_policy = SCHED_NORMAL;
    a.sched_flags = 0x8000; /* not in SCHED_FLAG_ALL */
    CHECK_ERR(sys_setattr(0, &a, 0), EINVAL, "unknown sched_flags bit -> EINVAL");
}

/* RESET_ON_FORK round-trips through getattr. */
static void test_reset_on_fork(void)
{
    struct sched_attr a;
    memset(&a, 0, sizeof(a));
    a.size = sizeof(a);
    a.sched_policy = SCHED_NORMAL;
    a.sched_flags = SCHED_FLAG_RESET_ON_FORK;
    CHECK_RET(sys_setattr(0, &a, 0), 0, "setattr RESET_ON_FORK");

    struct sched_attr b;
    memset(&b, 0, sizeof(b));
    CHECK_RET(sys_getattr(0, &b, sizeof(b), 0), 0, "getattr after RESET_ON_FORK");
    CHECK((b.sched_flags & SCHED_FLAG_RESET_ON_FORK) != 0,
          "RESET_ON_FORK reflected by getattr");
    /* getscheduler ORs in SCHED_RESET_ON_FORK (0x40000000). */
    CHECK((sys_getscheduler(0) & 0x40000000) != 0,
          "sched_getscheduler ORs SCHED_RESET_ON_FORK");

    /* Clear it again. */
    a.sched_flags = 0;
    CHECK_RET(sys_setattr(0, &a, 0), 0, "clear RESET_ON_FORK");
    memset(&b, 0, sizeof(b));
    sys_getattr(0, &b, sizeof(b), 0);
    CHECK((b.sched_flags & SCHED_FLAG_RESET_ON_FORK) == 0, "RESET_ON_FORK cleared");
}

/* KEEP_POLICY keeps the current policy but applies new params;
 * KEEP_PARAMS keeps the current params. */
static void test_keep_flags(void)
{
    struct sched_attr a;
    memset(&a, 0, sizeof(a));
    a.size = sizeof(a);

    /* Establish FIFO prio 30. */
    a.sched_policy = SCHED_FIFO;
    a.sched_priority = 30;
    CHECK_RET(sys_setattr(0, &a, 0), 0, "seed FIFO prio 30");

    /* KEEP_POLICY: policy field ignored, params (priority) applied. Provide a
     * bogus policy to prove it is ignored. */
    a.sched_policy = 999;
    a.sched_priority = 55;
    a.sched_flags = SCHED_FLAG_KEEP_POLICY;
    CHECK_RET(sys_setattr(0, &a, 0), 0, "KEEP_POLICY ignores bogus policy");
    struct sched_attr b;
    memset(&b, 0, sizeof(b));
    sys_getattr(0, &b, sizeof(b), 0);
    CHECK(b.sched_policy == SCHED_FIFO, "KEEP_POLICY kept FIFO");
    CHECK(b.sched_priority == 55, "KEEP_POLICY applied new priority 55");

    /* KEEP_PARAMS: params ignored, current params kept. */
    a.sched_policy = SCHED_FIFO;
    a.sched_priority = 7;
    a.sched_flags = SCHED_FLAG_KEEP_PARAMS;
    CHECK_RET(sys_setattr(0, &a, 0), 0, "KEEP_PARAMS accepted");
    memset(&b, 0, sizeof(b));
    sys_getattr(0, &b, sizeof(b), 0);
    CHECK(b.sched_priority == 55, "KEEP_PARAMS kept priority 55 (ignored 7)");

    /* Restore NORMAL. */
    a.sched_flags = 0;
    a.sched_policy = SCHED_NORMAL;
    a.sched_priority = 0;
    CHECK_RET(sys_setattr(0, &a, 0), 0, "restore NORMAL after keep-flag tests");
}

/* getattr truncated write: usize between VER0 and full struct writes only
 * min(usize, ksize) bytes and reports that as .size. */
static void test_getattr_truncation(void)
{
    /* Seed a known state first. */
    struct sched_attr s;
    memset(&s, 0, sizeof(s));
    s.size = sizeof(s);
    s.sched_policy = SCHED_RR;
    s.sched_priority = 21;
    CHECK_RET(sys_setattr(0, &s, 0), 0, "seed RR prio 21 for truncation test");

    unsigned char buf[128];
    memset(buf, 0xAB, sizeof(buf));
    struct sched_attr *pa = (struct sched_attr *)buf;
    /* Ask for exactly VER0 bytes: kernel writes size = min(VER0, sizeof). */
    CHECK_RET(sys_getattr(0, pa, SCHED_ATTR_SIZE_VER0, 0), 0, "getattr usize=VER0");
    CHECK(pa->size == SCHED_ATTR_SIZE_VER0, "getattr size reports VER0");
    CHECK(pa->sched_policy == SCHED_RR && pa->sched_priority == 21,
          "getattr VER0 still carries policy/prio");
    /* Bytes past VER0 must be untouched (still 0xAB). */
    CHECK(buf[SCHED_ATTR_SIZE_VER0] == 0xAB, "getattr did not write past usize");

    /* Restore NORMAL. */
    s.sched_policy = SCHED_NORMAL;
    s.sched_priority = 0;
    sys_setattr(0, &s, 0);
}

/* getattr usize below VER0 -> EINVAL; usize huge -> EINVAL (>PAGE_SIZE). */
static void test_getattr_bad_size(void)
{
    struct sched_attr a;
    memset(&a, 0, sizeof(a));
    CHECK_ERR(sys_getattr(0, &a, SCHED_ATTR_SIZE_VER0 - 1, 0), EINVAL,
              "getattr usize < VER0 -> EINVAL");
    CHECK_ERR(sys_getattr(0, &a, 1u << 20, 0), EINVAL,
              "getattr usize > PAGE_SIZE -> EINVAL");
}

/* pid<0 and flags!=0 -> EINVAL; missing pid -> ESRCH; NULL/bad ptr -> EFAULT. */
static void test_arg_errors(void)
{
    struct sched_attr a;
    memset(&a, 0, sizeof(a));
    a.size = sizeof(a);
    a.sched_policy = SCHED_NORMAL;

    CHECK_ERR(sys_setattr(-1, &a, 0), EINVAL, "setattr pid<0 -> EINVAL");
    CHECK_ERR(sys_setattr(0, &a, 1), EINVAL, "setattr flags!=0 -> EINVAL");
    CHECK_ERR(sys_setattr(0, NULL, 0), EINVAL, "setattr NULL attr -> EINVAL");

    CHECK_ERR(sys_getattr(-1, &a, sizeof(a), 0), EINVAL, "getattr pid<0 -> EINVAL");
    CHECK_ERR(sys_getattr(0, NULL, sizeof(a), 0), EINVAL, "getattr NULL attr -> EINVAL");
    /* getattr flags!=0 requires a DL task; on a non-DL task -> EINVAL. */
    CHECK_ERR(sys_getattr(0, &a, sizeof(a), 1), EINVAL,
              "getattr flags!=0 on non-DL task -> EINVAL");

    /* A pid that does not exist -> ESRCH. Use a very large tid. */
    CHECK_ERR(sys_setattr(0x7ffffff0, &a, 0), ESRCH, "setattr missing pid -> ESRCH");
    CHECK_ERR(sys_getattr(0x7ffffff0, &a, sizeof(a), 0), ESRCH,
              "getattr missing pid -> ESRCH");
}

/* Operate on another thread by tid, verify readback, and check the errno for
 * a bad pointer once more from a child so a crash cannot mask it. */
static void test_cross_thread(void)
{
    /* Set self to FIFO, read it via explicit tid==gettid(). */
    pid_t tid = (pid_t)syscall(SYS_gettid);
    struct sched_attr a;
    memset(&a, 0, sizeof(a));
    a.size = sizeof(a);
    a.sched_policy = SCHED_FIFO;
    a.sched_priority = 12;
    CHECK_RET(sys_setattr(tid, &a, 0), 0, "setattr by explicit tid");

    struct sched_attr b;
    memset(&b, 0, sizeof(b));
    CHECK_RET(sys_getattr(tid, &b, sizeof(b), 0), 0, "getattr by explicit tid");
    CHECK(b.sched_policy == SCHED_FIFO && b.sched_priority == 12,
          "explicit-tid readback matches");

    /* Restore. */
    a.sched_policy = SCHED_NORMAL;
    a.sched_priority = 0;
    sys_setattr(tid, &a, 0);
}

int main(void)
{
    TEST_START("sched_setattr / sched_getattr");

    test_present();
    test_getattr_self();
    test_setattr_fifo_roundtrip();
    test_setattr_normal_nice();
    test_bad_policy();
    test_size_abi();
    test_util_clamp_size();
    test_unknown_flags();
    test_reset_on_fork();
    test_keep_flags();
    test_getattr_truncation();
    test_getattr_bad_size();
    test_arg_errors();
    test_cross_thread();

    TEST_DONE();
}
