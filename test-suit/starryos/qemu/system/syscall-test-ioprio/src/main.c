#include "test_framework.h"

#include <sched.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <unistd.h>

/*
 * musl provides no libc wrapper for ioprio_get/ioprio_set (only the SYS_
 * numbers and uapi <linux/ioprio.h>), so every call goes through syscall(2)
 * directly. Semantics mirror Linux block/ioprio.c and include/uapi/linux/ioprio.h.
 */

#define IOPRIO_CLASS_SHIFT 13
#define IOPRIO_NR_CLASSES  8
#define IOPRIO_CLASS_MASK  (IOPRIO_NR_CLASSES - 1)
#define IOPRIO_PRIO_MASK   ((1UL << IOPRIO_CLASS_SHIFT) - 1)

#define IOPRIO_PRIO_CLASS(v) (((v) >> IOPRIO_CLASS_SHIFT) & IOPRIO_CLASS_MASK)
#define IOPRIO_PRIO_DATA(v)  ((v) & IOPRIO_PRIO_MASK)
#define IOPRIO_PRIO_VALUE(c, d) (((c) << IOPRIO_CLASS_SHIFT) | (d))

#define IOPRIO_CLASS_NONE    0
#define IOPRIO_CLASS_RT      1
#define IOPRIO_CLASS_BE      2
#define IOPRIO_CLASS_IDLE    3
#define IOPRIO_CLASS_INVALID 7

#define IOPRIO_WHO_PROCESS 1
#define IOPRIO_WHO_PGRP    2
#define IOPRIO_WHO_USER    3

#define IOPRIO_NR_LEVELS 8

static long ioprio_set(int which, int who, int ioprio)
{
    return syscall(SYS_ioprio_set, which, who, ioprio);
}

static long ioprio_get(int which, int who)
{
    return syscall(SYS_ioprio_get, which, who);
}

/* Probe: on a kernel that lacks the syscall the raw call returns -ENOSYS. */
static int syscall_is_implemented(void)
{
    errno = 0;
    long r = ioprio_get(IOPRIO_WHO_PROCESS, 0);
    if (r == -1 && errno == ENOSYS)
    {
        return 0;
    }
    return 1;
}

int main(void)
{
    TEST_START("ioprio_get/ioprio_set semantic checks");

    /* -------- 0. implemented (not ENOSYS) probe -------- */
    CHECK(syscall_is_implemented(),
          "ioprio_get is implemented (not ENOSYS)");

    int self = (int)getpid();

    /* -------- 1. default ioprio of a fresh task is IOPRIO_DEFAULT (0) -------- */
    /*
     * get_task_raw_ioprio() returns the value stored by userspace; a task that
     * never called ioprio_set reports IOPRIO_PRIO_VALUE(NONE, 0) == 0.
     */
    CHECK_RET(ioprio_get(IOPRIO_WHO_PROCESS, 0), 0,
              "ioprio_get WHO_PROCESS who=0 (self) default => 0");
    CHECK_RET(ioprio_get(IOPRIO_WHO_PROCESS, self), 0,
              "ioprio_get WHO_PROCESS who=self-pid default => 0");

    /* -------- 1b. WHO_PGRP/WHO_USER derive from nice for NONE-class tasks -- */
    /*
     * WHO_PROCESS get uses get_task_raw_ioprio -> the stored value verbatim
     * (0 for a fresh task). WHO_PGRP/WHO_USER get uses get_task_ioprio, which
     * for a NONE-class task converts the CPU scheduler nice value into a
     * BE-class I/O priority (block/ioprio.c + include/linux/ioprio.h), then
     * folds the group/user with ioprio_best (min). While every task is still
     * fresh, WHO_PROCESS must read raw 0 yet WHO_PGRP/WHO_USER must read the
     * nonzero nice-derived value. A kernel that returned the raw stored value
     * for the aggregate would report 0 here and fail.
     */
    long pg_fresh = ioprio_get(IOPRIO_WHO_PGRP, 0);
    CHECK(pg_fresh > 0,
          "fresh WHO_PGRP derives nonzero ioprio from nice (not raw 0)");
    CHECK(IOPRIO_PRIO_CLASS(pg_fresh) == IOPRIO_CLASS_BE,
          "fresh WHO_PGRP derived class is BE");
    long us_fresh = ioprio_get(IOPRIO_WHO_USER, 0);
    CHECK(us_fresh > 0,
          "fresh WHO_USER derives nonzero ioprio from nice (not raw 0)");
    CHECK(IOPRIO_PRIO_CLASS(us_fresh) == IOPRIO_CLASS_BE,
          "fresh WHO_USER derived class is BE");

    /* -------- 2. set BE class and read it back exactly -------- */
    int be3 = IOPRIO_PRIO_VALUE(IOPRIO_CLASS_BE, 3);
    CHECK_RET(ioprio_set(IOPRIO_WHO_PROCESS, 0, be3), 0,
              "ioprio_set WHO_PROCESS who=0 BE level 3 => 0");
    CHECK_RET(ioprio_get(IOPRIO_WHO_PROCESS, 0), be3,
              "ioprio_get reads back BE level 3 raw value");
    CHECK(IOPRIO_PRIO_CLASS(ioprio_get(IOPRIO_WHO_PROCESS, 0)) == IOPRIO_CLASS_BE,
          "readback class field == BE");
    CHECK(IOPRIO_PRIO_DATA(ioprio_get(IOPRIO_WHO_PROCESS, 0)) == 3,
          "readback data field == 3");

    /* -------- 3. IDLE class needs no privilege; readback exact -------- */
    int idle0 = IOPRIO_PRIO_VALUE(IOPRIO_CLASS_IDLE, 0);
    CHECK_RET(ioprio_set(IOPRIO_WHO_PROCESS, self, idle0), 0,
              "ioprio_set WHO_PROCESS who=self IDLE => 0");
    CHECK_RET(ioprio_get(IOPRIO_WHO_PROCESS, self), idle0,
              "ioprio_get reads back IDLE value");

    /* -------- 4. NONE class with level 0 is accepted; level!=0 => EINVAL ---- */
    int none0 = IOPRIO_PRIO_VALUE(IOPRIO_CLASS_NONE, 0);
    CHECK_RET(ioprio_set(IOPRIO_WHO_PROCESS, 0, none0), 0,
              "ioprio_set NONE level 0 => 0 (resets to default)");
    CHECK_RET(ioprio_get(IOPRIO_WHO_PROCESS, 0), none0,
              "ioprio_get after NONE reset => 0");
    int none_bad = IOPRIO_PRIO_VALUE(IOPRIO_CLASS_NONE, 1);
    CHECK_ERR(ioprio_set(IOPRIO_WHO_PROCESS, 0, none_bad), EINVAL,
              "ioprio_set NONE with nonzero level => EINVAL");

    /* -------- 5. invalid class values => EINVAL (ioprio_check_cap) --------- */
    /* class 7 is IOPRIO_CLASS_INVALID -> default arm returns EINVAL */
    CHECK_ERR(ioprio_set(IOPRIO_WHO_PROCESS, 0,
                         IOPRIO_PRIO_VALUE(IOPRIO_CLASS_INVALID, 0)),
              EINVAL, "ioprio_set INVALID class (7) => EINVAL");
    /* class 4/5/6 also hit the default arm of the switch => EINVAL */
    CHECK_ERR(ioprio_set(IOPRIO_WHO_PROCESS, 0, IOPRIO_PRIO_VALUE(4, 0)),
              EINVAL, "ioprio_set class 4 (unused) => EINVAL");
    CHECK_ERR(ioprio_set(IOPRIO_WHO_PROCESS, 0, IOPRIO_PRIO_VALUE(6, 2)),
              EINVAL, "ioprio_set class 6 (unused) => EINVAL");

    /* -------- 6. cap-check ordering: EINVAL(class) precedes ESRCH(who) ----- */
    /*
     * ioprio_check_cap() runs before the who lookup, so a bad class with a
     * bogus pid must report EINVAL, not ESRCH.
     */
    CHECK_ERR(ioprio_set(IOPRIO_WHO_PROCESS, 0x7ffffff0,
                         IOPRIO_PRIO_VALUE(IOPRIO_CLASS_INVALID, 0)),
              EINVAL, "bad class + bogus pid => EINVAL (cap check first)");

    /* -------- 7. bad 'which' => EINVAL (default switch arm) ---------------- */
    /* which is validated AFTER ioprio_check_cap, so use a valid ioprio here. */
    CHECK_ERR(ioprio_set(0, 0, be3), EINVAL,
              "ioprio_set which=0 (invalid) => EINVAL");
    CHECK_ERR(ioprio_set(4, 0, be3), EINVAL,
              "ioprio_set which=4 (invalid) => EINVAL");
    CHECK_ERR(ioprio_get(0, 0), EINVAL, "ioprio_get which=0 (invalid) => EINVAL");
    CHECK_ERR(ioprio_get(4, 0), EINVAL, "ioprio_get which=4 (invalid) => EINVAL");

    /* -------- 8. bad 'which' must be EINVAL even with a nonzero who -------- */
    CHECK_ERR(ioprio_get(99, self), EINVAL,
              "ioprio_get which=99 who=self => EINVAL");

    /* -------- 9. ESRCH: process that does not exist ----------------------- */
    /* pid 0x7ffffff0 will not exist in this tiny system. */
    CHECK_ERR(ioprio_get(IOPRIO_WHO_PROCESS, 0x7ffffff0), ESRCH,
              "ioprio_get WHO_PROCESS bogus pid => ESRCH");
    CHECK_ERR(ioprio_set(IOPRIO_WHO_PROCESS, 0x7ffffff0, be3), ESRCH,
              "ioprio_set WHO_PROCESS bogus pid (valid class) => ESRCH");

    /* -------- 10. WHO_PGRP self resolution: highest prio (lowest value) --- */
    /*
     * ioprio_get(PGRP) returns ioprio_best == min over the group. We set our
     * own process to a known value; who=0 means "our process group".
     */
    int be5 = IOPRIO_PRIO_VALUE(IOPRIO_CLASS_BE, 5);
    CHECK_RET(ioprio_set(IOPRIO_WHO_PROCESS, 0, be5), 0,
              "ioprio_set self BE level 5 (prep for PGRP get)");
    long pg = ioprio_get(IOPRIO_WHO_PGRP, 0);
    CHECK(pg >= 0, "ioprio_get WHO_PGRP who=0 (own group) succeeds");
    /* The best (min) over the group is <= our own value. */
    CHECK(pg >= 0 && pg <= be5,
          "ioprio_get WHO_PGRP returns highest priority (<= our value)");

    /* WHO_PGRP with our own pgid explicitly. */
    int pgid = (int)getpgrp();
    long pg2 = ioprio_get(IOPRIO_WHO_PGRP, pgid);
    CHECK(pg2 >= 0, "ioprio_get WHO_PGRP who=own-pgid succeeds");

    /* WHO_PGRP set applies to every member of the group (at least ourselves). */
    int be2 = IOPRIO_PRIO_VALUE(IOPRIO_CLASS_BE, 2);
    CHECK_RET(ioprio_set(IOPRIO_WHO_PGRP, 0, be2), 0,
              "ioprio_set WHO_PGRP who=0 BE level 2 => 0");
    CHECK_RET(ioprio_get(IOPRIO_WHO_PROCESS, 0), be2,
              "our task picked up the pgrp-wide ioprio");

    /* WHO_PGRP bogus group => ESRCH. */
    CHECK_ERR(ioprio_get(IOPRIO_WHO_PGRP, 0x7ffffff0), ESRCH,
              "ioprio_get WHO_PGRP bogus pgid => ESRCH");

    /* -------- 11. WHO_USER self resolution --------------------------------- */
    int uid = (int)getuid();
    long us = ioprio_get(IOPRIO_WHO_USER, 0);
    CHECK(us >= 0, "ioprio_get WHO_USER who=0 (current user) succeeds");
    long us2 = ioprio_get(IOPRIO_WHO_USER, uid);
    CHECK(us2 >= 0, "ioprio_get WHO_USER who=own-uid succeeds");
    /* who=0 (current_user) and who=own-uid must agree. */
    CHECK(us == us2, "ioprio_get WHO_USER who=0 == who=own-uid");

    /* WHO_USER set touches every task owned by the uid (>=1 => ourselves). */
    int be1 = IOPRIO_PRIO_VALUE(IOPRIO_CLASS_BE, 1);
    CHECK_RET(ioprio_set(IOPRIO_WHO_USER, 0, be1), 0,
              "ioprio_set WHO_USER who=0 BE level 1 => 0");
    CHECK_RET(ioprio_get(IOPRIO_WHO_PROCESS, 0), be1,
              "our task picked up the per-user ioprio");

    /* -------- 12. RT class capability gate -------------------------------- */
    /*
     * Setting IOPRIO_CLASS_RT requires CAP_SYS_ADMIN or CAP_SYS_NICE. When the
     * test runs as root (the default StarryOS init identity) it must succeed
     * and read back exactly; if it runs unprivileged it must be EPERM. Accept
     * exactly one of the two deterministic outcomes.
     */
    int rt4 = IOPRIO_PRIO_VALUE(IOPRIO_CLASS_RT, 4);
    errno = 0;
    long rt_ret = ioprio_set(IOPRIO_WHO_PROCESS, 0, rt4);
    if (rt_ret == 0)
    {
        CHECK_RET(ioprio_get(IOPRIO_WHO_PROCESS, 0), rt4,
                  "privileged: ioprio_set RT succeeded, reads back RT value");
    }
    else
    {
        CHECK(rt_ret == -1 && errno == EPERM,
              "unprivileged: ioprio_set RT => EPERM");
    }

    /* -------- 13. BE data byte round-trips unchanged (13-bit data) -------- */
    /*
     * ioprio_check_cap does NOT clamp the data field for BE/RT, so a data value
     * outside 0..7 is stored verbatim and read back verbatim.
     */
    int be_hi = IOPRIO_PRIO_VALUE(IOPRIO_CLASS_BE, IOPRIO_NR_LEVELS + 1);
    CHECK_RET(ioprio_set(IOPRIO_WHO_PROCESS, 0, be_hi), 0,
              "ioprio_set BE with data==9 accepted (no clamp in check_cap)");
    CHECK_RET(ioprio_get(IOPRIO_WHO_PROCESS, 0), be_hi,
              "ioprio_get reads back BE data==9 verbatim");

    /* Restore a clean default before finishing. */
    (void)ioprio_set(IOPRIO_WHO_PROCESS, 0, none0);
    CHECK_RET(ioprio_get(IOPRIO_WHO_PROCESS, 0), none0,
              "final reset to IOPRIO_DEFAULT reads back 0");

    TEST_DONE();
}
