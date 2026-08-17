/*
 * System V semaphores (semget/semop/semtimedop/semctl) conformance.
 *
 * Ground truth: semget(2)/semop(2)/semctl(2) man pages and Linux ipc/sem.c.
 * Covers set lifecycle, semctl command surface, atomic all-or-nothing multi-op
 * semops with rollback, blocking with cross-process wakeup, semtimedop timeout,
 * IPC_RMID/EIDRM, SEM_UNDO applied at process exit, and EINTR (semop is never
 * restarted by SA_RESTART). On a kernel lacking semaphores every call returns
 * ENOSYS, so this whole suite fails there.
 */

#include "test_framework.h"

#include <sys/ipc.h>
#include <sys/sem.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <signal.h>
#include <time.h>
#include <unistd.h>

#ifndef SEM_UNDO
#define SEM_UNDO 0x1000
#endif

/* seminfo is not exposed by musl's <sys/sem.h>; declare the kernel layout. */
struct sem_info_local
{
    int semmap, semmni, semmns, semmnu, semmsl;
    int semopm, semume, semusz, semvmx, semaem;
};

/* union semun is application-defined per POSIX. */
union semun
{
    int val;
    struct semid_ds *buf;
    unsigned short *array;
    void *ptr;
};

static int getval(int id, int num)
{
    union semun arg = {0};
    return semctl(id, num, GETVAL, arg);
}

static int setval(int id, int num, int v)
{
    union semun arg;
    arg.val = v;
    return semctl(id, num, SETVAL, arg);
}

static double now_s(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double)ts.tv_sec + (double)ts.tv_nsec / 1e9;
}

static volatile sig_atomic_t alarm_fired;
static void on_alarm(int s) { (void)s; alarm_fired++; }

static void test_semget(void)
{
    int priv = semget(IPC_PRIVATE, 3, 0600);
    CHECK(priv >= 0, "semget(IPC_PRIVATE,3) creates a set");

    key_t key = (key_t)(((unsigned)getpid() << 8) ^ 0x53454dU);
    if (key == IPC_PRIVATE)
        key ^= 0x11;
    (void)semctl(semget(key, 0, 0), 0, IPC_RMID, (union semun){0});

    int a = semget(key, 2, IPC_CREAT | 0600);
    CHECK(a >= 0, "semget(key,2,IPC_CREAT) creates");
    CHECK_ERR(semget(key, 2, IPC_CREAT | IPC_EXCL | 0600), EEXIST,
              "semget IPC_EXCL on existing set -> EEXIST");
    CHECK_RET(semget(key, 0, 0600), a, "semget(key,0) looks up existing id");
    CHECK_ERR(semget(key, 5, IPC_CREAT | 0600), EINVAL,
              "semget nsems larger than existing set -> EINVAL");

    key_t missing = key ^ 0x7ff0;
    CHECK_ERR(semget(missing, 1, 0600), ENOENT,
              "semget without IPC_CREAT on missing key -> ENOENT");
    CHECK_ERR(semget(IPC_PRIVATE, 0, 0600), EINVAL,
              "semget nsems==0 on create -> EINVAL");

    CHECK_RET(semctl(a, 0, IPC_RMID, (union semun){0}), 0, "IPC_RMID lookup set");
    CHECK_RET(semctl(priv, 0, IPC_RMID, (union semun){0}), 0, "IPC_RMID private set");
}

static void test_semctl(void)
{
    int id = semget(IPC_PRIVATE, 3, 0600);
    CHECK(id >= 0, "semctl fixture set");

    CHECK_RET(setval(id, 0, 5), 0, "SETVAL sem0=5");
    CHECK_RET(getval(id, 0), 5, "GETVAL sem0==5");
    CHECK_ERR(setval(id, 0, 32768), ERANGE, "SETVAL beyond SEMVMX -> ERANGE");
    CHECK_RET(setval(id, 0, 32767), 0, "SETVAL SEMVMX boundary ok");
    CHECK_ERR(getval(id, 9), EINVAL, "GETVAL out-of-range semnum -> EINVAL");

    unsigned short vals[3] = {1, 2, 3};
    union semun sa;
    sa.array = vals;
    CHECK_RET(semctl(id, 0, SETALL, sa), 0, "SETALL {1,2,3}");
    unsigned short got[3] = {0, 0, 0};
    sa.array = got;
    CHECK_RET(semctl(id, 0, GETALL, sa), 0, "GETALL");
    CHECK(got[0] == 1 && got[1] == 2 && got[2] == 3, "GETALL returns {1,2,3}");

    struct semid_ds ds;
    union semun sb;
    sb.buf = &ds;
    memset(&ds, 0, sizeof(ds));
    CHECK_RET(semctl(id, 0, IPC_STAT, sb), 0, "IPC_STAT");
    CHECK(ds.sem_nsems == 3, "IPC_STAT sem_nsems==3");
    CHECK((ds.sem_perm.mode & 0777) == 0600, "IPC_STAT mode==0600");

    ds.sem_perm.mode = (ds.sem_perm.mode & ~0777) | 0640;
    CHECK_RET(semctl(id, 0, IPC_SET, sb), 0, "IPC_SET mode=0640");
    memset(&ds, 0, sizeof(ds));
    CHECK_RET(semctl(id, 0, IPC_STAT, sb), 0, "IPC_STAT after IPC_SET");
    CHECK((ds.sem_perm.mode & 0777) == 0640, "IPC_SET applied mode");

    struct sem_info_local si;
    union semun sc;
    sc.ptr = &si;
    memset(&si, 0, sizeof(si));
    CHECK(semctl(id, 0, IPC_INFO, sc) >= 0, "IPC_INFO");
    CHECK(si.semvmx == 32767, "IPC_INFO semvmx==32767");
    CHECK(si.semmsl > 0 && si.semopm > 0, "IPC_INFO limits populated");

    CHECK_RET(getval(id, 0), 1, "GETNCNT baseline value from SETALL");
    CHECK_RET(semctl(id, 0, GETNCNT, (union semun){0}), 0, "GETNCNT==0 no waiters");
    CHECK_RET(semctl(id, 0, GETZCNT, (union semun){0}), 0, "GETZCNT==0 no waiters");

    /* GETPID reflects the last operating process. */
    struct sembuf op = {0, 1, 0};
    CHECK_RET(semop(id, &op, 1), 0, "semop V for GETPID");
    CHECK_RET(semctl(id, 0, GETPID, (union semun){0}), getpid(), "GETPID==getpid()");

    CHECK_RET(semctl(id, 0, IPC_RMID, (union semun){0}), 0, "IPC_RMID");
    CHECK_ERR(getval(id, 0), EINVAL, "operation on removed set -> EINVAL");
}

static void test_semop_single(void)
{
    int id = semget(IPC_PRIVATE, 1, 0600);
    CHECK(id >= 0, "single-op fixture");
    setval(id, 0, 0);

    struct sembuf v5 = {0, 5, 0};
    CHECK_RET(semop(id, &v5, 1), 0, "V(+5)");
    CHECK_RET(getval(id, 0), 5, "value==5");

    struct sembuf p3 = {0, -3, 0};
    CHECK_RET(semop(id, &p3, 1), 0, "P(-3)");
    CHECK_RET(getval(id, 0), 2, "value==2");

    struct sembuf p5nw = {0, -5, IPC_NOWAIT};
    CHECK_ERR(semop(id, &p5nw, 1), EAGAIN, "P(-5) IPC_NOWAIT on 2 -> EAGAIN");
    CHECK_RET(getval(id, 0), 2, "value unchanged after EAGAIN");

    struct sembuf znw = {0, 0, IPC_NOWAIT};
    CHECK_ERR(semop(id, &znw, 1), EAGAIN, "wait-zero IPC_NOWAIT on 2 -> EAGAIN");
    setval(id, 0, 0);
    CHECK_RET(semop(id, &znw, 1), 0, "wait-zero on 0 succeeds");

    struct sembuf bad = {7, 1, 0};
    CHECK_ERR(semop(id, &bad, 1), EFBIG, "op on out-of-range sem_num -> EFBIG");

    CHECK_ERR(semop(id, &v5, 0), EINVAL, "nsops==0 -> EINVAL");

    semctl(id, 0, IPC_RMID, (union semun){0});
}

static void test_semop_atomic(void)
{
    int id = semget(IPC_PRIVATE, 2, 0600);
    CHECK(id >= 0, "atomic fixture");
    setval(id, 0, 1);
    setval(id, 1, 0);

    /* Second op cannot proceed: whole call fails, first op rolled back. */
    struct sembuf both[2] = {{0, -1, IPC_NOWAIT}, {1, -1, IPC_NOWAIT}};
    CHECK_ERR(semop(id, both, 2), EAGAIN, "atomic P(sem0)+P(sem1) -> EAGAIN");
    CHECK_RET(getval(id, 0), 1, "sem0 rolled back to 1");
    CHECK_RET(getval(id, 1), 0, "sem1 untouched");

    /* Sequential ops on the same sem within one call, with rollback. */
    struct sembuf seq[2] = {{0, 1, IPC_NOWAIT}, {0, -3, IPC_NOWAIT}};
    CHECK_ERR(semop(id, seq, 2), EAGAIN, "same-sem +1 then -3 underflows -> EAGAIN");
    CHECK_RET(getval(id, 0), 1, "sem0 rolled back after intra-call underflow");

    /* A fully satisfiable multi-op applies atomically. */
    setval(id, 0, 3);
    setval(id, 1, 3);
    struct sembuf ok[2] = {{0, -2, 0}, {1, 2, 0}};
    CHECK_RET(semop(id, ok, 2), 0, "atomic P(sem0,-2)+V(sem1,+2)");
    CHECK_RET(getval(id, 0), 1, "sem0==1");
    CHECK_RET(getval(id, 1), 5, "sem1==5");

    semctl(id, 0, IPC_RMID, (union semun){0});
}

static void test_semop_blocking(void)
{
    int id = semget(IPC_PRIVATE, 1, 0600);
    CHECK(id >= 0, "blocking fixture");
    setval(id, 0, 0);

    pid_t pid = fork();
    if (pid == 0)
    {
        struct sembuf p = {0, -1, 0};
        int r = semop(id, &p, 1);
        _exit(r == 0 ? 0 : 1);
    }
    usleep(300000);
    struct sembuf v = {0, 1, 0};
    CHECK_RET(semop(id, &v, 1), 0, "parent V wakes blocked child");
    int status = 0;
    waitpid(pid, &status, 0);
    CHECK(WIFEXITED(status) && WEXITSTATUS(status) == 0,
          "child P unblocked and returned 0");

    semctl(id, 0, IPC_RMID, (union semun){0});
}

static void test_semtimedop_timeout(void)
{
    int id = semget(IPC_PRIVATE, 1, 0600);
    CHECK(id >= 0, "semtimedop fixture");
    setval(id, 0, 0);

    struct sembuf p = {0, -1, 0};
    struct timespec ts = {0, 300000000};
    double t0 = now_s();
    errno = 0;
    int r = semtimedop(id, &p, 1, &ts);
    double dt = now_s() - t0;
    CHECK(r == -1 && errno == EAGAIN, "semtimedop times out -> EAGAIN");
    CHECK(dt >= 0.25, "semtimedop waited about the timeout");

    semctl(id, 0, IPC_RMID, (union semun){0});
}

static void test_sem_undo(void)
{
    int id = semget(IPC_PRIVATE, 1, 0600);
    CHECK(id >= 0, "SEM_UNDO fixture");

    setval(id, 0, 0);
    pid_t pid = fork();
    if (pid == 0)
    {
        struct sembuf v = {0, 5, SEM_UNDO};
        semop(id, &v, 1);
        _exit(0);
    }
    int status = 0;
    waitpid(pid, &status, 0);
    CHECK_RET(getval(id, 0), 0, "SEM_UNDO reverts child's +5 at exit");

    /* Negative control: without SEM_UNDO the change persists. */
    setval(id, 0, 0);
    pid = fork();
    if (pid == 0)
    {
        struct sembuf v = {0, 7, 0};
        semop(id, &v, 1);
        _exit(0);
    }
    waitpid(pid, &status, 0);
    CHECK_RET(getval(id, 0), 7, "no SEM_UNDO leaves child's +7 in place");

    semctl(id, 0, IPC_RMID, (union semun){0});
}

static void test_eidrm(void)
{
    int id = semget(IPC_PRIVATE, 1, 0600);
    CHECK(id >= 0, "EIDRM fixture");
    setval(id, 0, 0);

    pid_t pid = fork();
    if (pid == 0)
    {
        struct sembuf p = {0, -1, 0};
        errno = 0;
        int r = semop(id, &p, 1);
        _exit(r == -1 && errno == EIDRM ? 0 : 1);
    }
    usleep(300000);
    CHECK_RET(semctl(id, 0, IPC_RMID, (union semun){0}), 0, "IPC_RMID wakes blocked waiter");
    int status = 0;
    waitpid(pid, &status, 0);
    CHECK(WIFEXITED(status) && WEXITSTATUS(status) == 0,
          "blocked semop returns EIDRM after IPC_RMID");
}

static void test_eintr(void)
{
    int id = semget(IPC_PRIVATE, 1, 0600);
    CHECK(id >= 0, "EINTR fixture");
    setval(id, 0, 0);

    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = on_alarm;
    sa.sa_flags = 0; /* no SA_RESTART: semop must still fail with EINTR */
    sigaction(SIGALRM, &sa, NULL);

    alarm_fired = 0;
    alarm(1);
    struct sembuf p = {0, -1, 0};
    errno = 0;
    int r = semop(id, &p, 1);
    CHECK(r == -1 && errno == EINTR, "semop interrupted by signal -> EINTR");
    CHECK(alarm_fired == 1, "SIGALRM handler ran");

    semctl(id, 0, IPC_RMID, (union semun){0});
}

int main(void)
{
    TEST_START("System V semaphores");

    test_semget();
    test_semctl();
    test_semop_single();
    test_semop_atomic();
    test_semop_blocking();
    test_semtimedop_timeout();
    test_sem_undo();
    test_eidrm();
    test_eintr();

    TEST_DONE();
}
