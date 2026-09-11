/* lab_init.c — QEMU lab init (PID 1) for vivo Y75 vmlinux_new.elf (4.14.186 g6de)
 * Static, no libc runtime deps. Mounts pseudo-fs, dumps kallsyms (unrestricted in lab),
 * prints symbol table for cross-check vs kallsyms_output.txt, then runs the race oracle.
 * A panic here is a QEMU restart — snapshot-safe by design.
 * Build: aarch64-linux-gnu-gcc -O2 -static -o lab_init lab_init.c
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/reboot.h>
#include <sys/wait.h>
#include <signal.h>

static void mkdirs(const char *p){ mkdir(p, 0755); }

static void dump_kallsyms(void){
    FILE *in = fopen("/proc/kallsyms", "r");
    FILE *out = fopen("/lab/kallsyms_qemu.txt", "w");
    if(!in || !out){ if(in)fclose(in); if(out)fclose(out); return; }
    char line[256];
    /* Print key symbols to console and full table to /lab */
    static const char *keys[] = {
        "futex_wait_requeue_pi","futex_requeue","futex_lock_pi","futex_wait",
        "core_sys_select","sys_pselect6","do_select","rb_erase_cached",
        "rt_mutex_adjust_prio_chain","task_blocks_on_rt_mutex","rt_mutex_init_waiter",
        "do_futex","SyS_futex","selinux_state","init_task","init_cred","init_thread_union",
        "commit_creds","prepare_kernel_cred","modprobe_path","_text","_stext",NULL};
    int found[32] = {0};
    while(fgets(line, sizeof(line), in)){
        fputs(line, out);
        for(int i=0; keys[i]; i++){
            if(!found[i] && strstr(line, keys[i])){
                /* console output: addr type name */
                printf("SYM %s", line);
                found[i]=1;
            }
        }
    }
    fclose(in); fclose(out);
    printf("LAB kallsyms dumped -> /lab/kallsyms_qemu.txt\n");
}

int main(void){
    setbuf(stdout, NULL);
    printf("\n=== QEMU LAB INIT — vivo Y75 vmlinux 4.14.186 (g6de) ===\n");

    mkdirs("/proc"); mkdirs("/sys"); mkdirs("/dev"); mkdirs("/lab"); mkdirs("/tmp");
    if(mount("proc", "/proc", "proc", 0, NULL)) printf("mount proc: %s\n", strerror(errno));
    if(mount("sysfs", "/sys", "sysfs", 0, NULL)) printf("mount sysfs: %s\n", strerror(errno));
    if(mount("devtmpfs", "/dev", "devtmpfs", 0, NULL)) printf("mount dev: %s\n", strerror(errno));
    if(mount("tmpfs", "/tmp", "tmpfs", 0, NULL)) printf("mount tmp: %s\n", strerror(errno));

    FILE *v = fopen("/proc/version", "r");
    if(v){ char b[256]; if(fgets(b,sizeof(b),v)) printf("VER %s", b); fclose(v); }

    FILE *p = fopen("/proc/sys/kernel/perf_event_paranoid", "r");
    if(p){ int x=-99; fscanf(p,"%d",&x); fclose(p); printf("LAB perf_event_paranoid = %d\n", x);
           p = fopen("/proc/sys/kernel/perf_event_paranoid","w");
           if(p){ fprintf(p,"-1"); fclose(p); printf("LAB set paranoid -> -1\n"); } }

    dump_kallsyms();

    /* Run the same race oracle already proven 8/8 on the phone */
    printf("LAB running race_oracle inside emulated kernel...\n");
    pid_t pid = fork();
    if(pid == 0){
        execl("/bin/race_oracle", "race_oracle", (char*)NULL);
        _exit(127);
    }
    int st; waitpid(pid, &st, 0);
    printf("LAB race_oracle exit=%d\n", WIFEXITED(st)?WEXITSTATUS(st):(-1));

    printf("LAB done. Panics here are QEMU restarts only.\nLAB powering off.\n");
    sync();
    reboot(RB_POWER_OFF);
    for(;;) pause();
}
