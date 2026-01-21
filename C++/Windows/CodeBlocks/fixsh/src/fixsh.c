#define _GNU_SOURCE
#include <signal.h>
#include <stdio.h>
#include <unistd.h>
#include <errno.h>

int main(int argc, char *argv[], char *envp[]) {
    pid_t pid = getpid();
    pid_t pgid = getpgrp();
    pid_t sid = getsid(0);
    pid_t fg = tcgetpgrp(STDIN_FILENO);
    char *ctty = ttyname(STDIN_FILENO);
    printf("[fixsh] pid=%d pgrp=%d sid=%d ctty=%s fg_pgrp=%d\n",
           (int)pid, (int)pgid, (int)sid, ctty ? ctty : "(null)", (int)fg);

    /* 恢复默认处置并清空屏蔽，避免继承 dsh 的 SIG_IGN */
    struct sigaction sa; sigemptyset(&sa.sa_mask); sa.sa_flags = 0; sa.sa_handler = SIG_DFL;
    for (int s = 1; s < NSIG; ++s) if (s != SIGKILL && s != SIGSTOP) sigaction(s, &sa, NULL);
    sigset_t empty; sigemptyset(&empty); sigprocmask(SIG_SETMASK, &empty, NULL);

    if (access("/bin/busybox", R_OK) != 0) {
        argv[0] = (char *)"/bin/bash";
        execve("/bin/bash", argv, envp);
    } else {
        argv[0] = (char *)"-/bin/sh";
        execve("/bin/busybox", argv, envp);
    }
    _exit(errno);                              /* exec 失败时退出 */
}