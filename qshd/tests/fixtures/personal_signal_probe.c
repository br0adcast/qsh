/* Test-only initial exec state and same-session PTY descriptor holder. */
#define _GNU_SOURCE
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <signal.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>

int main(int argc, char **argv) {
    if (argc == 2 && strcmp(argv[1], "--inherited-control") == 0) {
        /* Only this owned setup child creates a deliberately inherited fd. */
        const char *path = getenv("QSH_TEST_PERSONAL_SENTINEL");
        if (!path) return 98;
        int sentinel = open(path, O_RDONLY); /* intentionally without CLOEXEC */
        if (sentinel < 3) return 98;
        char number[32];
        snprintf(number, sizeof(number), "%d", sentinel);
        if (setenv("QSH_TEST_PERSONAL_SENTINEL_FD", number, 1)) return 98;
        sigset_t blocked;
        sigemptyset(&blocked);
        sigaddset(&blocked, SIGTERM);
        if (signal(SIGINT, SIG_IGN) == SIG_ERR || sigprocmask(SIG_BLOCK, &blocked, NULL)) return 98;
        execl(argv[0], argv[0], (char *)NULL);
        return 99;
    }
    if (argc > 3 && strcmp(argv[1], "--deny-signal") == 0) {
        unsigned int denied = (unsigned int)atoi(argv[2]);
        struct sock_filter instructions[] = {
            BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, nr)),
            BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_rt_sigaction, 0, 3),
            BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, args[0])),
            BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, denied, 0, 1),
            BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | EPERM),
            BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
        };
        struct sock_fprog program = {6, instructions};
        if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) ||
            prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &program)) return 90;
        execv(argv[3], &argv[3]);
        return 91;
    }
    /* Inspect before changing mask, dispositions, descriptors, or directory. */
    sigset_t mask;
    struct sigaction term, interrupt;
    if (sigprocmask(SIG_SETMASK, NULL, &mask) ||
        sigaction(SIGTERM, NULL, &term) || sigaction(SIGINT, NULL, &interrupt)) return 92;
    DIR *fds = opendir("/proc/self/fd");
    if (!fds) return 93;
    int inherited = 0;
    struct dirent *entry;
    while ((entry = readdir(fds))) {
        char *end;
        long fd = strtol(entry->d_name, &end, 10);
        if (*end == '\0' && fd > 2 && fd != dirfd(fds)) inherited++;
    }
    closedir(fds);
    int sentinel_inherited = 0;
    const char *sentinel_number = getenv("QSH_TEST_PERSONAL_SENTINEL_FD");
    if (sentinel_number) {
        const char *path = getenv("QSH_TEST_PERSONAL_SENTINEL");
        struct stat actual, expected;
        int fd = atoi(sentinel_number);
        int flags = fcntl(fd, F_GETFD);
        if (path && fd > 2 && flags >= 0 && !(flags & FD_CLOEXEC) &&
            !fstat(fd, &actual) && !stat(path, &expected) && S_ISREG(actual.st_mode) &&
            actual.st_dev == expected.st_dev && actual.st_ino == expected.st_ino)
            sentinel_inherited = 1;
    }
    const char *home = getenv("HOME"), *expected = getenv("QSH_TEST_PERSONAL_HOME");
    struct stat info;
    if (!home || !expected || strcmp(home, expected) || stat(home, &info) ||
        info.st_uid != getuid() || !S_ISDIR(info.st_mode)) return 94;
    FILE *report = fopen(getenv("QSH_TEST_PERSONAL_PROBE"), "w");
    if (!report) return 95;
    fprintf(report, "pid=%ld term_blocked=%d int_blocked=%d term_default=%d int_default=%d inherited_fds=%d home_owned=1 sentinel_inherited=%d\n",
        (long)getpid(), sigismember(&mask, SIGTERM), sigismember(&mask, SIGINT),
        term.sa_handler == SIG_DFL, interrupt.sa_handler == SIG_DFL, inherited, sentinel_inherited);
    if (fclose(report)) return 96;
    if (getenv("QSH_TEST_PERSONAL_PROBE_ONLY")) return 0;
    if (chdir(home)) return 96;
    execl("/bin/sh", "sh", "-c",
        "if [ -n \"$QSH_TEST_PERSONAL_RELEASE\" ]; then "
        "trap 'printf held > \"$QSH_TEST_PERSONAL_HELD\"; IFS= read -r value < \"$QSH_TEST_PERSONAL_RELEASE\"; exit 0' HUP; fi; "
        "(trap '' HUP TERM; printf ready > \"$QSH_TEST_PERSONAL_PIDS.job-ready\"; exec /bin/sleep 60) & "
        "job=$!; while [ ! -f \"$QSH_TEST_PERSONAL_PIDS.job-ready\" ]; do :; done; "
        "printf '%s %s\\n' \"$$\" \"$job\" > \"$QSH_TEST_PERSONAL_PIDS.tmp\"; "
        "mv \"$QSH_TEST_PERSONAL_PIDS.tmp\" \"$QSH_TEST_PERSONAL_PIDS\"; wait", (char *)NULL);
    return 97;
}
