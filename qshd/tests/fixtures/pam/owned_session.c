
#include <security/pam_modules.h>
#include <unistd.h>
#include <sys/wait.h>
#include <errno.h>
PAM_EXTERN int pam_sm_open_session(pam_handle_t *p, int flags, int argc, const char **argv) {
    (void)p; (void)flags;
    if (argc != 1) return PAM_SESSION_ERR;
    pid_t child = fork();
    if (child < 0) return PAM_SESSION_ERR;
    if (child == 0) { execl(argv[0], argv[0], (char *)0); _exit(127); }
    int status;
    while (waitpid(child, &status, 0) < 0) {
        if (errno != EINTR) return PAM_SESSION_ERR;
    }
    return WIFEXITED(status) && WEXITSTATUS(status) == 0 ? PAM_SUCCESS : PAM_SESSION_ERR;
}
PAM_EXTERN int pam_sm_close_session(pam_handle_t *p, int flags, int argc, const char **argv) {
    (void)p; (void)flags; (void)argc; (void)argv;
    return PAM_SUCCESS;
}
