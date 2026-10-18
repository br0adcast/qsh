/* Test-only Linux-PAM module. All identities are synthetic disposable fixtures.
 * Mutate the PAM caller itself: pam_exec cannot test session credentials. */
#define _GNU_SOURCE
#include <security/pam_modules.h>
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define MAX_GROUPS 256
struct config {
    char path[1024];
    char phase[16];
    char action[16];
    char fail[16];
    gid_t gid;
    int has_gid;
};

static int groups(gid_t *out) { return getgroups(MAX_GROUPS, out); }
static int record(const struct config *c, const char *phase,
                  const gid_t *before, int nb, const gid_t *after, int na) {
    char line[8192];
    char children_path[128], children[1024];
    snprintf(children_path, sizeof(children_path), "/proc/self/task/%ld/children", (long)getpid());
    int children_fd = open(children_path, O_RDONLY | O_CLOEXEC);
    if (children_fd < 0) return PAM_SYSTEM_ERR;
    ssize_t children_size = read(children_fd, children, sizeof(children));
    int children_closed = close(children_fd);
    if (children_size < 0 || children_closed) return PAM_SYSTEM_ERR;
    int n = snprintf(line, sizeof(line), "%ld %s children=%s before=", (long)getpid(), phase,
                     children_size == 0 ? "none" : "present");
    for (int i = 0; i < nb; ++i)
        n += snprintf(line + n, sizeof(line) - (size_t)n, "%s%u", i ? "," : "", before[i]);
    n += snprintf(line + n, sizeof(line) - (size_t)n, " after=");
    for (int i = 0; i < na; ++i)
        n += snprintf(line + n, sizeof(line) - (size_t)n, "%s%u", i ? "," : "", after[i]);
    n += snprintf(line + n, sizeof(line) - (size_t)n, "\n");
    if (n < 0 || (size_t)n >= sizeof(line)) return PAM_SYSTEM_ERR;
    int fd = open(c->path, O_WRONLY | O_APPEND | O_CREAT | O_CLOEXEC, 0600);
    if (fd < 0) return PAM_SYSTEM_ERR;
    ssize_t written = write(fd, line, (size_t)n);
    int closed = close(fd);
    return written == n && closed == 0 ? PAM_SUCCESS : PAM_SYSTEM_ERR;
}
static void cleanup(pam_handle_t *pamh, void *data, int status) {
    (void)pamh; (void)status;
    struct config *c = data;
    gid_t list[MAX_GROUPS];
    int n = groups(list);
    /* Failure must be visible to the test, even though pam_end ignores callbacks. */
    if (n < 0 || record(c, "end", list, n, list, n) != PAM_SUCCESS) _exit(98);
    free(c);
}
static int config(pam_handle_t *pamh, int argc, const char **argv, const struct config **out) {
    const void *existing = NULL;
    if (pam_get_data(pamh, "qshd-test-session-groups", &existing) == PAM_SUCCESS) {
        *out = existing;
        return PAM_SUCCESS;
    }
    struct config *c = calloc(1, sizeof(*c));
    if (!c) return PAM_BUF_ERR;
    strcpy(c->phase, "establish");
    strcpy(c->action, "add");
    for (int i = 0; i < argc; ++i) {
        const char *v = strchr(argv[i], '=');
        if (!v) goto bad;
        ++v;
        if (!strncmp(argv[i], "record=", 7) && strlen(v) < sizeof(c->path)) strcpy(c->path, v);
        else if (!strncmp(argv[i], "phase=", 6) && (!strcmp(v, "establish") || !strcmp(v, "open"))) strcpy(c->phase, v);
        else if (!strncmp(argv[i], "action=", 7) && (!strcmp(v, "add") || !strcmp(v, "replace") || !strcmp(v, "empty"))) strcpy(c->action, v);
        else if (!strncmp(argv[i], "fail=", 5) && (!strcmp(v, "establish") || !strcmp(v, "open"))) strcpy(c->fail, v);
        else if (!strncmp(argv[i], "gid=", 4)) {
            char *end;
            errno = 0;
            unsigned long value = strtoul(v, &end, 10);
            if (!*v || *end || errno || value > (gid_t)-1 || *v == '-') goto bad;
            c->gid = (gid_t)value;
            c->has_gid = 1;
        } else goto bad;
    }
    if (c->path[0] != '/' || (!c->has_gid && strcmp(c->action, "empty"))) goto bad;
    int result = pam_set_data(pamh, "qshd-test-session-groups", c, cleanup);
    if (result != PAM_SUCCESS) { free(c); return result; }
    *out = c;
    return PAM_SUCCESS;
bad:
    free(c);
    return PAM_SERVICE_ERR;
}
static int phase(pam_handle_t *pamh, int argc, const char **argv, const char *name) {
    const struct config *c;
    int result = config(pamh, argc, argv, &c);
    if (result != PAM_SUCCESS) return result;
    gid_t before[MAX_GROUPS], after[MAX_GROUPS];
    int nb = groups(before);
    if (nb < 0) return PAM_SYSTEM_ERR;
    if (!strcmp(name, c->phase) && strcmp(name, c->fail)) {
        int n = nb;
        memcpy(after, before, (size_t)nb * sizeof(gid_t));
        if (!strcmp(c->action, "empty")) n = 0;
        else if (!strcmp(c->action, "replace")) { n = 1; after[0] = c->gid; }
        else {
            int found = 0;
            for (int i = 0; i < n; ++i) if (after[i] == c->gid) found = 1;
            if (!found) { if (n == MAX_GROUPS) return PAM_SYSTEM_ERR; after[n++] = c->gid; }
        }
        if (setgroups((size_t)n, after)) return PAM_SYSTEM_ERR;
    }
    int na = groups(after);
    if (na < 0) return PAM_SYSTEM_ERR;
    result = record(c, name, before, nb, after, na);
    if (result != PAM_SUCCESS) return result;
    return !strcmp(name, c->fail) ? PAM_PERM_DENIED : PAM_SUCCESS;
}
PAM_EXTERN int pam_sm_authenticate(pam_handle_t *p, int f, int n, const char **a) { (void)f; return phase(p,n,a,"authenticate"); }
PAM_EXTERN int pam_sm_acct_mgmt(pam_handle_t *p, int f, int n, const char **a) { (void)f; return phase(p,n,a,"account"); }
PAM_EXTERN int pam_sm_setcred(pam_handle_t *p, int f, int n, const char **a) { return phase(p,n,a,(f & PAM_DELETE_CRED) ? "delete" : "establish"); }
PAM_EXTERN int pam_sm_open_session(pam_handle_t *p, int f, int n, const char **a) { (void)f; return phase(p,n,a,"open"); }
PAM_EXTERN int pam_sm_close_session(pam_handle_t *p, int f, int n, const char **a) { (void)f; return phase(p,n,a,"close"); }
PAM_EXTERN int pam_sm_chauthtok(pam_handle_t *p, int f, int n, const char **a) { (void)f; return phase(p,n,a,"chauthtok"); }
