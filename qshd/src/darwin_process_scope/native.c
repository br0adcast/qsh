/* Exact Darwin process operations. No numeric-PID signalling or consuming wait. */
#include "native.h"
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <libproc.h>
#include <limits.h>
#include <mach/mach.h>
#include <pthread.h>
#include <signal.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <sys/event.h>
#include <sys/ioctl.h>
#include <sys/proc.h>
#include <sys/proc_info.h>
#include <sys/sysctl.h>
#include <sys/wait.h>
#include <sys/utsname.h>
#include <unistd.h>

/* Private compatibility layout reviewed against xnu-10063.141.1 and
 * xnu-11417.140.69;
 * bsd/sys/proc_info_private.h. This is not a stable public SDK promise. */
struct identity_record {
    uint8_t uuid[16]; uint64_t uniqueid, parent_uniqueid;
    int32_t idversion; uint32_t reserved2; uint64_t reserved3, reserved4;
};
_Static_assert(sizeof(void *) == 8, "LP64 contract required");
_Static_assert(sizeof(pid_t) == sizeof(int32_t), "PID wire size");
_Static_assert(sizeof(struct identity_record) == 56, "identity size");
_Static_assert(offsetof(struct identity_record, uniqueid) == 16, "uniqueid offset");
_Static_assert(offsetof(struct identity_record, idversion) == 32, "idversion offset");
_Static_assert(sizeof(audit_token_t) == sizeof(struct qsh_scope_token), "audit token size");
_Static_assert(TASK_AUDIT_TOKEN_COUNT == sizeof(audit_token_t) / sizeof(natural_t), "audit token count");
_Static_assert(sizeof(struct qsh_scope_identity) == 16, "identity wire size");
#if __has_include(<sys/proc_info_private.h>)
#include <sys/proc_info_private.h>
_Static_assert(PROC_PIDUNIQIDENTIFIERINFO == 17, "SDK identity flavor");
_Static_assert(sizeof(struct proc_uniqidentifierinfo) == 56, "SDK identity size");
_Static_assert(offsetof(struct proc_uniqidentifierinfo, p_uniqueid) == 16, "SDK uniqueid offset");
_Static_assert(offsetof(struct proc_uniqidentifierinfo, p_idversion) == 32, "SDK version offset");
#endif

typedef int (*signal_fn)(audit_token_t *, int);
typedef int (*identity_fn)(int, int, uint64_t, void *, int);
typedef int (*list_fn)(uint32_t, uint32_t, void *, int);
_Static_assert(__builtin_types_compatible_p(__typeof__(&proc_pidinfo), identity_fn), "identity ABI");
_Static_assert(__builtin_types_compatible_p(__typeof__(&proc_listpids), list_fn), "raw list ABI");
_Static_assert(__builtin_types_compatible_p(__typeof__(&proc_signal_with_audittoken), signal_fn), "signal ABI");
static pthread_once_t symbols_once = PTHREAD_ONCE_INIT;
static signal_fn exact_signal;
static void load_symbols(void) {
    void *library = dlopen("/usr/lib/libproc.dylib", RTLD_LAZY | RTLD_LOCAL);
    if (library) exact_signal = (signal_fn)dlsym(library, "proc_signal_with_audittoken");
    /* Keep the library loaded for the lifetime of the cached function pointer. */
}
static int failure(struct qsh_scope_error *error, int domain, int code) {
    *error = (struct qsh_scope_error){domain, code}; return -1;
}
static int invalid(struct qsh_scope_error *error) { return failure(error, 3, 0); }
static int unix_error(struct qsh_scope_error *error) { return failure(error, 1, errno ? errno : EIO); }
static int same(struct qsh_scope_identity a, struct qsh_scope_identity b) {
    return a.pid == b.pid && a.unique && a.unique == b.unique;
}
int qsh_scope_identity(int32_t pid, struct qsh_scope_identity *out, struct qsh_scope_error *error) {
    if (pid <= 0) return invalid(error);
    struct identity_record record = {0};
    errno = 0;
    /* arg1 includes zombies for this reviewed flavor. */
    int size = proc_pidinfo(pid, 17, 1, &record, (int)sizeof(record));
    if (size <= 0) return unix_error(error);
    if (size != (int)sizeof(record) || !record.uniqueid) return invalid(error);
    *out = (struct qsh_scope_identity){pid, (uint32_t)record.idversion, record.uniqueid};
    return 0;
}
int qsh_scope_classification_matches(struct qsh_scope_class before, struct qsh_scope_class after) {
    return same(before.identity, after.identity) && before.identity.version == after.identity.version &&
        before.zombie <= 1 && before.zombie == after.zombie && before.sid == after.sid &&
        (before.zombie ? before.sid == 0 : before.sid > 0);
}
int qsh_scope_classify(int32_t pid, struct qsh_scope_class *out, struct qsh_scope_error *error) {
    struct qsh_scope_identity before, after;
    if (qsh_scope_identity(pid, &before, error)) return -1;
    struct proc_bsdshortinfo short_info = {0};
    errno = 0;
    int size = proc_pidinfo(pid, PROC_PIDT_SHORTBSDINFO, 1, &short_info, sizeof(short_info));
    if (size <= 0) return unix_error(error);
    if (size != (int)sizeof(short_info) || short_info.pbsi_pid != (uint32_t)pid) return invalid(error);
    int zombie = short_info.pbsi_status == SZOMB;
    pid_t sid = 0;
    if (!zombie) {
        sid = getsid(pid);
        if (sid < 0) return unix_error(error);
        if (sid == 0) return invalid(error);
    }
    uint32_t final_zombie = (uint32_t)zombie;
    if (zombie) {
        struct proc_bsdshortinfo final_info = {0};
        errno = 0;
        int final_size = proc_pidinfo(pid, PROC_PIDT_SHORTBSDINFO, 1, &final_info, sizeof(final_info));
        if (final_size <= 0) return unix_error(error);
        if (final_size != (int)sizeof(final_info) || final_info.pbsi_pid != (uint32_t)pid) return invalid(error);
        final_zombie = final_info.pbsi_status == SZOMB;
    }
    if (qsh_scope_identity(pid, &after, error)) return -1;
    struct qsh_scope_class first = {before, sid, (uint32_t)zombie};
    struct qsh_scope_class last = {after, sid, final_zombie};
    if (!qsh_scope_classification_matches(first, last)) return invalid(error);
    *out = last;
    return 0;
}
int qsh_scope_all(int32_t *pids, uint32_t slots, uint32_t *bytes, struct qsh_scope_error *error) {
    if (slots != 4096 || slots > INT_MAX / sizeof(pid_t)) return invalid(error);
    errno = 0;
    int result = proc_listpids(PROC_ALL_PIDS, 0, pids, slots * sizeof(pid_t));
    if (result <= 0) return unix_error(error);
    if ((uint32_t)result > slots * sizeof(pid_t) || result % sizeof(pid_t)) return invalid(error);
    *bytes = (uint32_t)result; return 0;
}
int qsh_scope_bind(struct qsh_scope_identity expected, uint64_t cookie, int32_t *out,
                   struct qsh_scope_identity *bound, struct qsh_scope_error *error) {
    *out = -1;
    struct qsh_scope_identity before, after;
    if (!cookie || cookie > UINTPTR_MAX) return invalid(error);
    if (qsh_scope_identity(expected.pid, &before, error)) return -1;
    if (!same(expected, before)) return invalid(error);
    int queue = kqueue();
    if (queue < 0) return unix_error(error);
    if (fcntl(queue, F_SETFD, FD_CLOEXEC) < 0) { unix_error(error); goto refused; }
    struct kevent change, receipt;
    EV_SET(&change, (uintptr_t)expected.pid, EVFILT_PROC, EV_ADD | EV_ONESHOT | EV_RECEIPT,
           NOTE_EXIT, 0, (void *)(uintptr_t)cookie);
    struct timespec zero = {0, 0};
    int count;
    do { count = kevent(queue, &change, 1, &receipt, 1, &zero); } while (count < 0 && errno == EINTR);
    if (count < 0) { unix_error(error); goto refused; }
    if (count != 1 || receipt.ident != (uintptr_t)expected.pid || receipt.filter != EVFILT_PROC ||
        receipt.udata != (void *)(uintptr_t)cookie || !(receipt.flags & EV_ERROR)) {
        invalid(error); goto refused;
    }
    if (receipt.data != 0) {
        if (receipt.data > 0 && receipt.data <= INT_MAX) failure(error, 1, (int)receipt.data);
        else invalid(error);
        goto refused;
    }
    if (qsh_scope_identity(expected.pid, &after, error)) goto refused;
    if (!same(before, after)) { invalid(error); goto refused; }
    *out = queue; *bound = after; return 0;
refused:
    close(queue); return -1;
}
int qsh_scope_exit(int32_t queue, int32_t pid, uint64_t cookie, uint32_t *exited,
                   struct qsh_scope_error *error) {
    struct kevent event;
    struct timespec zero = {0, 0};
    int count;
    do { count = kevent(queue, NULL, 0, &event, 1, &zero); } while (count < 0 && errno == EINTR);
    if (count < 0) return unix_error(error);
    *exited = 0;
    if (!count) return 0;
    if (count != 1 || event.ident != (uintptr_t)pid || event.filter != EVFILT_PROC ||
        event.udata != (void *)(uintptr_t)cookie || (event.flags & EV_ERROR) || !(event.fflags & NOTE_EXIT))
        return invalid(error);
    *exited = 1; return 0;
}
int qsh_scope_token(struct qsh_scope_identity expected, int32_t sid, struct qsh_scope_token *out,
                    struct qsh_scope_error *error) {
    struct qsh_scope_class before, after;
    if (qsh_scope_classify(expected.pid, &before, error)) return -1;
    if (!same(expected, before.identity) || expected.version != before.identity.version ||
        before.zombie || before.sid != sid) return invalid(error);
    mach_port_t name = MACH_PORT_NULL;
    kern_return_t result = task_name_for_pid(mach_task_self(), expected.pid, &name);
    if (result != KERN_SUCCESS) {
        if (MACH_PORT_VALID(name)) mach_port_deallocate(mach_task_self(), name);
        return failure(error, 2, result);
    }
    if (!MACH_PORT_VALID(name)) return invalid(error);
    audit_token_t token = {{0}};
    mach_msg_type_number_t count = TASK_AUDIT_TOKEN_COUNT;
    result = task_info(name, TASK_AUDIT_TOKEN, (task_info_t)&token, &count);
    kern_return_t released = mach_port_deallocate(mach_task_self(), name);
    if (result != KERN_SUCCESS) return failure(error, 2, result);
    if (released != KERN_SUCCESS) return failure(error, 2, released);
    if (count != TASK_AUDIT_TOKEN_COUNT || token.val[5] != (uint32_t)expected.pid ||
        token.val[7] != expected.version) return invalid(error);
    if (qsh_scope_classify(expected.pid, &after, error)) return -1;
    if (!same(expected, after.identity) || expected.version != after.identity.version ||
        after.zombie || after.sid != sid) return invalid(error);
    memcpy(out, &token, sizeof(token)); return 0;
}
int qsh_scope_signal(const struct qsh_scope_token *value, int32_t signal, struct qsh_scope_error *error) {
    if (signal != SIGHUP && signal != SIGKILL) return invalid(error);
    pthread_once(&symbols_once, load_symbols);
    if (!exact_signal) return failure(error, 1, ENOSYS);
    audit_token_t token;
    memcpy(&token, value, sizeof(token));
    int result = exact_signal(&token, signal);
    if (result) return failure(error, 1, result);
    return 0;
}
int qsh_scope_leader(int32_t pid, uint32_t *exited, int32_t *code, struct qsh_scope_error *error) {
    if (pid <= 0) return invalid(error);
    siginfo_t info = {0};
    int result;
    do { result = waitid(P_PID, (id_t)pid, &info, WEXITED | WNOHANG | WNOWAIT); } while (result < 0 && errno == EINTR);
    if (result < 0) return unix_error(error);
    *exited = 0;
    if (!info.si_pid) return 0;
    if (info.si_pid != pid) return invalid(error);
    if (info.si_code == CLD_EXITED) *code = info.si_status;
    else if (info.si_code == CLD_KILLED || info.si_code == CLD_DUMPED) *code = 1;
    else return invalid(error);
    *exited = 1; return 0;
}
static int runtime_string(const char *name, char *value, size_t capacity, struct qsh_scope_error *error) {
    size_t size = capacity;
    if (sysctlbyname(name, value, &size, NULL, 0) < 0) return unix_error(error);
    if (!size || size > capacity || value[size - 1] != '\0' || strlen(value) + 1 != size) return invalid(error);
    return 0;
}
/* This probe reports only the loaded atomic-signal symbol. Admission and
 * observation errors belong to their selected backend and never trigger fallback. */
int qsh_scope_modern_signal_available(void) {
    pthread_once(&symbols_once, load_symbols);
    return exact_signal != NULL;
}
int qsh_scope_prepare(struct qsh_scope_runtime *runtime, struct qsh_scope_error *error) {
    pthread_once(&symbols_once, load_symbols);
    if (!exact_signal) return failure(error, 1, ENOSYS);
    struct sigaction action;
    if (sigaction(SIGCHLD, NULL, &action) < 0) return unix_error(error);
    if (action.sa_handler == SIG_IGN || (action.sa_flags & SA_NOCLDWAIT)) return invalid(error);
    struct utsname system;
    if (uname(&system) < 0) return unix_error(error);
    if (strcmp(system.sysname, "Darwin")) return invalid(error);
    memset(runtime, 0, sizeof(*runtime));
    if (runtime_string("kern.osrelease", runtime->release, sizeof(runtime->release), error) ||
        runtime_string("kern.version", runtime->version, sizeof(runtime->version), error) ||
        runtime_string("kern.osversion", runtime->build, sizeof(runtime->build), error)) return -1;
    size_t machine_size = strnlen(system.machine, sizeof(system.machine));
    if (machine_size >= sizeof(runtime->machine)) return invalid(error);
    memcpy(runtime->machine, system.machine, machine_size + 1);
    struct qsh_scope_class self;
    if (qsh_scope_classify(getpid(), &self, error)) return -1;
    struct qsh_scope_token token;
    if (qsh_scope_token(self.identity, self.sid, &token, error)) return -1;
    return 0;
}

/* Keeper admission shares observation/ABI guards, never modern signal-symbol
 * admission. The actual broker watch is acquired before application admission. */
int qsh_scope_keeper_prepare(struct qsh_scope_runtime *runtime, struct qsh_scope_error *error) {
    struct sigaction action;
    if (sigaction(SIGCHLD, NULL, &action) < 0) return unix_error(error);
    if (action.sa_handler == SIG_IGN || (action.sa_flags & SA_NOCLDWAIT)) return invalid(error);
    struct utsname system;
    if (uname(&system) < 0) return unix_error(error);
    if (strcmp(system.sysname, "Darwin")) return invalid(error);
    memset(runtime, 0, sizeof(*runtime));
    if (runtime_string("kern.osrelease", runtime->release, sizeof(runtime->release), error) ||
        runtime_string("kern.version", runtime->version, sizeof(runtime->version), error) ||
        runtime_string("kern.osversion", runtime->build, sizeof(runtime->build), error)) return -1;
    size_t machine_size = strnlen(system.machine, sizeof(system.machine));
    if (machine_size >= sizeof(runtime->machine)) return invalid(error);
    memcpy(runtime->machine, system.machine, machine_size + 1);
    struct qsh_scope_class self;
    return qsh_scope_classify(getpid(), &self, error);
}

int qsh_scope_group(struct qsh_scope_identity expected, int32_t sid, int32_t *group,
                    struct qsh_scope_error *error) {
    struct qsh_scope_class before, after;
    if (qsh_scope_classify(expected.pid, &before, error)) return -1;
    if (!same(expected, before.identity) || expected.version != before.identity.version ||
        before.zombie || before.sid != sid) return invalid(error);
    pid_t actual = getpgid(expected.pid);
    if (actual < 0) return unix_error(error);
    if (qsh_scope_classify(expected.pid, &after, error)) return -1;
    if (!qsh_scope_classification_matches(before, after) || actual <= 0) return invalid(error);
    *group = actual;
    return 0;
}


/* Called only in Command's child pre-exec hook. All descriptors already exist
 * and remain owned in Q until spawn returns; none can be the subsequently
 * allocated std exec-error pipe. No fixed descriptor slot is used. */
int qsh_scope_keeper_pre_exec(int32_t slave, int32_t session, int32_t broker) {
    if (slave < 3 || session < 3 || broker < 3 || slave == session || slave == broker || session == broker) {
        errno = EINVAL; return -1;
    }
    sigset_t empty;
    if (sigemptyset(&empty) || sigprocmask(SIG_SETMASK, &empty, NULL)) return -1;
    struct sigaction action;
    memset(&action, 0, sizeof(action));
    action.sa_handler = SIG_DFL;
    if (sigemptyset(&action.sa_mask)) return -1;
    const int signals[] = {SIGHUP, SIGINT, SIGQUIT, SIGTERM, SIGALRM, SIGPIPE, SIGCHLD, SIGTTIN, SIGTTOU, SIGTSTP};
    for (size_t i = 0; i < sizeof(signals) / sizeof(signals[0]); ++i)
        if (sigaction(signals[i], &action, NULL)) return -1;
    if (setsid() < 0 || ioctl(slave, TIOCSCTTY, 0) < 0) return -1;
    for (int fd = 0; fd < 3; ++fd) if (dup2(slave, fd) < 0) return -1;
    if (close(slave) < 0) return -1;
    const int inherited[] = {session, broker};
    for (size_t i = 0; i < sizeof(inherited) / sizeof(inherited[0]); ++i) {
        int flags = fcntl(inherited[i], F_GETFD);
        if (flags < 0 || fcntl(inherited[i], F_SETFD, flags & ~FD_CLOEXEC) < 0) return -1;
    }
    return 0;
}

/* Fixture-only callers. Queries neither open descriptor paths nor control processes. */
_Static_assert(sizeof(struct qsh_scope_fixture_fd) == 40, "fixture scalar size");
_Static_assert(_Alignof(struct qsh_scope_fixture_fd) == 8, "fixture scalar alignment");
_Static_assert(offsetof(struct qsh_scope_fixture_fd, fd) == 0, "fixture fd offset");
_Static_assert(offsetof(struct qsh_scope_fixture_fd, type) == 4, "fixture type offset");
_Static_assert(offsetof(struct qsh_scope_fixture_fd, dev) == 8, "fixture dev offset");
_Static_assert(offsetof(struct qsh_scope_fixture_fd, rdev) == 16, "fixture rdev offset");
_Static_assert(offsetof(struct qsh_scope_fixture_fd, ino) == 24, "fixture inode offset");
_Static_assert(offsetof(struct qsh_scope_fixture_fd, mode) == 32, "fixture mode offset");
_Static_assert(offsetof(struct qsh_scope_fixture_fd, reserved) == 36, "fixture reserved offset");
_Static_assert(sizeof(((struct vinfo_stat *)0)->vst_dev) == 4, "SDK dev width");
_Static_assert(sizeof(((struct vinfo_stat *)0)->vst_rdev) == 4, "SDK rdev width");
_Static_assert(sizeof(((struct vinfo_stat *)0)->vst_ino) == 8, "SDK inode width");
_Static_assert(sizeof(((struct vinfo_stat *)0)->vst_mode) == 2, "SDK mode width");
_Static_assert(sizeof(dev_t) == 4 && (dev_t)-1 < 0, "actor signed dev_t contract");
typedef int (*fixture_fd_fn)(int, int, int, void *, int);
_Static_assert(__builtin_types_compatible_p(__typeof__(&proc_pidfdinfo), fixture_fd_fn), "SDK fd query ABI");
static int fixture_type(uint32_t type) {
    switch (type) {
    case PROX_FDTYPE_ATALK: case PROX_FDTYPE_VNODE: case PROX_FDTYPE_SOCKET:
    case PROX_FDTYPE_PSHM: case PROX_FDTYPE_PSEM: case PROX_FDTYPE_KQUEUE:
    case PROX_FDTYPE_PIPE: case PROX_FDTYPE_FSEVENTS: case PROX_FDTYPE_NETPOLICY:
    case PROX_FDTYPE_CHANNEL: case PROX_FDTYPE_NEXUS: return 1;
    default: return 0;
    }
}
int qsh_scope_fixture_fds(int32_t pid, struct qsh_scope_fixture_fd *rows,
    uint32_t capacity, uint32_t *count, struct qsh_scope_error *error) {
    if (!error) return -1;
    if (pid <= 0 || !rows || !count || capacity != 129) return invalid(error);
    *count = 0;
    memset(rows, 0, capacity * sizeof(*rows));
    struct proc_fdinfo info[129] = {{0}};
    errno = 0;
    int bytes = proc_pidinfo(pid, PROC_PIDLISTFDS, 0, info, sizeof(info));
    /* libproc maps syscall failure to zero; never certify an empty result. */
    if (bytes <= 0) return unix_error(error);
    if (bytes >= (int)sizeof(info) || bytes % (int)sizeof(info[0])) return invalid(error);
    uint32_t n = (uint32_t)bytes / sizeof(info[0]);
    if (n > 128) return invalid(error);
    for (uint32_t i = 0; i < n; ++i) {
        if (info[i].proc_fd < 0 || !fixture_type(info[i].proc_fdtype)) return invalid(error);
        for (uint32_t j = 0; j < i; ++j) if (info[j].proc_fd == info[i].proc_fd) return invalid(error);
        rows[i].fd = info[i].proc_fd;
        rows[i].type = info[i].proc_fdtype;
    }
    *count = n;
    return 0;
}
int qsh_scope_fixture_vnode(int32_t pid, int32_t fd,
    struct qsh_scope_fixture_fd *row, struct qsh_scope_error *error) {
    if (!error) return -1;
    if (pid <= 0 || fd < 0 || !row) return invalid(error);
    memset(row, 0, sizeof(*row));
    struct vnode_fdinfo info = {0};
    errno = 0;
    int bytes = proc_pidfdinfo(pid, fd, PROC_PIDFDVNODEINFO, &info, sizeof(info));
    if (bytes <= 0) return unix_error(error);
    if (bytes != (int)sizeof(info)) return invalid(error);
    row->fd = fd; row->type = PROX_FDTYPE_VNODE;
    row->dev = (uint64_t)(int64_t)(int32_t)info.pvi.vi_stat.vst_dev;
    row->rdev = (uint64_t)(int64_t)(int32_t)info.pvi.vi_stat.vst_rdev;
    row->ino = info.pvi.vi_stat.vst_ino;
    row->mode = info.pvi.vi_stat.vst_mode;
    return 0;
}

_Static_assert(PROX_FDTYPE_ATALK == 0 && PROX_FDTYPE_VNODE == 1 && PROX_FDTYPE_SOCKET == 2 &&
    PROX_FDTYPE_PSHM == 3 && PROX_FDTYPE_PSEM == 4 && PROX_FDTYPE_KQUEUE == 5 &&
    PROX_FDTYPE_PIPE == 6 && PROX_FDTYPE_FSEVENTS == 7 && PROX_FDTYPE_NETPOLICY == 9 &&
    PROX_FDTYPE_CHANNEL == 10 && PROX_FDTYPE_NEXUS == 11, "fixture type scalar mapping");
