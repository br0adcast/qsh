/* Case-specific owned Darwin controls. Never a production process supervisor. */
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <libproc.h>
#include <limits.h>
#include <mach/mach.h>
#include <poll.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/event.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>
#include "darwin-process-metadata.h"

typedef int (*signal_fn)(audit_token_t *, int);
typedef int (*identity_fn)(int, int, uint64_t, void *, int);
typedef int (*list_fn)(uint32_t, uint32_t, void *, int);
_Static_assert(__builtin_types_compatible_p(__typeof__(&proc_signal_with_audittoken), signal_fn), "signal ABI");
_Static_assert(__builtin_types_compatible_p(__typeof__(&proc_pidinfo), identity_fn), "metadata ABI");
_Static_assert(__builtin_types_compatible_p(__typeof__(&proc_listpids), list_fn), "list ABI");
static signal_fn exact_signal;
static identity_fn identity;
static list_fn list_pids;
static void *library;
static const char *executable;
static volatile sig_atomic_t interrupted, delivered, write_fault;
static int acknowledgment = -1;

struct frame {
    uint32_t kind, code, count, fault;
    uint64_t uniqueid;
    audit_token_t token;
};
_Static_assert(sizeof(struct frame) <= PIPE_BUF, "atomic frame required");
struct actor { pid_t pid; int command, reply, reaped, status; };
static int waits, rescues;

enum fault {
    NONE, REGISTRATION, POST_SHORT, POST_DENIED, POST_MISMATCH,
    CLOSED_QUEUE, FOREIGN_COOKIE, EOF_ONLY, ZERO_EVENTS, EVENT_ERROR, FOREIGN_IDENT
};
static const struct { const char *name; enum fault fault; } cases[] = {
    {"exec_then_reap_before_note_exit", NONE},
    {"injected_registration_error", REGISTRATION},
    {"injected_short_postcapture", POST_SHORT},
    {"injected_denied_postcapture", POST_DENIED},
    {"injected_mismatched_postcapture", POST_MISMATCH},
    {"actual_closed_queue", CLOSED_QUEUE},
    {"injected_foreign_cookie", FOREIGN_COOKIE},
    {"injected_eof_without_note_exit", EOF_ONLY},
    {"injected_zero_event_result", ZERO_EVENTS},
    {"injected_event_error", EVENT_ERROR},
    {"injected_foreign_ident", FOREIGN_IDENT}
};

static int64_t now_ms(void) {
    struct timespec t;
    return clock_gettime(CLOCK_MONOTONIC, &t) ? -1 : (int64_t)t.tv_sec * 1000 + t.tv_nsec / 1000000;
}
static void stop_requested(int number) { (void)number; interrupted = 1; }
static int send_frame(int fd, struct frame *message) {
    ssize_t n = write(fd, message, sizeof(*message));
    return n == (ssize_t)sizeof(*message) ? 0 : -1;
}
static int receive_frame(int fd, struct frame *message, int64_t deadline) {
    for (;;) {
        int64_t now = now_ms();
        if (interrupted || now < 0 || now >= deadline) return -1;
        struct pollfd p = {fd, POLLIN, 0};
        int n = poll(&p, 1, (int)(deadline - now));
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) return -1;
        ssize_t size = read(fd, message, sizeof(*message));
        if (size < 0 && (errno == EINTR || errno == EAGAIN)) continue;
        return size == (ssize_t)sizeof(*message) ? 0 : -1;
    }
}
static int command(struct actor *actor, uint32_t kind, const audit_token_t *token) {
    struct frame message = {0};
    message.kind = kind;
    if (token) message.token = *token;
    return send_frame(actor->command, &message);
}
static int metadata(pid_t pid, struct qsh_process_identity *record, int *error) {
    memset(record, 0, sizeof(*record));
    errno = 0;
    int size = identity(pid, QSH_IDENTITY_FLAVOR, 0, record, sizeof(*record));
    *error = size == 0 ? errno : 0;
    return size == (int)sizeof(*record) && record->uniqueid ? 0 : -1;
}
static int own_token(audit_token_t *token) {
    mach_msg_type_number_t count = TASK_AUDIT_TOKEN_COUNT;
    return task_info(mach_task_self(), TASK_AUDIT_TOKEN, (task_info_t)token, &count) == KERN_SUCCESS &&
        count == TASK_AUDIT_TOKEN_COUNT ? 0 : -1;
}
static int load_wrappers(void) {
    library = dlopen("/usr/lib/libproc.dylib", RTLD_LAZY | RTLD_LOCAL);
    if (!library) return -1;
    exact_signal = (signal_fn)dlsym(library, "proc_signal_with_audittoken");
    identity = (identity_fn)dlsym(library, "proc_pidinfo");
    list_pids = (list_fn)dlsym(library, "proc_listpids");
    return exact_signal && identity && list_pids ? 0 : -1;
}
static void acknowledge(int number) {
    int saved = errno;
    (void)number;
    struct frame message = {0};
    if (delivered < 2) delivered++; else write_fault = 1;
    message.kind = 'S'; message.count = (uint32_t)delivered;
    if (write(acknowledgment, &message, sizeof(message)) != (ssize_t)sizeof(message)) write_fault = 1;
    errno = saved;
}
static int actor_setup(void) {
    struct sigaction action = {0};
    action.sa_handler = SIG_DFL; sigemptyset(&action.sa_mask);
    sigset_t set; sigemptyset(&set); sigaddset(&set, SIGALRM); sigaddset(&set, SIGUSR1);
    if (sigaction(SIGALRM, &action, NULL) || sigprocmask(SIG_UNBLOCK, &set, NULL)) return -1;
    alarm(15); /* Installed before any actor publishes a token or ready frame. */
    return 0;
}
static int target(int input, int output, int stage) {
    if (actor_setup()) return 20;
    acknowledgment = output;
    struct sigaction action = {0}; action.sa_handler = acknowledge; sigemptyset(&action.sa_mask);
    if (sigaction(SIGUSR1, &action, NULL)) return 21;
    struct frame message = {0}; message.kind = 'R'; message.code = (uint32_t)stage;
    if (own_token(&message.token) || send_frame(output, &message)) return 22;
    int64_t deadline = now_ms() + 12000;
    for (;;) {
        if (receive_frame(input, &message, deadline)) return 23;
        if (message.kind == 'E' && stage == 0) {
            char in[24], out[24]; snprintf(in, sizeof(in), "%d", input); snprintf(out, sizeof(out), "%d", output);
            execl(executable, executable, "--target", in, out, "1", (char *)NULL);
            return 24;
        }
        if (message.kind != 'P' && message.kind != 'X') return 25;
        uint32_t operation = message.kind;
        memset(&message, 0, sizeof(message));
        message.kind = operation == 'P' ? 'P' : 'F';
        message.count = (uint32_t)delivered; message.fault = (uint32_t)write_fault;
        if (send_frame(output, &message)) return 26;
        if (operation == 'X') return write_fault ? 27 : 0;
    }
}

static int terminal_event(const struct kevent *event, pid_t pid, void *cookie) {
    return event->ident == (uintptr_t)pid && event->filter == EVFILT_PROC && event->udata == cookie &&
        !(event->flags & EV_ERROR) && (event->fflags & NOTE_EXIT);
}
static int binding_accepted(const struct qsh_process_identity *before,
    const struct qsh_process_identity *after, int size, int error,
    const struct kevent *receipt, pid_t pid, void *cookie) {
    return size == (int)sizeof(*after) && !error && before->uniqueid &&
        before->uniqueid == after->uniqueid && receipt->ident == (uintptr_t)pid &&
        receipt->filter == EVFILT_PROC && receipt->udata == cookie &&
        (receipt->flags & EV_ERROR) && receipt->data == 0;
}
static int event_after_reap(int queue, struct kevent *event, int64_t deadline) {
    for (;;) {
        int64_t now = now_ms();
        if (interrupted || now < 0 || now >= deadline) return -1;
        struct timespec timeout = {(deadline - now) / 1000, ((deadline - now) % 1000) * 1000000};
        int count = kevent(queue, NULL, 0, event, 1, &timeout);
        if (count < 0 && errno == EINTR) continue;
        return count;
    }
}
static int observer(int input, int output, int case_index) {
    if (actor_setup() || load_wrappers()) return 30;
    enum fault fault = cases[case_index].fault;
    int64_t deadline = now_ms() + 12000;
    struct frame message;
    if (receive_frame(input, &message, deadline) || message.kind != 'B') return 31;
    audit_token_t old = message.token;
    pid_t pid = (pid_t)old.val[5];
    struct qsh_process_identity before, after; int error;
    if (pid <= 0 || metadata(pid, &before, &error) || (uint32_t)before.idversion != old.val[7]) return 32;
    int queue = kqueue();
    if (queue < 0) return 33;
    int result = 34; char cookie;
    struct kevent change, receipt;
    EV_SET(&change, (uintptr_t)pid, EVFILT_PROC, EV_ADD | EV_ENABLE | EV_RECEIPT, NOTE_EXIT, 0, &cookie);
    struct timespec zero = {0, 0};
    int count = kevent(queue, &change, 1, &receipt, 1, &zero);
    if (count != 1 || receipt.ident != (uintptr_t)pid || receipt.filter != EVFILT_PROC ||
        receipt.udata != &cookie || !(receipt.flags & EV_ERROR) || receipt.data != 0) goto finish;
    if (metadata(pid, &after, &error)) goto finish;
    if (before.uniqueid != after.uniqueid || (uint32_t)after.idversion != old.val[7]) goto finish;
    int ignored;
    errno = 0;
    if (waitpid(pid, &ignored, WNOHANG) != -1 || errno != ECHILD) goto finish;
    int bound = binding_accepted(&before, &after, sizeof(after), 0, &receipt, pid, &cookie);
    memset(&message, 0, sizeof(message)); message.kind = 'B'; message.code = (uint32_t)bound;
    message.uniqueid = before.uniqueid;
    if (send_frame(output, &message)) goto finish;
    if (!bound) { result = 0; goto finish; }
    if (receive_frame(input, &message, deadline) || message.kind != 'E') goto finish;
    audit_token_t current = message.token;
    if (current.val[5] != old.val[5] || current.val[7] == old.val[7] ||
        metadata(pid, &after, &error) || after.uniqueid != before.uniqueid ||
        (uint32_t)after.idversion != current.val[7] || exact_signal(&old, SIGUSR1) != ESRCH) goto finish;
    memset(&message, 0, sizeof(message)); message.kind = 'E'; message.uniqueid = after.uniqueid;
    if (send_frame(output, &message) || receive_frame(input, &message, deadline) || message.kind != 'S') goto finish;
    if (exact_signal(&current, SIGUSR1) != 0) goto finish;
    memset(&message, 0, sizeof(message)); message.kind = 'S';
    if (send_frame(output, &message) || receive_frame(input, &message, deadline) || message.kind != 'R') goto finish;
    /* Controller has consumed T's native wait. This is the FIRST event read. */
    if (fault == CLOSED_QUEUE) {
        if (close(queue)) goto finish;
        queue = -1; errno = 0;
        if (kevent(queue, NULL, 0, &receipt, 1, &zero) != -1 || errno != EBADF) goto finish;
        count = 0;
    } else {
        count = event_after_reap(queue, &receipt, deadline);
        if (count != 1 || !terminal_event(&receipt, pid, &cookie)) goto finish;
    }
    memset(&message, 0, sizeof(message)); message.kind = 'R';
    message.code = count == 1 && terminal_event(&receipt, pid, &cookie);
    if (send_frame(output, &message)) goto finish;
    result = 0;
finish:
    if (queue >= 0 && close(queue)) result = 35;
    if (dlclose(library)) result = 36;
    return result;
}

static int make_pipe(int pipe_ends[2]) {
    if (pipe(pipe_ends)) return -1;
    for (int i = 0; i < 2; i++) {
        if (fcntl(pipe_ends[i], F_SETFD, FD_CLOEXEC) || fcntl(pipe_ends[i], F_SETFL, O_NONBLOCK)) {
            close(pipe_ends[0]); close(pipe_ends[1]); return -1;
        }
    }
    return 0;
}
static int spawn_actor(struct actor actors[2], int slot, const char *mode, int stage) {
    int in[2], out[2];
    if (make_pipe(in)) return -1;
    if (make_pipe(out)) { close(in[0]); close(in[1]); return -1; }
    pid_t pid = fork();
    if (pid == 0) {
        close(in[1]); close(out[0]);
        for (int i = 0; i < 2; i++) {
            if (actors[i].command >= 0) close(actors[i].command);
            if (actors[i].reply >= 0) close(actors[i].reply);
        }
        if (fcntl(in[0], F_SETFD, 0) || fcntl(out[1], F_SETFD, 0)) _exit(40);
        char a[24], b[24], c[24];
        snprintf(a, sizeof(a), "%d", in[0]); snprintf(b, sizeof(b), "%d", out[1]);
        snprintf(c, sizeof(c), "%d", stage);
        execl(executable, executable, mode, a, b, c, (char *)NULL);
        _exit(41);
    }
    close(in[0]); close(out[1]);
    if (pid < 0) { close(in[1]); close(out[0]); return -1; }
    actors[slot] = (struct actor){pid, in[1], out[0], 0, 0};
    return 0;
}
static int native_wait(struct actor *actor, int64_t deadline) {
    while (!actor->reaped) {
        int64_t now = now_ms();
        if (now < 0 || now >= deadline || interrupted) return 0;
        pid_t pid = waitpid(actor->pid, &actor->status, WNOHANG);
        if (pid == actor->pid) { actor->reaped = 1; waits++; return 1; }
        if (pid < 0 && errno == EINTR) continue;
        if (pid < 0) return -1; /* Lost custody is never successful cleanup. */
        struct timespec delay = {0, 1000000}; nanosleep(&delay, NULL);
    }
    return 1;
}
static int settled(struct actor actors[2]) {
    int clean = 1;
    for (int i = 0; i < 2; i++) {
        if (actors[i].command >= 0) { close(actors[i].command); actors[i].command = -1; }
    }
    for (int i = 0; i < 2; i++) {
        struct actor *actor = &actors[i];
        if (actor->pid > 0 && !actor->reaped) {
            int64_t now = now_ms();
            int result = native_wait(actor, now < 0 ? 0 : now + 1000);
            if (result == 0) {
                rescues++; clean = 0;
                /* Reserved direct child, not metadata-derived nonchild authority. */
                if (kill(actor->pid, SIGKILL) && errno != ESRCH) clean = 0;
                pid_t pid;
                do pid = waitpid(actor->pid, &actor->status, 0); while (pid < 0 && errno == EINTR);
                if (pid == actor->pid) { actor->reaped = 1; waits++; }
            }
            if (!actor->reaped) clean = 0;
        }
        if (actor->reply >= 0) { close(actor->reply); actor->reply = -1; }
    }
    return clean;
}
static int exited_zero(const struct actor *actor) {
    return actor->reaped && WIFEXITED(actor->status) && WEXITSTATUS(actor->status) == 0;
}
static int reply_is(struct actor *actor, struct frame *message, uint32_t kind, int64_t deadline) {
    return !receive_frame(actor->reply, message, deadline) && message->kind == kind && !message->fault;
}
static int no_extra_frames(struct actor *actor) {
    struct frame message;
    return read(actor->reply, &message, sizeof(message)) == 0;
}
static void init_actors(struct actor actors[2]) {
    for (int i = 0; i < 2; i++) actors[i] = (struct actor){0, -1, -1, 0, 0};
}

static int native_case(int index) {
    struct actor actors[2]; init_actors(actors);
    struct actor *t = &actors[0], *o = &actors[1];
    struct frame message; audit_token_t old, current;
    const char *failure = NULL;
    int initial_waits = waits, initial_rescues = rescues;
    int64_t start = now_ms();
    if (start < 0) return -1;
    int64_t deadline = start + 8000;
#define NEED(test, phase) do { if (!(test)) { failure = phase; goto cleanup; } } while (0)
    NEED(!spawn_actor(actors, 0, "--target", 0), "spawn_target");
    NEED(reply_is(t, &message, 'R', deadline) && message.code == 0 &&
        message.token.val[5] == (uint32_t)t->pid, "target_ready");
    old = message.token;
    NEED(!spawn_actor(actors, 1, "--observer", index), "spawn_observer");
    NEED(!command(o, 'B', &old) && reply_is(o, &message, 'B', deadline) && message.code == 1,
        "bound_registration_and_nonparent");
    uint64_t uniqueid = message.uniqueid;
    NEED(!command(t, 'E', NULL) && reply_is(t, &message, 'R', deadline) && message.code == 1 &&
        message.token.val[5] == (uint32_t)t->pid, "target_exec");
    current = message.token;
    NEED(!command(o, 'E', &current) && reply_is(o, &message, 'E', deadline) &&
        message.uniqueid == uniqueid, "stable_identity_and_old_token_rejection");
    NEED(!command(t, 'P', NULL) && reply_is(t, &message, 'P', deadline) && message.count == 0,
        "old_token_not_terminal_or_delivered");
    NEED(!command(o, 'S', NULL) && reply_is(o, &message, 'S', deadline), "refreshed_signal");
    NEED(reply_is(t, &message, 'S', deadline) && message.count == 1, "signal_ack");
    NEED(!command(t, 'X', NULL) && reply_is(t, &message, 'F', deadline) && message.count == 1,
        "target_finish");
    NEED(native_wait(t, deadline) == 1 && exited_zero(t) && no_extra_frames(t), "target_actual_reap");
    NEED(!command(o, 'R', NULL) && reply_is(o, &message, 'R', deadline) &&
        message.code == (cases[index].fault == NONE), "post_reap_terminal_decision");
    NEED(native_wait(o, deadline) == 1 && exited_zero(o) && no_extra_frames(o), "observer_actual_wait");
cleanup:
    if (!settled(actors) && !failure) failure = "cleanup";
    if (failure || waits - initial_waits != 2 || rescues != initial_rescues) {
        fprintf(stderr, "native_case=%s failed_phase=%s waits=%d rescues=%d\n", cases[index].name,
            failure ? failure : "wait_counts", waits - initial_waits, rescues - initial_rescues);
        return -1;
    }
    printf("native_case=%s metadata_exec=observed nonparent=ECHILD token_refresh=observed "
        "terminal=%s controller_waits=2 rescues=0\n", cases[index].name,
        cases[index].fault == NONE ? "bound_NOTE_EXIT_after_reap" : "rejected_closed_queue");
    return 0;
}

/* These are source-predicate controls, not native errors or actor observations. */
static int certificate(size_t capacity, size_t returned, size_t confirmed, int mapped) {
    return mapped && confirmed <= SIZE_MAX - 20 && returned < capacity && returned < confirmed + 20;
}
static int same_identity(uint64_t before, int size, const struct qsh_process_identity *after) {
    return before && size == (int)sizeof(*after) && before == after->uniqueid;
}
static int synthetic_controls(void) {
    int rows = 0; char cookie;
    for (size_t i = 1; i < sizeof(cases) / sizeof(cases[0]); i++) {
        enum fault fault = cases[i].fault;
        if (fault == CLOSED_QUEUE) continue;
        struct qsh_process_identity before = {0}, after = {0};
        before.uniqueid = after.uniqueid = 11;
        struct kevent event;
        EV_SET(&event, 1234, EVFILT_PROC, EV_ERROR, NOTE_EXIT, 0, &cookie);
        int size = sizeof(after), error = 0, count = 1, accepted;
        if (fault == REGISTRATION) event.data = EACCES;
        if (fault == POST_SHORT) size--;
        if (fault == POST_DENIED) { size = 0; error = EACCES; }
        if (fault == POST_MISMATCH) after.uniqueid = 12;
        if (fault <= POST_MISMATCH) {
            accepted = binding_accepted(&before, &after, size, error, &event, 1234, &cookie);
        } else {
            event.flags = EV_EOF | EV_ONESHOT;
            if (fault == FOREIGN_COOKIE) event.udata = NULL;
            if (fault == EOF_ONLY) event.fflags = 0;
            if (fault == ZERO_EVENTS) count = 0;
            if (fault == EVENT_ERROR) event.flags |= EV_ERROR;
            if (fault == FOREIGN_IDENT) event.ident = 0;
            accepted = count == 1 && terminal_event(&event, 1234, &cookie);
        }
        if (accepted) { fprintf(stderr, "synthetic_refusal_failed=%s\n", cases[i].name); return -1; }
        rows++;
    }
    static const struct { size_t c, n, p; int mapped, expected; } arithmetic[] = {
        {100, 20, 2, 1, 1}, {20, 20, 2, 1, 0}, {100, 22, 2, 1, 0},
        {100, 20, 2, 0, 0}, {100, 20, SIZE_MAX, 1, 0}
    };
    for (size_t i = 0; i < sizeof(arithmetic) / sizeof(arithmetic[0]); i++) {
        if (certificate(arithmetic[i].c, arithmetic[i].n, arithmetic[i].p, arithmetic[i].mapped) !=
            arithmetic[i].expected) return -1;
    }
    struct qsh_process_identity after = {0}; after.uniqueid = 11;
    if (!same_identity(11, sizeof(after), &after) || same_identity(11, 0, &after) ||
        same_identity(12, sizeof(after), &after)) return -1;
    /* Losing one confirmation reduces P, but need not invalidate an inequality. */
    if (!certificate(100, 20, 1, 1)) return -1;
    printf("synthetic_refusal_rows=%d synthetic_arithmetic_rows=5 synthetic_confirmation_rows=4 "
        "native_permission_claim=no\n", rows);
    return rows == 9 ? 0 : -1;
}

enum { PID_CAPACITY = 4096 };
_Static_assert(PID_CAPACITY <= INT_MAX / sizeof(pid_t), "bounded signed-int wrapper bytes");
struct baseline { pid_t pid; uint64_t uniqueid; };
static int inventory(pid_t buffer[PID_CAPACITY], int *error) {
    errno = 0;
    int bytes = list_pids(PROC_ALL_PIDS, 0, buffer, PID_CAPACITY * sizeof(pid_t));
    *error = bytes <= 0 ? errno : 0;
    if (bytes <= 0 || bytes > (int)(PID_CAPACITY * sizeof(pid_t)) || bytes % sizeof(pid_t)) return -1;
    int count = bytes / (int)sizeof(pid_t);
    for (int i = 0; i < count; i++) {
        for (int j = 0; j < i; j++) if (buffer[i] == buffer[j]) return -1;
    }
    return count;
}
static void baseline_add(struct baseline values[PID_CAPACITY], size_t *count,
    pid_t pid, const struct qsh_process_identity *record) {
    if (pid <= 0 || !record->uniqueid || *count == PID_CAPACITY) return;
    for (size_t i = 0; i < *count; i++) if (values[i].uniqueid == record->uniqueid) return;
    values[(*count)++] = (struct baseline){pid, record->uniqueid};
}
static int witness_case(int disappearance) {
    struct actor actors[2]; init_actors(actors);
    struct actor *u = &actors[0];
    struct frame message;
    struct qsh_process_identity before, after;
    struct baseline baseline[PID_CAPACITY]; size_t baseline_count = 0, confirmed = 0;
    pid_t pids[PID_CAPACITY];
    const char *failure = NULL;
    int error, initial_waits = waits, initial_rescues = rescues;
    int64_t start = now_ms();
    if (start < 0) return -1;
    int64_t deadline = start + 8000;
    NEED(!spawn_actor(actors, 0, "--target", 0), "spawn_witness");
    NEED(reply_is(u, &message, 'R', deadline) && message.token.val[5] == (uint32_t)u->pid,
        "witness_ready");
    NEED(!metadata(u->pid, &before, &error), "witness_baseline");
    baseline_add(baseline, &baseline_count, u->pid, &before);
    /* Preliminary inventory seeds candidates only; it certifies nothing. */
    int preliminary_error, count = inventory(pids, &preliminary_error);
    for (int i = 0; i < count; i++) {
        if (!metadata(pids[i], &after, &error)) baseline_add(baseline, &baseline_count, pids[i], &after);
        int64_t observed = now_ms();
        NEED(observed >= 0 && observed < deadline, "baseline_deadline");
    }
    /* All baseline acquisitions FINISHED before this particular raw ALL call. */
    int list_error, returned = inventory(pids, &list_error);
    if (disappearance) {
        NEED(!command(u, 'X', NULL) && reply_is(u, &message, 'F', deadline) && message.count == 0,
            "witness_exit");
        NEED(native_wait(u, deadline) == 1 && exited_zero(u) && no_extra_frames(u), "witness_actual_reap");
    } else {
        NEED(!command(u, 'E', NULL) && reply_is(u, &message, 'R', deadline) && message.code == 1,
            "witness_exec");
        NEED(!metadata(u->pid, &after, &error) && after.uniqueid == before.uniqueid &&
            (uint32_t)after.idversion == message.token.val[7], "witness_exec_identity");
    }
    /* Every confirmation begins AFTER the raw call returns; no cross-call credit. */
    int witness_confirmed = 0;
    for (size_t i = 0; i < baseline_count; i++) {
        int valid = !metadata(baseline[i].pid, &after, &error) &&
            same_identity(baseline[i].uniqueid, sizeof(after), &after);
        confirmed += (size_t)valid;
        if (baseline[i].uniqueid == before.uniqueid) witness_confirmed = valid;
        int64_t observed = now_ms();
        NEED(observed >= 0 && observed < deadline, "confirmation_deadline");
    }
    NEED(witness_confirmed == !disappearance, "witness_confirmation");
    if (!disappearance) {
        NEED(!command(u, 'X', NULL) && reply_is(u, &message, 'F', deadline) && message.count == 0,
            "witness_finish");
        NEED(native_wait(u, deadline) == 1 && exited_zero(u) && no_extra_frames(u), "witness_wait");
    }
    /* No actual build has an approved capacity-critical source mapping yet.
     * In particular, a 10063 prefix alone must NEVER enable the +20 premise. */
    printf("native_witness=%s C=%d N=%d P=%zu baseline=%zu witness_confirmed=%d "
        "preliminary_error=%d list_error=%d arithmetic_observation=%s capacity_qualification=unqualified "
        "source_mapping=unmapped outsider_claim=no\n", disappearance ? "actually_reaped" : "controlled_exec",
        PID_CAPACITY, returned, confirmed, baseline_count, witness_confirmed,
        preliminary_error, list_error,
        returned > 0 && certificate(PID_CAPACITY, (size_t)returned, confirmed, 1) ? "satisfied" : "not_satisfied");
cleanup:
    if (!settled(actors) && !failure) failure = "cleanup";
    if (failure || waits - initial_waits != 1 || rescues != initial_rescues) {
        fprintf(stderr, "witness_failed=%s phase=%s waits=%d rescues=%d\n",
            disappearance ? "reap" : "exec", failure ? failure : "wait_counts",
            waits - initial_waits, rescues - initial_rescues);
        return -1;
    }
    return 0;
}

static int parse_number(const char *text, int *number) {
    char *end; errno = 0;
    long value = strtol(text, &end, 10);
    if (errno || !*text || *end || value < 0 || value > INT_MAX) return -1;
    *number = (int)value;
    return 0;
}
int main(int argc, char **argv) {
    executable = argv[0];
    if (argc == 5) {
        int input, output, stage;
        if (parse_number(argv[2], &input) || parse_number(argv[3], &output) ||
            parse_number(argv[4], &stage)) return 50;
        if (!strcmp(argv[1], "--target") && stage <= 1) return target(input, output, stage);
        if (!strcmp(argv[1], "--observer") && (stage == 0 || stage == 5)) return observer(input, output, stage);
        return 51;
    }
    if (argc != 1) return 52;
    puts("custody_qualification=unqualified");
    printf("metadata_layout=56/16/32 sdk_private_header=%d\n", QSH_PRIVATE_HEADER_EXPOSED);
    puts("capacity_source_mapping=unmapped capacity_qualification=unqualified");
    if (load_wrappers()) { puts("owned_primitives=unsupported_wrappers"); return 0; }
    struct qsh_process_identity self; int error;
    audit_token_t token;
    if (metadata(getpid(), &self, &error) || own_token(&token) ||
        token.val[5] != (uint32_t)getpid() || token.val[7] != (uint32_t)self.idversion) {
        printf("owned_primitives=unsupported_metadata errno=%d\n", error);
        dlclose(library); return 0;
    }
    struct sigaction action = {0}; sigemptyset(&action.sa_mask);
    action.sa_handler = stop_requested;
    if (sigaction(SIGTERM, &action, NULL) || sigaction(SIGINT, &action, NULL)) return 1;
    action.sa_handler = SIG_IGN;
    if (sigaction(SIGPIPE, &action, NULL)) return 1;
    action.sa_handler = SIG_DFL; /* Direct children must not be auto-reaped. */
    if (sigaction(SIGCHLD, &action, NULL)) return 1;
    int failed = synthetic_controls() || native_case(0) || native_case(5) || witness_case(0) || witness_case(1);
    int closed = dlclose(library);
    if (failed || closed || waits != 6 || rescues) {
        fprintf(stderr, "primitive_run=failed exact_waits=%d rescues=%d\n", waits, rescues);
        return 1;
    }
    printf("primitive_run=observed native_cases=2 witness_cases=2 exact_waits=%d rescues=0 "
        "capacity_qualification=unqualified custody_qualification=unqualified\n", waits);
    return 0;
}
