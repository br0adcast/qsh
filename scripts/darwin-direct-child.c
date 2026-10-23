/* One reserved direct child only; this does not qualify session custody. */
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
#include <string.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

typedef int (*signal_token_fn)(audit_token_t *, int);
_Static_assert(__builtin_types_compatible_p(
    __typeof__(&proc_signal_with_audittoken), signal_token_fn),
    "selected SDK audit-token signal signature differs");

struct frame {
    uint32_t kind;
    uint32_t count;
    uint32_t fault;
    audit_token_t token;
};
_Static_assert(sizeof(struct frame) <= PIPE_BUF, "atomic pipe frame required");
static volatile sig_atomic_t delivered;
static volatile sig_atomic_t write_fault;
static volatile sig_atomic_t interrupted;
static int acknowledgment = -1;

static void signal_ack(int signal_number) {
    int saved_errno = errno;
    (void)signal_number;
    struct frame message = {0};
    if (delivered < 2) delivered++;
    else write_fault = 1;
    message.kind = 'S';
    message.count = (uint32_t)delivered;
    if (write(acknowledgment, &message, sizeof(message)) != (ssize_t)sizeof(message))
        write_fault = 1;
    errno = saved_errno;
}

static void parent_interrupted(int signal_number) {
    (void)signal_number;
    interrupted = 1;
}

static int64_t milliseconds(void) {
    struct timespec now;
    if (clock_gettime(CLOCK_MONOTONIC, &now)) return -1;
    return (int64_t)now.tv_sec * 1000 + now.tv_nsec / 1000000;
}

static int private_pipe(int ends[2]) {
    if (pipe(ends)) return -1;
    for (int i = 0; i < 2; i++) {
        if (fcntl(ends[i], F_SETFD, FD_CLOEXEC) ||
            fcntl(ends[i], F_SETFL, O_NONBLOCK)) {
            close(ends[0]);
            close(ends[1]);
            return -1;
        }
    }
    return 0;
}

/* Every retry uses the same absolute deadline. Partial/extra frames fail. */
static int receive_frame(int fd, struct frame *message, int64_t deadline) {
    for (;;) {
        int64_t now = milliseconds();
        if (interrupted || now < 0 || now >= deadline) return -1;
        struct pollfd ready = {fd, POLLIN, 0};
        int result = poll(&ready, 1, (int)(deadline - now));
        if (result < 0 && errno == EINTR) continue;
        if (result <= 0) return -1;
        ssize_t size = read(fd, message, sizeof(*message));
        if (size < 0 && (errno == EINTR || errno == EAGAIN)) continue;
        return size == (ssize_t)sizeof(*message) ? 0 : -1;
    }
}

static int send_command(int fd, char command) {
    ssize_t size;
    do size = write(fd, &command, 1); while (size < 0 && errno == EINTR && !interrupted);
    return size == 1 ? 0 : -1;
}

static int send_frame(int fd, struct frame *message) {
    message->count = (uint32_t)delivered;
    message->fault = (uint32_t)write_fault;
    return write(fd, message, sizeof(*message)) == (ssize_t)sizeof(*message) ? 0 : -1;
}

static void child_main(int commands, int replies) {
    acknowledgment = replies;
    /* Parent loss cannot leave this voluntary fixture waiting indefinitely. */
    struct sigaction alarm_action = {0}, user_action = {0};
    alarm_action.sa_handler = SIG_DFL;
    sigemptyset(&alarm_action.sa_mask);
    sigset_t unblocked;
    sigemptyset(&unblocked);
    sigaddset(&unblocked, SIGALRM);
    sigaddset(&unblocked, SIGUSR1);
    if (sigaction(SIGALRM, &alarm_action, NULL) ||
        sigprocmask(SIG_UNBLOCK, &unblocked, NULL)) _exit(10);
    alarm(10);
    user_action.sa_handler = signal_ack;
    sigemptyset(&user_action.sa_mask);
    if (sigaction(SIGUSR1, &user_action, NULL)) _exit(11);
    struct frame message = {0};
    mach_msg_type_number_t count = TASK_AUDIT_TOKEN_COUNT;
    if (task_info(mach_task_self(), TASK_AUDIT_TOKEN,
            (task_info_t)&message.token, &count) != KERN_SUCCESS ||
        count != TASK_AUDIT_TOKEN_COUNT) _exit(12);
    message.kind = 'R';
    if (send_frame(replies, &message)) _exit(13);
    for (;;) {
        struct pollfd ready = {commands, POLLIN, 0};
        int result = poll(&ready, 1, -1);
        if (result < 0 && errno == EINTR) continue;
        if (result <= 0) _exit(14);
        char command;
        ssize_t size = read(commands, &command, 1);
        if (size < 0 && (errno == EINTR || errno == EAGAIN)) continue;
        if (size == 0) _exit(15);
        if (size != 1 || (command != 'P' && command != 'X')) _exit(16);
        message.kind = command == 'P' ? 'P' : 'F';
        if (send_frame(replies, &message)) _exit(17);
        if (command == 'X') _exit(write_fault ? 18 : 0);
    }
}

/* 1 means consuming wait, 0 observation expiry, -1 lost/error custody. */
static int observe_wait(pid_t child, int *status, int64_t deadline) {
    for (;;) {
        int64_t now = milliseconds();
        if (now < 0 || now >= deadline || interrupted) return 0;
        pid_t waited = waitpid(child, status, WNOHANG);
        if (waited == child) return 1;
        if (waited < 0 && errno == EINTR) continue;
        if (waited < 0) return -1;
        struct timespec delay = {0, 1000000};
        nanosleep(&delay, NULL);
    }
}

int main(void) {
    puts("sdk_signature=matched");
    puts("custody_qualification=unqualified");
    void *library = dlopen("/usr/lib/libproc.dylib", RTLD_LAZY | RTLD_LOCAL);
    if (!library) { puts("direct_child_mechanism=unsupported_library"); return 0; }
    dlerror();
    signal_token_fn signal_token = (signal_token_fn)dlsym(library, "proc_signal_with_audittoken");
    if (dlerror() || !signal_token) {
        puts("direct_child_mechanism=unsupported_symbol");
        return dlclose(library) ? 1 : 0;
    }
    struct sigaction stop_action = {0}, pipe_action = {0}, child_action = {0};
    stop_action.sa_handler = parent_interrupted;
    sigemptyset(&stop_action.sa_mask);
    pipe_action.sa_handler = SIG_IGN;
    sigemptyset(&pipe_action.sa_mask);
    child_action.sa_handler = SIG_DFL;
    sigemptyset(&child_action.sa_mask);
    if (sigaction(SIGTERM, &stop_action, NULL) || sigaction(SIGINT, &stop_action, NULL) ||
        sigaction(SIGPIPE, &pipe_action, NULL) || sigaction(SIGCHLD, &child_action, NULL)) return 1;
    int commands[2], replies[2];
    if (private_pipe(commands)) return 1;
    if (private_pipe(replies)) { close(commands[0]); close(commands[1]); return 1; }
    pid_t child = fork();
    if (child == 0) {
        close(commands[1]); close(replies[0]);
        child_main(commands[0], replies[1]);
        _exit(19);
    }
    close(commands[0]); close(replies[1]);
    if (child < 0) { close(commands[1]); close(replies[0]); return 1; }
    /* Every post-fork parent failure goes through this exact child's wait. */
    const char *failure = NULL;
    int reaped = 0, rescued = 0, status = 0;
    int64_t start = milliseconds();
    int64_t deadline = start + 5000;
    struct frame message;
#define REQUIRE(condition, phase) do { if (!(condition)) { failure = phase; goto settle; } } while (0)
    REQUIRE(start >= 0, "clock");
    REQUIRE(!receive_frame(replies[0], &message, deadline), "ready_frame");
    REQUIRE(message.kind == 'R' && message.count == 0 && message.fault == 0 &&
        message.token.val[5] == (uint32_t)child, "owned_token");
    audit_token_t correct = message.token;
    audit_token_t wrong = correct;
    wrong.val[7] ^= 1u;
    REQUIRE(signal_token(&wrong, SIGUSR1) == ESRCH, "wrong_version");
    REQUIRE(!send_command(commands[1], 'P'), "wrong_version_roundtrip_send");
    REQUIRE(!receive_frame(replies[0], &message, deadline) && message.kind == 'P' &&
        message.count == 0 && message.fault == 0, "wrong_version_roundtrip");
    REQUIRE(signal_token(&correct, SIGUSR1) == 0, "correct_signal");
    REQUIRE(!receive_frame(replies[0], &message, deadline) && message.kind == 'S' &&
        message.count == 1 && message.fault == 0, "correct_ack");
    REQUIRE(!send_command(commands[1], 'X'), "finish_send");
    REQUIRE(!receive_frame(replies[0], &message, deadline) && message.kind == 'F' &&
        message.count == 1 && message.fault == 0, "final_count");
    {
        int outcome = observe_wait(child, &status, deadline);
        reaped = outcome == 1;
        REQUIRE(reaped, "native_wait");
    }
    REQUIRE(WIFEXITED(status) && WEXITSTATUS(status) == 0, "native_exit");
    REQUIRE(read(replies[0], &message, sizeof(message)) == 0, "extra_ack_or_missing_eof");
settle:
    close(commands[1]);
    if (!reaped) {
        int64_t now = milliseconds();
        int outcome = observe_wait(child, &status, now < 0 ? 0 : now + 1000);
        reaped = outcome == 1;
        if (outcome == 0) {
            rescued = 1;
            /* The unreaped direct-child reservation prevents numeric PID reuse. */
            if (kill(child, SIGKILL) && errno != ESRCH) failure = failure ? failure : "rescue_signal";
            pid_t waited;
            do waited = waitpid(child, &status, 0); while (waited < 0 && errno == EINTR);
            reaped = waited == child;
        }
    }
    close(replies[0]);
    int closed = dlclose(library);
    if (failure || !reaped || rescued || closed) {
        fprintf(stderr, "direct_child_mechanism=failed phase=%s waited=%d rescue=%d\n",
            failure ? failure : "cleanup", reaped, rescued);
        return 1;
    }
    puts("wrong_version=ESRCH");
    puts("correct_signal=exactly_one_ack");
    puts("child_native_exit=0");
    puts("rescue_used=no");
    puts("direct_child_mechanism=qualified_only_for_this_control");
    return 0;
}
