// Darwin does not expose SO_ACCEPTCONN through getsockopt. The public libproc
// snapshot includes the kernel option bit; compile its layout from the SDK.
// https://github.com/apple-oss-distributions/xnu/blob/xnu-10063.141.1/bsd/kern/socket_info.c
// https://github.com/apple-oss-distributions/xnu/blob/xnu-10063.141.1/bsd/sys/proc_info.h
#include <errno.h>
#include <libproc.h>
#include <sys/proc_info.h>
#include <sys/socket.h>
#include <unistd.h>

// 1: Unix stream listener; 0: other socket; negative errno: query failure.
// This query does not accept, connect, listen, or change descriptor flags.
int qsh_handover_unix_listener_state(int fd) {
    struct socket_fdinfo info = {0};
    errno = 0;
    int size = proc_pidfdinfo(getpid(), fd, PROC_PIDFDSOCKETINFO,
                            &info, (int)sizeof(info));
    if (size != (int)sizeof(info)) {
        int error = size > 0 ? EMSGSIZE : (errno != 0 ? errno : EIO);
        return -error;
    }
    return info.psi.soi_family == AF_UNIX && info.psi.soi_type == SOCK_STREAM &&
           (info.psi.soi_options & SO_ACCEPTCONN) != 0;
}
