#ifndef QSH_DARWIN_PROCESS_METADATA_H
#define QSH_DARWIN_PROCESS_METADATA_H
#include <stddef.h>
#include <stdint.h>

/* Exact LP64 compatibility layout from Apple's xnu-10063.141.1:
 * bsd/sys/proc_info_private.h, proc_uniqidentifierinfo and flavor 17.
 * https://github.com/apple-oss-distributions/xnu/blob/xnu-10063.141.1/bsd/sys/proc_info_private.h
 * This is a qualification fixture, not a stable public API declaration. */
struct qsh_process_identity {
    uint8_t uuid[16];
    uint64_t uniqueid;
    uint64_t parent_uniqueid;
    int32_t idversion;
    uint32_t reserved2;
    uint64_t reserved3;
    uint64_t reserved4;
};
enum { QSH_IDENTITY_FLAVOR = 17 };
_Static_assert(sizeof(void *) == 8, "LP64 qualification only");
_Static_assert(sizeof(struct qsh_process_identity) == 56, "identity record size");
_Static_assert(offsetof(struct qsh_process_identity, uniqueid) == 16, "uniqueid offset");
_Static_assert(offsetof(struct qsh_process_identity, idversion) == 32, "version offset");

#if __has_include(<sys/proc_info_private.h>)
#include <sys/proc_info_private.h>
_Static_assert(PROC_PIDUNIQIDENTIFIERINFO == QSH_IDENTITY_FLAVOR, "SDK flavor differs");
_Static_assert(sizeof(struct proc_uniqidentifierinfo) == sizeof(struct qsh_process_identity),
    "SDK private identity size differs");
_Static_assert(offsetof(struct proc_uniqidentifierinfo, p_uniqueid) == 16, "SDK uniqueid differs");
_Static_assert(offsetof(struct proc_uniqidentifierinfo, p_idversion) == 32, "SDK version differs");
#define QSH_PRIVATE_HEADER_EXPOSED 1
#else
#define QSH_PRIVATE_HEADER_EXPOSED 0
#endif
#endif
