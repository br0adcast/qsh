#ifndef QSH_DARWIN_SCOPE_H
#define QSH_DARWIN_SCOPE_H
#include <stdint.h>

/* Scalars only across the boundary; SDK structs remain inside native.c. */
struct qsh_scope_error { int32_t domain, code; };
struct qsh_scope_identity { int32_t pid; uint32_t version; uint64_t unique; };
struct qsh_scope_class { struct qsh_scope_identity identity; int32_t sid; uint32_t zombie; };
struct qsh_scope_token { uint32_t words[8]; };
struct qsh_scope_runtime { char release[64], version[512], build[64], machine[32]; };
int qsh_scope_modern_signal_available(void);
int qsh_scope_observation_prepare(struct qsh_scope_runtime *, struct qsh_scope_error *);
int qsh_scope_prepare(struct qsh_scope_runtime *, struct qsh_scope_error *);
int qsh_scope_identity(int32_t, struct qsh_scope_identity *, struct qsh_scope_error *);
int qsh_scope_classification_matches(struct qsh_scope_class, struct qsh_scope_class);
int qsh_scope_classify(int32_t, struct qsh_scope_class *, struct qsh_scope_error *);
int qsh_scope_all(int32_t *, uint32_t, uint32_t *, struct qsh_scope_error *);
int qsh_scope_bind(struct qsh_scope_identity, uint64_t, int32_t *, struct qsh_scope_identity *, struct qsh_scope_error *);
int qsh_scope_exit(int32_t, int32_t, uint64_t, uint32_t *, struct qsh_scope_error *);
int qsh_scope_token(struct qsh_scope_identity, int32_t, struct qsh_scope_token *, struct qsh_scope_error *);
int qsh_scope_signal(const struct qsh_scope_token *, int32_t, struct qsh_scope_error *);
int qsh_scope_leader(int32_t, uint32_t *, int32_t *, struct qsh_scope_error *);
int qsh_scope_keeper_prepare(struct qsh_scope_runtime *, struct qsh_scope_error *);
int qsh_scope_group(struct qsh_scope_identity, int32_t, int32_t *, struct qsh_scope_error *);
int qsh_scope_keeper_pre_exec(int32_t, int32_t, int32_t);
/* Read-only fixture queries; SDK structures never cross this boundary. */
struct qsh_scope_fixture_fd {
    int32_t fd; uint32_t type;
    uint64_t dev, rdev, ino;
    uint32_t mode, reserved;
};
int qsh_scope_fixture_fds(int32_t, struct qsh_scope_fixture_fd *, uint32_t, uint32_t *, struct qsh_scope_error *);
int qsh_scope_fixture_vnode(int32_t, int32_t, struct qsh_scope_fixture_fd *, struct qsh_scope_error *);
#endif
