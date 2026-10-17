/*
 * A stand-in for libpam.so.0 as Linux-PAM 1.3.1 (Ubuntu 20.04, RHEL 8)
 * exports it -- for the loader only, never for a PAM transaction.
 *
 * What matters is the version script beside it (libpam.map): every symbol
 * here sits in the LIBPAM_1.0 node, and there is no LIBPAM_1.4 node, so
 * there is no pam_start_confdir. scripts/check-pam-linkage.sh builds this
 * and starts `qshd --version` against it: a qshd that needs anything
 * newer is refused by the dynamic loader before `main`, exactly as it
 * would be on such a machine.
 *
 * The list covers the calls `qshd/src/helper/pam.rs` makes. All of them are
 * LIBPAM_1.0 in Linux-PAM (check with `objdump -T` on a real libpam); a new
 * call qshd makes must be added here, to the same node, only if Linux-PAM
 * 1.3.1 exported it there. The script names any import missing here. The
 * bodies are never meant to run: each refuses (PAM_ABORT, 26).
 */
int pam_start(void) { return 26; }
int pam_end(void) { return 26; }
int pam_acct_mgmt(void) { return 26; }
int pam_open_session(void) { return 26; }
int pam_close_session(void) { return 26; }
int pam_setcred(void) { return 26; }
int pam_set_item(void) { return 26; }
void *pam_getenvlist(void) { return 0; }
const char *pam_strerror(void) { return "Linux-PAM 1.3.1 stand-in"; }
