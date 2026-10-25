//! Version reconciliation for `ensure` when a daemon is already alive: the
//! pure function [`reconcile`], no I/O. Ordering is
//! given by the build stamp (`build`); the checksum only answers the
//! question "same byte-for-byte executable or not" -- it does not order
//! versions on its own.

use crate::control::StatusResponse;

/// `ensure`'s decision when a daemon is already alive: replace it, leave it
/// as is, or leave it with a warning for the user.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReconcileAction {
    /// The same byte-for-byte executable -- the daemon is up to date, do nothing.
    UpToDate,
    /// The app is newer and there are no active connections -- kill the
    /// old daemon, bring up a new one.
    Replace,
    /// Don't touch the running daemon; the string is the reason, and goes
    /// into the `warning` field of the QSH-READY response.
    KeepOldWarn(String),
}

/// Whether a binary should replace a running daemon -- the one table both
/// replacement paths decide by: `transport-ensure` over SSH (`reconcile`)
/// and an offer over qsh (`crate::update::decide_offer`). `others` is how
/// many active sessions a replacement would cut off; each caller counts it
/// its own way (over qsh the offering session itself does not count).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Replacement {
    UpToDate,
    DaemonNewer,
    Busy { others: u64 },
    Replace,
}

pub fn replacement(
    offer_build: u64,
    offer_checksum: &str,
    daemon_build: u64,
    daemon_checksum: &str,
    others: u64,
) -> Replacement {
    if offer_checksum == daemon_checksum {
        return Replacement::UpToDate;
    }
    if offer_build < daemon_build {
        return Replacement::DaemonNewer;
    }
    // `>=`: a tied stamp with different bytes still replaces when idle, so
    // a cached or stale stamp cannot wedge an update.
    if others == 0 {
        Replacement::Replace
    } else {
        Replacement::Busy { others }
    }
}

/// The version reconciliation decision for `ensure` when a daemon is
/// already alive. `ensure_build`/`ensure_checksum` are the build stamp and
/// checksum of the freshly uploaded executable (that's us), `daemon` is the
/// `STATUS` response of the running daemon. Ordering is given by the build
/// stamp (`build`); the checksum only answers the question "same
/// executable or not".
pub fn reconcile(
    ensure_build: u64,
    ensure_checksum: &str,
    daemon: &StatusResponse,
) -> ReconcileAction {
    match replacement(
        ensure_build,
        ensure_checksum,
        daemon.build,
        &daemon.checksum,
        daemon.total_connections,
    ) {
        // A newer daemon serving an older app is fine: reuse, no warning.
        Replacement::UpToDate | Replacement::DaemonNewer => ReconcileAction::UpToDate,
        Replacement::Replace => ReconcileAction::Replace,
        Replacement::Busy { others } => ReconcileAction::KeepOldWarn(format!(
            "the daemon's version differs from the app's, but it has active sessions \
             connected ({others}) -- not replacing"
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::control::StatusResponse;

    fn daemon(build: u64, checksum: &str, conns: u64) -> StatusResponse {
        StatusResponse {
            logging_warning: None,
            cleanup: None,
            version: "0.1.0".into(),
            build,
            checksum: checksum.into(),
            ports: vec![],
            total_connections: conns,
            pid: 0,
        }
    }

    #[test]
    fn up_to_date_when_checksum_matches() {
        assert_eq!(
            reconcile(10, "aa", &daemon(9, "aa", 5)),
            ReconcileAction::UpToDate
        );
    }

    #[test]
    fn reuse_when_app_is_older_than_daemon() {
        // Different bytes, but the running daemon is NEWER -- reuse it as is,
        // no warning, no downgrade.
        assert_eq!(
            reconcile(8, "bb", &daemon(9, "aa", 0)),
            ReconcileAction::UpToDate
        );
    }

    #[test]
    fn replaces_when_newer_and_no_active_sessions() {
        assert_eq!(
            reconcile(10, "bb", &daemon(9, "aa", 0)),
            ReconcileAction::Replace
        );
    }

    #[test]
    fn replaces_on_equal_build_different_bytes_and_idle() {
        // The exact bug: cached build stamp ties, checksums differ, nobody
        // active -> must still replace.
        assert_eq!(
            reconcile(9, "bb", &daemon(9, "aa", 0)),
            ReconcileAction::Replace
        );
    }

    #[test]
    fn keeps_old_when_newer_but_others_are_active() {
        assert!(matches!(
            reconcile(10, "bb", &daemon(9, "aa", 2)),
            ReconcileAction::KeepOldWarn(_)
        ));
    }

    #[test]
    fn keeps_old_on_equal_build_different_bytes_when_active() {
        assert!(matches!(
            reconcile(9, "bb", &daemon(9, "aa", 1)),
            ReconcileAction::KeepOldWarn(_)
        ));
    }

    #[test]
    fn replacement_is_up_to_date_on_equal_checksums_whatever_the_builds() {
        assert_eq!(replacement(1, "aa", 9, "aa", 3), Replacement::UpToDate);
    }

    #[test]
    fn replacement_never_downgrades() {
        assert_eq!(replacement(8, "bb", 9, "aa", 0), Replacement::DaemonNewer);
    }

    #[test]
    fn replacement_replaces_when_nobody_else_is_there() {
        assert_eq!(replacement(10, "bb", 9, "aa", 0), Replacement::Replace);
        assert_eq!(
            replacement(9, "bb", 9, "aa", 0),
            Replacement::Replace,
            "a tied stamp with different bytes still replaces"
        );
    }

    #[test]
    fn replacement_is_busy_while_others_are_active() {
        assert_eq!(
            replacement(10, "bb", 9, "aa", 2),
            Replacement::Busy { others: 2 }
        );
    }
}
