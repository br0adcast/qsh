//! Interactive foreground updates of an older personal `qshd` over `qsh`
//! (`CONTROL_STREAM` + `UPDATE_STREAM`), with an explicit SSH compatibility
//! fallback for older daemons that predate reporting their OS in `About`.

use std::sync::mpsc::Receiver;
use std::sync::Arc;
use std::time::{Duration, Instant};

use bringup::{
    BringUpObserver, BringUpProgress, BringUpStage, DaemonImage, ImageError, ImageRequest,
    ImageSource, InstallTiming, Platform, ServerOs,
};
use transport::channel::{
    decode_server, encode_client, About, ClientRecord, DaemonMode, RejectCode, ServerRecord,
    UpdateAnswer, UpdateOffer, UpdateResult, CONTROL_STREAM, UPDATE_STREAM,
};
use transport::shell_frame::RecordDeframer;
use transport::LinkState;

use crate::connect::Attempt;
use crate::install_ui::InstallProgress;
use crate::prompt::Tty;
use crate::session::UiEvent;
use crate::{identity, log, report};

/// How long to wait for `ServerRecord::About` after sending `AboutRequest`.
const ABOUT_TIMEOUT: Duration = Duration::from_secs(2);
/// How long to wait for `ServerRecord::UpdateAnswer` after sending `UpdateOffer`.
const ANSWER_TIMEOUT: Duration = Duration::from_secs(10);
/// How long to wait for `ServerRecord::UpdateResult` after uploading all bytes.
const RESULT_TIMEOUT: Duration = Duration::from_secs(60);
/// Upload chunk size on `UPDATE_STREAM`, matching `qshd` tests and `WRITE_CHUNK`.
const UPLOAD_CHUNK_BYTES: usize = 64 * 1024;
/// Bounded wait per `UPDATE_STREAM` chunk for flow-control backpressure.
const CHUNK_SEND_TIMEOUT: Duration = Duration::from_secs(30);

#[cfg(all(test, target_os = "linux"))]
static TEST_CLIENT_VERSION: std::sync::Mutex<Option<String>> = std::sync::Mutex::new(None);
#[cfg(all(test, target_os = "linux"))]
static TEST_CLIENT_BUILD: std::sync::Mutex<Option<u64>> = std::sync::Mutex::new(None);

#[cfg(all(test, target_os = "linux"))]
pub(crate) fn set_test_release_identity(version: Option<String>, build: Option<u64>) {
    *TEST_CLIENT_VERSION
        .lock()
        .unwrap_or_else(|e| e.into_inner()) = version;
    *TEST_CLIENT_BUILD.lock().unwrap_or_else(|e| e.into_inner()) = build;
}

/// The client release version offered when checking whether a connected `qshd`
/// is older.
pub(crate) fn client_version() -> String {
    #[cfg(all(test, target_os = "linux"))]
    if let Some(version) = TEST_CLIENT_VERSION
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .clone()
    {
        return version;
    }
    env!("CARGO_PKG_VERSION").to_string()
}

/// The commit-epoch build stamp paired with [`client_version`].
fn client_build() -> u64 {
    #[cfg(all(test, target_os = "linux"))]
    if let Some(build) = *TEST_CLIENT_BUILD.lock().unwrap_or_else(|e| e.into_inner()) {
        return build;
    }
    env!("QSH_BUILD").parse::<u64>().unwrap_or(0)
}

/// Whether `version` is a release or a prerelease spelled like release tags:
/// `alpha.N`, `beta.N`, or `rc.N` (matching `bringup::locate::release_spelled`).
fn release_spelled(version: &semver::Version) -> bool {
    if version.pre.is_empty() {
        return true;
    }
    let mut identifiers = version.pre.as_str().split('.');
    matches!(
        (identifiers.next(), identifiers.next(), identifiers.next()),
        (Some("alpha" | "beta" | "rc"), Some(number), None)
            if !number.is_empty() && number.bytes().all(|byte| byte.is_ascii_digit())
    )
}

/// Whether an authenticated `server_core` version is older than `client_core`
/// and eligible for a daemon update offer.
///
/// Matches `bringup::locate::older_than_bundled`: equal versions (ignoring
/// SemVer build metadata) are never offered; release-spelled prereleases follow
/// SemVer precedence; non-release-spelled server prereleases (such as the
/// withdrawn `0.6.0-rc1`) count as older than any client with the same or
/// higher `major.minor.patch`.
pub(crate) fn should_offer_daemon_update(server_core: &str, client_core: &str) -> bool {
    let Ok(mut server) = semver::Version::parse(server_core) else {
        return false;
    };
    let Ok(mut client) = semver::Version::parse(client_core) else {
        return false;
    };
    server.build = semver::BuildMetadata::EMPTY;
    client.build = semver::BuildMetadata::EMPTY;
    if server == client {
        return false;
    }
    let core = |v: &semver::Version| (v.major, v.minor, v.patch);
    if release_spelled(&server) {
        server < client
    } else {
        core(&server) <= core(&client)
    }
}

/// Outcome of the pre-shell daemon update check on a direct foreground login.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum DaemonUpdateOutcome {
    /// Continue with the already-authenticated direct connection (open shell).
    ContinueDirect,
    /// The daemon accepted the update over `qsh` and is restarting/swapping
    /// its frontend: close this empty connection and reconnect directly.
    ReconnectDirect,
    /// The running daemon predates reporting its OS in `About` and the user
    /// explicitly approved updating it via the SSH compatibility path.
    FallbackToSsh,
    /// Interrupted by Ctrl-C / termination signal.
    Cancelled,
}

pub(crate) struct UpdateContext<'a> {
    pub login: &'a str,
    pub host: &'a str,
    pub server_version: &'a str,
    pub has_ssh_route: bool,
    pub tty: &'a Tty,
    pub images: Arc<dyn ImageSource>,
    pub cancel: &'a knock::Cancel,
    pub interrupted: &'a dyn Fn() -> bool,
    pub say: &'a dyn Fn(&str),
}

/// Inspect an older directly-connected `qshd` and, with explicit user consent,
/// update it over `qsh` (or hand off to the legacy SSH path when `About.os` is
/// absent).
pub(crate) fn maybe_update(
    att: &Attempt,
    rx: &Receiver<UiEvent>,
    ctx: &UpdateContext<'_>,
) -> DaemonUpdateOutcome {
    let target_version = client_version();
    if !should_offer_daemon_update(ctx.server_version, &target_version) {
        return DaemonUpdateOutcome::ContinueDirect;
    }

    let mut deframer = RecordDeframer::new();
    let about = match query_about(att, rx, &mut deframer, ABOUT_TIMEOUT, ctx.interrupted) {
        AboutReply::About(about) => Some(about),
        AboutReply::Unavailable => None,
        AboutReply::Cancelled => return DaemonUpdateOutcome::Cancelled,
    };

    match about {
        Some(about) if about.mode == DaemonMode::Managed => {
            log::log("running qshd is managed; skipping personal daemon update");
            DaemonUpdateOutcome::ContinueDirect
        }
        Some(about) if about.os.is_some() => {
            let os = about.os.as_deref().expect("checked above");
            run_over_qsh(att, rx, &mut deframer, &about, os, &target_version, ctx)
        }
        Some(_) | None => run_legacy_ssh_fallback(&target_version, ctx),
    }
}

fn run_over_qsh(
    att: &Attempt,
    rx: &Receiver<UiEvent>,
    deframer: &mut RecordDeframer,
    about: &About,
    os: &str,
    target_version: &str,
    ctx: &UpdateContext<'_>,
) -> DaemonUpdateOutcome {
    let platform = match Platform::from_rust_consts(os, &about.arch) {
        Ok(platform) => platform,
        Err(error) => {
            log::log(&format!(
                "running qshd platform {os}/{} is unsupported for over-qsh update: {error}",
                about.arch
            ));
            return DaemonUpdateOutcome::ContinueDirect;
        }
    };
    let request = match ImageRequest::new(platform, target_version) {
        Ok(request) => request,
        Err(error) => {
            log::log(&format!(
                "client version {target_version} cannot be requested as a daemon image: {error}"
            ));
            return DaemonUpdateOutcome::ContinueDirect;
        }
    };

    let build = client_build();
    if build != 0 && about.build >= build {
        log::log(&format!(
            "running qshd build {} is already at or newer than client build {}; skipping update",
            about.build, build
        ));
        return DaemonUpdateOutcome::ContinueDirect;
    }

    let question = over_qsh_question(
        ctx.login,
        ctx.host,
        ctx.server_version,
        target_version,
        platform,
    );
    match ctx.tty.confirm_install(&question, ctx.cancel) {
        Ok(true) => {}
        Ok(false) => {
            log::log("user declined over-qsh daemon update");
            return DaemonUpdateOutcome::ContinueDirect;
        }
        Err(_) => return DaemonUpdateOutcome::Cancelled,
    }

    let progress = InstallProgress::new(false);
    let image = match ctx
        .images
        .load(&request, &InstallTiming::default(), ctx.cancel, &progress)
    {
        Ok(image) => {
            drop(progress);
            image
        }
        Err(ImageError::Cancelled) => return DaemonUpdateOutcome::Cancelled,
        Err(error) => {
            drop(progress);
            (ctx.say)(&format!(
                "qsh: could not fetch qshd {target_version} ({}); continuing with qshd {}",
                report::printable(&error.to_string()),
                report::printable(ctx.server_version),
            ));
            return DaemonUpdateOutcome::ContinueDirect;
        }
    };

    let mut offer = UpdateOffer {
        build,
        checksum: image.sha256,
        arch: about.arch.clone(),
        size: image.size,
        prefer_frontend_upgrade: true,
        allow_frontend_disrupt: false,
    };

    loop {
        let answer =
            match send_offer_and_wait(att, rx, deframer, &offer, ANSWER_TIMEOUT, ctx.interrupted) {
                Ok(answer) => answer,
                Err(ControlWaitError::Cancelled) => return DaemonUpdateOutcome::Cancelled,
                Err(ControlWaitError::Failed(why)) => {
                    (ctx.say)(&format!(
                        "qsh: qshd update did not start ({why}); continuing with qshd {}",
                        report::printable(ctx.server_version),
                    ));
                    return DaemonUpdateOutcome::ContinueDirect;
                }
            };

        match answer {
            UpdateAnswer::Accept => break,
            UpdateAnswer::Busy { others } => {
                if platform.os == ServerOs::Linux && !offer.allow_frontend_disrupt {
                    let question = busy_disrupt_question(ctx.host, others);
                    match ctx.tty.confirm_cancellable(&question, ctx.cancel) {
                        Ok(true) => {
                            offer.allow_frontend_disrupt = true;
                            continue;
                        }
                        Ok(false) => {
                            (ctx.say)(&format!(
                                "qsh: keeping the running qshd {}",
                                report::printable(ctx.server_version),
                            ));
                            return DaemonUpdateOutcome::ContinueDirect;
                        }
                        Err(_) => return DaemonUpdateOutcome::Cancelled,
                    }
                }
                (ctx.say)(&format!(
                    "qsh: qshd on {} has {others} other active client(s); continuing with qshd {}",
                    identity::show(ctx.host),
                    report::printable(ctx.server_version),
                ));
                return DaemonUpdateOutcome::ContinueDirect;
            }
            UpdateAnswer::UpToDate => {
                log::log("daemon reported it is already up to date");
                return DaemonUpdateOutcome::ContinueDirect;
            }
            UpdateAnswer::DaemonNewer => {
                (ctx.say)(&format!(
                    "qsh: running qshd has a newer build; continuing with qshd {}",
                    report::printable(ctx.server_version),
                ));
                return DaemonUpdateOutcome::ContinueDirect;
            }
            UpdateAnswer::Managed => {
                log::log("daemon reported Managed on offer");
                return DaemonUpdateOutcome::ContinueDirect;
            }
            other => {
                (ctx.say)(&format!(
                    "qsh: qshd refused the update ({}); continuing with qshd {}",
                    answer_reason(&other),
                    report::printable(ctx.server_version),
                ));
                return DaemonUpdateOutcome::ContinueDirect;
            }
        }
    }

    let upload_progress = InstallProgress::new(false);
    let result = upload_and_wait(att, rx, deframer, &image, &upload_progress, ctx.interrupted);
    drop(upload_progress);

    match result {
        Ok(UpdateResult::Restarting) => {
            (ctx.say)(&format!(
                "qsh: updated qshd on {} to {target_version}; reconnecting...",
                identity::show(ctx.host),
            ));
            DaemonUpdateOutcome::ReconnectDirect
        }
        Ok(UpdateResult::Busy { others }) => {
            (ctx.say)(&format!(
                "qsh: qshd on {} became busy ({others} other active client(s)); continuing with qshd {}",
                identity::show(ctx.host),
                report::printable(ctx.server_version),
            ));
            DaemonUpdateOutcome::ContinueDirect
        }
        Ok(UpdateResult::Rejected { code, detail }) => {
            let why = if detail.is_empty() {
                reject_reason(code).to_string()
            } else {
                report::printable(&detail)
            };
            (ctx.say)(&format!(
                "qsh: qshd update was not applied ({why}); continuing with qshd {}",
                report::printable(ctx.server_version),
            ));
            DaemonUpdateOutcome::ContinueDirect
        }
        Ok(UpdateResult::Unknown(code)) => {
            (ctx.say)(&format!(
                "qsh: qshd returned an unrecognized update status ({code}); continuing with qshd {}",
                report::printable(ctx.server_version),
            ));
            DaemonUpdateOutcome::ContinueDirect
        }
        Err(ControlWaitError::Cancelled) => DaemonUpdateOutcome::Cancelled,
        Err(ControlWaitError::Failed(why)) => {
            (ctx.say)(&format!(
                "qsh: qshd update did not complete ({why}); continuing with qshd {}",
                report::printable(ctx.server_version),
            ));
            DaemonUpdateOutcome::ContinueDirect
        }
    }
}

fn run_legacy_ssh_fallback(target_version: &str, ctx: &UpdateContext<'_>) -> DaemonUpdateOutcome {
    if !ctx.has_ssh_route {
        log::log(&format!(
            "running qshd {} predates over-qsh updates and no SSH route is configured; \
             continuing with compatible direct session",
            ctx.server_version
        ));
        return DaemonUpdateOutcome::ContinueDirect;
    }
    let question = legacy_ssh_question(ctx.login, ctx.host, ctx.server_version, target_version);
    match ctx.tty.confirm_install(&question, ctx.cancel) {
        Ok(true) => DaemonUpdateOutcome::FallbackToSsh,
        Ok(false) => {
            log::log("user declined legacy SSH update fallback; continuing direct");
            DaemonUpdateOutcome::ContinueDirect
        }
        Err(_) => DaemonUpdateOutcome::Cancelled,
    }
}

fn over_qsh_question(
    login: &str,
    host: &str,
    server_version: &str,
    client_version: &str,
    platform: Platform,
) -> String {
    let user = identity::show(login);
    let host_shown = identity::show(host);
    let preserve = if platform.os == ServerOs::Linux {
        " Active sessions are preserved."
    } else {
        ""
    };
    identity::with_note(
        format!(
            "\nqshd {} on {user}@{host_shown} is older than this client's {client_version}.\n\n  \
             Version   {client_version}\n  \
             Platform  {}\n  \
             Method    Direct over qsh (no SSH)\n  \
             Source    GitHub Releases\n\n\
             Update qshd to {client_version}?{preserve}",
            report::printable(server_version),
            platform.target(),
        ),
        &[login, host],
    )
}

fn busy_disrupt_question(host: &str, others: u32) -> String {
    let host_shown = identity::show(host);
    let clients = if others == 1 {
        "1 other active client".to_string()
    } else {
        format!("{others} other active clients")
    };
    identity::with_note(
        format!(
            "\nqshd on {host_shown} currently has {clients}.\n\
             Updating now keeps all sessions alive, and other clients will briefly reconnect.\n\
             Update qshd now?"
        ),
        &[host],
    )
}

fn legacy_ssh_question(
    login: &str,
    host: &str,
    server_version: &str,
    client_version: &str,
) -> String {
    let user = identity::show(login);
    let host_shown = identity::show(host);
    identity::with_note(
        format!(
            "\nqshd {} on {user}@{host_shown} is older than this client's {client_version} \
             and predates direct updates over qsh.\n\
             Update qshd to {client_version} over SSH? (Declining or unavailable SSH continues \
             directly with qshd {}.)",
            report::printable(server_version),
            report::printable(server_version),
        ),
        &[login, host],
    )
}

fn answer_reason(answer: &UpdateAnswer) -> &'static str {
    match answer {
        UpdateAnswer::Accept => "accepted",
        UpdateAnswer::UpToDate => "already up to date",
        UpdateAnswer::DaemonNewer => "daemon is newer",
        UpdateAnswer::Busy { .. } => "daemon is busy",
        UpdateAnswer::Managed => "daemon is managed",
        UpdateAnswer::ArchMismatch => "architecture mismatch",
        UpdateAnswer::TooLarge => "image too large",
        UpdateAnswer::NotAllowed => "not allowed",
        UpdateAnswer::InProgress => "another update is already in progress",
        UpdateAnswer::ResourceExhausted => "daemon resource limit reached",
        UpdateAnswer::ProviderFailed => "daemon update provider failed",
        UpdateAnswer::Unknown(_) => "unrecognized refusal",
    }
}

fn reject_reason(code: RejectCode) -> &'static str {
    match code {
        RejectCode::Other => "rejected",
        RejectCode::SizeMismatch => "size mismatch",
        RejectCode::ChecksumMismatch => "checksum mismatch",
        RejectCode::SelfCheckFailed => "self-check failed",
        RejectCode::VersionNotAccepted => "version not accepted",
        RejectCode::DiskError => "disk error on server",
        RejectCode::ExecFailed => "restart failed on server",
        RejectCode::TransferStalled => "transfer stalled",
        RejectCode::ControlBusy => "daemon control socket busy",
        RejectCode::Unknown(_) => "unrecognized rejection",
    }
}

enum AboutReply {
    About(About),
    Unavailable,
    Cancelled,
}

enum ControlWaitError {
    Cancelled,
    Failed(String),
}

fn query_about(
    att: &Attempt,
    rx: &Receiver<UiEvent>,
    deframer: &mut RecordDeframer,
    timeout: Duration,
    interrupted: &dyn Fn() -> bool,
) -> AboutReply {
    if att
        .client
        .send_bytes(CONTROL_STREAM, encode_client(&ClientRecord::AboutRequest))
        .is_err()
    {
        return AboutReply::Unavailable;
    }
    let deadline = Instant::now() + timeout;
    loop {
        if interrupted() {
            return AboutReply::Cancelled;
        }
        if att.is_closed() || Instant::now() >= deadline {
            return AboutReply::Unavailable;
        }
        let step = deadline
            .saturating_duration_since(Instant::now())
            .min(Duration::from_millis(20));
        match rx.recv_timeout(step) {
            Ok(UiEvent::Wire {
                stream: CONTROL_STREAM,
                bytes,
            }) => {
                att.events.took(bytes.len());
                att.client.consumed(CONTROL_STREAM, bytes.len());
                for raw in deframer.push(&bytes) {
                    match decode_server(&raw) {
                        Ok(ServerRecord::About(about)) => return AboutReply::About(about),
                        Ok(ServerRecord::AboutUnavailable(_)) => return AboutReply::Unavailable,
                        _ => {}
                    }
                }
            }
            Ok(UiEvent::Wire { stream, bytes }) => {
                att.events.took(bytes.len());
                att.client.consumed(stream, bytes.len());
            }
            Ok(UiEvent::Link(LinkState::Closed)) => return AboutReply::Unavailable,
            Ok(_) => {}
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {}
            Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => return AboutReply::Unavailable,
        }
    }
}

fn send_offer_and_wait(
    att: &Attempt,
    rx: &Receiver<UiEvent>,
    deframer: &mut RecordDeframer,
    offer: &UpdateOffer,
    timeout: Duration,
    interrupted: &dyn Fn() -> bool,
) -> Result<UpdateAnswer, ControlWaitError> {
    att.client
        .send_bytes(
            CONTROL_STREAM,
            encode_client(&ClientRecord::UpdateOffer(offer.clone())),
        )
        .map_err(|_| ControlWaitError::Failed("could not send update offer".into()))?;
    let deadline = Instant::now() + timeout;
    loop {
        if interrupted() {
            return Err(ControlWaitError::Cancelled);
        }
        if att.is_closed() {
            return Err(ControlWaitError::Failed("connection closed".into()));
        }
        if Instant::now() >= deadline {
            return Err(ControlWaitError::Failed(
                "timed out waiting for daemon answer".into(),
            ));
        }
        let step = deadline
            .saturating_duration_since(Instant::now())
            .min(Duration::from_millis(20));
        match rx.recv_timeout(step) {
            Ok(UiEvent::Wire {
                stream: CONTROL_STREAM,
                bytes,
            }) => {
                att.events.took(bytes.len());
                att.client.consumed(CONTROL_STREAM, bytes.len());
                for raw in deframer.push(&bytes) {
                    if let Ok(ServerRecord::UpdateAnswer(answer)) = decode_server(&raw) {
                        return Ok(answer);
                    }
                }
            }
            Ok(UiEvent::Wire { stream, bytes }) => {
                att.events.took(bytes.len());
                att.client.consumed(stream, bytes.len());
            }
            Ok(UiEvent::Link(LinkState::Closed)) => {
                return Err(ControlWaitError::Failed("connection closed".into()));
            }
            Ok(_) => {}
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {}
            Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
                return Err(ControlWaitError::Failed("connection closed".into()));
            }
        }
    }
}

fn upload_and_wait(
    att: &Attempt,
    rx: &Receiver<UiEvent>,
    deframer: &mut RecordDeframer,
    image: &DaemonImage,
    observer: &dyn BringUpObserver,
    interrupted: &dyn Fn() -> bool,
) -> Result<UpdateResult, ControlWaitError> {
    let total = image.size;
    let mut sent = 0u64;
    observer.on_progress(BringUpProgress {
        stage: BringUpStage::Uploading,
        completed: 0,
        total: Some(total),
        finished: total == 0,
    });

    for chunk in image.bytes.chunks(UPLOAD_CHUNK_BYTES) {
        if interrupted() {
            return Err(ControlWaitError::Cancelled);
        }
        // Check for an early refusal or disconnect before queuing more bytes.
        if let Some(early) = poll_control_nonblocking(att, rx, deframer)? {
            return Ok(early);
        }
        att.client
            .send_bytes_bounded(UPDATE_STREAM, chunk.to_vec(), CHUNK_SEND_TIMEOUT)
            .map_err(|_| ControlWaitError::Failed("upload failed or timed out".into()))?;
        sent += chunk.len() as u64;
        observer.on_progress(BringUpProgress {
            stage: BringUpStage::Uploading,
            completed: sent,
            total: Some(total),
            finished: sent == total,
        });
    }

    let deadline = Instant::now() + RESULT_TIMEOUT;
    let mut saw_restarting = false;
    loop {
        if interrupted() {
            return Err(ControlWaitError::Cancelled);
        }
        if att.is_closed() {
            return if saw_restarting {
                Ok(UpdateResult::Restarting)
            } else {
                Err(ControlWaitError::Failed(
                    "connection closed before daemon confirmed the update".into(),
                ))
            };
        }
        if Instant::now() >= deadline {
            return Err(ControlWaitError::Failed(
                "timed out waiting for daemon verification".into(),
            ));
        }
        let step = deadline
            .saturating_duration_since(Instant::now())
            .min(Duration::from_millis(20));
        match rx.recv_timeout(step) {
            Ok(UiEvent::Wire {
                stream: CONTROL_STREAM,
                bytes,
            }) => {
                att.events.took(bytes.len());
                att.client.consumed(CONTROL_STREAM, bytes.len());
                for raw in deframer.push(&bytes) {
                    match decode_server(&raw) {
                        Ok(ServerRecord::UpdateResult(result)) => return Ok(result),
                        Ok(ServerRecord::Restarting) => saw_restarting = true,
                        _ => {}
                    }
                }
            }
            Ok(UiEvent::Wire { stream, bytes }) => {
                att.events.took(bytes.len());
                att.client.consumed(stream, bytes.len());
            }
            Ok(UiEvent::Link(LinkState::Closed)) => {
                return if saw_restarting {
                    Ok(UpdateResult::Restarting)
                } else {
                    Err(ControlWaitError::Failed(
                        "connection closed before daemon confirmed the update".into(),
                    ))
                };
            }
            Ok(_) => {}
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {}
            Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
                return if saw_restarting {
                    Ok(UpdateResult::Restarting)
                } else {
                    Err(ControlWaitError::Failed("connection closed".into()))
                };
            }
        }
    }
}

fn poll_control_nonblocking(
    att: &Attempt,
    rx: &Receiver<UiEvent>,
    deframer: &mut RecordDeframer,
) -> Result<Option<UpdateResult>, ControlWaitError> {
    while let Ok(event) = rx.try_recv() {
        match event {
            UiEvent::Wire {
                stream: CONTROL_STREAM,
                bytes,
            } => {
                att.events.took(bytes.len());
                att.client.consumed(CONTROL_STREAM, bytes.len());
                for raw in deframer.push(&bytes) {
                    if let Ok(ServerRecord::UpdateResult(result)) = decode_server(&raw) {
                        return Ok(Some(result));
                    }
                }
            }
            UiEvent::Wire { stream, bytes } => {
                att.events.took(bytes.len());
                att.client.consumed(stream, bytes.len());
            }
            UiEvent::Link(LinkState::Closed) => {
                return Err(ControlWaitError::Failed(
                    "connection closed during upload".into(),
                ));
            }
            _ => {}
        }
    }
    Ok(None)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_comparison_matches_release_ordering() {
        assert!(should_offer_daemon_update("0.6.0-alpha.3", "0.6.0-alpha.4"));
        assert!(should_offer_daemon_update("0.6.0-alpha.4", "0.6.0-alpha.5"));
        assert!(should_offer_daemon_update("0.6.0-alpha.4", "0.6.0"));
        assert!(should_offer_daemon_update("0.5.9", "0.6.0-alpha.4"));
        assert!(should_offer_daemon_update("0.6.0-rc1", "0.6.0-alpha.4"));
        assert!(should_offer_daemon_update(
            "0.6.0-alpha.3+local",
            "0.6.0-alpha.4"
        ));
        assert!(!should_offer_daemon_update(
            "0.6.0-alpha.4",
            "0.6.0-alpha.4"
        ));
        assert!(!should_offer_daemon_update(
            "0.6.0-alpha.4+local",
            "0.6.0-alpha.4"
        ));
        assert!(!should_offer_daemon_update(
            "0.6.0-alpha.5",
            "0.6.0-alpha.4"
        ));
        assert!(!should_offer_daemon_update("0.6.0", "0.6.0-alpha.4"));
        assert!(!should_offer_daemon_update(
            "not-a-version",
            "0.6.0-alpha.4"
        ));
        assert!(!should_offer_daemon_update(
            "0.6.0-alpha.3",
            "not-a-version"
        ));
    }

    #[test]
    fn over_qsh_prompt_mentions_no_ssh_and_linux_session_preservation() {
        let linux = over_qsh_question(
            "alice",
            "example.test",
            "0.6.0-alpha.4",
            "0.6.0-alpha.5",
            Platform::from_rust_consts("linux", "x86_64").unwrap(),
        );
        assert!(linux.contains("Direct over qsh (no SSH)"));
        assert!(linux.contains("Active sessions are preserved."));
        let macos = over_qsh_question(
            "alice",
            "example.test",
            "0.6.0-alpha.4",
            "0.6.0-alpha.5",
            Platform::from_rust_consts("macos", "aarch64").unwrap(),
        );
        assert!(macos.contains("Direct over qsh (no SSH)"));
        assert!(!macos.contains("Active sessions are preserved."));
    }

    #[test]
    fn legacy_ssh_prompt_explains_fallback() {
        let prompt = legacy_ssh_question("alice", "example.test", "0.6.0-alpha.3", "0.6.0-alpha.5");
        assert!(prompt.contains("predates direct updates over qsh"));
        assert!(prompt.contains("over SSH"));
    }

    #[test]
    fn legacy_ssh_fallback_respects_ssh_availability_and_tty_answer() {
        use std::io::Write;
        struct NoImages;
        impl ImageSource for NoImages {
            fn load(
                &self,
                _: &ImageRequest,
                _: &InstallTiming,
                _: &knock::Cancel,
                _: &dyn BringUpObserver,
            ) -> Result<DaemonImage, ImageError> {
                panic!("legacy SSH fallback must not load images directly");
            }
        }
        let dir = tempfile::tempdir().unwrap();
        let cancel = knock::Cancel::new();
        let no_tty = Tty::at(dir.path().join("missing-tty"));
        let ctx_no_ssh = UpdateContext {
            login: "alice",
            host: "example.test",
            server_version: "0.6.0-alpha.3",
            has_ssh_route: false,
            tty: &no_tty,
            images: Arc::new(NoImages),
            cancel: &cancel,
            interrupted: &|| false,
            say: &|_| {},
        };
        assert_eq!(
            run_legacy_ssh_fallback("0.6.0-alpha.5", &ctx_no_ssh),
            DaemonUpdateOutcome::ContinueDirect
        );

        let pty = nix::pty::openpty(None, None).unwrap();
        let slave_name = format!(
            "/proc/self/fd/{}",
            std::os::fd::AsRawFd::as_raw_fd(&pty.slave)
        );
        let tty = Tty::at(&slave_name);
        let mut master = std::fs::File::from(pty.master);

        let ctx_with_ssh = UpdateContext {
            has_ssh_route: true,
            tty: &tty,
            ..ctx_no_ssh
        };
        master.write_all(b"yes\n").unwrap();
        assert_eq!(
            run_legacy_ssh_fallback("0.6.0-alpha.5", &ctx_with_ssh),
            DaemonUpdateOutcome::FallbackToSsh
        );
        master.write_all(b"no\n").unwrap();
        assert_eq!(
            run_legacy_ssh_fallback("0.6.0-alpha.5", &ctx_with_ssh),
            DaemonUpdateOutcome::ContinueDirect
        );
    }
}
