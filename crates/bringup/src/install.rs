//! Installation on the authenticated SSH connection, with atomic publication.

use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};
use std::time::{Duration, Instant};

use sha2::{Digest, Sha256};

use crate::{
    ensure, exec, locate, shell, BringUpError, BringUpHooks, BringUpObserver, BringUpProgress,
    BringUpRequest, BringUpStage, DaemonImage, IdentifiedReady, ImageError, ImageRequest,
    InstallOffer, InstallPolicy, ServerOs,
};

const MAX_IMAGE: u64 = 32 * 1024 * 1024;

/// Owns both cleanup and disconnect, including early returns and unwinding.
struct Session {
    conn: ssh::SshConnection,
    sub: ssh::SshSubstrate,
    events: exec::Events,
    stream: u8,
    temporary: Option<(String, Arc<AtomicBool>)>,
}

impl Session {
    fn command(
        &mut self,
        what: &str,
        script: &str,
        budget: Duration,
        cancel: &knock::Cancel,
    ) -> Result<exec::Output, BringUpError> {
        self.stream += 1;
        exec::run(
            &mut self.sub.with_cancel(cancel),
            &self.events,
            self.stream,
            what,
            script,
            budget,
            cancel,
        )
    }

    fn checked(
        &mut self,
        stage: BringUpStage,
        script: &str,
        budget: Duration,
        cancel: &knock::Cancel,
    ) -> Result<(), BringUpError> {
        let output = self
            .command(stage_name(stage), script, budget, cancel)
            .map_err(|error| stage_error(stage, error))?;
        if output.code != 0 {
            return Err(stage_error(stage, command_error(stage, &output)));
        }
        Ok(())
    }

    fn matches(
        &mut self,
        path: &str,
        image: &DaemonImage,
        hooks: &BringUpHooks,
        cancel: &knock::Cancel,
    ) -> Result<bool, BringUpError> {
        let hash = match image.request.platform.os {
            ServerOs::Linux => "sha256sum",
            ServerOs::Darwin => "shasum -a 256",
        };
        let tool = hash.split_whitespace().next().unwrap();
        let path = shell::quote(path);
        let script = format!(
            "command -v {tool} >/dev/null 2>&1 || exit 127; \
             if [ ! -e {path} ] && [ ! -L {path} ]; then exit 3; fi; \
             [ -f {path} ] && [ ! -L {path} ] || exit 1; \
             size=$(wc -c < {path}) || exit $?; \
             sum=$({hash} < {path}) || exit $?; \
             printf '%s\\n%s\\n' \"$size\" \"$sum\""
        );
        let output = self
            .command("qshd verification", &script, hooks.timing.verify, cancel)
            .map_err(|error| stage_error(BringUpStage::Verifying, error))?;
        if output.code == 3 {
            return Ok(false);
        }
        if output.code != 0 {
            return Err(stage_error(
                BringUpStage::Verifying,
                command_error(BringUpStage::Verifying, &output),
            ));
        }
        let mut lines = output.text.lines();
        let size = lines
            .next()
            .and_then(|line| line.trim().parse::<u64>().ok());
        let sum = lines.next().and_then(|line| line.split_whitespace().next());
        let expected = hex(&image.sha256);
        match (size, sum) {
            (Some(size), Some(sum))
                if sum.len() == 64
                    && sum.bytes().all(|b| b.is_ascii_hexdigit())
                    && lines.next().is_none() =>
            {
                Ok(size == image.size && sum.eq_ignore_ascii_case(&expected))
            }
            _ => Err(BringUpError::Verify(
                "invalid size or SHA-256 response".into(),
            )),
        }
    }

    fn install(
        &mut self,
        path: &str,
        image: DaemonImage,
        hooks: &BringUpHooks,
        cancel: &knock::Cancel,
    ) -> Result<(), BringUpError> {
        progress(hooks.observer.as_ref(), BringUpStage::Verifying, false);
        check_cancel(cancel)?;
        let matches = self.matches(path, &image, hooks, cancel)?;
        progress(hooks.observer.as_ref(), BringUpStage::Verifying, true);
        check_cancel(cancel)?;
        if matches {
            self.checked(
                BringUpStage::Publishing,
                &format!("chmod 700 {}", shell::quote(path)),
                hooks.timing.publish,
                cancel,
            )?;
            return Ok(());
        }
        let directory = path.rsplit_once('/').unwrap().0;
        let upload_started = Instant::now();
        self.checked(
            BringUpStage::Uploading,
            &format!("umask 077; mkdir -p {}", shell::quote(directory)),
            hooks.timing.upload,
            cancel,
        )?;
        // 128 random bits; SFTP's exclusive create refuses a collision.
        let temporary = format!("{directory}/.qshd-{}.tmp", hex(&rand::random::<[u8; 16]>()));
        let owned = Arc::new(AtomicBool::new(false));
        // An exclusive-create failure does not prove ownership. Only an
        // acknowledged write or a successful upload permits cleanup. A lost
        // first reply can leave a hidden file rather than delete a foreign one.
        self.temporary = Some((temporary.clone(), Arc::clone(&owned)));
        progress(hooks.observer.as_ref(), BringUpStage::Uploading, false);
        check_cancel(cancel)?;
        self.conn
            .upload_file(
                &temporary,
                Arc::clone(&image.bytes),
                ssh::TransferLimits {
                    total: hooks.timing.upload.saturating_sub(upload_started.elapsed()),
                    idle: hooks.timing.upload_idle,
                    max_bytes: MAX_IMAGE,
                },
                Arc::new(UploadObserver {
                    observer: Arc::clone(&hooks.observer),
                    owned: Arc::clone(&owned),
                }),
                cancel,
            )
            .map_err(|error| stage_error(BringUpStage::Uploading, BringUpError::Ssh(error)))?;
        owned.store(true, Ordering::SeqCst);
        progress(hooks.observer.as_ref(), BringUpStage::Verifying, false);
        check_cancel(cancel)?;
        if !self.matches(&temporary, &image, hooks, cancel)? {
            return Err(BringUpError::Verify(
                "uploaded image size or SHA-256 does not match".into(),
            ));
        }
        progress(hooks.observer.as_ref(), BringUpStage::Verifying, true);
        // Another operation may have published this image while we uploaded.
        let already_published = self.matches(path, &image, hooks, cancel)?;
        progress(hooks.observer.as_ref(), BringUpStage::Publishing, false);
        check_cancel(cancel)?;
        let script = if already_published {
            format!(
                "chmod 700 {} && rm -f {}",
                shell::quote(path),
                shell::quote(&temporary)
            )
        } else {
            format!(
                "chmod 700 {} && mv -f {} {}",
                shell::quote(&temporary),
                shell::quote(&temporary),
                shell::quote(path)
            )
        };
        self.checked(
            BringUpStage::Publishing,
            &script,
            hooks.timing.publish,
            cancel,
        )?;
        self.temporary = None;
        progress(hooks.observer.as_ref(), BringUpStage::Publishing, true);
        check_cancel(cancel)
    }
}

impl Drop for Session {
    fn drop(&mut self) {
        if let Some((path, owned)) = self
            .temporary
            .take()
            .filter(|(_, owned)| owned.load(Ordering::SeqCst))
        {
            drop(owned);
            // A fresh token permits bounded cleanup even after user cancellation.
            let _ = self.command(
                "qshd temporary file cleanup",
                &format!("rm -f {}", shell::quote(&path)),
                Duration::from_secs(1),
                &knock::Cancel::new(),
            );
        }
        self.conn.close();
    }
}

pub(crate) fn bring_up(
    req: BringUpRequest,
    policy: InstallPolicy,
    hooks: BringUpHooks,
    bind: Arc<dyn knock::SocketBind>,
    cancel: &knock::Cancel,
) -> Result<IdentifiedReady, BringUpError> {
    check_cancel(cancel)?;
    if let InstallPolicy::AskIfMissing { version } | InstallPolicy::EnsureBundled { version } =
        &policy
    {
        if crate::image::valid_version(version).is_none() {
            return Err(BringUpError::InvalidRequest(
                "the image version must be SemVer without build metadata".into(),
            ));
        }
    }
    if req.name.contains('\0') || req.qsh_port == 0 {
        return Err(BringUpError::InvalidRequest(
            "the name must not contain NUL and the port must be nonzero".into(),
        ));
    }
    let host = req.ssh.host.clone();
    let username = req.ssh.username.clone();
    let ssh_port = req.ssh.port;
    check_cancel(cancel)?;
    let (collector, events) = exec::collector(Arc::clone(&hooks.observer));
    let (conn, sub) = ssh::connect(req.ssh, req.auth, bind, Arc::new(collector), cancel)
        .map_err(BringUpError::Ssh)?;
    let mut session = Session {
        conn,
        sub,
        events,
        stream: 0,
        temporary: None,
    };
    progress(hooks.observer.as_ref(), BringUpStage::Connecting, true);
    progress(hooks.observer.as_ref(), BringUpStage::Locating, false);
    let output = session.command(
        "the qshd lookup",
        locate::SCRIPT,
        hooks.timing.locate,
        cancel,
    )?;
    let probe = locate::probe(output.code, &output.text)?;
    progress(hooks.observer.as_ref(), BringUpStage::Locating, true);
    check_cancel(cancel)?;
    if let locate::Located::Service(kind) = probe.located {
        return Err(BringUpError::ServiceRunning(kind));
    }
    let path = match (&policy, probe.located) {
        (
            InstallPolicy::ExistingOnly | InstallPolicy::AskIfMissing { .. },
            locate::Located::Found(path),
        ) => path,
        (InstallPolicy::ExistingOnly, _) => return Err(BringUpError::InstallRequired),
        (InstallPolicy::AskIfMissing { version } | InstallPolicy::EnsureBundled { version }, _) => {
            let request = ImageRequest::new(probe.platform, version.clone())?;
            request.validate()?;
            let path = probe
                .home
                .join(".cache/qsh")
                .join(probe.platform.file_name(version))
                .to_str()
                .ok_or_else(|| BringUpError::InvalidRequest("remote HOME is not UTF-8".into()))?
                .to_owned();
            if matches!(policy, InstallPolicy::AskIfMissing { .. }) {
                let offer = InstallOffer {
                    username,
                    host,
                    ssh_port,
                    image: request.clone(),
                    remote_path: path.clone(),
                };
                let accepted = hooks.approval.approve(&offer, cancel)?;
                check_cancel(cancel)?;
                if !accepted {
                    return Err(BringUpError::Declined);
                }
            }
            let source = hooks.source.as_ref().ok_or_else(|| {
                BringUpError::InvalidRequest("installation requires an image source".into())
            })?;
            check_cancel(cancel)?;
            let image = source
                .load(&request, &hooks.timing, cancel, hooks.observer.as_ref())
                .map_err(BringUpError::Image)?;
            check_cancel(cancel)?;
            validate_image(&request, &image, cancel)?;
            session.install(&path, image, &hooks, cancel)?;
            path
        }
    };
    progress(hooks.observer.as_ref(), BringUpStage::Starting, false);
    check_cancel(cancel)?;
    let output = session.command(
        "qshd transport-ensure",
        &ensure::command(&path, &req.name, req.qsh_port, &req.client_pubkey),
        hooks.timing.ensure,
        cancel,
    )?;
    let ready = ensure::parse(output.code, &output.text)?;
    progress(hooks.observer.as_ref(), BringUpStage::Starting, true);
    check_cancel(cancel)?;
    Ok(IdentifiedReady {
        ready,
        ssh_host_key: session.conn.server_host_key(),
    })
}

fn validate_image(
    request: &ImageRequest,
    image: &DaemonImage,
    cancel: &knock::Cancel,
) -> Result<(), BringUpError> {
    request.validate()?;
    if image.request != *request
        || image.size == 0
        || image.size > MAX_IMAGE
        || image.size != image.bytes.len() as u64
    {
        return Err(BringUpError::Image(ImageError::Invalid(
            "platform, version or size does not match the request".into(),
        )));
    }
    let mut hash = Sha256::new();
    for chunk in image.bytes.chunks(1024 * 1024) {
        check_cancel(cancel)?;
        hash.update(chunk);
    }
    if <[u8; 32]>::from(hash.finalize()) != image.sha256 {
        return Err(BringUpError::Image(ImageError::Checksum));
    }
    Ok(())
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn check_cancel(cancel: &knock::Cancel) -> Result<(), BringUpError> {
    if cancel.is_cancelled() {
        Err(BringUpError::Ssh(ssh::SshError::Cancelled))
    } else {
        Ok(())
    }
}

fn progress(observer: &dyn BringUpObserver, stage: BringUpStage, finished: bool) {
    observer.on_progress(BringUpProgress {
        stage,
        completed: 0,
        total: None,
        finished,
    });
}

struct UploadObserver {
    observer: Arc<dyn BringUpObserver>,
    owned: Arc<AtomicBool>,
}
impl ssh::UploadProgress for UploadObserver {
    fn uploaded(&self, bytes: u64, total: u64) {
        if bytes > 0 {
            self.owned.store(true, Ordering::SeqCst);
        }
        self.observer.on_progress(BringUpProgress {
            stage: BringUpStage::Uploading,
            completed: bytes,
            total: Some(total),
            finished: bytes == total,
        });
    }
}

fn stage_name(stage: BringUpStage) -> &'static str {
    match stage {
        BringUpStage::Uploading => "qshd transfer",
        BringUpStage::Publishing => "qshd publication",
        _ => "qshd verification",
    }
}

fn command_error(stage: BringUpStage, output: &exec::Output) -> BringUpError {
    let text: String = output
        .text
        .chars()
        .filter(|c| !c.is_control() || matches!(c, '\n' | '\t'))
        .take(1000)
        .collect();
    BringUpError::EnsureFailed(format!(
        "{} failed (exit {}): {}",
        stage_name(stage),
        output.code,
        text.trim()
    ))
}

fn stage_error(stage: BringUpStage, error: BringUpError) -> BringUpError {
    if matches!(error, BringUpError::Ssh(ssh::SshError::Cancelled)) {
        return error;
    }
    match stage {
        BringUpStage::Uploading => BringUpError::Transfer(error.to_string()),
        BringUpStage::Publishing => BringUpError::Publish(error.to_string()),
        _ => BringUpError::Verify(error.to_string()),
    }
}
