use super::{FetchError, FetchLimits, ReleaseTransport};
use bringup::{BringUpObserver, ImageError};
use knock::Cancel;
use std::cell::Cell;

pub(super) struct HttpsTransport;
impl ReleaseTransport for HttpsTransport {
    fn fetch(
        &self,
        url: &str,
        limits: FetchLimits,
        cancel: &Cancel,
        observer: &dyn BringUpObserver,
    ) -> Result<Vec<u8>, FetchError> {
        fetch(reqwest::Client::builder(), url, limits, cancel, observer)
    }
}
// Dropping a runtime normally joins blocking DNS workers. Cancellation must
// return while a system resolver is still stuck, including during unwinding.
struct RuntimeOwner(Option<tokio::runtime::Runtime>);
impl Drop for RuntimeOwner {
    fn drop(&mut self) {
        if let Some(runtime) = self.0.take() {
            runtime.shutdown_background();
        }
    }
}

fn fetch(
    builder: reqwest::ClientBuilder,
    url: &str,
    limits: FetchLimits,
    cancel: &Cancel,
    observer: &dyn BringUpObserver,
) -> Result<Vec<u8>, FetchError> {
    if cancel.is_cancelled() {
        return Err(FetchError::Rejected(ImageError::Cancelled));
    }
    let runtime = RuntimeOwner(Some(
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|error| rejected(clean(&error.to_string())))?,
    ));
    let body_started = Cell::new(false);
    runtime
        .0
        .as_ref()
        .expect("runtime is alive")
        .block_on(with_deadline(
            limits,
            cancel,
            &body_started,
            download(builder, url, limits, observer, &body_started),
        ))
}

async fn with_deadline<T>(
    limits: FetchLimits,
    cancel: &Cancel,
    body_started: &Cell<bool>,
    download: impl std::future::Future<Output = Result<T, FetchError>>,
) -> Result<T, FetchError> {
    // One deadline surrounds DNS, connect, redirects, headers and body.
    let result = tokio::select! {
        biased;
        _ = cancelled(cancel) => Err(FetchError::Rejected(ImageError::Cancelled)),
        _ = tokio::time::sleep(limits.total) => Err(FetchError::TemporarilyUnavailable("release download deadline exceeded".into())),
        result = download => result,
    };
    match result {
        Err(FetchError::TemporarilyUnavailable(reason)) if body_started.get() => {
            Err(FetchError::InterruptedResponse(reason))
        }
        other => other,
    }
}

async fn download(
    builder: reqwest::ClientBuilder,
    url: &str,
    limits: FetchLimits,
    observer: &dyn BringUpObserver,
    body_started: &Cell<bool>,
) -> Result<Vec<u8>, FetchError> {
    let client = builder
        .https_only(true)
        .user_agent(concat!("qsh/", env!("CARGO_PKG_VERSION")))
        .no_gzip()
        .no_brotli()
        .no_deflate()
        .no_zstd()
        // Handle each response explicitly: headers are progress for the idle
        // timer, while fetch's outer deadline spans the complete redirect chain.
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .map_err(download_error)?;
    let url = reqwest::Url::parse(url).map_err(|error| rejected(clean(&error.to_string())))?;
    let mut response =
        request_following_redirects(url, limits.idle, |url| client.get(url).send()).await?;
    if response.status() == reqwest::StatusCode::NOT_FOUND {
        return Err(missing("release asset not found (HTTP 404)".into()));
    }
    if response.status().is_server_error() || matches!(response.status().as_u16(), 408 | 429) {
        return Err(FetchError::TemporarilyUnavailable(format!(
            "release server returned HTTP {}",
            response.status().as_u16()
        )));
    }
    if !response.status().is_success() {
        return Err(rejected(format!(
            "release server returned HTTP {}",
            response.status().as_u16()
        )));
    }
    let total = response.content_length();
    if total.is_some_and(|size| size > limits.max_bytes as u64) {
        return Err(rejected("release download exceeds its size limit".into()));
    }
    let mut bytes = Vec::new();
    let mut last_progress = std::time::Instant::now();
    loop {
        let chunk = tokio::time::timeout(limits.idle, response.chunk())
            .await
            .map_err(|_| {
                FetchError::TemporarilyUnavailable("release download idle timeout".into())
            })?
            .map_err(download_error)?;
        let Some(chunk) = chunk else { break };
        if !chunk.is_empty() {
            body_started.set(true);
        }
        if chunk.len() > limits.max_bytes.saturating_sub(bytes.len()) {
            return Err(rejected("release download exceeds its size limit".into()));
        }
        bytes.extend_from_slice(&chunk);
        if last_progress.elapsed() >= std::time::Duration::from_millis(250) {
            observer.on_progress(bringup::BringUpProgress {
                stage: bringup::BringUpStage::Downloading,
                completed: bytes.len() as u64,
                total,
                finished: false,
            });
            last_progress = std::time::Instant::now();
        }
    }
    observer.on_progress(bringup::BringUpProgress {
        stage: bringup::BringUpStage::Downloading,
        completed: bytes.len() as u64,
        total,
        finished: true,
    });
    Ok(bytes)
}

async fn request_following_redirects<F, Fut>(
    mut url: reqwest::Url,
    idle: std::time::Duration,
    mut send: F,
) -> Result<reqwest::Response, FetchError>
where
    F: FnMut(reqwest::Url) -> Fut,
    Fut: std::future::Future<Output = Result<reqwest::Response, reqwest::Error>>,
{
    let mut redirects = 0;
    loop {
        if url.scheme() != "https" {
            return Err(rejected("release URLs must use HTTPS".into()));
        }
        let response = tokio::time::timeout(idle, send(url.clone()))
            .await
            .map_err(|_| {
                FetchError::TemporarilyUnavailable("release download idle timeout".into())
            })?
            .map_err(download_error)?;
        if matches!(response.status().as_u16(), 301 | 302 | 303 | 307 | 308) {
            if redirects == 5 {
                return Err(rejected("release has more than five redirects".into()));
            }
            let location = response
                .headers()
                .get(reqwest::header::LOCATION)
                .and_then(|value| value.to_str().ok())
                .ok_or_else(|| rejected("invalid release redirect location".into()))?;
            url = response
                .url()
                .join(location)
                .map_err(|error| rejected(clean(&error.to_string())))?;
            redirects += 1;
        } else {
            return Ok(response);
        }
    }
}

async fn cancelled(cancel: &Cancel) {
    while !cancel.is_cancelled() {
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
}

fn clean(text: &str) -> String {
    text.chars()
        .filter(|character| !character.is_control())
        .take(240)
        .collect()
}

fn rejected(reason: String) -> FetchError {
    FetchError::Rejected(ImageError::Download(reason))
}

fn missing(reason: String) -> FetchError {
    FetchError::Rejected(ImageError::Unavailable(reason))
}

fn download_error(error: reqwest::Error) -> FetchError {
    // reqwest classifies TLS verification failures as connection failures too.
    // Inspect the typed source chain, never human-readable error text.
    let mut source: Option<&(dyn std::error::Error + 'static)> = Some(&error);
    let mut tls_failure = false;
    while let Some(cause) = source {
        tls_failure |= cause.is::<rustls::Error>();
        // io::Error::source skips its payload's outer layer. Follow get_ref
        // instead so nested I/O wrappers cannot hide the rustls error.
        source = if let Some(io) = cause.downcast_ref::<std::io::Error>() {
            io.get_ref()
                .map(|inner| inner as &(dyn std::error::Error + 'static))
        } else {
            cause.source()
        };
    }
    let temporary = !tls_failure && (error.is_connect() || error.is_timeout());
    let reason = clean(&error.without_url().to_string());
    if temporary {
        FetchError::TemporarilyUnavailable(reason)
    } else {
        rejected(reason)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        io::{BufRead, BufReader},
        process::{Child, Command, Stdio},
        sync::Arc,
        time::{Duration, Instant},
    };
    struct Silent;
    impl BringUpObserver for Silent {
        fn on_progress(&self, _: bringup::BringUpProgress) {}
    }
    struct Server {
        child: Child,
        dir: tempfile::TempDir,
        port: u16,
    }
    impl Drop for Server {
        fn drop(&mut self) {
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
    }
    impl Server {
        fn start() -> Self {
            let dir = tempfile::tempdir().unwrap();
            assert!(Command::new("openssl")
                .args([
                    "req",
                    "-x509",
                    "-newkey",
                    "ec",
                    "-pkeyopt",
                    "ec_paramgen_curve:prime256v1",
                    "-nodes",
                    "-days",
                    "1",
                    "-subj",
                    "/CN=localhost",
                    "-addext",
                    "subjectAltName=DNS:localhost",
                    "-addext",
                    "basicConstraints=critical,CA:FALSE",
                    "-keyout"
                ])
                .arg(dir.path().join("key.pem"))
                .arg("-out")
                .arg(dir.path().join("cert.pem"))
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status()
                .unwrap()
                .success());
            let script = r#"
import gzip, socket, ssl, sys, threading, time
ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
ctx.load_cert_chain(sys.argv[1] + '/cert.pem', sys.argv[1] + '/key.pem')
listener = socket.socket(); listener.bind(('127.0.0.1', 0)); listener.listen()
print(listener.getsockname()[1], flush=True)
def serve(raw):
 try:
  with ctx.wrap_socket(raw, server_side=True) as s:
   data = b''
   while b'\r\n\r\n' not in data: data += s.recv(4096)
   path = data.split(b' ')[1].decode()
   if path.startswith('/redirect/') or path.startswith('/slowredirect/'):
    n = int(path.rsplit('/', 1)[1])
    if path.startswith('/slow'): time.sleep(.06)
    target = path.rsplit('/', 1)[0] + '/' + str(n-1) if n else '/ok'
    # This handler closes the socket after each response.
    s.sendall(('HTTP/1.1 302 Found\r\nConnection: close\r\nLocation: https://localhost:%d%s\r\nContent-Length: 0\r\n\r\n' % (listener.getsockname()[1], target)).encode()); return
   if path == '/downgrade': s.sendall(b'HTTP/1.1 302 Found\r\nLocation: http://localhost:1/no\r\nContent-Length: 0\r\n\r\n'); return
   if path == '/relative/start': s.sendall(b'HTTP/1.1 302 Found\r\nConnection: close\r\nLocation: ../ok\r\nContent-Length: 0\r\n\r\n'); return
   if path == '/encoded':
    body = gzip.compress(b'abcd'); s.sendall(('HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\nContent-Length: %d\r\n\r\n' % len(body)).encode() + body); return
   if path.startswith('/status/'):
    code = int(path.rsplit('/', 1)[1]); s.sendall(('HTTP/1.1 %d Status\r\nContent-Length: 0\r\n\r\n' % code).encode()); return
   if path == '/404': s.sendall(b'HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n'); return
   if path == '/headers':
    open(sys.argv[1] + '/headers-seen', 'w').close(); time.sleep(2)
   if path == '/huge': s.sendall(b'HTTP/1.1 200 OK\r\nContent-Length: 999999999\r\n\r\n'); return
   if path == '/chunked': s.sendall(b'HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n8\r\n12345678\r\n8\r\n12345678\r\n0\r\n\r\n'); return
   s.sendall(b'HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\na')
   if path == '/cut': return
   if path == '/stall': time.sleep(2)
   if path == '/drip':
    for b in b'bcd': time.sleep(.06); s.sendall(bytes([b]))
   else: s.sendall(b'bcd')
 except (OSError, ssl.SSLError): pass
while True:
 raw, _ = listener.accept(); threading.Thread(target=serve, args=(raw,), daemon=True).start()
"#;
            let mut child = Command::new("python3")
                .args(["-u", "-c", script])
                .arg(dir.path())
                .stdout(Stdio::piped())
                .stderr(Stdio::null())
                .spawn()
                .unwrap();
            let mut line = String::new();
            BufReader::new(child.stdout.take().unwrap())
                .read_line(&mut line)
                .unwrap();
            Self {
                child,
                dir,
                port: line.trim().parse().unwrap(),
            }
        }
        fn builder(&self) -> reqwest::ClientBuilder {
            reqwest::Client::builder().no_proxy().add_root_certificate(
                reqwest::Certificate::from_pem(
                    &std::fs::read(self.dir.path().join("cert.pem")).unwrap(),
                )
                .unwrap(),
            )
        }
        fn get(
            &self,
            path: &str,
            limits: FetchLimits,
            cancel: &Cancel,
        ) -> Result<Vec<u8>, FetchError> {
            fetch(
                self.builder(),
                &format!("https://localhost:{}{path}", self.port),
                limits,
                cancel,
                &Silent,
            )
        }
    }
    fn limits() -> FetchLimits {
        FetchLimits {
            total: Duration::from_secs(2),
            idle: Duration::from_secs(1),
            max_bytes: 10,
        }
    }
    #[test]
    fn https_status_body_limits_and_redirect_policy() {
        let server = Server::start();
        let cancel = Cancel::new();
        assert_eq!(server.get("/ok", limits(), &cancel).unwrap(), b"abcd");
        for path in ["/redirect/5", "/downgrade", "/cut", "/huge", "/chunked"] {
            assert!(
                matches!(
                    server.get(path, limits(), &cancel),
                    Err(FetchError::Rejected(ImageError::Download(_)))
                ),
                "{path}"
            );
        }
        assert!(matches!(
            server.get("/404", limits(), &cancel),
            Err(FetchError::Rejected(ImageError::Unavailable(_)))
        ));
        assert!(fetch(
            server.builder(),
            "http://localhost:1/no",
            limits(),
            &cancel,
            &Silent
        )
        .is_err());
        assert!(matches!(
            fetch(
                reqwest::Client::builder().no_proxy(),
                &format!("https://localhost:{}/ok", server.port),
                limits(),
                &cancel,
                &Silent
            ),
            Err(FetchError::Rejected(ImageError::Download(_)))
        ));
    }
    #[test]
    fn temporary_http_failures_allow_fallback_but_other_statuses_do_not() {
        let server = Server::start();
        for code in [408, 429, 500, 502, 503, 504] {
            assert!(
                matches!(
                    server.get(&format!("/status/{code}"), limits(), &Cancel::new()),
                    Err(FetchError::TemporarilyUnavailable(_))
                ),
                "HTTP {code}"
            );
        }
        for code in [401, 403, 410] {
            assert!(
                matches!(
                    server.get(&format!("/status/{code}"), limits(), &Cancel::new()),
                    Err(FetchError::Rejected(_))
                ),
                "HTTP {code}"
            );
        }
    }

    struct FailedDns;
    impl reqwest::dns::Resolve for FailedDns {
        fn resolve(&self, _: reqwest::dns::Name) -> reqwest::dns::Resolving {
            Box::pin(async { Err(std::io::Error::other("test DNS unavailable").into()) })
        }
    }

    #[test]
    fn dns_outage_is_a_temporary_failure() {
        let result = fetch(
            reqwest::Client::builder()
                .no_proxy()
                .dns_resolver(Arc::new(FailedDns)),
            "https://unreachable.invalid/",
            limits(),
            &Cancel::new(),
            &Silent,
        );
        assert!(
            matches!(result, Err(FetchError::TemporarilyUnavailable(_))),
            "{result:?}"
        );
    }

    #[test]
    fn idle_total_and_redirect_deadlines_include_headers() {
        let server = Server::start();
        let cancel = Cancel::new();
        for path in ["/headers", "/stall"] {
            let start = Instant::now();
            assert!(match server.get(
                path,
                FetchLimits {
                    idle: Duration::from_millis(80),
                    ..limits()
                },
                &cancel
            ) {
                Err(FetchError::TemporarilyUnavailable(reason)) if path == "/headers" =>
                    reason.contains("idle"),
                Err(FetchError::InterruptedResponse(reason)) if path == "/stall" =>
                    reason.contains("idle"),
                _ => false,
            });
            assert!(start.elapsed() < Duration::from_millis(500));
        }
        for path in ["/drip", "/slowredirect/4"] {
            let start = Instant::now();
            assert!(match server.get(
                path,
                FetchLimits {
                    total: Duration::from_millis(130),
                    idle: Duration::from_secs(1),
                    ..limits()
                },
                &cancel
            ) {
                Err(FetchError::TemporarilyUnavailable(reason)) if path == "/slowredirect/4" =>
                    reason.contains("deadline"),
                Err(FetchError::InterruptedResponse(reason)) if path == "/drip" =>
                    reason.contains("deadline"),
                _ => false,
            });
            assert!(start.elapsed() < Duration::from_millis(400));
        }
    }
    #[test]
    fn a_partial_body_outage_cannot_claim_zero_received_bytes() {
        let server = Server::start();
        for (path, total, idle) in [
            ("/stall", Duration::from_secs(1), Duration::from_millis(80)),
            ("/drip", Duration::from_millis(130), Duration::from_secs(1)),
        ] {
            let result = server.get(
                path,
                FetchLimits {
                    total,
                    idle,
                    ..limits()
                },
                &Cancel::new(),
            );
            assert!(result.is_err());
            assert!(
                matches!(result, Err(FetchError::InterruptedResponse(_))),
                "received body bytes must reach idle and total classification: {path}"
            );
        }
    }

    #[test]
    fn https_redirect_chains_and_relative_locations_reach_the_body() {
        let server = Server::start();
        for path in ["/redirect/4", "/relative/start"] {
            assert_eq!(server.get(path, limits(), &Cancel::new()).unwrap(), b"abcd");
        }
    }

    fn scripted_redirect(url: reqwest::Url) -> reqwest::Response {
        use reqwest::ResponseBuilderExt;
        let response = http::Response::builder().url(url.clone());
        if url.path() == "/ok" {
            response.body("abcd").unwrap().into()
        } else {
            let n: u8 = url.path().rsplit('/').next().unwrap().parse().unwrap();
            let target = if n == 0 {
                "/ok".to_owned()
            } else {
                format!("/redirect/{}", n - 1)
            };
            response
                .status(302)
                .header(reqwest::header::LOCATION, target)
                .body("")
                .unwrap()
                .into()
        }
    }

    async fn timed_redirect_chain(limits: FetchLimits) -> Result<reqwest::Response, FetchError> {
        let cancel = Cancel::new();
        with_deadline(
            limits,
            &cancel,
            &Cell::new(false),
            request_following_redirects(
                reqwest::Url::parse("https://releases.invalid/redirect/4").unwrap(),
                limits.idle,
                |url| async move {
                    if url.path() != "/ok" {
                        tokio::time::sleep(Duration::from_millis(60)).await;
                    }
                    Ok(scripted_redirect(url))
                },
            ),
        )
        .await
    }

    #[tokio::test(start_paused = true)]
    async fn redirect_headers_reset_idle_for_each_request() {
        let started = tokio::time::Instant::now();
        let response = timed_redirect_chain(FetchLimits {
            idle: Duration::from_millis(100),
            ..limits()
        })
        .await
        .unwrap();
        assert_eq!(response.url().as_str(), "https://releases.invalid/ok");
        assert_eq!(response.bytes().await.unwrap().as_ref(), b"abcd");
        assert_eq!(started.elapsed(), Duration::from_millis(300));
    }

    #[tokio::test(start_paused = true)]
    async fn redirect_headers_do_not_reset_the_total_deadline() {
        let started = tokio::time::Instant::now();
        let result = timed_redirect_chain(FetchLimits {
            total: Duration::from_millis(130),
            idle: Duration::from_millis(100),
            ..limits()
        })
        .await;
        assert!(
            matches!(result, Err(FetchError::TemporarilyUnavailable(reason)) if reason.contains("deadline"))
        );
        assert_eq!(started.elapsed(), Duration::from_millis(130));
    }

    #[tokio::test(start_paused = true)]
    async fn total_timeout_keeps_body_progress_when_it_drops_download() {
        for nonempty in [false, true] {
            let cancel = Cancel::new();
            let body_started = Cell::new(false);
            let result = with_deadline(
                FetchLimits {
                    total: Duration::from_millis(130),
                    ..limits()
                },
                &cancel,
                &body_started,
                async {
                    tokio::time::sleep(Duration::from_millis(20)).await;
                    if nonempty {
                        body_started.set(true);
                    }
                    std::future::pending::<Result<(), FetchError>>().await
                },
            )
            .await;
            assert_eq!(body_started.get(), nonempty);
            assert!(if nonempty {
                matches!(result, Err(FetchError::InterruptedResponse(_)))
            } else {
                matches!(result, Err(FetchError::TemporarilyUnavailable(_)))
            });
        }
    }

    #[tokio::test(start_paused = true)]
    async fn temporary_read_failure_keeps_progress_but_hard_rejection_and_cancel_win() {
        for started in [false, true] {
            let cancel = Cancel::new();
            let body_started = Cell::new(false);
            let result = with_deadline(limits(), &cancel, &body_started, async {
                if started {
                    body_started.set(true);
                }
                Err::<(), _>(FetchError::TemporarilyUnavailable("read timed out".into()))
            })
            .await;
            assert!(if started {
                matches!(result, Err(FetchError::InterruptedResponse(_)))
            } else {
                matches!(result, Err(FetchError::TemporarilyUnavailable(_)))
            });
        }
        let cancel = Cancel::new();
        let started = Cell::new(true);
        let result = with_deadline(
            limits(),
            &cancel,
            &started,
            std::future::ready(Err::<(), _>(rejected("hard body/TLS rejection".into()))),
        )
        .await;
        assert!(matches!(
            result,
            Err(FetchError::Rejected(ImageError::Download(_)))
        ));
        cancel.cancel();
        let result = with_deadline(
            limits(),
            &cancel,
            &started,
            std::future::ready(Err::<(), _>(FetchError::TemporarilyUnavailable(
                "ready outage".into(),
            ))),
        )
        .await;
        assert!(matches!(
            result,
            Err(FetchError::Rejected(ImageError::Cancelled))
        ));
    }

    #[tokio::test(start_paused = true)]
    async fn a_request_without_headers_exhausts_its_own_idle_budget() {
        let started = tokio::time::Instant::now();
        let result = request_following_redirects(
            reqwest::Url::parse("https://releases.invalid/redirect/4").unwrap(),
            Duration::from_millis(100),
            |url| async move {
                tokio::time::sleep(Duration::from_millis(101)).await;
                Ok(scripted_redirect(url))
            },
        )
        .await;
        assert!(
            matches!(result, Err(FetchError::TemporarilyUnavailable(reason)) if reason.contains("idle"))
        );
        assert_eq!(started.elapsed(), Duration::from_millis(100));
    }

    #[tokio::test(start_paused = true)]
    async fn cancellation_precedes_ready_deadline_and_download() {
        let cancel = Cancel::new();
        cancel.cancel();
        let result = with_deadline(
            FetchLimits {
                total: Duration::ZERO,
                ..limits()
            },
            &cancel,
            &Cell::new(false),
            std::future::ready(Ok(b"abcd")),
        )
        .await;
        assert!(matches!(
            result,
            Err(FetchError::Rejected(ImageError::Cancelled))
        ));
    }

    #[tokio::test(start_paused = true)]
    async fn total_deadline_precedes_a_download_ready_at_the_same_time() {
        let cancel = Cancel::new();
        let result = with_deadline(
            FetchLimits {
                total: Duration::from_millis(130),
                ..limits()
            },
            &cancel,
            &Cell::new(false),
            async {
                tokio::time::sleep(Duration::from_millis(130)).await;
                Ok(b"abcd")
            },
        )
        .await;
        assert!(
            matches!(result, Err(FetchError::TemporarilyUnavailable(reason)) if reason.contains("deadline"))
        );
    }

    #[test]
    fn reading_cancel_returns_before_network_budget() {
        let server = Server::start();
        let cancel = Cancel::new();
        let copy = cancel.clone();
        let thread = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(100));
            copy.cancel();
        });
        let start = Instant::now();
        assert!(matches!(
            server.get("/stall", limits(), &cancel),
            Err(FetchError::Rejected(ImageError::Cancelled))
        ));
        assert!(start.elapsed() < Duration::from_millis(500));
        thread.join().unwrap();
    }
    #[test]
    fn http_content_encoding_preserves_archive_bytes() {
        use std::io::Read;
        let server = Server::start();
        let bytes = server
            .get(
                "/encoded",
                FetchLimits {
                    max_bytes: 100,
                    ..limits()
                },
                &Cancel::new(),
            )
            .unwrap();
        assert_eq!(&bytes[..2], &[0x1f, 0x8b]);
        let mut decoded = Vec::new();
        flate2::read::GzDecoder::new(bytes.as_slice())
            .read_to_end(&mut decoded)
            .unwrap();
        assert_eq!(decoded, b"abcd");
    }
    #[test]
    fn diagnostic_text_cannot_emit_terminal_controls_or_unbounded_data() {
        let text = format!("\x1b[31m\n{}\r\u{7f}", "x".repeat(1000));
        let result = clean(&text);
        assert!(!result.chars().any(char::is_control));
        assert_eq!(result.chars().count(), 240);
    }
    struct SlowDns {
        started: Arc<std::sync::atomic::AtomicBool>,
    }
    impl reqwest::dns::Resolve for SlowDns {
        fn resolve(&self, _: reqwest::dns::Name) -> reqwest::dns::Resolving {
            let started = self.started.clone();
            Box::pin(async move {
                tokio::task::spawn_blocking(move || {
                    started.store(true, std::sync::atomic::Ordering::SeqCst);
                    std::thread::sleep(Duration::from_secs(2));
                    Ok(Box::new(std::iter::empty()) as reqwest::dns::Addrs)
                })
                .await
                .unwrap()
            })
        }
    }
    #[test]
    fn blocked_dns_cancel_and_timeout_include_runtime_drop() {
        for cancelled in [true, false] {
            let started = Arc::new(std::sync::atomic::AtomicBool::new(false));
            let signal = started.clone();
            let cancel = Cancel::new();
            let copy = cancel.clone();
            let thread = std::thread::spawn(move || {
                let deadline = Instant::now() + Duration::from_secs(2);
                while !signal.load(std::sync::atomic::Ordering::SeqCst) && Instant::now() < deadline
                {
                    std::thread::sleep(Duration::from_millis(1));
                }
                if cancelled {
                    copy.cancel();
                }
            });
            let start = Instant::now();
            let result = fetch(
                reqwest::Client::builder()
                    .no_proxy()
                    .dns_resolver(Arc::new(SlowDns {
                        started: started.clone(),
                    })),
                "https://blocked.invalid/",
                FetchLimits {
                    total: Duration::from_millis(150),
                    ..limits()
                },
                &cancel,
                &Silent,
            );
            assert!(
                start.elapsed() < Duration::from_millis(500),
                "runtime Drop waited for DNS"
            );
            assert!(started.load(std::sync::atomic::Ordering::SeqCst));
            if cancelled {
                assert!(matches!(
                    result,
                    Err(FetchError::Rejected(ImageError::Cancelled))
                ));
            } else {
                assert!(matches!(result, Err(FetchError::TemporarilyUnavailable(_))));
            }
            thread.join().unwrap();
        }
    }

    const CACHED_IMAGE: &[u8] = b"verified cached metadata-wait fixture";

    fn seeded_release_cache() -> (tempfile::TempDir, bringup::ImageRequest) {
        use bringup::ImageSource;
        let request = bringup::ImageRequest::new(
            bringup::Platform::from_uname("Linux", "x86_64").unwrap(),
            "0.4.0",
        )
        .unwrap();
        let stem = "qsh-0.4.0-x86_64-unknown-linux-musl";
        let mut tar = tar::Builder::new(Vec::new());
        let mut header = tar::Header::new_gnu();
        header.set_mode(0o755);
        header.set_size(CACHED_IMAGE.len() as u64);
        header.set_cksum();
        tar.append_data(&mut header, format!("{stem}/qshd"), CACHED_IMAGE)
            .unwrap();
        let mut gzip = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
        std::io::Write::write_all(&mut gzip, &tar.into_inner().unwrap()).unwrap();
        let archive = gzip.finish().unwrap();
        use std::os::unix::fs::PermissionsExt;
        let root = tempfile::Builder::new()
            .permissions(std::fs::Permissions::from_mode(0o700))
            .tempdir()
            .unwrap();
        crate::releases::GitHubImages::fixture(
            root.path().into(),
            crate::releases::test_support::Fake::new(archive),
        )
        .load(
            &request,
            &bringup::InstallTiming::default(),
            &Cancel::new(),
            &Silent,
        )
        .unwrap();
        (root, request)
    }

    fn metadata_source(
        server: &Server,
        root: &std::path::Path,
        trust: bool,
    ) -> crate::releases::GitHubImages {
        struct Endpoint {
            url: String,
            root: Option<Vec<u8>>,
        }
        impl ReleaseTransport for Endpoint {
            fn fetch(
                &self,
                url: &str,
                limits: FetchLimits,
                cancel: &Cancel,
                observer: &dyn BringUpObserver,
            ) -> Result<Vec<u8>, FetchError> {
                assert!(
                    url.ends_with("SHA256SUMS"),
                    "these cases must not fetch an archive"
                );
                let mut builder = reqwest::Client::builder().no_proxy();
                if let Some(root) = &self.root {
                    builder =
                        builder.add_root_certificate(reqwest::Certificate::from_pem(root).unwrap());
                }
                fetch(builder, &self.url, limits, cancel, observer)
            }
        }
        crate::releases::GitHubImages::fixture(
            root.into(),
            Arc::new(Endpoint {
                url: format!("https://localhost:{}/headers", server.port),
                root: trust.then(|| std::fs::read(server.dir.path().join("cert.pem")).unwrap()),
            }),
        )
    }

    #[test]
    fn silent_metadata_timeout_uses_reverified_cache() {
        use bringup::ImageSource;
        let server = Server::start();
        let (root, request) = seeded_release_cache();
        let started = Instant::now();
        let image = metadata_source(&server, root.path(), true)
            .load(
                &request,
                &bringup::InstallTiming {
                    metadata: Duration::from_millis(350),
                    ..Default::default()
                },
                &Cancel::new(),
                &Silent,
            )
            .unwrap();
        assert_eq!(&*image.bytes, CACHED_IMAGE);
        assert!(
            server.dir.path().join("headers-seen").exists(),
            "must reach silent HTTP headers"
        );
        assert!(
            started.elapsed() >= Duration::from_millis(350),
            "must attempt metadata before cache reuse"
        );
        assert!(started.elapsed() < Duration::from_secs(2));
    }

    #[test]
    fn cancelling_silent_metadata_never_selects_seeded_cache() {
        use bringup::ImageSource;
        let server = Server::start();
        let (root, request) = seeded_release_cache();
        let cancel = Cancel::new();
        let copy = cancel.clone();
        let marker = server.dir.path().join("headers-seen");
        let started = Instant::now();
        let (result, reached) = std::thread::scope(|scope| {
            let thread = scope.spawn(move || {
                let deadline = Instant::now() + Duration::from_secs(2);
                while !marker.exists() && Instant::now() < deadline {
                    std::thread::sleep(Duration::from_millis(1));
                }
                let reached = marker.exists();
                copy.cancel();
                reached
            });
            let result = metadata_source(&server, root.path(), true).load(
                &request,
                &bringup::InstallTiming {
                    metadata: Duration::from_secs(3),
                    ..Default::default()
                },
                &cancel,
                &Silent,
            );
            (result, thread.join().unwrap())
        });
        assert!(reached, "cancel only after request reaches silent headers");
        assert!(matches!(result, Err(ImageError::Cancelled)), "{result:?}");
        assert!(started.elapsed() < Duration::from_secs(2));
    }

    #[test]
    fn invalid_tls_metadata_never_selects_seeded_cache() {
        use bringup::ImageSource;
        let server = Server::start();
        let (root, request) = seeded_release_cache();
        let result = metadata_source(&server, root.path(), false).load(
            &request,
            &bringup::InstallTiming {
                metadata: Duration::from_secs(2),
                ..Default::default()
            },
            &Cancel::new(),
            &Silent,
        );
        assert!(matches!(result, Err(ImageError::Download(_))), "{result:?}");
    }
}
