use super::{FetchError, FetchLimits, ReleaseTransport};
use bringup::{BringUpObserver, ImageError};
use knock::Cancel;

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
    runtime.0.as_ref().expect("runtime is alive").block_on(async {
        // One deadline surrounds DNS, connect, redirects, headers and body.
        tokio::select! {
            biased;
            _ = cancelled(cancel) => Err(FetchError::Rejected(ImageError::Cancelled)),
            _ = tokio::time::sleep(limits.total) => Err(FetchError::TemporarilyUnavailable("release download deadline exceeded".into())),
            result = download(builder, url, limits, observer) => result,
        }
    })
}

async fn download(
    builder: reqwest::ClientBuilder,
    url: &str,
    limits: FetchLimits,
    observer: &dyn BringUpObserver,
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
    let mut url = reqwest::Url::parse(url).map_err(|error| rejected(clean(&error.to_string())))?;
    let mut redirects = 0;
    let mut response = loop {
        if url.scheme() != "https" {
            return Err(rejected("release URLs must use HTTPS".into()));
        }
        let response = tokio::time::timeout(limits.idle, client.get(url.clone()).send())
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
            break response;
        }
    };
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
   if path == '/encoded':
    body = gzip.compress(b'abcd'); s.sendall(('HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\nContent-Length: %d\r\n\r\n' % len(body)).encode() + body); return
   if path.startswith('/status/'):
    code = int(path.rsplit('/', 1)[1]); s.sendall(('HTTP/1.1 %d Status\r\nContent-Length: 0\r\n\r\n' % code).encode()); return
   if path == '/404': s.sendall(b'HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n'); return
   if path == '/headers': time.sleep(2)
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
        assert_eq!(
            server.get("/redirect/4", limits(), &cancel).unwrap(),
            b"abcd"
        );
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
            assert!(
                matches!(server.get(path, FetchLimits { idle: Duration::from_millis(80), ..limits() }, &cancel), Err(FetchError::TemporarilyUnavailable(reason)) if reason.contains("idle"))
            );
            assert!(start.elapsed() < Duration::from_millis(500));
        }
        for path in ["/drip", "/slowredirect/4"] {
            let start = Instant::now();
            assert!(
                matches!(server.get(path, FetchLimits { total: Duration::from_millis(130), idle: Duration::from_secs(1), ..limits() }, &cancel), Err(FetchError::TemporarilyUnavailable(reason)) if reason.contains("deadline"))
            );
            assert!(start.elapsed() < Duration::from_millis(400));
        }
    }
    #[test]
    fn each_redirect_response_resets_idle_but_not_the_total_deadline() {
        let server = Server::start();
        let bytes = server
            .get(
                "/slowredirect/4",
                FetchLimits {
                    idle: Duration::from_millis(100),
                    ..limits()
                },
                &Cancel::new(),
            )
            .unwrap();
        assert_eq!(bytes, b"abcd");
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
}
