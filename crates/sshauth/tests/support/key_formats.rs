//! Generated container conversions used only by private-key format tests.
use std::{
    path::Path,
    process::{Child, Command, Stdio},
    time::{Duration, Instant},
};

struct OwnedChild(Child);
impl Drop for OwnedChild {
    fn drop(&mut self) {
        if !matches!(self.0.try_wait(), Ok(Some(_))) {
            let _ = self.0.kill();
        }
        let _ = self.0.wait();
    }
}

/// OpenSSL converts only generated files supplied by the test. No private
/// material reaches stdout, stderr, command diagnostics, or personal stores.
pub fn openssl(input: &Path, output: &Path, args: &[&str]) {
    let mut child = OwnedChild(
        Command::new("openssl")
            .args(args)
            .arg("-in")
            .arg(input)
            .arg("-out")
            .arg(output)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("OpenSSL must be installed for generated container tests"),
    );
    let started = Instant::now();
    loop {
        if let Some(status) = child.0.try_wait().expect("poll fixture converter") {
            assert!(status.success(), "generated container conversion failed");
            return;
        }
        assert!(
            started.elapsed() < Duration::from_secs(5),
            "fixture converter timed out"
        );
        std::thread::sleep(Duration::from_millis(10));
    }
}
