//! Identity-bound Darwin process ownership and personal PTY cleanup.
mod scope;

pub(super) const CAPACITY: usize = 4096;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Failure {
    Errno(i32),
    Mach(i32),
    Invalid,
    Capacity,
    LostBinding,
    Leader,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct Identity {
    pub pid: i32,
    pub unique: u64,
    pub version: u32,
}
impl Identity {
    fn valid(self) -> bool {
        self.pid > 0 && self.unique != 0
    }
    fn same_process(self, other: Self) -> bool {
        self.pid == other.pid && self.unique == other.unique
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Class {
    Session(i32),
    /// Exact short-BSD zombie state bracketed by matching identities.
    Zombie,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct Classified {
    pub identity: Identity,
    pub class: Class,
}

/// Only a reviewed native prepare path may construct production qualification.
/// The native constructor checks a compiled source-contract row and real APIs.
pub(super) struct QualifiedDarwin {
    contract: &'static str,
}

pub(super) struct Registration<W> {
    pub identity: Identity,
    pub cookie: u64,
    pub handle: W,
}
#[derive(Clone, Copy, Debug)]
pub(super) struct ExitEvent {
    pub pid: i32,
    pub cookie: u64,
    pub process_filter: bool,
    pub note_exit: bool,
    pub error: bool,
}
pub(super) struct SignalToken<T> {
    pub identity: Identity,
    pub sid: i32,
    pub handle: T,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Signal {
    Hup,
    Kill,
}

/// Each method owns the complete bracket/receipt it names. Errors never carry
/// zero-filled success data. Native adapters must dispose failed acquisitions.
pub(super) trait Ops<C> {
    type Watch;
    type Token;
    fn baseline(&mut self) -> Result<Vec<Classified>, Failure>;
    fn raw_all(&mut self, pids: &mut [i32; CAPACITY]) -> Result<usize, Failure>;
    fn confirm(&mut self, identity: Identity) -> Result<Identity, Failure>;
    fn classify(&mut self, pid: i32) -> Result<Classified, Failure>;
    fn bind_exit(
        &mut self,
        process: Classified,
        cookie: u64,
    ) -> Result<Registration<Self::Watch>, Failure>;
    fn observe_exit(&mut self, watch: &mut Self::Watch) -> Result<Option<ExitEvent>, Failure>;
    fn acquire_signal_token(
        &mut self,
        identity: Identity,
        sid: i32,
    ) -> Result<SignalToken<Self::Token>, Failure>;
    fn signal_exact(&mut self, token: &Self::Token, signal: Signal) -> Result<(), Failure>;
    /// Non-consuming, exclusively owned leader observation.
    fn observe_leader(&mut self, child: &mut C) -> Result<Option<i32>, Failure>;
    fn reap_leader(&mut self, child: &mut C) -> Result<i32, Failure>;
}

#[cfg(test)]
mod tests;

#[cfg(target_os = "macos")]
mod native;
#[cfg(target_os = "macos")]
pub(crate) use native::{own_child, prepare};
#[cfg(all(test, target_os = "macos"))]
mod native_tests;

/// Finite reviewed runtime candidates, pending actual production-path CI. The
/// public source tag and observed patched builds are deliberately separate.
#[derive(Debug, PartialEq, Eq)]
struct RuntimeContract {
    id: &'static str,
    release: &'static str,
    build: &'static str,
    kernel_token: &'static str,
    machine: &'static str,
    native_arch: &'static str,
}
const RUNTIME_CONTRACTS: [RuntimeContract; 2] = [
    RuntimeContract {
        id: "xnu-11417.140.69-darwin24.6.0-24H232-arm64-vmapple",
        release: "24.6.0",
        build: "24H232",
        kernel_token: "root:xnu-11417.140.69.713.47~2/RELEASE_ARM64_VMAPPLE",
        machine: "arm64",
        native_arch: "aarch64",
    },
    RuntimeContract {
        id: "xnu-11417.140.69-darwin24.6.0-24G830-x86_64",
        release: "24.6.0",
        build: "24G830",
        kernel_token: "root:xnu-11417.140.69.711.44~1/RELEASE_X86_64",
        machine: "x86_64",
        native_arch: "x86_64",
    },
];
#[cfg(test)]
impl RuntimeContract {
    fn receipt(&self) -> String {
        format!(
            "darwin223 public_source=xnu-11417.140.69 runtime_release={} os_build={} kernel_build={} machine={} native_arch={} premise=conditional",
            self.release, self.build, self.kernel_token.trim_start_matches("root:xnu-"),
            self.machine, self.native_arch,
        )
    }
}
fn runtime_contract(
    release: &str,
    version: &str,
    build: &str,
    machine: &str,
    native_arch: &str,
) -> Option<&'static RuntimeContract> {
    let mut tokens = version
        .split_ascii_whitespace()
        .filter(|word| word.starts_with("root:xnu-"));
    let token = tokens.next()?;
    if tokens.next().is_some() {
        return None;
    }
    RUNTIME_CONTRACTS.iter().find(|row| {
        release == row.release
            && build == row.build
            && token == row.kernel_token
            && machine == row.machine
            && native_arch == row.native_arch
    })
}
