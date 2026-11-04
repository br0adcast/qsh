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

/// Reviewed public source bases under the conditional semantic-preservation premise.
/// Observed host metadata is evidence, never a replacement for this static authority.
#[derive(Debug, PartialEq, Eq)]
struct SourceFamily {
    id: &'static str,
    public_source: &'static str,
    base: &'static str,
    major: &'static str,
}
const SOURCE_FAMILIES: [SourceFamily; 2] = [
    SourceFamily {
        id: "xnu-10063.141.1-conditional-v1",
        public_source: "xnu-10063.141.1",
        base: "10063.141.1",
        major: "23",
    },
    SourceFamily {
        id: "xnu-11417.140.69-conditional-v1",
        public_source: "xnu-11417.140.69",
        base: "11417.140.69",
        major: "24",
    },
];
#[derive(Debug, PartialEq, Eq)]
struct ObservedRuntime {
    family: &'static SourceFamily,
    release: String,
    build: String,
    kernel_token: String,
    machine: String,
    native_arch: String,
}
#[cfg(test)]
impl ObservedRuntime {
    fn receipt(&self) -> String {
        format!(
            "darwin223 public_source={} runtime_release={} os_build={} kernel_build={} machine={} native_arch={} premise=conditional",
            self.family.public_source, self.release, self.build,
            self.kernel_token, self.machine, self.native_arch,
        )
    }
}
fn bounded_text(value: &str, limit: usize) -> bool {
    !value.is_empty()
        && value.len() <= limit
        && value.bytes().all(|byte| (b' '..=b'~').contains(&byte))
        && !value.starts_with(' ')
        && !value.ends_with(' ')
}
fn decimal(value: &str) -> bool {
    !value.is_empty() && value.bytes().all(|byte| byte.is_ascii_digit())
}
fn runtime_contract(
    release: &str,
    version: &str,
    build: &str,
    machine: &str,
    native_arch: &str,
) -> Option<ObservedRuntime> {
    if !bounded_text(release, 63)
        || !bounded_text(version, 511)
        || !bounded_text(build, 63)
        || !bounded_text(machine, 31)
        || !matches!(native_arch, "aarch64" | "x86_64")
    {
        return None;
    }
    let release_parts: Vec<_> = release.split('.').collect();
    if release_parts.len() != 3 || !release_parts.iter().all(|part| decimal(part)) {
        return None;
    }
    let prefix = format!("Darwin Kernel Version {release}: ");
    let rest = version.strip_prefix(&prefix)?;
    let (description, token) = rest.rsplit_once(' ')?;
    if description.trim().is_empty() || version.matches("root:xnu-").count() != 1 {
        return None;
    }
    let kernel = token.strip_prefix("root:xnu-")?;
    let (revision, flavor) = kernel.split_once('/')?;
    let (revision, build_number) = revision.split_once('~')?;
    if !decimal(build_number) {
        return None;
    }
    let parts: Vec<_> = revision.split('.').collect();
    if parts.len() < 3 || !parts.iter().all(|part| decimal(part)) {
        return None;
    }
    let family = SOURCE_FAMILIES
        .iter()
        .find(|family| family.base == parts[..3].join(".") && family.major == release_parts[0])?;
    let build_suffix = build.strip_prefix(family.major)?;
    if build_suffix.len() < 2
        || !build_suffix.as_bytes()[0].is_ascii_uppercase()
        || !build_suffix[1..]
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric())
    {
        return None;
    }
    let suffix = if machine == "arm64" && native_arch == "aarch64" {
        flavor.strip_prefix("RELEASE_ARM64")?
    } else if machine == "x86_64" && native_arch == "x86_64" {
        flavor.strip_prefix("RELEASE_X86_64")?
    } else {
        return None;
    };
    if !suffix.is_empty()
        && !suffix.strip_prefix('_')?.split('_').all(|component| {
            !component.is_empty()
                && component
                    .bytes()
                    .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit())
        })
    {
        return None;
    }
    Some(ObservedRuntime {
        family,
        release: release.into(),
        build: build.into(),
        kernel_token: kernel.into(),
        machine: machine.into(),
        native_arch: native_arch.into(),
    })
}

mod keeper;
mod keeper_helper;
mod keeper_pty;
#[cfg(test)]
mod keeper_tests;

#[cfg(target_os = "macos")]
pub(crate) fn keeper_helper_entry(args: &[std::ffi::OsString]) -> Option<std::io::Result<()>> {
    keeper_helper::entry(args)
}
