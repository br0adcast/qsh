//! Bounded ownership/mode validation before using remote filesystem objects.
use crate::{shell, BringUpError, ServerOs};

#[derive(Clone, Copy)]
pub(crate) enum Purpose {
    Execute,
    InstallDirectory,
    /// An absent or safe, non-symlink regular destination; execute is not required.
    InstallFile,
}

fn valid_path(path: &str) -> bool {
    path.starts_with('/') && path.len() <= 4096 && !path.chars().any(char::is_control)
}

pub(crate) fn command(path: &str, os: ServerOs, purpose: Purpose) -> Result<String, BringUpError> {
    if !valid_path(path) {
        return Err(refusal("invalid or oversized path"));
    }
    let os = match os {
        ServerOs::Linux => "linux",
        ServerOs::Darwin => "darwin",
    };
    let purpose = match purpose {
        Purpose::Execute => "execute",
        Purpose::InstallDirectory => "directory",
        Purpose::InstallFile => "file",
    };
    Ok(format!(
        "path={}; os={os}; purpose={purpose};\n{}",
        shell::quote(path),
        include_str!("trust.sh")
    ))
}

fn refusal(boundary: &str) -> BringUpError {
    let escaped = boundary
        .chars()
        .flat_map(char::escape_default)
        .collect::<String>();
    let boundary = crate::exec::escaped(&escaped, 300);
    BringUpError::Verify(format!("unsafe qshd path at {boundary}: correct ownership/permissions or install in a private owned directory"))
}

pub(crate) fn parse(code: i32, stdout: &str) -> Result<String, BringUpError> {
    if let Some(path) = stdout
        .strip_prefix("QSH-TRUST ")
        .and_then(|s| s.strip_suffix('\n'))
    {
        if code == 0 && valid_path(path) {
            return Ok(path.to_owned());
        }
    }
    let boundary = stdout
        .strip_prefix("QSH-REFUSE ")
        .and_then(|s| s.strip_suffix('\n'))
        .filter(|s| valid_path(s))
        .unwrap_or("metadata unavailable or malformed");
    Err(refusal(boundary))
}

#[cfg(test)]
#[path = "trust_tests.rs"]
mod tests;
