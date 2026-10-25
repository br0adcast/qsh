//! Small, single-line startup diagnostics. Never pass credential contents here.
use std::io;
use std::path::Path;

/// Escape terminal/line controls and bound the encoded message to 1024 bytes.
pub fn diagnostic(text: &str) -> String {
    escaped(text, 1024)
}

fn escaped(text: &str, limit: usize) -> String {
    const TRUNCATED: &str = "[truncated]";
    let mut out = String::new();
    for c in text.chars() {
        let encoded = if c.is_control()
            || matches!(c, '\u{061c}' | '\u{200e}' | '\u{200f}' | '\u{2028}'..='\u{202e}' | '\u{2066}'..='\u{2069}')
        {
            c.escape_default().to_string()
        } else {
            c.to_string()
        };
        if out.len() + encoded.len() + TRUNCATED.len() > limit {
            out.push_str(TRUNCATED);
            break;
        }
        out.push_str(&encoded);
    }
    out
}

/// Attach the authoritative failing component, retaining the error kind.
/// Cap path and reason separately so a long path cannot hide the condition.
/// Contextual errors retain ErrorKind and OS-code text, but raw_os_error() is
/// None: callers must not use that accessor to recover an underlying errno.
pub fn path_error(path: &Path, operation: &str, error: io::Error) -> io::Error {
    io::Error::new(
        error.kind(),
        format!(
            "{} {}: {}",
            escaped(operation, 128),
            escaped(&format!("{path:?}"), 384),
            escaped(&error.to_string(), 384)
        ),
    )
}
