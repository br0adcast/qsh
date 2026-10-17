//! The log line format: `YYYY-MM-DD HH:MM:SS.mmm UTC [pid] LEVEL component: text`.

use std::time::{SystemTime, UNIX_EPOCH};

/// One record's lines, without trailing newlines; multi-line text gives
/// several lines, each with the full header. Control characters other than
/// '\t' (C0, DEL, C1 -- U+0085 among them) and the Unicode line and
/// paragraph separators U+2028/U+2029 become '?': a viewer that breaks a
/// line on any of them must not see a line the record did not start.
pub fn format_lines(
    at: SystemTime,
    pid: u32,
    level: log::Level,
    component: &str,
    text: &str,
) -> Vec<String> {
    let header = format!(
        "{} [{}] {:<5} {}: ",
        timestamp(at),
        pid,
        level.as_str(),
        component
    );
    let body = |l: &str| -> String {
        let clean = l.chars().map(|c| if breaks_the_line(c) { '?' } else { c });
        let mut s = header.clone();
        s.extend(clean);
        s
    };
    let mut lines: Vec<String> = text.lines().map(body).collect();
    if lines.is_empty() {
        lines.push(header);
    }
    lines
}

/// Whether `c` may not stand in a log line as it is: every control
/// character but '\t', and U+2028/U+2029, which are not controls to
/// Unicode but end a line for some viewers.
pub fn breaks_the_line(c: char) -> bool {
    (c.is_control() && c != '\t') || c == '\u{2028}' || c == '\u{2029}'
}

/// "transport::driver_std" -> "transport"; "" -> "?".
pub fn component_of(target: &str) -> &str {
    let c = target.split("::").next().unwrap_or("");
    if c.is_empty() {
        "?"
    } else {
        c
    }
}

/// `YYYY-MM-DD HH:MM:SS.mmm UTC`; instants before the epoch clamp to it.
fn timestamp(at: SystemTime) -> String {
    let ms = at
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis())
        .unwrap_or(0);
    let secs = (ms / 1000) as i64;
    let (y, m, d) = civil_from_days(secs.div_euclid(86_400));
    let sod = secs.rem_euclid(86_400);
    format!(
        "{y:04}-{m:02}-{d:02} {:02}:{:02}:{:02}.{:03} UTC",
        sod / 3600,
        sod % 3600 / 60,
        sod % 60,
        ms % 1000
    )
}

/// Days since 1970-01-01 -> (year, month, day), proleptic Gregorian
/// (Howard Hinnant's civil_from_days).
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    let y = yoe + era * 400 + i64::from(m <= 2);
    (y, m, d)
}
