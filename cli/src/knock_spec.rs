//! The knock steps of the command line (`tcp:7000+200ms+udp:8000:data`).
//! A knock is a secret: an error names where it went wrong, never what was
//! written there.

use knock::{KnockProtocol, KnockStep};

pub fn parse(spec: &str) -> Result<Vec<KnockStep>, String> {
    if spec.is_empty() {
        return Err("knock: no steps".into());
    }
    let mut steps: Vec<KnockStep> = Vec::new();
    let mut last_was_pause = false;
    for (i, element) in spec.split('+').enumerate() {
        let n = i + 1;
        let at = |what: &str| format!("knock element {n}: {what}");
        if let Some(rest) = element
            .strip_prefix("tcp:")
            .map(|r| (KnockProtocol::Tcp, r))
            .or_else(|| {
                element
                    .strip_prefix("udp:")
                    .map(|r| (KnockProtocol::Udp, r))
            })
        {
            let (protocol, rest) = rest;
            let (port, data) = match rest.split_once(':') {
                Some((p, d)) => (p, Some(d)),
                None => (rest, None),
            };
            let port = match port.parse::<u16>() {
                Ok(p) if p > 0 => p,
                _ => return Err(at("bad port")),
            };
            let payload = match (protocol, data) {
                (_, None) => Vec::new(),
                (KnockProtocol::Tcp, Some(_)) => return Err(at("a TCP knock carries no data")),
                (KnockProtocol::Udp, Some("")) => return Err(at("empty data")),
                (KnockProtocol::Udp, Some(d)) => match d.strip_prefix("0x") {
                    Some(hex) => decode_hex(hex).ok_or_else(|| {
                        at("data in 0x form must be hex with an even number of digits")
                    })?,
                    None => d.as_bytes().to_vec(),
                },
            };
            steps.push(KnockStep {
                protocol,
                port,
                payload,
                delay_after_ms: 0,
            });
            last_was_pause = false;
        } else if !element.is_empty() && element.bytes().all(|b| b.is_ascii_digit()) {
            return Err(at("a pause needs a unit: 200ms or 1s"));
        } else if let Some(ms) = pause_ms(element) {
            let ms = ms.ok_or_else(|| at("the pause is too long"))?;
            if steps.is_empty() {
                return Err("knock: a pause cannot come first".into());
            }
            if last_was_pause {
                return Err(at("two pauses in a row"));
            }
            steps.last_mut().expect("checked above").delay_after_ms = ms;
            last_was_pause = true;
        } else {
            return Err(at(
                "expected tcp:PORT, udp:PORT[:DATA] or a pause like 200ms",
            ));
        }
    }
    Ok(steps)
}

/// `Some(Some(ms))` for a pause, `Some(None)` for a pause too long for `u32`,
/// `None` when `element` is not a pause at all.
fn pause_ms(element: &str) -> Option<Option<u32>> {
    let (digits, scale) = match element.strip_suffix("ms") {
        Some(d) => (d, 1u64),
        None => (element.strip_suffix('s')?, 1000u64),
    };
    if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    Some(
        digits
            .parse::<u64>()
            .ok()
            .and_then(|v| v.checked_mul(scale))
            .and_then(|v| u32::try_from(v).ok()),
    )
}

fn decode_hex(hex: &str) -> Option<Vec<u8>> {
    if hex.is_empty() || !hex.len().is_multiple_of(2) {
        return None;
    }
    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(hex.get(i..i + 2)?, 16).ok())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use knock::{KnockProtocol::*, KnockStep};

    fn step(
        protocol: knock::KnockProtocol,
        port: u16,
        payload: &[u8],
        delay_after_ms: u32,
    ) -> KnockStep {
        KnockStep {
            protocol,
            port,
            payload: payload.to_vec(),
            delay_after_ms,
        }
    }

    #[test]
    fn steps_and_pauses_read_left_to_right() {
        assert_eq!(
            parse("tcp:7000+200ms+udp:8000+1s+tcp:9000").unwrap(),
            vec![
                step(Tcp, 7000, b"", 200),
                step(Udp, 8000, b"", 1000),
                step(Tcp, 9000, b"", 0)
            ]
        );
    }

    #[test]
    fn udp_data_runs_to_the_end_of_the_step_and_may_hold_colons() {
        assert_eq!(
            parse("udp:8000:a:b").unwrap(),
            vec![step(Udp, 8000, b"a:b", 0)]
        );
    }

    #[test]
    fn hex_data_is_decoded() {
        assert_eq!(
            parse("udp:8000:0x2c2b00ff").unwrap(),
            vec![step(Udp, 8000, &[0x2c, 0x2b, 0x00, 0xff], 0)]
        );
    }

    #[test]
    fn every_mistake_is_named_by_position() {
        let cases = [
            ("", "knock: no steps"),
            ("200ms+tcp:1", "knock: a pause cannot come first"),
            ("tcp:1+200ms+1s", "knock element 3: two pauses in a row"),
            (
                "tcp:1+200",
                "knock element 2: a pause needs a unit: 200ms or 1s",
            ),
            ("tcp:1:x", "knock element 1: a TCP knock carries no data"),
            ("udp:0", "knock element 1: bad port"),
            ("udp:70000", "knock element 1: bad port"),
            (
                "udp:1:0xabc",
                "knock element 1: data in 0x form must be hex with an even number of digits",
            ),
            ("udp:1:", "knock element 1: empty data"),
            (
                "tcp:1+99999999999ms",
                "knock element 2: the pause is too long",
            ),
            (
                "icmp:1",
                "knock element 1: expected tcp:PORT, udp:PORT[:DATA] or a pause like 200ms",
            ),
        ];
        for (spec, want) in cases {
            assert_eq!(parse(spec).unwrap_err(), want, "{spec}");
        }
    }

    #[test]
    fn a_knock_error_never_repeats_the_data() {
        let err = parse("udp:8000:s3cr3t+tcp:1:s3cr3t").unwrap_err();
        assert!(!err.contains("s3cr3t"), "{err}");
    }
}
