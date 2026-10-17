//! What the user's terminal can do. Only color depth for now (including "no
//! color at all") -- that is the one capability where guessing wrong is
//! visible immediately (a truecolor escape on a 16-color terminal paints the
//! wrong color or nothing at all).

/// How many colors the terminal can show.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ColorDepth {
    /// 24-bit color (`38;2;r;g;b`).
    Truecolor,
    /// The 256-entry xterm palette (`38;5;n`).
    Indexed256,
    /// The basic 16 colors only (`30..37`/`90..97`).
    Basic16,
    /// No colour at all (`TERM=dumb`, `vt100`, `*-mono`, `*-m`): attributes only.
    Mono,
}

/// Capabilities of the terminal we draw into.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TermCaps {
    pub color: ColorDepth,
}

impl TermCaps {
    /// Read the capabilities out of the environment: `COLORTERM` is the
    /// truecolor signal, `TERM` carries the 256-color hint. Anything we do
    /// not recognize is treated as a 16-color terminal -- the safe floor.
    pub fn detect(term: Option<&str>, colorterm: Option<&str>) -> TermCaps {
        let term_lc = term.unwrap_or_default().to_ascii_lowercase();
        if term_lc == "dumb"
            || term_lc.starts_with("vt1")
            || term_lc.starts_with("vt2")
            || term_lc.ends_with("-m")
            || term_lc.contains("-mono")
        {
            return TermCaps {
                color: ColorDepth::Mono,
            };
        }
        let colorterm = colorterm.unwrap_or_default().to_ascii_lowercase();
        if colorterm.contains("truecolor") || colorterm.contains("24bit") {
            return TermCaps {
                color: ColorDepth::Truecolor,
            };
        }
        let term = term.unwrap_or_default().to_ascii_lowercase();
        // A terminfo `*-direct` entry declares direct 24-bit color. It is
        // checked before "256color" on purpose: entries like
        // `xterm-direct256` carry both spellings, and the direct one wins.
        if term.contains("direct") {
            return TermCaps {
                color: ColorDepth::Truecolor,
            };
        }
        if term.contains("256color") {
            return TermCaps {
                color: ColorDepth::Indexed256,
            };
        }
        TermCaps {
            color: ColorDepth::Basic16,
        }
    }

    /// A terminal with full color -- what the tests and the server-side
    /// repaint use (the repaint is consumed by our own emulator, which
    /// understands everything).
    pub const fn truecolor() -> TermCaps {
        TermCaps {
            color: ColorDepth::Truecolor,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn colorterm_truecolor_wins() {
        assert_eq!(
            TermCaps::detect(Some("xterm-256color"), Some("truecolor")).color,
            ColorDepth::Truecolor
        );
        assert_eq!(
            TermCaps::detect(Some("xterm"), Some("24bit")).color,
            ColorDepth::Truecolor
        );
    }

    #[test]
    fn term_name_gives_256_colors() {
        assert_eq!(
            TermCaps::detect(Some("screen-256color"), None).color,
            ColorDepth::Indexed256
        );
    }

    #[test]
    fn a_direct_term_name_gives_truecolor() {
        assert_eq!(
            TermCaps::detect(Some("xterm-direct"), None).color,
            ColorDepth::Truecolor
        );
        // `*-direct256` is a direct-color entry as well, despite the "256".
        assert_eq!(
            TermCaps::detect(Some("xterm-direct256"), None).color,
            ColorDepth::Truecolor
        );
    }

    #[test]
    fn unknown_environment_falls_back_to_sixteen_colors() {
        assert_eq!(TermCaps::detect(None, None).color, ColorDepth::Basic16);
    }

    #[test]
    fn terminals_without_colour_are_mono() {
        for term in ["dumb", "vt100", "vt220", "xterm-mono", "wy50-m"] {
            assert_eq!(
                TermCaps::detect(Some(term), Some("truecolor")).color,
                ColorDepth::Mono,
                "{term}"
            );
        }
        assert_ne!(
            TermCaps::detect(Some("xterm-256color"), None).color,
            ColorDepth::Mono
        );
        assert_ne!(
            TermCaps::detect(Some("linux"), None).color,
            ColorDepth::Mono
        );
    }
}
