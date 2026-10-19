//! Turning a cell's appearance into SGR escapes, and downgrading colors the
//! terminal cannot show.

use terminal::{
    Color, Palette, FLAG_BOLD, FLAG_DIM, FLAG_HIDDEN, FLAG_ITALIC, FLAG_REVERSE, FLAG_UNDERLINE,
};

use crate::caps::{ColorDepth, TermCaps};

/// The part of a cell's appearance the renderer carries between writes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Style {
    pub fg: Color,
    pub bg: Color,
    pub flags: u16,
}

impl Style {
    /// Default appearance: default colors, no attributes -- the state a
    /// terminal is in right after `ESC [ 0 m`.
    pub fn default_style() -> Style {
        Style {
            fg: Color::Default,
            bg: Color::Default,
            flags: 0,
        }
    }
}

/// Append the escapes that take the terminal from `from` to `to`. Attributes
/// can only be added by SGR, never removed one by one in a portable way, so
/// dropping any attribute means a full `ESC [ 0 m` reset followed by whatever
/// `to` still needs.
pub fn write_sgr(out: &mut Vec<u8>, from: Style, to: Style, caps: TermCaps, palette: &Palette) {
    if from == to {
        return;
    }
    let dropped = from.flags & !to.flags != 0;
    let mut base = from;
    if dropped {
        out.extend_from_slice(b"\x1b[0m");
        base = Style::default_style();
        if base == to {
            return;
        }
    }
    if base.flags & FLAG_BOLD == 0 && to.flags & FLAG_BOLD != 0 {
        out.extend_from_slice(b"\x1b[1m");
    }
    if base.flags & FLAG_DIM == 0 && to.flags & FLAG_DIM != 0 {
        out.extend_from_slice(b"\x1b[2m");
    }
    if base.flags & FLAG_ITALIC == 0 && to.flags & FLAG_ITALIC != 0 {
        out.extend_from_slice(b"\x1b[3m");
    }
    if base.flags & FLAG_UNDERLINE == 0 && to.flags & FLAG_UNDERLINE != 0 {
        out.extend_from_slice(b"\x1b[4m");
    }
    if base.flags & FLAG_REVERSE == 0 && to.flags & FLAG_REVERSE != 0 {
        out.extend_from_slice(b"\x1b[7m");
    }
    if base.flags & FLAG_HIDDEN == 0 && to.flags & FLAG_HIDDEN != 0 {
        out.extend_from_slice(b"\x1b[8m");
    }
    if caps.color == ColorDepth::Mono {
        return;
    }
    if base.fg != to.fg {
        write_color(out, to.fg, true, caps, palette);
    }
    if base.bg != to.bg {
        write_color(out, to.bg, false, caps, palette);
    }
}

/// Write one color, degraded to what the terminal can show.
fn write_color(out: &mut Vec<u8>, color: Color, is_fg: bool, caps: TermCaps, palette: &Palette) {
    let color = degrade(color, caps, palette);
    match color {
        Color::Default => push_params(out, if is_fg { "39" } else { "49" }),
        Color::Indexed(i) if i < 8 => {
            let base = if is_fg { 30 } else { 40 };
            push_params(out, &format!("{}", base + i as u16));
        }
        Color::Indexed(i) if i < 16 => {
            let base = if is_fg { 90 } else { 100 };
            push_params(out, &format!("{}", base + (i - 8) as u16));
        }
        Color::Indexed(i) => {
            let lead = if is_fg { 38 } else { 48 };
            push_params(out, &format!("{lead};5;{i}"));
        }
        Color::Rgb(v) => {
            let lead = if is_fg { 38 } else { 48 };
            let (r, g, b) = ((v >> 16) & 0xff, (v >> 8) & 0xff, v & 0xff);
            push_params(out, &format!("{lead};2;{r};{g};{b}"));
        }
    }
}

/// Lower a color to what `caps` allows: nearest palette entry by squared RGB
/// distance. `Color::Default` never degrades -- the terminal's own default is
/// always available and is the one color we must not second-guess.
fn degrade(color: Color, caps: TermCaps, palette: &Palette) -> Color {
    match (caps.color, color) {
        (_, Color::Default) => Color::Default,
        (ColorDepth::Truecolor, c) => c,
        (ColorDepth::Indexed256, Color::Rgb(v)) => Color::Indexed(nearest(v, palette, 256)),
        (ColorDepth::Indexed256, c) => c,
        (ColorDepth::Basic16, Color::Rgb(v)) => Color::Indexed(nearest(v, palette, 16)),
        (ColorDepth::Basic16, Color::Indexed(i)) if i >= 16 => {
            Color::Indexed(nearest(palette.entries[i as usize], palette, 16))
        }
        (ColorDepth::Basic16, c) => c,
        (ColorDepth::Mono, _) => Color::Default,
    }
}

/// Index of the palette entry closest to `rgb` among the first `limit` ones.
fn nearest(rgb: u32, palette: &Palette, limit: usize) -> u8 {
    let (r, g, b) = ((rgb >> 16) & 0xff, (rgb >> 8) & 0xff, rgb & 0xff);
    let mut best = 0usize;
    let mut best_dist = u32::MAX;
    for (i, entry) in palette.entries.iter().take(limit).enumerate() {
        let (er, eg, eb) = ((entry >> 16) & 0xff, (entry >> 8) & 0xff, entry & 0xff);
        let dist = (r.abs_diff(er)).pow(2) + (g.abs_diff(eg)).pow(2) + (b.abs_diff(eb)).pow(2);
        if dist < best_dist {
            best_dist = dist;
            best = i;
        }
    }
    best as u8
}

/// Wrap SGR parameters into a complete escape.
fn push_params(out: &mut Vec<u8>, params: &str) {
    out.extend_from_slice(b"\x1b[");
    out.extend_from_slice(params.as_bytes());
    out.push(b'm');
}

#[cfg(test)]
mod tests {
    use super::*;
    use terminal::{Color, Palette};

    fn out_of(from: Style, to: Style, caps: TermCaps) -> String {
        let mut out = Vec::new();
        write_sgr(&mut out, from, to, caps, &Palette::xterm_default());
        String::from_utf8(out).expect("SGR output is ASCII")
    }

    #[test]
    fn no_change_writes_nothing() {
        let s = Style::default_style();
        assert_eq!(out_of(s, s, TermCaps::truecolor()), "");
    }

    #[test]
    fn dropping_an_attribute_resets_first() {
        let bold = Style {
            flags: terminal::FLAG_BOLD,
            ..Style::default_style()
        };
        // Bold -> plain cannot be expressed additively: reset, then nothing.
        assert_eq!(
            out_of(bold, Style::default_style(), TermCaps::truecolor()),
            "\x1b[0m"
        );
    }

    #[test]
    fn indexed_color_stays_indexed() {
        let red = Style {
            fg: Color::Indexed(1),
            ..Style::default_style()
        };
        assert_eq!(
            out_of(Style::default_style(), red, TermCaps::truecolor()),
            "\x1b[31m"
        );
        let bright = Style {
            fg: Color::Indexed(9),
            ..Style::default_style()
        };
        assert_eq!(
            out_of(Style::default_style(), bright, TermCaps::truecolor()),
            "\x1b[91m"
        );
        let high = Style {
            fg: Color::Indexed(200),
            ..Style::default_style()
        };
        assert_eq!(
            out_of(Style::default_style(), high, TermCaps::truecolor()),
            "\x1b[38;5;200m"
        );
    }

    #[test]
    fn truecolor_is_written_as_is() {
        let rgb = Style {
            fg: Color::Rgb(0x0001_0203),
            ..Style::default_style()
        };
        assert_eq!(
            out_of(Style::default_style(), rgb, TermCaps::truecolor()),
            "\x1b[38;2;1;2;3m"
        );
    }

    #[test]
    fn a_256_color_terminal_downgrades_rgb_to_the_nearest_entry() {
        let caps = TermCaps {
            color: ColorDepth::Indexed256,
        };
        // 0x5f/0x87/0xaf are cube components 1/2/3, i.e. palette entry
        // 16 + 36*1 + 6*2 + 3 = 67 exactly.
        let rgb = Style {
            fg: Color::Rgb(0x005f_87af),
            ..Style::default_style()
        };
        let written = out_of(Style::default_style(), rgb, caps);
        assert_eq!(written, "\x1b[38;5;67m");
        assert!(!written.contains("38;2;"), "must not use a 24-bit escape");
    }

    #[test]
    fn a_basic_index_keeps_its_compact_form_on_a_256_color_terminal() {
        let caps = TermCaps {
            color: ColorDepth::Indexed256,
        };
        let red = Style {
            fg: Color::Indexed(1),
            ..Style::default_style()
        };
        // The compact code is the same color and works on more terminals.
        assert_eq!(out_of(Style::default_style(), red, caps), "\x1b[31m");
    }

    #[test]
    fn a_16_color_terminal_downgrades_to_the_basic_palette() {
        let caps = TermCaps {
            color: ColorDepth::Basic16,
        };
        let far = Style {
            fg: Color::Indexed(200),
            ..Style::default_style()
        };
        let written = out_of(Style::default_style(), far, caps);
        assert!(
            written.starts_with("\x1b[3") || written.starts_with("\x1b[9"),
            "expected a basic color, got {written:?}"
        );
        assert!(
            !written.contains("38;5;"),
            "must not use a 256-color escape"
        );
    }

    #[test]
    fn default_color_is_written_as_the_terminal_default() {
        let red = Style {
            fg: Color::Indexed(1),
            ..Style::default_style()
        };
        assert_eq!(
            out_of(red, Style::default_style(), TermCaps::truecolor()),
            "\x1b[39m"
        );
    }

    #[test]
    fn a_mono_terminal_gets_no_colour_codes() {
        let caps = TermCaps {
            color: ColorDepth::Mono,
        };
        let palette = Palette::xterm_default();
        let mut out = Vec::new();
        let to = Style {
            fg: Color::Indexed(1),
            bg: Color::Rgb(0x112233),
            flags: terminal::FLAG_BOLD,
        };
        write_sgr(&mut out, Style::default_style(), to, caps, &palette);
        assert_eq!(
            out,
            b"\x1b[1m",
            "bold only: {:?}",
            String::from_utf8_lossy(&out)
        );
    }

    #[test]
    fn dim_is_sgr_2_and_dropping_it_resets() {
        let caps = TermCaps {
            color: ColorDepth::Basic16,
        };
        let palette = Palette::xterm_default();
        let mut out = Vec::new();
        let dim = Style {
            fg: Color::Default,
            bg: Color::Default,
            flags: terminal::FLAG_DIM,
        };
        write_sgr(&mut out, Style::default_style(), dim, caps, &palette);
        assert_eq!(out, b"\x1b[2m");
        let mut out = Vec::new();
        write_sgr(&mut out, dim, Style::default_style(), caps, &palette);
        assert_eq!(out, b"\x1b[0m");
    }
}
