//! Transfer progress before entering the terminal session.

use std::io::{self, IsTerminal, Write};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use bringup::{BringUpProgress, BringUpStage};

pub(crate) struct InstallProgress {
    background: bool,
    state: Mutex<Progress>,
}

impl InstallProgress {
    pub(crate) fn new(background: bool) -> Self {
        Self {
            background,
            state: Mutex::new(Progress::default()),
        }
    }
}

impl bringup::BringUpObserver for InstallProgress {
    fn on_progress(&self, event: BringUpProgress) {
        if self.background {
            return;
        }
        let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        let mut out = io::stderr().lock();
        let interactive = out.is_terminal()
            && std::env::var("TERM").is_ok_and(|term| term != "dumb" && !term.is_empty());
        let width = crate::tty::window_size(libc::STDERR_FILENO)
            .map(|(cols, _)| usize::from(cols))
            .unwrap_or(80);
        let utf8 = crate::window::utf8_locale(
            std::env::var("LC_ALL").ok().as_deref(),
            std::env::var("LC_CTYPE").ok().as_deref(),
            std::env::var("LANG").ok().as_deref(),
        );
        let _ = state.update(
            &mut out,
            event,
            Style {
                interactive,
                utf8,
                width,
            },
        );
    }
}

impl Drop for InstallProgress {
    fn drop(&mut self) {
        // An interrupted transfer must not leave the following error message
        // on the progress line, and must not claim the transfer completed.
        let state = self.state.get_mut().unwrap_or_else(|e| e.into_inner());
        let _ = state.finish_line(&mut io::stderr().lock());
    }
}

#[derive(Clone, Copy)]
struct Style {
    interactive: bool,
    utf8: bool,
    width: usize,
}

#[derive(Default)]
struct Progress {
    last: Option<(BringUpStage, Instant)>,
    line_open: bool,
}

impl Progress {
    fn finish_line(&mut self, out: &mut impl Write) -> io::Result<()> {
        if self.line_open {
            writeln!(out)?;
            out.flush()?;
            self.line_open = false;
        }
        Ok(())
    }

    fn update(
        &mut self,
        out: &mut impl Write,
        event: BringUpProgress,
        style: Style,
    ) -> io::Result<()> {
        let Style {
            interactive,
            utf8,
            width,
        } = style;
        if !matches!(
            event.stage,
            BringUpStage::Downloading | BringUpStage::Uploading
        ) {
            return Ok(());
        }
        let same_stage = self.last.is_some_and(|(stage, _)| stage == event.stage);
        if !event.finished
            && self.last.is_some_and(|(stage, at)| {
                stage == event.stage && (!interactive || at.elapsed() < Duration::from_millis(100))
            })
        {
            return Ok(());
        }
        if !same_stage {
            self.finish_line(out)?;
        }
        let line = transfer_line(
            event,
            if interactive {
                width.saturating_sub(1)
            } else {
                usize::MAX
            },
            interactive,
            utf8,
        );
        if interactive {
            write!(out, "\r\x1b[2K")?;
            write!(out, "{line}")?;
            self.line_open = true;
            if event.finished {
                self.finish_line(out)?;
            }
        } else {
            writeln!(out, "{line}")?;
        }
        out.flush()?;
        self.last = Some((event.stage, Instant::now()));
        Ok(())
    }
}

fn size(bytes: u64) -> String {
    for (unit, scale) in [("GiB", 1_u64 << 30), ("MiB", 1 << 20), ("KiB", 1 << 10)] {
        if bytes >= scale {
            return format!("{:.1} {unit}", bytes as f64 / scale as f64);
        }
    }
    format!("{bytes} B")
}

fn transfer_line(event: BringUpProgress, width: usize, bar: bool, utf8: bool) -> String {
    let stage = if event.stage == BringUpStage::Downloading {
        "Downloading"
    } else {
        "Uploading"
    };
    let label = format!("  {stage} qshd");
    let done = if event.finished { "  done" } else { "" };
    let (detail, percent) = match event.total.filter(|total| *total > 0) {
        Some(total) => {
            let percent =
                (u128::from(event.completed.min(total)) * 100 / u128::from(total)) as usize;
            (
                format!(
                    "{percent:3}%  {} / {}{done}",
                    size(event.completed),
                    size(total)
                ),
                Some(percent),
            )
        }
        None => (format!("{}{done}", size(event.completed)), None),
    };
    let plain = format!("{label}  {detail}");
    let room = width.saturating_sub(plain.len() + 4);
    let text = if let Some(percent) = percent.filter(|_| bar && room >= 6) {
        let filled = room * percent / 100;
        let (full, empty) = if utf8 { ("━", "─") } else { ("=", "-") };
        format!(
            "{label}  [{}{}]  {detail}",
            full.repeat(filled),
            empty.repeat(room - filled)
        )
    } else if plain.len() > width {
        // Keep the phase and percentage visible on narrow terminals.
        let compact = percent.map_or_else(|| size(event.completed), |p| format!("{p}%"));
        format!("{stage} {compact}{done}")
    } else {
        plain
    };
    text.chars().take(width).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn event(completed: u64, total: Option<u64>, finished: bool) -> BringUpProgress {
        BringUpProgress {
            stage: BringUpStage::Downloading,
            completed,
            total,
            finished,
        }
    }

    #[test]
    fn progress_uses_readable_sizes_and_fits_narrow_terminals() {
        let progress = event(5 << 20, Some(10 << 20), false);
        let line = transfer_line(progress, 79, true, true);
        assert!(line.contains("50%"));
        assert!(line.contains("5.0 MiB / 10.0 MiB"));
        assert!(line.contains('━'));
        for width in [0, 1, 10, 20, 40, 79] {
            assert!(transfer_line(progress, width, true, true).chars().count() <= width);
        }
        assert!(transfer_line(progress, 30, true, false).contains("50%"));
    }

    #[test]
    fn progress_bar_uses_the_available_terminal_width() {
        for stage in [BringUpStage::Downloading, BringUpStage::Uploading] {
            for utf8 in [false, true] {
                for completed in [0, 5 << 20, 10 << 20] {
                    let mut progress = event(completed, Some(10 << 20), completed == 10 << 20);
                    progress.stage = stage;
                    for width in [63, 79, 119, 159] {
                        let line = transfer_line(progress, width, true, utf8);
                        assert_eq!(line.chars().count(), width, "unused space: {line}");
                        assert!(line.contains('[') && line.contains(']'));
                    }
                }
            }
        }
    }

    #[test]
    fn redirected_progress_has_no_escapes_or_repeated_intermediate_lines() {
        let mut state = Progress::default();
        let mut output = Vec::new();
        for n in 0..=10 {
            state
                .update(
                    &mut output,
                    event(n << 20, Some(10 << 20), n == 10),
                    Style {
                        interactive: false,
                        utf8: false,
                        width: 80,
                    },
                )
                .unwrap();
        }
        let text = String::from_utf8(output).unwrap();
        assert_eq!(text.lines().count(), 2);
        assert!(!text.contains(['\r', '\x1b']));
        assert!(text.ends_with("10.0 MiB / 10.0 MiB  done\n"));
    }

    #[test]
    fn unfinished_progress_ends_cleanly_without_claiming_success() {
        let mut state = Progress::default();
        let mut output = Vec::new();
        state
            .update(
                &mut output,
                event(1024, None, false),
                Style {
                    interactive: true,
                    utf8: false,
                    width: 40,
                },
            )
            .unwrap();
        assert!(!output.ends_with(b"\n"));
        state.finish_line(&mut output).unwrap();
        state.finish_line(&mut output).unwrap();
        let text = String::from_utf8(output).unwrap();
        assert!(text.ends_with("1.0 KiB\n"));
        assert!(!text.contains("done"));
        assert!(!text.contains("%"));
        assert_eq!(text.matches('\n').count(), 1);
    }

    #[test]
    fn interactive_progress_updates_in_place_and_finishes_each_phase() {
        let mut state = Progress::default();
        let mut output = Vec::new();
        let style = Style {
            interactive: true,
            utf8: true,
            width: 80,
        };
        state
            .update(&mut output, event(0, Some(1024), false), style)
            .unwrap();
        state
            .update(&mut output, event(1024, Some(1024), true), style)
            .unwrap();
        let mut upload = event(0, Some(1024), false);
        upload.stage = BringUpStage::Uploading;
        state.update(&mut output, upload, style).unwrap();
        state.finish_line(&mut output).unwrap();
        let text = String::from_utf8(output).unwrap();
        assert_eq!(text.matches('\n').count(), 2);
        assert_eq!(text.matches("\r\x1b[2K").count(), 3);
        assert_eq!(
            text.matches('\x1b').count(),
            3,
            "only line erasure uses escapes"
        );
        assert!(text.contains("Uploading qshd"));
        assert!(text.contains("100%"));
    }

    #[test]
    fn unknown_zero_and_oversized_totals_are_safe() {
        for progress in [
            event(10, None, true),
            event(10, Some(0), true),
            event(u64::MAX, Some(1), true),
        ] {
            let line = transfer_line(progress, 79, true, false);
            assert!(line.contains("done"));
            assert!(!line.contains("NaN"));
            assert!(line.chars().count() <= 79);
        }
    }
}
