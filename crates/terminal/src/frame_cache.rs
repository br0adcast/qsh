//! Bounded, core-owned extraction cache. Returned frames never own its cells.
use std::mem::size_of;

use alacritty_terminal::term::color::{Colors, COUNT};
use alacritty_terminal::term::TermDamage;

use super::*;

/// Retained cache cells only; Frame/palette metadata and caller frames are separate.
pub(super) const MAX_CELL_BYTES: usize = 1 << 20;

pub(super) struct CachedFrame {
    pub frame: Frame,
    colors: Colors,
    pub fresh: bool,
}

#[cfg(test)]
#[derive(Default)]
pub(super) struct CacheCounts {
    pub full: usize,
    pub partial: usize,
    pub rebuilds: usize,
    pub promoted: usize,
    pub colors_changed: usize,
}

fn cells_fit(cells: usize) -> bool {
    cells
        .checked_mul(size_of::<Cell>())
        .is_some_and(|bytes| bytes <= MAX_CELL_BYTES)
}

impl CachedFrame {
    pub(super) fn colors_match(&self, colors: &Colors) -> bool {
        (0..COUNT).all(|index| self.colors[index] == colors[index])
    }
}

impl TerminalCore {
    /// A snapshot using bounded row-damage reuse. The immutable [`Self::frame`]
    /// remains a full extraction. Cache cells are independent of every result.
    ///
    /// At most 1 MiB of cache cell capacity is retained, excluding small cache
    /// metadata/palette allocations. Larger grids use full extraction. Geometry
    /// changes release the old cache; a later proper partial update rebuilds it.
    pub fn frame_cached(&mut self) -> Frame {
        let mut frame = self.empty_frame();
        self.frame_into_cached(&mut frame);
        frame
    }

    /// [`Self::frame_cached`] into caller-owned reusable storage. Every field is
    /// replaced, including metadata when no visible row has changed. Full damage
    /// and partial damage covering every visible row bypass cache copying.
    pub fn frame_into_cached(&mut self, output: &mut Frame) {
        let cols = self.term.columns();
        let rows = self.term.screen_lines();
        let needed = cols.checked_mul(rows);
        if self.frame_cache.as_ref().is_some_and(|cache| {
            usize::from(cache.frame.cols) != cols
                || usize::from(cache.frame.rows) != rows
                || !cells_fit(cache.frame.cells.capacity())
        }) {
            self.frame_cache = None;
        }
        if !needed.is_some_and(cells_fit) || rows > usize::from(terminal_size::MAX_TERMINAL_ROWS) {
            self.frame_cache = None;
            self.frame_into(output);
            return;
        }

        // No row mask, palette comparison or mirror handling on raw Full.
        let (damaged, invalid_row) = match self.term.damage() {
            TermDamage::Full => {
                self.term.reset_damage();
                self.cached_full(output);
                return;
            }
            TermDamage::Partial(lines) => {
                let mut mask = [false; terminal_size::MAX_TERMINAL_ROWS as usize];
                let mut invalid = false;
                for line in lines {
                    if line.line < rows {
                        mask[line.line] = true;
                    } else {
                        invalid = true;
                    }
                }
                (mask, invalid)
            }
        };
        self.term.reset_damage();
        if invalid_row || damaged[..rows].iter().all(|changed| *changed) {
            #[cfg(test)]
            {
                self.cache_counts.promoted += usize::from(!invalid_row);
            }
            self.cached_full(output);
            return;
        }
        let any = damaged[..rows].iter().any(|changed| *changed);
        let fresh = self.frame_cache.as_ref().is_some_and(|cache| cache.fresh);
        if !fresh && !any {
            self.cached_full(output);
            return;
        }
        if fresh
            && !self
                .frame_cache
                .as_ref()
                .expect("fresh cache exists")
                .colors_match(self.term.colors())
        {
            #[cfg(test)]
            {
                self.cache_counts.colors_changed += 1;
            }
            self.cached_full(output);
            return;
        }

        #[cfg(test)]
        let mut damaged = damaged;
        let mut cache = match self.frame_cache.take() {
            Some(cache) => cache,
            None => {
                // Allocate from the model, never clone caller/prediction storage.
                let frame = self.frame();
                if !cells_fit(frame.cells.capacity()) {
                    self.frame_into(output);
                    return;
                }
                Box::new(CachedFrame {
                    frame,
                    colors: *self.term.colors(),
                    fresh: true,
                })
            }
        };
        if !fresh {
            if !cache.fresh {
                self.frame_into(&mut cache.frame);
            }
            cache.colors = *self.term.colors();
            cache.fresh = true;
            #[cfg(test)]
            {
                self.cache_counts.rebuilds += 1;
            }
        } else {
            #[cfg(test)]
            if let Some(row) = self.cache_omit_row {
                if let Some(changed) = damaged.get_mut(row) {
                    *changed = false;
                }
            }
            let offset = self.term.grid().display_offset() as i32;
            let colors = self.term.colors();
            for (row, changed) in damaged[..rows].iter().enumerate() {
                if !changed {
                    continue;
                }
                for col in 0..cols {
                    let cell =
                        &self.term.grid()[Point::new(Line(row as i32 - offset), Column(col))];
                    cache.frame.cells[row * cols + col] = Cell {
                        ch: cell.c,
                        combining: CombiningMarks::from_slice(cell.zerowidth().unwrap_or_default()),
                        fg: convert_color(cell.fg, colors),
                        bg: convert_color(cell.bg, colors),
                        flags: convert_flags(cell.flags),
                    };
                }
            }
            self.cached_metadata(&mut cache.frame);
            #[cfg(test)]
            {
                self.cache_counts.partial += usize::from(any);
            }
        }
        if !cells_fit(cache.frame.cells.capacity()) {
            // Never retain allocator capacity above the cell budget.
            drop(cache);
            self.frame_into(output);
            return;
        }
        output.clone_from(&cache.frame);
        self.frame_cache = Some(cache);
    }

    fn cached_metadata(&self, frame: &mut Frame) {
        let palette = snapshot_palette(self.term.colors());
        if *frame.palette != palette {
            match Arc::get_mut(&mut frame.palette) {
                Some(owned) => *owned = palette,
                None => frame.palette = Arc::new(palette),
            }
        }
        self.fill_metadata(frame);
    }

    fn cached_full(&mut self, output: &mut Frame) {
        self.invalidate_frame_cache();
        #[cfg(test)]
        {
            self.cache_counts.full += 1;
        }
        self.frame_into(output);
    }

    pub(super) fn invalidate_frame_cache(&mut self) {
        if let Some(cache) = &mut self.frame_cache {
            cache.fresh = false;
        }
    }
}
