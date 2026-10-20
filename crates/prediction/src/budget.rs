//! Per-episode speculation limits. Authoritative frame storage is owned by the terminal.

pub(crate) const MAX_BYTES: usize = 4 * 1024 * 1024;
pub(crate) const MAX_CURSORS: usize = 64;
pub(crate) const MAX_WORK: usize = 65_536;

#[derive(Debug)]
pub(crate) struct Exhausted;
pub(crate) type Result<T = ()> = std::result::Result<T, Exhausted>;

#[cfg(test)]
#[derive(Clone, Copy)]
pub(crate) struct Limits {
    pub(crate) bytes: usize,
    pub(crate) work: usize,
    pub(crate) cursors: usize,
}
#[cfg(test)]
impl Default for Limits {
    fn default() -> Self {
        Self {
            bytes: MAX_BYTES,
            work: MAX_WORK,
            cursors: MAX_CURSORS,
        }
    }
}

#[derive(Default)]
pub(crate) struct Budget {
    #[cfg(test)]
    pub(crate) limits: Limits,
    #[cfg(test)]
    pub(crate) peak_bytes: usize,
    pub(crate) bytes: usize,
    pub(crate) used: usize,
    // Reserve destruction/accounting work when a row is allocated. Fallback can
    // always release its nested vectors after the ordinary allowance runs out.
    cleanup: usize,
}

impl Budget {
    fn max_bytes(&self) -> usize {
        #[cfg(test)]
        {
            self.limits.bytes
        }
        #[cfg(not(test))]
        {
            MAX_BYTES
        }
    }
    fn max_work(&self) -> usize {
        #[cfg(test)]
        {
            self.limits.work
        }
        #[cfg(not(test))]
        {
            MAX_WORK
        }
    }
    pub(crate) fn max_cursors(&self) -> usize {
        #[cfg(test)]
        {
            self.limits.cursors
        }
        #[cfg(not(test))]
        {
            MAX_CURSORS
        }
    }
    pub(crate) fn work(&mut self, units: usize) -> Result {
        if units > self.max_work().saturating_sub(self.used + self.cleanup) {
            return Err(Exhausted);
        }
        self.used += units;
        Ok(())
    }

    pub(crate) fn reserve_cleanup(&mut self, units: usize) -> Result {
        self.work(units)?;
        self.used -= units;
        self.cleanup += units;
        Ok(())
    }

    pub(crate) fn release_row(&mut self, bytes: usize, cells: usize) {
        self.bytes -= bytes;
        let units = 2 * cells + 1;
        self.cleanup -= units;
        self.used += units;
    }

    pub(crate) fn release_all(&mut self) {
        self.used += self.cleanup;
        self.cleanup = 0;
        self.bytes = 0;
    }

    pub(crate) fn acknowledged(&mut self) {
        self.used = 0;
    }
}

/// Reserve before Vec growth, charging the requested backing and a conservative
/// move cost. No unbounded amortized push is allowed on speculative vectors.
pub(crate) fn reserve<T>(vec: &mut Vec<T>, additional: usize, budget: &mut Budget) -> Result {
    let needed = vec.len().checked_add(additional).ok_or(Exhausted)?;
    if needed <= vec.capacity() {
        return Ok(());
    }
    let target = needed.max(vec.capacity().saturating_mul(2)).max(4);
    let bytes = (target - vec.capacity())
        .checked_mul(std::mem::size_of::<T>())
        .ok_or(Exhausted)?;
    if bytes > budget.max_bytes().saturating_sub(budget.bytes) {
        return Err(Exhausted);
    }
    budget.work(vec.capacity())?;
    let before = vec.capacity();
    vec.try_reserve_exact(target - vec.len())
        .map_err(|_| Exhausted)?;
    let actual = (vec.capacity() - before) * std::mem::size_of::<T>();
    budget.bytes += actual;
    #[cfg(test)]
    {
        budget.peak_bytes = budget.peak_bytes.max(budget.bytes);
    }
    if budget.bytes > budget.max_bytes() {
        return Err(Exhausted);
    }
    Ok(())
}

pub(crate) fn push<T>(vec: &mut Vec<T>, value: T, budget: &mut Budget) -> Result {
    budget.work(1)?;
    reserve(vec, 1, budget)?;
    vec.push(value);
    Ok(())
}
