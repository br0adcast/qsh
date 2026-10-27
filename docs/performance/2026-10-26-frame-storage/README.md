# Frame storage runs: 2026-10-26 (superseded)

These records are kept as they were taken. They are superseded by
[`../2026-10-27-frame-storage/`](../2026-10-27-frame-storage/), for these
reasons:

- **The time field is elapsed time.** `cpu_us_per_step` was measured with
  a monotonic clock, so it includes any time the process was descheduled.
  It is not CPU time. Read it as elapsed time per step.
- **The bookkeeping was inside the samples.** The harness grew its own
  result vectors during the measured steps. Some allocation calls, bytes and
  peaks therefore include the recorder, and the live-heap figures include
  its vectors. These are a few kilobytes, far below one grid, so the
  grid-allocation figures are unaffected. The exact byte, peak and retained
  figures are not session-only measurements.
- **The change measured is `09236be`.** It did not yet bound every spare
  frame after a shrink. No workload here shrinks the display, so this does
  not change these figures.

In both musl builds of these runs, `memcmp` sits at the same offset, 27
modulo 64. Of the musl timings, these are the ones taken with matching
`memcmp` placement. See `../2026-10-27-frame-storage/profiles.md`.
