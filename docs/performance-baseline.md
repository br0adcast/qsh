# CPU and latency baseline

`scripts/perf_baseline.py` is the owned procedure for measuring qsh and qshd
CPU, scheduling activity, traffic and latency before accepting quantified
performance claims. It records raw per-run data and the identity of the
measured binaries, so a later change can be compared on the same host with
dispersion rather than with single numbers.

It is a measurement procedure, not a test. It sets no thresholds and does not
run in ordinary CI; only its own accounting, ordering and isolation controls
(`scripts/tests/test_perf_baseline.py`) do. Wakeup and deadline behavior is
qualified by deterministic tests with controlled events and clocks next to the
code that schedules it, never by a latency bound on a shared CI runner.

The harness runs on Linux only: it reads `/proc`.

## What one run does

Every run is independent and starts from nothing:

- A private directory holds a generated Ed25519 key, `authorized_keys`, the
  host key and the logs. Nothing is read from or written to the invoking
  account's SSH keys, agent, known hosts, qsh configuration or daemon.
- `qshd serve` and every `qsh` get a fresh environment. Only `PATH` is
  inherited; `USER`/`LOGNAME` come from the password database. `HOME`, all
  `XDG_*` directories, `ZDOTDIR` and `HISTFILE=/dev/null` are private, and
  `BASH_ENV`/`ENV` point at `/dev/null`. The session shell is `/bin/sh` with
  empty startup files (the same isolation as the integration fixtures), and
  `HTTPS_PROXY` points at a closed port so no release check reaches the
  network. `SSH_AUTH_SOCK` and every other inherited variable are absent.
- The daemon counts as ready only when the UDP port it was given is held by
  that owned `qshd` process: every socket bound to the port must be in its
  descriptor table. A socket of any other process on that port, or a daemon
  that exited, fails the run before a client starts or any traffic is
  forwarded. The check is repeated before every client starts.
- A UDP relay owned by the harness sits between `qsh` and `qshd`. It counts
  the datagrams and bytes of this one session in each direction, timestamps
  each client datagram when it is received, and can drop everything to
  simulate an outage.
- `qsh` runs as a session leader on its own pseudo-terminal (120x40). One
  reader thread drains, counts and timestamps its output. The terminal's
  descriptors are owned from the moment they are opened, so a failed setup
  or spawn still closes them. The reader uses them only while it holds
  custody, and they are closed only after it has given custody back, even
  when its start was interrupted; a reader that does not stop fails the run
  and keeps them open.
- The harness makes itself a child subreaper. At the end it terminates the
  client and daemon sessions (SIGTERM, then SIGKILL), reaps both with
  `wait4`, and then kills and reaps every remaining descendant, such as
  session shells, verified by start time. A run that leaves processes
  behind, or whose setup fails, is recorded as failed together with bounded
  log and terminal tails.

## Metrics

Per measured process, over the workload's window:

| Metric | Meaning and limits |
|---|---|
| `cpu_s`, `cpu_percent` | User plus system CPU from `/proc/<pid>/stat`. This includes threads that exited during the window. The resolution is one clock tick, usually 10 ms. |
| `run_s_live_threads` | On-CPU time from per-thread `schedstat`, nanosecond resolution, covering only threads alive for the whole window. |
| `timeslices_per_s` | Field 3 of `schedstat`: timeslices run, **not wakeups**. Under load it includes preemption and depends on the worker count. Live threads only. |
| `voluntary_switches_per_s` | Voluntary context switches: the thread blocked and was later woken. This is the closest available measure of sleep/wake cycles. Live threads only. |
| `involuntary_switches_per_s` | Preemptions. |
| `threads_*` | Thread counts at both ends, plus threads that exited or were created between them. When either churn count is nonzero, the live-thread counters are partial. A thread that starts and exits between the two samples appears in neither count, so zero churn does not prove that the live-thread counters are complete. `cpu_s` includes such threads. |
| `peak_rss_kib`, `rss_kib` | `VmHWM` and `VmRSS` at the end of the window. |

For the session as a whole:

| Metric | Meaning and limits |
|---|---|
| `relay.*` | Datagrams and bytes of this session only, per direction. Traffic is encrypted, so frame types (data, acknowledgement, keepalive, path probe) are not distinguished. |
| `terminal.bytes` | Bytes the client wrote to its terminal. These are rendered screen updates, not the remote output: a fast stream can be presented as fewer bytes than it produced. |
| `terminal.presented_frames` | Number of cursor-visibility sequences. The renderer ends every presented frame with one, so this counts frames, as a renderer-specific proxy. |
| `typing.stdin_to_next_datagram_ms` | Time from a timestamp taken immediately before a key is written to the client's terminal until the first client datagram the relay received at or after that timestamp, without prediction. This is an **uncorrelated proxy**, not the dispatch of the key: traffic is encrypted, so the datagram is not known to carry it. A keepalive or acknowledgement sent shortly after the timestamp is attributed to it. |
| `typing.echo_ms` | Time from writing a key until the reader thread's read that completed the remote echo returned. It includes the client's input, transport, server, PTY echo, return path and rendering. |
| `saturation.completion_s` | Wall time for a fixed amount of output to complete end to end, up to when the harness observed the completion marker (it polls every 5 ms). |
| `reconnect.recovery_s` | Time from restoring the path until the reader thread read the output of a command typed at that moment. |
| `lifetime.*` | `wait4` resource usage over a process's whole life, all threads included. `ru_maxrss` is deliberately not recorded: a forked child starts with the harness's resident size as its high-water mark. |
| `harness_cpu_s` | The harness's own CPU for the run: relay, PTY drain and polling. It shares the host with the measured processes. |

Latency times are taken where the event arrives: by the relay thread when
it receives a datagram and by the PTY reader thread when its read returns,
not when the measuring loop later polls. Each key's times are measured from
one timestamp taken immediately before the key is written, and the first
relevant event at or after it is used, even when later ones arrived before
the loop looked.

The harness's PTY reader does not model the rendering cost of a real terminal
emulator, and the relay adds one local hop. Profilers and tracers are not part
of these runs; profile separately, never in the same runs as the absolute
baseline.

## Workloads

| Workload | What happens in the window |
|---|---|
| `idle` | A connected session with no input or output. |
| `typing` | `--predict never --status off`; the remote side runs `cat > /dev/null` in non-canonical mode. One key is sent every 100 ms (100 keys by default), and each key's next-datagram and echo times are recorded. A run in which any key lacks either sample fails; its partial result is kept in the run file but never summarized. |
| `redraw` | A remote script redraws the full screen with distinct content at 20 frames per second for the window. |
| `saturation` | `seq 1 2000000` on the remote side, followed by a completion marker. The window is the whole fixed amount of work. |
| `reconnect` | The relay drops all traffic for the window; the outage CPU and traffic are measured, and then recovery time. |
| `retained` | Eight clients each start their own session (separate client homes) and leave with `Ctrl-] .`. The run checks that eight session processes remain under qshd, then measures qshd with no client attached. |

Each run settles for 2 seconds after connecting before its window starts.

## Procedure

Build the binaries to compare into separate directories. For the release
configurations, from the repository root:

```sh
gnu=$(bash scripts/build-openssl.sh --target x86_64-unknown-linux-gnu \
  --cache "$PWD/target/native-crypto" --jobs 2)
OPENSSL_DIR=$gnu OPENSSL_STATIC=1 \
  cargo build --release --locked -p qsh -p qshd --target x86_64-unknown-linux-gnu

uapi="$PWD/target/kernel-uapi"   # as in .github/workflows/release.yml
mkdir -p "$uapi"
ln -sfn /usr/include/linux "$uapi/linux"
ln -sfn /usr/include/asm-generic "$uapi/asm-generic"
ln -sfn "/usr/include/$(gcc -dumpmachine)/asm" "$uapi/asm"
musl=$(bash scripts/build-openssl.sh --target x86_64-unknown-linux-musl \
  --cache "$PWD/target/native-crypto" --cflag=-idirafter --cflag="$uapi" --jobs 2)
CC=musl-gcc OPENSSL_DIR=$musl OPENSSL_STATIC=1 \
  cargo build --release --locked -p qsh -p qshd --target x86_64-unknown-linux-musl
```

Copy each pair of `qsh` and `qshd` into its own directory, because another
build overwrites `target/`. Strip the musl pair as the release does. Then:

```sh
python3 scripts/perf_baseline.py run \
  --build glibc="$OWNED/bin-glibc" --build musl="$OWNED/bin-musl" \
  --out "$OWNED/baseline" --repetitions 5 --order interleaved \
  --source-commit "$(git rev-parse HEAD)" --note "release profile, rustc ..."
python3 scripts/perf_baseline.py summarize "$OWNED/baseline"
```

`--out` must not exist yet. It receives `manifest.json` and one JSON file per
run under `runs/`, written as soon as the run ends. SIGTERM, SIGINT or SIGHUP
stop the harness after cleaning up the current run's processes and private
directory; the runs already written are kept.

The manifest records:

- each binary's SHA-256, size, `--version` output (run on an owned
  pseudo-terminal, like every other qsh invocation), linkage, interpreter
  name and the toolchain strings from its `.comment` section;
- the kernel, CPU model and online CPUs. The host name and absolute paths are
  not recorded.
- the settings and the complete run order.

`summarize` reads only these files. For each workload, metric and build it
prints the median, interquartile range and run count. With two builds it adds
the ratio of medians and how many repetition pairs had the second build lower,
with ties counted separately.
Use `--metric REGEX` to select rows and `--json` for machine-readable output.

Guidance for comparisons:

- Compare builds only within one `run`, on one otherwise idle host. Use at
  least five repetitions.
- `interleaved` alternates which build runs first in every repetition (ABBA);
  `random --seed N` shuffles the whole order reproducibly. Never compare runs
  executed in a fixed A-then-B block.
- Report dispersion and the pair count together with any ratio. Prefer
  fixed-work completion time, latency and output-delivery metrics over CPU
  percentage when the workload saturates a CPU.
- Keep the output directory with any reported result. A ratio obtained on one
  VM is a signal for that host, not a portable improvement factor.


## Recorded baselines: 2026-10-26

All runs were made on one host: a 4-vCPU KVM VM (Intel Xeon W-2295),
Debian 12, kernel 6.1. The host was not otherwise idle; an unrelated personal
qshd was running. These are not quiet-host acceptance runs. SHA-256 hashes,
linkage and toolchain strings of every binary are in each manifest.

- The two full runs measured 2 builds x 6 workloads x 5 repetitions in
  interleaved order with harness version 1. All 120 runs succeeded and left
  no processes behind. That version timed latencies when its 5 ms polling
  loop noticed an event, and took the latest client datagram rather than the
  first. Its `typing` latencies and `reconnect` recovery times are withdrawn
  and omitted below. Their CPU, scheduling, traffic and memory records are
  unaffected and remain.
- Two latency runs then measured `typing` and `reconnect` for the same
  binaries (2 builds x 2 workloads x 5 repetitions, interleaved) with harness
  version 2, which takes every time at arrival. All 40 runs succeeded and
  left no processes behind, and each of the 20 `typing` runs had 100 of 100
  echo and datagram samples. Version 2 selected the first datagram after a
  count taken just before each key's timestamp; version 3 selects it by the
  timestamp itself. In all 2000 version 2 samples the selected datagram
  arrived at least 0.36 ms after the timestamp, so both rules select the same
  datagrams and the samples stand.

The tables show medians with interquartile range and run count. The last two
columns compare the second build with the first: the ratio of medians, and
how many of the five repetition pairs had the second build lower (ties in
parentheses). CPU percentages are of one CPU. Rows that are zero for both
builds are omitted.

### glibc and musl builds of `e044d08`

Raw data: [`performance/2026-10-26-e044d08-glibc-musl/`](performance/2026-10-26-e044d08-glibc-musl/).

- **Builds:** release profile, rustc 1.98.1.
  - `glibc`: `x86_64-unknown-linux-gnu`, dynamic, unstripped.
  - `musl`: `x86_64-unknown-linux-musl` built with `musl-gcc` as in
    `.github/workflows/release.yml`, static, stripped.

| Workload | Metric | glibc median (p25-p75, n) | musl median (p25-p75, n) | musl/glibc | pairs with musl lower (tied) |
|---|---|---|---|---|---|
| idle | window.qsh.cpu_percent | 3.6 (3.6-3.6, 5) | 10.2 (10-10.2, 5) | 2.83 | 0/5 (0) |
| idle | window.qsh.voluntary_switches_per_s | 119 (118-119, 5) | 115 (115-116, 5) | 0.974 | 5/5 (0) |
| idle | window.qshd.cpu_percent | 0.8 (0.8-0.8, 5) | 0.7 (0.7-0.7, 5) | 0.875 | 4/5 (1) |
| idle | window.qshd.voluntary_switches_per_s | 120 (119-120, 5) | 117 (117-120, 5) | 0.977 | 3/5 (0) |
| idle | window.relay.c2s_datagrams_per_s | 1.4 (1.4-1.4, 5) | 1.4 (1.4-1.4, 5) | 1 | 0/5 (5) |
| idle | window.relay.s2c_datagrams_per_s | 1.4 (1.4-1.4, 5) | 1.4 (1.4-1.4, 5) | 1 | 0/5 (5) |
| typing | window.qsh.cpu_percent | 2.2 (2.2-2.2, 5) | 5.89 (5.79-5.89, 5) | 2.68 | 0/5 (0) |
| typing | window.qsh.voluntary_switches_per_s | 155 (155-156, 5) | 155 (154-155, 5) | 0.996 | 4/5 (0) |
| typing | window.qshd.cpu_percent | 1.3 (1.3-1.4, 5) | 1.2 (1.2-1.3, 5) | 0.923 | 3/5 (1) |
| typing | window.qshd.voluntary_switches_per_s | 267 (266-267, 5) | 267 (266-271, 5) | 1 | 2/5 (0) |
| typing | window.relay.c2s_datagrams_per_s | 21.1 (21.1-21.1, 5) | 21.2 (21.1-21.2, 5) | 1 | 1/5 (1) |
| typing | window.relay.s2c_datagrams_per_s | 21.4 (21.4-21.4, 5) | 21.4 (21.4-21.4, 5) | 1 | 1/5 (3) |
| typing | window.terminal.presented_frames_per_s | 9.98 (9.98-9.98, 5) | 9.98 (9.98-9.98, 5) | 1 | 0/5 (5) |
| redraw | window.qsh.cpu_percent | 3.07 (2.87-3.07, 5) | 7.24 (7.23-15.4, 5) | 2.36 | 0/5 (0) |
| redraw | window.qsh.voluntary_switches_per_s | 178 (176-185, 5) | 181 (180-186, 5) | 1.02 | 1/5 (0) |
| redraw | window.qshd.cpu_percent | 2.18 (2.18-2.18, 5) | 2.18 (2.18-2.28, 5) | 1 | 1/5 (0) |
| redraw | window.qshd.voluntary_switches_per_s | 412 (411-413, 5) | 411 (411-414, 5) | 0.998 | 3/5 (0) |
| redraw | window.relay.c2s_datagrams_per_s | 41.3 (41.3-41.4, 5) | 41.2 (41.2-41.2, 5) | 0.998 | 3/5 (0) |
| redraw | window.relay.s2c_datagrams_per_s | 102 (102-103, 5) | 103 (103-103, 5) | 1 | 2/5 (0) |
| redraw | window.terminal.presented_frames_per_s | 20.3 (20.1-20.4, 5) | 20.1 (20.1-20.3, 5) | 0.99 | 3/5 (1) |
| saturation | completion_s | 2.2 (2.13-2.3, 5) | 2.81 (2.37-2.94, 5) | 1.28 | 1/5 (0) |
| saturation | window.qsh.cpu_percent | 47.8 (47.6-51.6, 5) | 83.6 (77.8-85.2, 5) | 1.75 | 0/5 (0) |
| saturation | window.qsh.voluntary_switches_per_s | 8602 (7876-8863, 5) | 5241 (4920-6023, 5) | 0.609 | 5/5 (0) |
| saturation | window.qshd.cpu_percent | 84 (84-94.9, 5) | 83 (78.2-86.9, 5) | 0.987 | 3/5 (0) |
| saturation | window.qshd.voluntary_switches_per_s | 56685 (56052-60131, 5) | 69581 (67226-71641, 5) | 1.23 | 0/5 (0) |
| saturation | window.relay.c2s_datagrams_per_s | 4288 (3547-5220, 5) | 2884 (1727-2987, 5) | 0.673 | 5/5 (0) |
| saturation | window.relay.s2c_datagrams_per_s | 8150 (7564-8285, 5) | 5303 (5081-5868, 5) | 0.651 | 5/5 (0) |
| saturation | window.terminal.presented_frames_per_s | 395 (376-434, 5) | 271 (271-273, 5) | 0.685 | 5/5 (0) |
| reconnect | outage.qsh.cpu_percent | 5.6 (5.6-9.7, 5) | 15.7 (15.4-15.7, 5) | 2.8 | 0/5 (0) |
| reconnect | outage.qsh.voluntary_switches_per_s | 117 (114-117, 5) | 112 (112-112, 5) | 0.958 | 5/5 (0) |
| reconnect | outage.qshd.cpu_percent | 0.7 (0.7-0.8, 5) | 0.7 (0.6-0.7, 5) | 1 | 3/5 (2) |
| reconnect | outage.qshd.voluntary_switches_per_s | 114 (113-115, 5) | 116 (113-116, 5) | 1.02 | 2/5 (0) |
| reconnect | outage.terminal.presented_frames_per_s | 0.1 (0.1-0.2, 5) | 0.2 (0.2-0.2, 5) | 2 | 1/5 (1) |
| retained | window.qshd.cpu_percent | 3.8 (3.7-4.1, 5) | 3.9 (3.9-4, 5) | 1.03 | 2/5 (1) |
| retained | window.qshd.voluntary_switches_per_s | 873 (868-881, 5) | 921 (882-930, 5) | 1.05 | 1/5 (0) |
| retained | window.relay.s2c_datagrams_per_s | 5.4 (5.4-5.4, 5) | 5.3 (5.3-5.4, 5) | 0.982 | 3/5 (1) |

Latency, from [`performance/2026-10-26-e044d08-glibc-musl-latency/`](performance/2026-10-26-e044d08-glibc-musl-latency/):

| Workload | Metric | glibc median (p25-p75, n) | musl median (p25-p75, n) | musl/glibc | pairs with musl lower (tied) |
|---|---|---|---|---|---|
| typing | echo_ms.p50 | 28.1 (27.7-29.5, 5) | 31.9 (31.7-31.9, 5) | 1.14 | 1/5 (0) |
| typing | echo_ms.p90 | 50.8 (49.8-51.9, 5) | 53.7 (53.5-54.5, 5) | 1.06 | 0/5 (0) |
| typing | stdin_to_next_datagram_ms.p50 | 26.7 (26.3-27.8, 5) | 28 (28-28.4, 5) | 1.05 | 1/5 (0) |
| typing | stdin_to_next_datagram_ms.p90 | 49.2 (48.3-50.7, 5) | 50 (49.3-50.8, 5) | 1.02 | 1/5 (0) |
| reconnect | recovery_s | 1.46 (1.46-1.47, 5) | 1.48 (1.47-1.48, 5) | 1.01 | 1/5 (0) |

### Published v0.5.0 and the musl build of `e044d08`

Raw data: [`performance/2026-10-26-v0.5.0-vs-e044d08-musl/`](performance/2026-10-26-v0.5.0-vs-e044d08-musl/).

- **Builds:**
  - `release-0.5.0`: `qsh` and `qshd` from the published
    `qsh-0.5.0-x86_64-unknown-linux-musl.tar.gz`. Its hash was checked against
    the release's `SHA256SUMS`; the release publishes no signature.
  - `musl-e044d08`: the musl build above.

| Workload | Metric | release-0.5.0 median (p25-p75, n) | musl-e044d08 median (p25-p75, n) | musl-e044d08/release-0.5.0 | pairs with musl-e044d08 lower (tied) |
|---|---|---|---|---|---|
| idle | window.qsh.cpu_percent | 0.3 (0.3-0.3, 5) | 9.8 (9.7-9.8, 5) | 32.7 | 0/5 (0) |
| idle | window.qsh.voluntary_switches_per_s | 70.6 (70.6-70.7, 5) | 116 (115-116, 5) | 1.64 | 0/5 (0) |
| idle | window.qshd.cpu_percent | 0.4 (0.4-0.4, 5) | 0.7 (0.7-0.7, 5) | 1.75 | 0/5 (0) |
| idle | window.qshd.voluntary_switches_per_s | 69.8 (69.8-69.9, 5) | 117 (117-120, 5) | 1.67 | 0/5 (0) |
| idle | window.relay.c2s_datagrams_per_s | 1.4 (1.4-1.4, 5) | 1.4 (1.4-1.4, 5) | 1 | 0/5 (5) |
| idle | window.relay.s2c_datagrams_per_s | 1.4 (1.4-1.4, 5) | 1.4 (1.4-1.4, 5) | 1 | 0/5 (5) |
| typing | window.qsh.cpu_percent | 1.5 (1.4-1.5, 5) | 5.79 (5.79-5.89, 5) | 3.87 | 0/5 (0) |
| typing | window.qsh.voluntary_switches_per_s | 118 (117-118, 5) | 155 (154-155, 5) | 1.31 | 0/5 (0) |
| typing | window.qshd.cpu_percent | 0.899 (0.899-0.899, 5) | 1.2 (1.2-1.3, 5) | 1.33 | 0/5 (0) |
| typing | window.qshd.voluntary_switches_per_s | 223 (222-223, 5) | 267 (266-269, 5) | 1.19 | 0/5 (0) |
| typing | window.relay.c2s_datagrams_per_s | 21.2 (21.2-21.2, 5) | 21.1 (21.1-21.2, 5) | 0.995 | 2/5 (1) |
| typing | window.relay.s2c_datagrams_per_s | 21.4 (21.4-21.4, 5) | 21.4 (21.4-21.4, 5) | 1 | 0/5 (5) |
| typing | window.terminal.presented_frames_per_s | 9.98 (9.98-9.99, 5) | 9.98 (9.98-9.99, 5) | 1 | 1/5 (3) |
| redraw | window.qsh.cpu_percent | 2.39 (2.38-2.48, 5) | 7.23 (7.15-7.34, 5) | 3.03 | 0/5 (0) |
| redraw | window.qsh.voluntary_switches_per_s | 126 (126-130, 5) | 177 (174-180, 5) | 1.4 | 0/5 (0) |
| redraw | window.qshd.cpu_percent | 1.89 (1.89-1.99, 5) | 2.29 (2.28-2.38, 5) | 1.21 | 0/5 (0) |
| redraw | window.qshd.voluntary_switches_per_s | 363 (360-363, 5) | 410 (410-411, 5) | 1.13 | 0/5 (0) |
| redraw | window.relay.c2s_datagrams_per_s | 41.4 (41.2-41.6, 5) | 41.5 (41.4-42, 5) | 1 | 2/5 (0) |
| redraw | window.relay.s2c_datagrams_per_s | 102 (102-105, 5) | 102 (102-105, 5) | 1 | 2/5 (0) |
| redraw | window.terminal.presented_frames_per_s | 20.2 (20.2-20.4, 5) | 20.1 (20.1-20.6, 5) | 0.997 | 4/5 (0) |
| saturation | completion_s | 2.58 (2.39-2.78, 5) | 2.95 (2.78-3.04, 5) | 1.14 | 1/5 (0) |
| saturation | window.qsh.cpu_percent | 30.5 (24.3-32.4, 5) | 83.6 (81.3-85.5, 5) | 2.74 | 0/5 (0) |
| saturation | window.qsh.voluntary_switches_per_s | 8123 (6131-9426, 5) | 6757 (6505-6892, 5) | 0.832 | 3/5 (0) |
| saturation | window.qshd.cpu_percent | 113 (112-120, 5) | 88.1 (83.6-94, 5) | 0.781 | 5/5 (0) |
| saturation | window.qshd.voluntary_switches_per_s | 70174 (66475-75897, 5) | 72274 (71914-75946, 5) | 1.03 | 1/5 (0) |
| saturation | window.relay.c2s_datagrams_per_s | 4636 (4276-4960, 5) | 3225 (3007-3362, 5) | 0.696 | 5/5 (0) |
| saturation | window.relay.s2c_datagrams_per_s | 7171 (6592-7586, 5) | 6154 (6085-6440, 5) | 0.858 | 4/5 (0) |
| saturation | window.terminal.presented_frames_per_s | 244 (159-267, 5) | 272 (266-303, 5) | 1.12 | 1/5 (0) |
| reconnect | outage.qsh.cpu_percent | 1.9 (1.8-1.9, 5) | 15.4 (15.4-15.7, 5) | 8.1 | 0/5 (0) |
| reconnect | outage.qsh.voluntary_switches_per_s | 68.5 (68.5-68.5, 5) | 112 (112-112, 5) | 1.63 | 0/5 (0) |
| reconnect | outage.qshd.cpu_percent | 0.3 (0.3-0.4, 5) | 0.7 (0.7-0.7, 5) | 2.33 | 0/5 (0) |
| reconnect | outage.qshd.voluntary_switches_per_s | 66.4 (66.3-66.5, 5) | 116 (113-116, 5) | 1.74 | 0/5 (0) |
| reconnect | outage.terminal.presented_frames_per_s | 0.7 (0.7-0.8, 5) | 0.2 (0.1-0.2, 5) | 0.286 | 5/5 (0) |
| retained | window.qshd.cpu_percent | 1.6 (1.6-1.7, 5) | 3.7 (3.6-3.8, 5) | 2.31 | 0/5 (0) |
| retained | window.qshd.voluntary_switches_per_s | 413 (412-417, 5) | 859 (856-877, 5) | 2.08 | 0/5 (0) |
| retained | window.relay.s2c_datagrams_per_s | 5.6 (5.6-5.6, 5) | 5.3 (5.3-5.3, 5) | 0.946 | 5/5 (0) |

Latency, from [`performance/2026-10-26-v0.5.0-vs-e044d08-musl-latency/`](performance/2026-10-26-v0.5.0-vs-e044d08-musl-latency/):

| Workload | Metric | release-0.5.0 median (p25-p75, n) | musl-e044d08 median (p25-p75, n) | musl-e044d08/release-0.5.0 | pairs with musl-e044d08 lower (tied) |
|---|---|---|---|---|---|
| typing | echo_ms.p50 | 29 (28.8-30, 5) | 33.1 (31.6-33.7, 5) | 1.14 | 0/5 (0) |
| typing | echo_ms.p90 | 51.5 (51.1-53.2, 5) | 55.5 (55.4-55.6, 5) | 1.08 | 0/5 (0) |
| typing | stdin_to_next_datagram_ms.p50 | 27.9 (27.7-29, 5) | 29.2 (27.8-29.7, 5) | 1.04 | 2/5 (0) |
| typing | stdin_to_next_datagram_ms.p90 | 50.5 (49.6-52, 5) | 51.4 (51.4-51.7, 5) | 1.02 | 3/5 (0) |
| reconnect | recovery_s | 1.45 (1.45-1.46, 5) | 1.49 (1.49-1.5, 5) | 1.02 | 0/5 (0) |

### What these baselines show, for this host only

- **Idle and interactive client CPU regressed after v0.5.0.** An idle
  connected client uses 0.3% of a CPU in v0.5.0 and 9.8% in the musl build of
  `e044d08`; the glibc build of `e044d08` uses 3.6%. Its voluntary switches
  rose from about 71 to about 116 per second, and the server's from about 70
  to about 117. Typing, redraw and outage CPU grew similarly. With eight
  retained sessions, qshd uses 1.6% of a CPU in v0.5.0 and 3.7-3.9% now.
  These datasets do not establish a cause.
- **The musl client costs 1.8-2.8 times the glibc client's CPU** at the same
  activity: equal voluntary switches, presented frames and datagrams. The
  released Linux binaries are musl builds. Server CPU differs little between
  the two builds (#307).
- **Typing.** The median time from a key to the next client datagram is
  27-29 ms in every build, and its 90th percentile is 49-51 ms. This
  uncorrelated proxy does not show that the datagram carried the key; the
  spread is consistent with, but does not prove, the client driver's 50 ms
  command polling (#300). The median echo is 28-29 ms for glibc `e044d08`
  and v0.5.0 and 32-33 ms for musl `e044d08`, which was later than glibc in
  4 of 5 pairs and later than v0.5.0 in all 5. Within a run, the per-key
  difference between the echo and the next datagram has a median of about
  1.1-1.4 ms for v0.5.0 and glibc and about 3.6 ms for musl `e044d08`; these
  runs do not show where that time is spent.
- **Saturation.** `seq 1 2000000` completes in 2.2 s with glibc, 2.8 s with
  musl and 2.6 s with v0.5.0. musl was slower than glibc in 4 of 5 pairs.
  qshd uses most of a CPU while the output runs: 113% in v0.5.0 and 83-88%
  now.
- **Idle traffic** is 1.4 datagrams per second in each direction in all
  builds. Recovery after a 10 s outage takes about 1.5 s. With eight retained
  sessions, qshd still sends about 5.4 datagrams per second toward the
  departed clients' addresses; the window starts 2 s after the last client
  left.
- A few `retained` runs created threads during the window. Their live-thread
  counters are partial; `cpu_percent` is complete.

### Provisional observations, not part of this baseline

An informal bisection and profiles, made outside these runs and not
retained, pointed at the idle work of the client's prediction tick, which
was added with #112, and at full-frame building and copying. They are leads,
not evidence, and none of the numbers above depends on them. That work is
tracked in #303, with frame copies in #301 and presentation cadence in #304;
a change to it should be measured with this procedure, with the raw results
kept.

These numbers are a reference for later comparisons on the same host, not
performance promises for other platforms.
