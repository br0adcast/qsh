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
  the datagrams and bytes of the run's sessions in each direction,
  timestamps each client datagram when it is received, and can drop
  everything to simulate an outage. Each client address gets its own socket
  toward the daemon, so qshd sees every client at an address of its own and
  each reply goes back to the client it was sent to. Before harness version
  4, and in the first runtime-worker dataset below, the relay had one such
  socket and sent every reply to the client heard from last, which is
  correct only while one client is connected at a time, as in every
  workload of the earlier versions.
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
| `relay.*` | Datagrams and bytes of the run's sessions, per direction. Traffic is encrypted, so frame types (data, acknowledgement, keepalive, path probe) are not distinguished. |
| `terminal.bytes` | Bytes the client wrote to its terminal. These are rendered screen updates, not the remote output: a fast stream can be presented as fewer bytes than it produced. |
| `terminal.presented_frames` | Number of cursor-visibility sequences. The renderer ends every presented frame with one, so this counts frames, as a renderer-specific proxy. |
| `typing.stdin_to_next_datagram_ms` | Time from a timestamp taken immediately before a key is written to the client's terminal until the first client datagram the relay received at or after that timestamp, without prediction. This is an **uncorrelated proxy**, not the dispatch of the key: traffic is encrypted, so the datagram is not known to carry it. A keepalive or acknowledgement sent shortly after the timestamp is attributed to it. |
| `typing.echo_ms` | Time from writing a key until the reader thread's read that completed the remote echo returned. It includes the client's input, transport, server, PTY echo, return path and rendering. |
| `saturation.completion_s` | Wall time for a fixed amount of output to complete end to end, up to when the harness observed the completion marker (it polls every 5 ms). |
| `reconnect.recovery_s` | Time from restoring the path until the reader thread read the output of a command typed at that moment. |
| `busy.echo_ms` | As `typing.echo_ms`, for the typing session among the redrawing ones. |
| `busy.busy_terminal_bytes_per_s` | Bytes all redrawing clients wrote to their terminals per second during the window. |
| `busy.busy_overrun_s` | How much later than its nominal duration each redraw's completion marker reached the client's terminal, median and maximum over the redrawing sessions. A redraw paces itself, so this is an end-to-end overrun of a paced producer: it includes the producer's own scheduling on qshd's CPUs (the redraws are descendants of qshd), the shell, qshd, the relay and the terminal drain, not qshd's delay alone. |
| `qshd.allowed_cpus`, `qshd.runtime_workers`, `qshd.runtime_workers_expected` | Recorded per run: the CPUs the running qshd may use, from `/proc/<pid>/status`; the async worker count its log reports (`runtime workers N`); and the count the run required, or null when it required none. A run whose qshd runs on other CPUs than its variant names fails. How the worker count is checked is described under [Procedure](#procedure). |
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
| `busy` | One typing session as in `typing`, beside four other sessions (`--busy-sessions`) that each redraw their full screen at 20 frames per second, all through the same qshd. The window covers the keys. Only the echo is measured: with several clients behind the relay, the next client datagram need not be the typing client's. A run in which any key lacks its echo fails. With many sessions the harness itself, one Python process relaying every datagram, can delay echoes; compare `harness_cpu_s` with the run's length before attributing a latency tail to qshd. |

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

To compare runtime configurations of one build, name variants. Each variant
runs one `--build` with qshd confined to a CPU list and, optionally, with
`--runtime-threads N`; the runs and summary columns are named after the
variants:

```sh
python3 scripts/perf_baseline.py run --build cur="$OWNED/bin" \
  --variant c1=cur,cpus=0 --variant c2=cur,cpus=0-1 \
  --variant c2t1=cur,cpus=0-1,threads=1 \
  --harness-cpus 2-3 --out "$OWNED/workers" ...
```

qshd is started through `taskset`, which sets its CPUs before it executes
qshd, so Tokio's default worker count follows them. `--harness-cpus` keeps
the harness, its relay and every client on other CPUs; a variant without
CPUs of its own then runs qshd on every CPU the harness started with. The
processes a session starts inherit qshd's CPUs.

A variant that names CPUs or a worker count is a runtime-worker
experiment, and its run fails unless qshd's log reports the count it
should run:

- with `threads=N`, N;
- otherwise Tokio's default for that qshd: `TOKIO_WORKER_THREADS` if the
  environment the harness gave qshd sets it (it passes on only `PATH`, so
  normally it does not), else one worker per CPU qshd may run on. A cgroup
  CPU quota also lowers Tokio's default, so a run under one, or outside a
  cgroup v2 hierarchy where none can be seen, fails and asks for
  `threads=N` instead.

A build run without variants, or a variant that names neither, only
records the count; a build without the log line records none.

A variant with `system` runs `qshd serve --system` instead, which the
harness does only as root with `QSHD_TEST_DISPOSABLE_HOST=1` set: it runs
qshd as root and writes the benchmark account's `authorized_keys`. Run it in
a disposable container that has the PAM service file, an account to log in
as (`--system-account`) with empty shell startup files, and a worker account
(`--worker-user`, default `nobody`).
`scripts/perf_baseline_system.Dockerfile` builds one, with the account
`qshbench`. The container needs `CAP_SYS_PTRACE`:
the worker drops its privileges, and without that capability root cannot
read the worker's `/proc` descriptors and counters. In these runs `qshd` is
the worker, which runs the async runtime, and `qshd_helper` is the
privileged helper:

```sh
docker run --rm --init --cap-add SYS_PTRACE -e QSHD_TEST_DISPOSABLE_HOST=1 \
  -v "$OWNED/bin-system:/bench/bin:ro" -v "$PWD/scripts/perf_baseline.py:/bench/perf_baseline.py:ro" \
  -v "$OWNED/out:/bench/out" qsh-bench-system \
  python3 -I /bench/perf_baseline.py run --build cur=/bench/bin \
    --variant s1=cur,system,cpus=0 --system-account qshbench ... --out /bench/out/system
```

`--out` must not exist yet. It receives `manifest.json` and one JSON file per
run under `runs/`, written as soon as the run ends. SIGTERM, SIGINT or SIGHUP
stop the harness after cleaning up the current run's processes and private
directory; the runs already written are kept. A failed run's file includes
the tails of the daemon's log and of each client's terminal; in personal
mode the log names the account the harness ran as, so check failed runs
before publishing a dataset.

The manifest records:

- each binary's SHA-256, size, `--version` output (run on an owned
  pseudo-terminal, like every other qsh invocation), linkage, interpreter
  name and the toolchain strings from its `.comment` section;
- the kernel, CPU model and online CPUs. The host name and absolute paths are
  not recorded.
- the settings, the variants and the CPUs each one gave qshd, and the
  complete run order.

`summarize` reads only these files. For each workload, metric and build (or
variant) it
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

## Runtime worker threads: 2026-10-26

These runs compare the async worker count of one qshd build (#308). They
were made on the same 4-vCPU VM as the baselines above, with the same
unrelated personal qshd running, so they are not quiet-host runs either.
The VM has 4 CPUs; nothing here was measured on a larger host.

- **Build:** `583cc51`, glibc release build (`x86_64-unknown-linux-gnu`),
  rustc 1.98.1. The system-mode runs used a build of the same commit with
  `--features qshd/system`, in an `ubuntu:24.04` container built from
  `scripts/perf_baseline_system.Dockerfile`, with the worker account
  `nobody`. Hashes are in each manifest. The client is the `qsh` of the
  same commit, which predates the UI-wait changes of #339; client-side
  figures here do not describe later clients.
- **Variants:** qshd confined to CPU 0 (`c1`/`s1`), CPUs 0-1 (`c2`/`s2`)
  or CPUs 0-3 (`c4`/`s4`) with Tokio's default worker count, which then is
  1, 2 or 4; a `t1` or `t2` suffix adds `--runtime-threads 1` or `2`. `c`
  is personal mode and `s` system mode. Every run checked the CPUs of the
  running qshd, and the worker count it reported when the variant set
  `threads=`. Harness version 4, which made these runs, recorded the default
  count without checking it; version 5 checks it as described under
  [Procedure](#procedure). All 240 records with the default count match
  the number of CPUs they record. The harness, its relay and every client
  ran on CPUs 2-3, so in the 4-CPU variants they shared CPUs with qshd.
  Session shells, and with them the redraw scripts, run on qshd's CPUs.
- **Order:** 5 repetitions, interleaved: the variant order is reversed in
  every other repetition. All 480 runs kept here succeeded and left no
  processes behind.
- **Harness:** version 4. The first personal-mode dataset was recorded
  before the relay change described under [What one run does](#what-one-run-does),
  which is correct for its idle, typing, saturation, reconnect and retained
  runs: each had one client connected at a time. Its 30 `busy` runs did
  not; replies reached the wrong client, which delayed echoes by up to
  about 200 ms and failed one run. They are withdrawn and omitted from the
  raw data, and `busy` was measured again with the per-client relay.
- **Many sessions:** 16 sessions per daemon, the per-owner limit, as one
  typing session beside 15 redrawing ones (`--busy-sessions 15`) and as 16
  retained sessions. The system-wide limit of 128 sessions was not
  measured.

In system mode, `qshd` is the worker process, which runs the async runtime,
and `qshd_helper` the privileged helper.

### Personal mode

Raw data: [`performance/2026-10-26-runtime-workers-personal/`](performance/2026-10-26-runtime-workers-personal/)
(one session, and eight retained),
[`-personal-busy/`](performance/2026-10-26-runtime-workers-personal-busy/)
(`busy`, five sessions) and
[`-personal-16/`](performance/2026-10-26-runtime-workers-personal-16/)
(16 sessions).

One session, and eight retained:

| Workload | Metric | c1 median (p25-p75, n) | c2 median (p25-p75, n) | c2t1 median (p25-p75, n) | c4 median (p25-p75, n) | c4t1 median (p25-p75, n) | c4t2 median (p25-p75, n) |
|---|---|---|---|---|---|---|---|
| idle | window.qshd.cpu_percent | 0.7 (0.7-0.7, 5) | 0.8 (0.7-0.8, 5) | 0.8 (0.8-0.8, 5) | 0.7 (0.7-0.7, 5) | 0.8 (0.8-0.8, 5) | 0.8 (0.7-0.8, 5) |
| idle | window.qshd.voluntary_switches_per_s | 113 (112-113, 5) | 116 (116-116, 5) | 114 (113-114, 5) | 116 (116-117, 5) | 114 (114-114, 5) | 116 (116-116, 5) |
| typing | echo_ms.p50 | 1.43 (1.43-1.46, 5) | 1.48 (1.47-1.49, 5) | 1.48 (1.46-1.48, 5) | 1.49 (1.48-1.52, 5) | 1.43 (1.42-1.47, 5) | 1.49 (1.46-1.53, 5) |
| typing | echo_ms.p90 | 1.91 (1.73-1.93, 5) | 1.88 (1.78-1.93, 5) | 1.93 (1.84-1.95, 5) | 1.96 (1.86-1.98, 5) | 1.89 (1.82-1.9, 5) | 1.81 (1.8-1.88, 5) |
| typing | window.qshd.cpu_percent | 1.1 (1.1-1.1, 5) | 1.3 (1.3-1.3, 5) | 1.2 (1.2-1.3, 5) | 1.4 (1.3-1.5, 5) | 1.3 (1.3-1.3, 5) | 1.4 (1.4-1.4, 5) |
| typing | window.qshd.involuntary_switches_per_s | 84 (81.2-84.6, 5) | 5.29 (3.19-5.99, 5) | 2.8 (2.7-3.3, 5) | 2.1 (2.1-2.5, 5) | 1.3 (0.8-1.5, 5) | 2.1 (1.2-2.2, 5) |
| typing | window.qshd.voluntary_switches_per_s | 175 (175-176, 5) | 262 (262-263, 5) | 207 (206-207, 5) | 271 (267-272, 5) | 207 (206-208, 5) | 265 (265-265, 5) |
| saturation | completion_s | 2.35 (2.23-2.44, 5) | 2 (1.96-2.15, 5) | 1.99 (1.92-2.13, 5) | 2.2 (2.15-2.32, 5) | 2.16 (2.1-2.31, 5) | 2.38 (2.02-2.47, 5) |
| saturation | window.qshd.cpu_percent | 55.8 (55.6-56.4, 5) | 92.7 (73.7-93.8, 5) | 73.5 (58.7-82.3, 5) | 95.3 (94.4-97.4, 5) | 78.9 (77.1-81.8, 5) | 85.3 (85-92.2, 5) |
| saturation | window.qshd.involuntary_switches_per_s | 4076 (3927-4100, 5) | 56563 (53632-58802, 5) | 71276 (70648-77584, 5) | 49155 (41189-49423, 5) | 43476 (37955-48370, 5) | 58818 (55690-60063, 5) |
| saturation | window.qshd.threads_end | 6 (6-6, 5) | 7 (7-7, 5) | 6 (6-6, 5) | 8 (8-8, 5) | 5 (5-5, 5) | 6 (6-6, 5) |
| saturation | window.qshd.voluntary_switches_per_s | 19190 (19093-21725, 5) | 52774 (50459-60781, 5) | 46969 (39356-57452, 5) | 52702 (48537-55782, 5) | 37130 (32061-37863, 5) | 51244 (44249-54438, 5) |
| reconnect | recovery_s | 1.45 (1.45-1.45, 5) | 1.45 (1.45-1.45, 5) | 1.45 (1.45-1.45, 5) | 1.45 (1.45-1.45, 5) | 1.45 (1.45-1.45, 5) | 1.45 (1.45-1.45, 5) |
| retained | window.qshd.cpu_percent | 2.4 (2.3-2.4, 5) | 3.2 (3.2-3.3, 5) | 3.2 (2.9-3.2, 5) | 3.6 (3.3-3.6, 5) | 3.4 (3.2-3.4, 5) | 3.4 (3.3-3.4, 5) |
| retained | window.qshd.involuntary_switches_per_s | 373 (362-378, 5) | 190 (188-198, 5) | 34.1 (21.8-40.8, 5) | 55.5 (49.2-64.6, 5) | 2.8 (2.8-4.2, 5) | 17.5 (15.4-19.5, 5) |
| retained | window.qshd.voluntary_switches_per_s | 533 (490-551, 5) | 595 (561-639, 5) | 654 (642-682, 5) | 770 (691-796, 5) | 589 (574-676, 5) | 653 (649-670, 5) |

`busy`, one typing session beside four redrawing ones:

| Workload | Metric | c1 median (p25-p75, n) | c2 median (p25-p75, n) | c2t1 median (p25-p75, n) | c4 median (p25-p75, n) | c4t1 median (p25-p75, n) | c4t2 median (p25-p75, n) |
|---|---|---|---|---|---|---|---|
| busy | busy_overrun_s.median | 0.128 (0.127-0.133, 5) | 0.093 (0.091-0.095, 5) | 0.089 (0.088-0.091, 5) | 0.077 (0.077-0.081, 5) | 0.072 (0.072-0.073, 5) | 0.075 (0.072-0.075, 5) |
| busy | echo_ms.max | 4.37 (3.15-5.26, 5) | 4.22 (3.3-4.25, 5) | 5.7 (4.26-5.76, 5) | 3.43 (3.18-3.57, 5) | 3.34 (2.87-3.78, 5) | 2.68 (2.58-3.8, 5) |
| busy | echo_ms.p50 | 1.52 (1.49-1.53, 5) | 1.58 (1.57-1.6, 5) | 1.57 (1.54-1.6, 5) | 1.56 (1.52-1.62, 5) | 1.64 (1.57-1.64, 5) | 1.58 (1.54-1.61, 5) |
| busy | echo_ms.p90 | 1.95 (1.9-1.99, 5) | 2.14 (2.13-2.59, 5) | 2.27 (2.08-2.31, 5) | 2 (1.89-2.03, 5) | 2.32 (1.96-2.48, 5) | 2.02 (1.98-2.04, 5) |
| busy | window.qshd.cpu_percent | 6.39 (6.09-6.39, 5) | 7.79 (7.69-8.19, 5) | 7.09 (6.99-7.19, 5) | 8.39 (8.39-8.39, 5) | 7.29 (6.99-7.49, 5) | 8.59 (8.39-8.59, 5) |
| busy | window.qshd.involuntary_switches_per_s | 442 (440-442, 5) | 143 (129-168, 5) | 76.5 (74.2-82.6, 5) | 107 (74.2-146, 5) | 63.2 (61.8-70.2, 5) | 50.7 (42.3-56.7, 5) |
| busy | window.qshd.voluntary_switches_per_s | 915 (892-932, 5) | 1519 (1515-1542, 5) | 1186 (1118-1242, 5) | 1801 (1789-2010, 5) | 1167 (1133-1219, 5) | 1763 (1723-1768, 5) |

16 sessions:

| Workload | Metric | c1 median (p25-p75, n) | c2 median (p25-p75, n) | c2t1 median (p25-p75, n) | c4 median (p25-p75, n) | c4t1 median (p25-p75, n) | c4t2 median (p25-p75, n) |
|---|---|---|---|---|---|---|---|
| busy | busy_overrun_s.median | 0.363 (0.36-0.369, 5) | 0.231 (0.197-0.243, 5) | 0.199 (0.189-0.203, 5) | 0.134 (0.133-0.17, 5) | 0.135 (0.13-0.145, 5) | 0.153 (0.134-0.155, 5) |
| busy | busy_terminal_bytes_per_s | 1382297 (1381493-1382843, 5) | 1375484 (1372587-1381690, 5) | 1362510 (1359629-1364388, 5) | 1380327 (1379778-1382866, 5) | 1377523 (1374809-1381932, 5) | 1379770 (1378756-1390830, 5) |
| busy | echo_ms.max | 87 (9.21-131, 5) | 253 (242-332, 5) | 614 (457-666, 5) | 148 (16.3-194, 5) | 260 (224-263, 5) | 227 (211-402, 5) |
| busy | echo_ms.p50 | 1.62 (1.53-1.72, 5) | 2.03 (1.68-2.36, 5) | 2.43 (1.95-4.19, 5) | 1.99 (1.98-2.09, 5) | 2.16 (1.88-3.17, 5) | 1.95 (1.77-1.98, 5) |
| busy | echo_ms.p90 | 2.53 (2.48-3.45, 5) | 59.7 (19.8-70.6, 5) | 130 (45.7-147, 5) | 4.54 (4.4-59.7, 5) | 58.3 (5.98-90.7, 5) | 13.1 (12.9-19.3, 5) |
| busy | window.qshd.cpu_percent | 15.3 (15.2-16.3, 5) | 22 (21.7-22.8, 5) | 21 (20.3-22.4, 5) | 23.9 (23.6-25.2, 5) | 20.1 (19.8-20.3, 5) | 23.5 (23.3-24, 5) |
| busy | window.qshd.involuntary_switches_per_s | 1439 (1424-1442, 5) | 1226 (1205-1317, 5) | 882 (775-1161, 5) | 828 (671-1077, 5) | 556 (445-676, 5) | 819 (813-837, 5) |
| busy | window.qshd.threads_end | 39 (38-39, 5) | 40 (40-41, 5) | 42 (40-43, 5) | 45 (44-45, 5) | 40 (40-40, 5) | 42 (42-42, 5) |
| busy | window.qshd.voluntary_switches_per_s | 2629 (2617-2710, 5) | 6080 (6076-6237, 5) | 4792 (4635-5723, 5) | 6619 (6342-6624, 5) | 4306 (3711-4871, 5) | 6207 (6055-6271, 5) |
| busy | window.relay.s2c_datagrams_per_s | 1577 (1569-1582, 5) | 2714 (2573-2760, 5) | 2872 (2758-3719, 5) | 2347 (2196-2538, 5) | 2644 (2427-3117, 5) | 2479 (2408-2559, 5) |
| retained | window.qshd.cpu_percent | 3.7 (3.6-3.8, 5) | 5.1 (5-5.2, 5) | 4.7 (4.6-5.2, 5) | 6.1 (5.6-6.2, 5) | 4.9 (4.9-5, 5) | 5.4 (5.3-5.5, 5) |
| retained | window.qshd.involuntary_switches_per_s | 755 (750-756, 5) | 464 (453-464, 5) | 54.3 (34.2-54.6, 5) | 178 (178-210, 5) | 8.4 (7.2-8.8, 5) | 64.5 (60.6-67.3, 5) |
| retained | window.qshd.threads_end | 40 (38-42, 5) | 41 (40-42, 5) | 42 (42-43, 5) | 48 (46-49, 5) | 42 (42-42, 5) | 46 (46-47, 5) |
| retained | window.qshd.voluntary_switches_per_s | 1031 (1029-1031, 5) | 1212 (1202-1217, 5) | 1073 (1058-1207, 5) | 1507 (1362-1510, 5) | 1016 (987-1025, 5) | 1160 (1089-1179, 5) |

### System mode

Raw data: [`performance/2026-10-26-runtime-workers-system/`](performance/2026-10-26-runtime-workers-system/)
and [`-system-16/`](performance/2026-10-26-runtime-workers-system-16/)
(16 sessions).

One session, eight retained, and `busy` with five sessions:

| Workload | Metric | s1 median (p25-p75, n) | s2 median (p25-p75, n) | s2t1 median (p25-p75, n) | s4 median (p25-p75, n) | s4t1 median (p25-p75, n) | s4t2 median (p25-p75, n) |
|---|---|---|---|---|---|---|---|
| idle | window.qshd.cpu_percent | 0 (0-0, 5) | 0 (0-0, 5) | 0 (0-0, 5) | 0 (0-0.1, 5) | 0 (0-0, 5) | 0 (0-0.1, 5) |
| idle | window.qshd.voluntary_switches_per_s | 5.1 (5.1-5.2, 5) | 8 (8-8.3, 5) | 5.6 (5.3-5.6, 5) | 8.8 (8.6-8.9, 5) | 5.4 (5.2-5.4, 5) | 9 (8.9-9, 5) |
| idle | window.qshd_helper.cpu_percent | 0 (0-0.1, 5) | 0 (0-0, 5) | 0 (0-0, 5) | 0 (0-0, 5) | 0.1 (0-0.1, 5) | 0 (0-0, 5) |
| typing | echo_ms.p50 | 1.43 (1.42-1.45, 5) | 1.43 (1.42-1.49, 5) | 1.43 (1.42-1.46, 5) | 1.5 (1.5-1.51, 5) | 1.47 (1.45-1.48, 5) | 1.49 (1.47-1.5, 5) |
| typing | echo_ms.p90 | 1.78 (1.73-1.79, 5) | 1.82 (1.77-1.88, 5) | 1.77 (1.77-1.8, 5) | 1.89 (1.86-1.94, 5) | 1.89 (1.85-1.9, 5) | 1.84 (1.77-1.88, 5) |
| typing | window.qshd.cpu_percent | 0.499 (0.399-0.499, 5) | 0.699 (0.599-0.699, 5) | 0.599 (0.599-0.599, 5) | 0.699 (0.699-0.699, 5) | 0.599 (0.599-0.599, 5) | 0.699 (0.699-0.699, 5) |
| typing | window.qshd.involuntary_switches_per_s | 35.1 (35-35.5, 5) | 4.09 (3.89-4.19, 5) | 1.3 (1.1-1.4, 5) | 1.2 (1.1-1.3, 5) | 0.5 (0.5-0.6, 5) | 1.3 (1.3-1.8, 5) |
| typing | window.qshd.voluntary_switches_per_s | 69.7 (69.5-69.9, 5) | 171 (170-171, 5) | 102 (101-102, 5) | 185 (185-187, 5) | 102 (102-102, 5) | 185 (185-185, 5) |
| typing | window.qshd_helper.cpu_percent | 0 (0-0, 5) | 0 (0-0, 5) | 0 (0-0, 5) | 0 (0-0.1, 5) | 0 (0-0, 5) | 0 (0-0, 5) |
| saturation | completion_s | 2.44 (2.39-2.52, 5) | 1.8 (1.74-2.07, 5) | 1.87 (1.84-2.04, 5) | 2.04 (1.89-2.23, 5) | 2.16 (2.13-2.47, 5) | 2.11 (2.09-2.22, 5) |
| saturation | window.qshd.cpu_percent | 55.6 (55.6-55.8, 5) | 80.3 (78.1-82.4, 5) | 73.1 (72.6-83.9, 5) | 85.8 (85.6-96.5, 5) | 74.9 (71.6-75.4, 5) | 78.8 (70-85, 5) |
| saturation | window.qshd.involuntary_switches_per_s | 3899 (3838-3970, 5) | 74339 (62516-74369, 5) | 78337 (76029-80705, 5) | 43433 (41828-50179, 5) | 51957 (45491-57364, 5) | 51870 (50229-56471, 5) |
| saturation | window.qshd.voluntary_switches_per_s | 21441 (20862-21649, 5) | 60016 (55637-64884, 5) | 62341 (57632-66159, 5) | 58809 (57513-62544, 5) | 36676 (33257-37256, 5) | 42281 (41620-45305, 5) |
| saturation | window.qshd_helper.cpu_percent | 0 (0-0, 5) | 0 (0-0, 5) | 0 (0-0, 5) | 0 (0-0, 5) | 0 (0-0, 5) | 0 (0-0, 5) |
| reconnect | recovery_s | 1.45 (1.45-1.45, 5) | 1.45 (1.45-1.45, 5) | 1.45 (1.45-1.45, 5) | 1.45 (1.45-1.45, 5) | 1.45 (1.45-1.45, 5) | 1.45 (1.45-1.45, 5) |
| retained | window.qshd.cpu_percent | 0.2 (0.1-0.2, 5) | 0.1 (0.1-0.2, 5) | 0.1 (0.1-0.1, 5) | 0.1 (0.1-0.2, 5) | 0.2 (0.1-0.2, 5) | 0.2 (0.2-0.2, 5) |
| retained | window.qshd.voluntary_switches_per_s | 14.7 (14.6-14.7, 5) | 14.3 (14.1-14.3, 5) | 14.3 (14.3-14.6, 5) | 13.9 (13.8-14, 5) | 14.2 (13.9-14.3, 5) | 14.2 (13.9-14.3, 5) |
| retained | window.qshd_helper.cpu_percent | 0 (0-0.1, 5) | 0 (0-0.1, 5) | 0.1 (0-0.2, 5) | 0 (0-0.1, 5) | 0 (0-0.1, 5) | 0 (0-0.1, 5) |
| busy | busy_overrun_s.median | 0.106 (0.103-0.108, 5) | 0.083 (0.076-0.087, 5) | 0.078 (0.078-0.084, 5) | 0.066 (0.063-0.067, 5) | 0.069 (0.065-0.069, 5) | 0.066 (0.065-0.07, 5) |
| busy | echo_ms.p50 | 1.64 (1.61-1.68, 5) | 1.6 (1.57-1.63, 5) | 1.54 (1.53-1.65, 5) | 1.59 (1.55-1.61, 5) | 1.6 (1.52-1.62, 5) | 1.58 (1.57-1.59, 5) |
| busy | echo_ms.p90 | 2.2 (2.19-2.68, 5) | 2.15 (1.95-2.38, 5) | 1.98 (1.97-2.01, 5) | 2.2 (2.01-2.21, 5) | 1.98 (1.97-2.05, 5) | 2.23 (2.17-2.23, 5) |
| busy | window.qshd.cpu_percent | 4.59 (4.19-4.59, 5) | 5.99 (5.69-6.09, 5) | 5.39 (5.29-5.39, 5) | 6.39 (6.39-6.49, 5) | 4.99 (4.99-5.09, 5) | 6.39 (5.99-6.49, 5) |
| busy | window.qshd.involuntary_switches_per_s | 200 (198-201, 5) | 51.1 (37-67.8, 5) | 37.6 (34-44.1, 5) | 148 (69.8-160, 5) | 47.7 (34.5-49.2, 5) | 50.5 (44.3-78.2, 5) |
| busy | window.qshd.voluntary_switches_per_s | 497 (482-510, 5) | 1211 (1149-1292, 5) | 791 (756-833, 5) | 1652 (1456-1830, 5) | 713 (707-715, 5) | 1226 (1221-1301, 5) |
| busy | window.qshd_helper.cpu_percent | 0 (0-0.1, 5) | 0 (0-0, 5) | 0 (0-0, 5) | 0.1 (0.1-0.1, 5) | 0.1 (0-0.1, 5) | 0 (0-0.1, 5) |

16 sessions:

| Workload | Metric | s1 median (p25-p75, n) | s2 median (p25-p75, n) | s2t1 median (p25-p75, n) | s4 median (p25-p75, n) | s4t1 median (p25-p75, n) | s4t2 median (p25-p75, n) |
|---|---|---|---|---|---|---|---|
| busy | busy_overrun_s.median | 0.243 (0.238-0.263, 5) | 0.158 (0.15-0.16, 5) | 0.18 (0.174-0.19, 5) | 0.113 (0.111-0.131, 5) | 0.124 (0.122-0.124, 5) | 0.122 (0.121-0.125, 5) |
| busy | echo_ms.max | 15.7 (6.77-52, 5) | 300 (261-328, 5) | 210 (180-403, 5) | 184 (53.8-198, 5) | 266 (11-434, 5) | 158 (98-192, 5) |
| busy | echo_ms.p50 | 1.8 (1.77-1.98, 5) | 2.15 (1.87-2.58, 5) | 2.06 (1.79-2.17, 5) | 1.9 (1.62-1.96, 5) | 2.03 (1.84-2.23, 5) | 2.12 (1.67-3.22, 5) |
| busy | echo_ms.p90 | 4 (2.88-5.94, 5) | 58.9 (39-75.3, 5) | 5.37 (5.1-7.94, 5) | 3.62 (3.17-13, 5) | 4.31 (3.39-4.88, 5) | 4.99 (4.32-5.25, 5) |
| busy | window.qshd.cpu_percent | 13.4 (12.6-13.7, 5) | 19.4 (18.8-19.8, 5) | 17.5 (16.6-17.6, 5) | 18.7 (18.6-20.5, 5) | 16.2 (16.1-16.8, 5) | 19.5 (19.4-19.8, 5) |
| busy | window.qshd.involuntary_switches_per_s | 683 (677-684, 5) | 721 (590-864, 5) | 406 (307-406, 5) | 540 (495-684, 5) | 295 (243-440, 5) | 585 (573-590, 5) |
| busy | window.qshd.voluntary_switches_per_s | 1574 (1569-1589, 5) | 5365 (4984-5810, 5) | 3075 (2964-3348, 5) | 5456 (5318-5648, 5) | 2859 (2803-3386, 5) | 5150 (5008-5289, 5) |
| busy | window.qshd_helper.cpu_percent | 0.1 (0-0.1, 5) | 0.095 (0-0.096, 5) | 0.092 (0-0.097, 5) | 0.092 (0-0.099, 5) | 0.095 (0.089-0.097, 5) | 0.091 (0-0.099, 5) |
| busy | window.relay.s2c_datagrams_per_s | 1578 (1568-1604, 5) | 2568 (2444-3090, 5) | 2307 (2087-2523, 5) | 2290 (2192-2386, 5) | 2137 (2062-2716, 5) | 2532 (2486-2536, 5) |
| retained | window.qshd.cpu_percent | 0.2 (0.2-0.3, 5) | 0.3 (0.2-0.3, 5) | 0.2 (0.2-0.3, 5) | 0.3 (0.3-0.3, 5) | 0.3 (0.3-0.3, 5) | 0.2 (0.2-0.3, 5) |
| retained | window.qshd.voluntary_switches_per_s | 26.2 (25.9-26.2, 5) | 25.7 (25.3-25.7, 5) | 25.4 (25.3-25.4, 5) | 24.6 (24.6-25.5, 5) | 25 (24.9-25.6, 5) | 25.5 (25.4-25.9, 5) |
| retained | window.qshd_helper.cpu_percent | 0.1 (0.1-0.1, 5) | 0.1 (0.1-0.1, 5) | 0 (0-0.1, 5) | 0.1 (0.1-0.1, 5) | 0 (0-0.1, 5) | 0.1 (0.1-0.2, 5) |

### What these runs show, for this host only

- **No latency difference between worker counts was observed.** The
  median typing echo is 1.4-1.5 ms and its 90th percentile 1.8-2.0 ms in
  every variant of both modes; beside four redrawing sessions it is
  1.5-1.6 ms and 1.9-2.3 ms.
  Recovery after an outage is 1.45 s everywhere. Redraw output is delivered
  at the same rate in every variant.
- **Fewer workers cost less under load.** With two or four CPUs, one worker
  instead of one per CPU lowered qshd's CPU during saturation from 80-95%
  to 73-79%, with completion times within each other's spread, and lowered
  its voluntary switches with active sessions by a fifth to a half. With
  one CPU, the shell producing the output shares it with qshd: qshd used
  56% of it, and saturation took 2.35-2.44 s, against 1.8-2.4 s with more
  CPUs. The end-to-end redraw overrun was smallest with four CPUs,
  whatever the worker count; it includes the redraws' own scheduling on
  qshd's CPUs, not only qshd's delay.
- **The source of the 16-session latency tails is unresolved.** With 15
  redrawing sessions, some echoes per run took tens to hundreds of
  milliseconds, at most 670 ms, in bursts of consecutive keys. They
  correlate with the harness's load: the harness, one Python process that
  relays every datagram and drains every terminal, used 11-25 s of CPU per
  run of about 31-43 s, and the one-CPU variants, whose qshd coalesced the
  output into the fewest datagrams (about 1580 per second against
  2140-2870), had almost no late echoes. Harness saturation is a plausible
  confound, but correlation does not establish the cause, and affinity
  changes contention too: in the four-CPU variants qshd shares CPUs with
  the harness, and in every variant the redraws run on qshd's CPUs. These
  runs therefore neither attribute the tails to the worker count nor rule
  it out. Their CPU and switch counts stand.
- **The helper is unaffected.** In system mode the privileged helper stays
  single-threaded, at 0-0.1% of a CPU and about 5 voluntary switches per
  second, in every variant and workload.
- **Personal and system mode differ when idle, independent of workers.**
  An idle personal qshd uses 0.7% of a CPU and switches about 115 times per
  second; with 8 or 16 retained sessions, 2.4-6.1% and 530-1510 switches.
  The system-mode worker uses 0-0.3% and 5-26 switches in the same
  workloads. The difference grows by about 60-90 switches per second for
  each session, which matches a poll every 20 ms: in personal mode the
  session shell is qshd's own child, and its exit is observed by polling
  (`ActiveObservation::Poll`, the default of `ChannelWait` in
  `crates/transport/src/channel_server.rs`, which `NativeWait` keeps),
  while in system mode the helper owns the shell and notifies the worker
  of its exit (`ActiveObservation::Notification`). A per-thread sample of
  one idle personal session showed about 110 voluntary switches per second
  on three threads. No profiler confirmed the attribution.
- **Threads.** qshd's thread count is the async workers plus the blocking
  pool, which grows with the sessions: each terminal's reader and writer
  are blocking threads. With 16 sessions qshd had 38-48 threads in every
  variant.

The default stays one worker per CPU that qshd may use, with
`--runtime-threads` to set it explicitly (see
[the service guide](qshd-service.md#runtime-worker-threads)). These runs
support keeping that default and report the ranges observed on one 4-CPU
VM. They do not show that worker counts are equivalent elsewhere, and
establish no setting for hosts with many CPUs or for the system mode's 128
sessions, which were not measured.
