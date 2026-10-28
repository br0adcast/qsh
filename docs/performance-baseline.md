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

## Opt-in client-history qualification

The optional `--workloads history` exercises **client** history, separately
from `retained`, which keeps detached server sessions. Use the nominal ten-second
producer duration and 20 Hz redraw settings. The actual CPU window covers dispatch
through the producer completion checkpoint, including scheduling delay; it is not
truncated at ten seconds. Client application may finish a tail after that
checkpoint. Relay progress and a positive return-to-live marker are required
separately. Deterministic parser and ownership tests are not performance results.

The client requests 4,000 history lines at 120×40, within the logical-cell
cap. A finite FIFO-controlled producer fills 2,000
rows, then 6,000 more while a locally selected history viewport is pinned, then
produces 200 carriage-return updates. Fresh full-repaint probes using same-size
SIGWINCH observe positive scroll offset/total and numbered rows outside the CPU
window. They do not change the PTY extent. A producer checkpoint alone is not
proof the client ingested all output, so bounded observation probes wait for the
positive cap. Before the capped load, the fixture observes actual oldest numbered
rows at offset equal to total, then restores the original selected PageUp view.
After proving that view stayed pinned and returning live, a fresh actual top
observation must have total 4,000 and a first numbered row greater than the
initial oldest witness. This proves oldest advancement, not eviction of the
entire selected frame or delivery of all 8,000 producer rows. Navigation
requirements are checked inside the bounded repaint probe, so a repaint before
the navigation is applied is not accepted. Final return-to-live and top-of-history observations are required;
missing or changed oracles fail the run, and existing owned cleanup still runs.
Partial-fill and return-to-live markers also require a complete full-repaint
observation after producer completion. A diff may retain a visible marker's
leading cells, so escape-stripped raw substring matching is insufficient; a
captured cursor-position/common-prefix regression qualifies this boundary.
These selected text/status observations are not a complete framebuffer emulator.

Named memory phases record the measured client, not its server sessions:
endpoint VmRSS, smaps-rollup PSS and private clean plus dirty, and lifetime VmHWM.
Twenty-Hz RSS samples during the repaint window yield only a sampled maximum,
not an instantaneous peak. VmHWM is since exec, not reset per phase; PSS/private
are residency accounting, not pure heap allocation. Leaving history mode keeps
the configured terminal history, so memory need not return to startup levels.
No allocator trimming or kernel high-water reset is performed. Keep unfavorable
values and the sampler's whole-run harness overhead. Existing allocation and
frame-equivalence controls supply different evidence from these resident values.

Each phase uses owned private state and finite deadlines. A failed or truncated
producer, incomplete observation, missing memory field, client exit or cleanup
error cannot qualify as a successful history result. Preserve raw phase samples,
all errors and binary/build provenance. Failed runs retain completed phases,
the latest parsed navigation candidates and memory samples collected before a
failure, with `history_complete=false`. Even `history_complete=true` cannot
override a cleanup failure in the outer `ok` verdict. The history schema requires a corresponding completeness gate; a fixed gate for
a different workload set is not sufficient.
Final-marker observation includes the forced repaint and possibly its bounded
reprobe; it is not unperturbed client-tail latency. The observations do not
prove every numbered row was delivered or supply an output-loss metric.
No runtime measurement is part of ordinary CI.

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
read the worker's `/proc` descriptors and counters. In system-mode runs `qshd` is
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
mode the log names the account the harness ran as. Keep outputs local and review
them for private data before sharing any explicitly requested evidence.

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

## In-process probes

These optional fixed-workload tools run without a server or a client connection.
Their output is local experiment evidence, not a regression-test verdict.

### Frame storage probe

```sh
cargo run --release --locked -p qsh --example frame_storage -- [--time] [--steps N] [WORKLOAD...]
```

The probe drives client presentation through fixed workloads. Its default mode
counts allocations, requested bytes and retained live heap; `--time` measures
elapsed and thread CPU time without allocation accounting. `--steps N` selects
the amount of work, and zero performs preparation and warm-up only. Compare like
modes and workload counts. Whole-process counters include preparation unless a
matched zero-step control is subtracted. Output fingerprints are useful
consistency checks, not proof against every output difference or hash collision.

### Combining-mark comparison probe

```sh
cargo run --release --locked -p terminal --example cell_equality -- CASE [ROUNDS]
```

`CASE` is `empty`, `short`, `full` or `base-differs`. The probe compares frames
built from fixed terminal input and prints the number of equal cell pairs.
`base-differs` is a short-circuit control. Counts must agree before comparing
instruction or timing measurements. A whole-process counter also measures frame
construction; separate that fixed cost from repeated comparison work. These
synthetic cases do not establish end-to-end client latency or CPU savings.
