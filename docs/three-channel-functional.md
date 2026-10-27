# Three-channel functional qualification

This opt-in Linux fixture uses one connection with two Pipes and one Screen.
It checks bounded withheld Screen consumption, a positive server-side credit
blockage witness, credit recovery, finite producer completion and owned cleanup.
It is functional qualification for #305, not a throughput or latency benchmark.

Build the committed example using the repository's pinned compiler and qualified
native dependencies. The example uses the existing testnet-only support:

```sh
cargo build --locked --offline -p qsh --example three_channel305
```

Use an existing executable and a fresh state directory below a private parent.
The parent and all fixture state must belong to the invoking account with mode
0700. Do not use a personal daemon, SSH configuration or existing session:

```sh
umask 077
state_parent=$(mktemp -d)
chmod 0700 "$state_parent"
python3 -I -B scripts/three_channel_functional.py \
  --binary target/debug/examples/three_channel305 \
  --root "$state_parent/run"
```

The wrapper requires tracked-clean source. Build and run from the same reviewed
commit; retain the build command and toolchain/native provenance separately.
Recorded source, lock, script and binary hashes identify local inputs but do not
prove that an arbitrary binary was compiled from that source.

The fixed case transfers 4 MiB of bulk data and 32 echo responses while a finite,
grant-paced Screen producer exercises withheld consumption. The hold budget is
up to 5 seconds: observing the required blockage can release it sooner. The
internal work bound is 30 seconds and the outer bound is 40 seconds, including
room to report failure. Neither is a measured performance target. Output capture
is limited to 64 KiB. A half-second watcher requests stop above 256 MiB of owned
allocated data or below 12 GiB free space; this is sampled enforcement, not a
filesystem quota.

The wrapper creates a private environment and a new process session. It retains
an unreaped leader as the process-group identity anchor before one TERM, then
reaps its owned descendants. Cleanup has a 120-second grace; an overrun remains
a failure and retains custody until settlement. There is no KILL or retry.
The resource watcher is stopped and joined. Do not interrupt cleanup by killing
the wrapper; preserve its evidence and arrange an explicit ownership handoff if
cleanup cannot settle.

`provenance.json`, `output.log` and `result.json` stay under the new state root.
The result preserves complete bounded native output even when validation fails.
Success requires the complete native record, fixed work, ordered positive
blockage/release/recovery witnesses, the final marker, all producer exits,
driver/manager/registered cleanup receipts, zero retained raw/held data and no
remaining owned children. A settled cleanup does not turn work failure into
success. No existing output directory is overwritten.

The first private pilot failed with `missing owned Screen blockage`; its evidence
was preserved. The corrected grant-paced pilot passed in 2.306 seconds, with
blockage/release/recovery sequences 446/510/694, 4 MiB bulk, 32 echoes, the final
marker and all cleanup receipts. This was one no-loss functional case. Its
observer skipped two samples; snapshots are latest-value observations, not an
exhaustive event log. Producer completion before release was unobserved, and the
applied-model gap oracle was not qualified. Zero decoded gaps do not establish
all screen updates were applied. These results do not establish CPU benefit,
loss/reorder behavior, scheduling fairness or completion of #305.

Run the deterministic wrapper controls without qsh or daemon execution:

```sh
python3 -I -B scripts/test_three_channel_functional.py
```

## Fixed loss/reorder case

The default `--case no-loss` forwards all packets. The optional
`--case loss-reorder` uses a fixture-only loopback UDP relay; it changes no
production protocol or network policy. The relay arms only after authenticated
admission, all three channels are ready, and the current Screen model contains
the producer's READY marker, before the first producer grant. Server-to-client
packets are then numbered in arrival order: packet 3 is dropped, packet 7 is
held, and packet 8 is sent before packet 7. Client-to-server packets are always
forwarded. Payloads are neither decrypted nor logged by the relay.

Use the same command with a **new** state root for each case:

```sh
python3 -I -B scripts/three_channel_functional.py \
  --binary target/debug/examples/three_channel305 \
  --root "$state_parent/loss-case" --case loss-reorder
```

The relay retains at most one datagram and uses fixed receive buffers. Its arm
acknowledgment comes from its running task; cleanup stops and joins that task
and releases any held packet. A faulted result requires receipts for the actual
single drop and completed 8-before-7 forwarding, no canceled held packet, and
all existing work, credit-recovery and cleanup conditions. A no-loss result
cannot satisfy that faulted receipt requirement. Missing packet 8 or an
incomplete injection remains a failure, even if terminal work otherwise ends.
The existing 5/30/40-second work budgets and retained cleanup are unchanged.
This is a bounded functional case, not a loss-rate, CPU or fairness benchmark.
A fixed ordinal schedule does not promise identical logical losses across
other packetizations, and decoded gaps remain distinct from model-applied gaps.

## Scalar measurement scope

The native record additionally reports `measurement.process_cpu_ns` from
`CLOCK_PROCESS_CPUTIME_ID` and `measurement.elapsed_ns` from the monotonic clock.
`measurement.process_cpu_resolution_ns` is the nonzero kernel-reported clock
resolution, not an accuracy guarantee or error bound; nanosecond units alone do
not establish nanosecond measurement accuracy.
The window starts at native entry and ends after client, manager, relay and
registered cleanup have settled, before final JSON serialization and runtime
teardown. Wrapper startup, binary/source hashing and wrapper cleanup are outside
this window. Process CPU covers all fixture threads: client driver, server
manager, relay and model/fixture work. It excludes producer-process CPU; no child
CPU estimate or client/daemon attribution is provided. These scalar counters
prepare later matched release measurements; a debug functional pilot is not a
performance comparison.

The relay reports client/server ingress and completed-forward datagrams/bytes
for its whole lifetime, including authentication and teardown traffic. Dropped,
held and reordered fault receipts remain separate. A successful forward counts
a completed UDP send; ingress counts a received datagram. These counts are not
kernel syscall attempts and do not identify endpoint CPU. Screen producer grants
can vary with the observed credit path; retain their counts and unfavorable
outcomes rather than filtering runs to manufacture identical work or a gain.
