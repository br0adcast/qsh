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
