#!/bin/sh
# Fails a test run whose log says a test did not actually run.
#
# A skipped test reports as PASSED. `cargo test` has no notion of "skipped":
# a test that looks at the machine, decides it cannot do its work here and
# returns prints `SKIPPED ...` to stderr and exits normally, so libtest
# counts it in `N passed` and the job goes green. Without `--nocapture` the
# line is not even printed. Measured before this script existed: on a
# machine that is not root, three of the end-to-end PAM tests reported
# "3 passed" in 0.00 seconds having checked nothing at all.
#
# In the container tier every test is meant to run: that tier exists
# precisely because the ordinary job cannot be root. A `SKIPPED` line there
# is a failure OF THE TIER -- the tier did not do the one thing it is for --
# and not a property of the machine to be shrugged at.
#
# Two things are checked, because a run can report nothing for two
# different reasons:
#
#   1. Something ran. A `test result:` line saying `0 passed` is what an
#      empty test binary prints, and an empty test binary is exactly what
#      the five system suites compiled to for as long as the pipeline built
#      them without `--features qshd/system`: twenty-one binaries, five of
#      them silently containing no test, all green.
#   2. Nothing skipped, except what was explicitly named on the command
#      line. A name is allowed here ONLY when that test cannot run in this
#      kind of run at all AND another job runs it -- the library tests have
#      four that refuse to run AS ROOT (root would make the very call they
#      expect to fail succeed), and the ordinary non-root job is where
#      those four do their work. Everything else must run. A `SKIPPED` line
#      this cannot read a test name out of is a failure too: it cannot be
#      one of the allowed names, so it is one of the rest.
#
# A pass says which of those two runs it was -- whether anything was allowed
# to skip and what -- because "none skipped" reads identically for a run
# where nothing may skip and a run where four things may.
#
#   3. Nothing was taken OUT of the run. `#[ignore]` on a test, or a
#      `--skip` on the command line, removes it before it can skip or fail:
#      libtest then reports it in `N ignored` / `N filtered out` and counts
#      neither as a failure. Measured: `#[ignore]` on
#      `an_expired_account_is_refused` -- one of the two tests this tier is
#      judged by -- makes the suite report "2 passed; 1 ignored" and this
#      check, before it counted them, said `ok`. A test deliberately removed
#      from a run is exactly as dangerous as one that skipped.
#
#      `--ignored N` declares how many are expected: EXACTLY N, not "at most"
#      and not "any". Zero is the right answer for the five system suites --
#      nothing there may be left out. The library binary has 40, every one of
#      them a body a parent test re-invokes in a process of its own ("runs
#      only via ..."), so they ARE run, through another door; an exact count
#      is what makes a 41st somebody's decision rather than nobody's. A
#      filter is never expected and is not declarable: this tier passes none.
#
#   4. The tests this tier is judged by are still IN the binary and still
#      pass. `N passed` says how many ran, not WHICH -- a test compiled out
#      by a rename, a deletion, or `#[cfg(any())]` just makes N smaller, and
#      every test still in the binary still says `ok`. Measured, with
#      `#[cfg(any())]` standing in for a deletion the way the rest of this
#      file uses `#[ignore]` to stand in for one: put it on a litmus test and
#      the suite prints `2 passed; 0 failed; 0 ignored; 0 measured; 0
#      filtered out`, and this check, before this section existed, said `ok`.
#      That is a fourth, different way to report nothing: 1 catches an empty
#      binary, 1b and 2 catch a test that is still IN the binary but did not
#      run, and this catches a test that is not in the binary at all -- the
#      one hole those three cannot see, because there is no line to read: a
#      test that was never built leaves no trace in the log, only in a diff
#      nobody here is looking at.
#
#      `--require NAME` (repeatable) names a test whose own `test NAME ...`
#      must be followed by a bare `ok` before anything else happens. NOT a
#      substring search over the whole log: every suite in this tier runs
#      `--nocapture` (see the container job for why), so a passing test's
#      OWN stdout routinely lands between the `test NAME ... ` libtest
#      prints before the test body runs and the `ok` it prints once that
#      body returns -- "test NAME ... ok" as one physical line is the
#      exception, not the rule, and a plain `grep -q NAME` would also credit
#      a name that only appears in another test's output or panic message.
#      This instead walks the log in the order it was written -- true
#      because every suite here runs at --test-threads=1 -- and credits a
#      required name with whatever bare status line comes next after THAT
#      name's own `test NAME ... ` line, wherever the two fall.
#
#      That walk trusts a `test NAME ... ` control line unconditionally,
#      which is itself exploitable: at --test-threads=1 two of libtest's OWN
#      control lines never appear back to back with only another test's
#      body between them, so a `test NAME ... ` line arriving while a
#      PREVIOUS name is still waiting for its own outcome is not a second
#      test starting -- it is some test's --nocapture output that happens to
#      look like one, and trusting it lets the real test's next outcome line
#      get credited to a forged name instead. Measured on a real container
#      log with the litmus test physically cut out and one such line planted
#      in a different, still-running test's own output: `--require` said
#      `confirmed present and passing` for a test that was not in the binary
#      at all. This is refused as a corrupted log instead of guessed at --
#      see section 3 below for why guessing is not the fix.
#
#      Guarding an occupied `pending` still leaves an EMPTY `pending` open: a
#      self-contained forged `test NAME ... ok`, complete on one line, at the
#      top of the log or in the ordinary gap between two real tests, looks
#      exactly like a genuine quiet test and satisfies all three rules with
#      nothing to catch it -- tightening what one line must look like is a
#      race against the next shape that would still be waiting. Section 3
#      below instead reconciles a COUNT against libtest's own `N passed; M
#      failed; K ignored` line, which a forged outcome always inflates by
#      one wherever it lands, and a genuine removal never does (the count
#      falls with the test).
#
#      The count survives a subtler forgery, though: a genuinely FAILED
#      test can be whitewashed by a second, self-contained `test NAME ...
#      ok` reusing the SAME name, dropped in the ordinary gap after that
#      name's own real outcome. This changes no count section 3 tracks --
#      one distinct name before, the same one distinct name after -- and
#      steals no open `pending` (there is none left to steal once the real
#      outcome has already resolved it). So a name resolved once may never
#      be resolved again: the second resolution is refused as a corrupted
#      log, naming the test and both outcomes it was given, the same way
#      two overlapping announcements are refused above.
#
#      None of this means anything if $result itself cannot be trusted,
#      and it could not be: `test result: ...` was read by the first match
#      in the log (see section 1), which assumes a caller never runs more
#      than one binary through this script -- true of every real call site
#      here -- but does not defend against the BINARY ITSELF printing a
#      line shaped like that summary before its own genuine one. Measured,
#      not hypothetical: `channel.rs`'s
#      `a_second_descriptor_in_one_message_is_not_leaked` re-invokes this
#      same test binary as a child and, on ITS OWN failure path, echoes the
#      child's raw stdout -- ending in a real `test result:` line -- into
#      the parent's own --nocapture output. Section 1 now requires EXACTLY
#      one `test result:` line, refusing to prefer the first or the last
#      when there is more than one, for the same reason section 3 refuses
#      to guess which of two overlapping test names is real.
#
#      `--require` is a second list, and it is not the "may skip" list:
#      one says a name is ALLOWED to be missing from a passing run, the
#      other says a name is REQUIRED for the run to count as one. Treating
#      them as the same list would let an allowed skip stand in for a
#      required pass, or a required name quietly excuse itself from running.
#
# Usage: scripts/no-silent-skips.sh <log> [--ignored N] [--require NAME ...] [test-name-that-may-skip ...]
#
# Exit status:
#   0  the log shows tests running, nothing skipping unexpectedly, and every
#      required test present and passing
#   1  a test skipped where none may, a test was left out of the run, a
#      required test did not pass (or is gone from the binary), the log
#      itself is corrupted (two overlapping test announcements, the same
#      test name resolved twice, more than one `test result:` line, or a
#      credited-outcome count that disagrees with the summary line), or the
#      run ran no test at all
#   2  bad usage
set -eu

usage() {
    sed -n '2,/^set -eu/{/^set -eu/d;s/^# \{0,1\}//;p}' "$0" >&2
    exit 2
}

[ $# -ge 1 ] || usage
log=$1
shift
expected_ignored=0
# A space on each side of every name, exactly as `$allowed` below, so a
# `case` match is exact rather than a prefix: `the_worker` must not stand in
# for `the_worker_runs_as_its_configured_account`.
required=" "
# `--ignored` and `--require` may repeat and come in any order, but both
# must come before the free list of "may skip" names: that list is
# positional and starts at the first token that is not one of these two
# flags, exactly as it always has.
while [ $# -gt 0 ]; do
    case "$1" in
        --ignored)
            [ $# -ge 2 ] || usage
            expected_ignored=$2
            case $expected_ignored in
                '' | *[!0-9]*) usage ;;
            esac
            shift 2
            ;;
        --require)
            [ $# -ge 2 ] || usage
            required="$required$2 "
            shift 2
            ;;
        --)
            shift
            break
            ;;
        --*)
            usage
            ;;
        *)
            break
            ;;
    esac
done
# A late `--ignored`/`--require` -- one that lands after the free "may skip"
# list has already started -- is not a flag any more: the loop above has
# already switched into positional mode and does not look at it again. Left
# unchecked it is silently absorbed as a LITERAL SKIP NAME (the test named
# "--require", and whatever followed it as a separate name), and the run
# then reports zero required names with no error at all -- exit 0, "no
# --require names were declared for this run" -- for a caller who plainly
# asked for one. Measured: `mixed.log beta --require gamma` (a clean,
# otherwise all-green two-test log) does exactly this on the unguarded
# parser. No positional name in this domain can ever legitimately start with
# `--`: every name here is a Rust test identifier, and identifiers cannot
# start with `-`. So any remaining argument that does is always a mistake,
# not a rare valid case worth accommodating -- including one after an
# explicit `--` terminator, which exists only to end FLAG parsing, not to
# license a name shaped like a flag.
for arg in "$@"; do
    case "$arg" in
        --*) usage ;;
    esac
done
# A space on each side of every name, so `case` can ask for an exact match
# rather than a prefix: `the_worker` must not stand in for
# `the_worker_runs_as_its_configured_account`.
allowed=" $* "

if [ ! -f "$log" ]; then
    echo "no such log to check: $log" >&2
    exit 1
fi

failures=0
allowed_seen=0

# --- 1: the run ran something, and said so exactly once ----------------------
# `test result:` is libtest's own summary, and every later section that
# reads a count out of it -- 1b, and section 3's reconciliation -- trusts
# whichever line this picks. Every real call site here runs exactly one
# binary per log (one `docker run ... | tee "$logs/$name.log"` per
# `run_suite`, never concatenated), so "pick the first line" was never a
# convenience for multiple binaries sharing a log -- it was a hole: a line
# SHAPED like a summary, printed by the binary itself before its own real
# one, gets taken as the real one by every section that reads it, and the
# genuine line that follows is never looked at again. Measured, not
# imagined: `qshd/src/helper/channel.rs`'s
# `a_second_descriptor_in_one_message_is_not_leaked` re-invokes this same
# test binary as a child process and, on its own failure path, echoes the
# child's raw stdout -- which ends in a real `test result:` line -- into
# the parent's own --nocapture output. A forged early summary needs nothing
# more exotic than that same channel, already present in this repository,
# to become real.
#
# So there must be EXACTLY one `test result:` line -- not "the first" and
# not "the last". Two or more is not resolved by preferring either one:
# picking any one of them is exactly the kind of guess this script already
# refuses to make about which of two overlapping test names is real (see
# section 3). A log with more than one summary line is a log this script
# cannot judge, and says so instead of judging it anyway.
result_count=$(grep -c '^test result:' "$log" || true)
result=""
if [ "$result_count" -eq 0 ]; then
    echo "$log has no 'test result:' line at all: the run did not finish, or never started" >&2
    failures=$((failures + 1))
elif [ "$result_count" -gt 1 ]; then
    echo "$log has $result_count 'test result:' lines, and exactly one binary's real summary" \
        "is trustworthy -- something else in this run's own output produced the rest:" >&2
    grep '^test result:' "$log" | sed 's/^/  /' >&2
    failures=$((failures + 1))
else
    result=$(grep '^test result:' "$log")
fi
passed=$(printf '%s\n' "$result" | sed -n 's/^test result:.*[^0-9]\([0-9][0-9]*\) passed.*/\1/p')
if [ -n "$result" ] && { [ -z "$passed" ] || [ "$passed" -eq 0 ]; }; then
    echo "$log reports no test passing -- an empty test binary reports exactly this and exits 0:" >&2
    echo "  $result" >&2
    failures=$((failures + 1))
fi

# --- 1b: nothing was taken out of the run ------------------------------------
# An ignored or filtered test never gets as far as skipping: it is removed
# before it runs, and libtest reports it on the same line as a number that
# fails nothing. Both are read from `$result`, which is empty only in the
# case already reported above.
count_in_result() {
    printf '%s\n' "$result" | sed -n "s/^test result:.*[^0-9]\([0-9][0-9]*\) $1.*/\1/p"
}
if [ -n "$result" ]; then
    ignored=$(count_in_result ignored)
    filtered=$(count_in_result 'filtered out')
    # Read here for section 3 below, where it joins `passed` and `ignored`
    # in a reconciliation this summary line makes possible: the three
    # numbers together are libtest's own claim of how many outcomes it
    # produced, independent of anything section 3's resolver counts itself.
    failed=$(count_in_result failed)
    if [ "${ignored:-0}" -ne "$expected_ignored" ]; then
        echo "$log reports ${ignored:-0} ignored test(s), and exactly $expected_ignored was" \
            "declared -- an #[ignore] takes a test out of the run and fails nothing:" >&2
        grep -E '^test .* \.\.\. ignored' "$log" | sed 's/^/  /' >&2 || true
        echo "  If that is right, say so with --ignored ${ignored:-0} and why; otherwise the" \
            "test is missing from this run." >&2
        failures=$((failures + 1))
    fi
    if [ "${filtered:-0}" -ne 0 ]; then
        echo "$log reports ${filtered:-0} test(s) filtered out: this tier passes no filter, so" \
            "something removed tests from the run:" >&2
        echo "  $result" >&2
        failures=$((failures + 1))
    fi
fi

# --- 2: nothing skipped that was not named -----------------------------------
skips=$(grep 'SKIPPED' "$log" || true)
while IFS= read -r line; do
    [ -n "$line" ] || continue
    # `SKIPPED <test name>: <reason>` is the shape every skip line in this
    # repository has. A line that does not have it is not readable as an
    # allowed skip, so it is a failure whatever it says.
    name=$(printf '%s\n' "$line" | sed -n 's/.*SKIPPED \([A-Za-z0-9_]\{1,\}\).*/\1/p')
    # A line whose test name this cannot read is NOT on the command line,
    # whatever else is true of it -- so it is a skip that may not happen.
    # Without this the `case` below was reached with an empty name, and an
    # empty name matched an empty allow-list: `" $* "` with no arguments is
    # two spaces, and so is `" $name "`. The hole was open exactly where the
    # five system suites are checked, which are the runs where nothing may
    # skip at all.
    if [ -z "$name" ]; then
        echo "a line says SKIPPED and no test name can be read out of it, so it is not one of \
the names allowed on the command line:" >&2
        echo "  $line" >&2
        failures=$((failures + 1))
        continue
    fi
    case "$allowed" in
        *" $name "*)
            echo "note  a skip named on the command line, run by another job: $line"
            allowed_seen=$((allowed_seen + 1))
            ;;
        *)
            echo "a test skipped in a run where nothing may skip:" >&2
            echo "  $line" >&2
            failures=$((failures + 1))
            ;;
    esac
done <<EOF
$skips
EOF

# --- 3: the required tests are still in the binary and still passed ---------
# See point 4 in the header for why this is not a `grep -q NAME` over the
# whole log. Because every suite here runs at --test-threads=1, the log is
# the order the tests actually ran in: a line that starts a test (`test NAME
# ... ` with nothing, or something other than a bare status word, after it)
# is followed -- once that test's own --nocapture output, if any, has gone
# by -- by a line that is exactly `ok`, `FAILED`, or `ignored`, and by
# nothing else that looks like a fresh `test ... ... ` start before it. That
# next bare status line is credited to the test that is pending, i.e. the
# most recently started one whose status has not yet been seen. A required
# name that never starts a `test NAME ... ` line at all -- renamed, deleted,
# `#[cfg]`'d out -- is simply never credited with anything, `ok` included.
#
# A test announcement -- either shape, `test NAME ... ok` all on one line or
# `test NAME ... ` alone -- arriving while a PREVIOUS one is still pending is
# not a second test starting: at --test-threads=1 libtest never interleaves
# two tests' own control lines, only a test's --nocapture body ever sits
# between them. Such a line is therefore always synthetic -- another test's
# own output that happens to look like a `libtest` control line -- and
# trusting it is exactly how a name that never really ran gets credited
# `ok`: the forged line supplies the name, and the REAL test's own genuine
# outcome line supplies the `ok` a moment later, for a name that was never
# actually run in this binary. Measured: an untouched real container log for
# `system_mode_pam`, with `an_expired_account_is_refused` physically cut out
# and a single forged `test an_expired_account_is_refused ... ` line dropped
# into the middle of a DIFFERENT, still-running real test's own output --
# --require said `confirmed present and passing` for a test that is not in
# the binary at all. Rather than guess which of the two names is the real
# one, this is refused outright as a corrupted log: named, both names, and
# failed, because a log that can be read two ways cannot be the thing
# `--require` is trusted to answer.
#
# That guard only fires when a test announcement lands ON TOP OF a pending
# one -- it says nothing about a SELF-CONTAINED forged line (`test NAME ...
# ok` complete in one line) landing where `pending` is already empty, which
# is most of the log: the top, before the first real test has announced
# itself, or the ordinary gap between one test resolving and the next
# starting. Nothing about that shape looks wrong on its own -- it is
# indistinguishable from a genuine quiet test -- so no amount of tightening
# what a single line must look like closes it; the next unexamined gap is
# always still there. Measured on a real container log for `system_mode_pam`
# with the litmus test physically cut out and a single forged `test
# an_expired_account_is_refused ... ok` dropped into that exact gap, touching
# no other test's output at all: `--require` again said `confirmed present
# and passing`, zero HIJACK lines, for a test not in the binary.
#
# The fix does not try to recognize this shape by how it looks -- it
# reconciles a COUNT instead. `test result: N passed; M failed; K ignored`
# is libtest's own claim of how many outcomes it produced; every outcome
# this resolver credits (anyone in `seen`, real or forged) must total
# exactly N+M+K, no more and no fewer. A forged line credits ONE outcome the
# summary never produced, wherever it is dropped -- this does not need to
# know where, only that the two counts disagree. A genuine removal is the
# opposite: the summary falls WITH the test, so the two counts stay equal,
# and catching that stays the job of `--require`'s own MISSING report, not
# this one.
if [ "$required" != " " ]; then
    resolved=$(awk -v want="$required" '
        BEGIN { n = split(want, req, " "); for (i = 1; i <= n; i++) need[req[i]] = 1 }
        # `- should panic` decorates the start line of any `#[should_panic]`
        # test ("test NAME - should panic ... ok"), on the two rules below
        # that can actually see one (see the ignored-rule comment further
        # down for the third), the same way "ignored, <reason>" decorates
        # an #[ignore]d one: it is not part of the name (`$2` is unaffected,
        # since the decoration always follows a space) and not part of the
        # outcome ($NF is still the last token). Missing it is silent in
        # the wrong direction from a hijack: the whole line matches NONE of
        # these rules (there is text where `\.\.\. ` is expected), so it is
        # not read as a test at all -- neither an announcement nor an
        # outcome -- and a should_panic test that genuinely passed is
        # simply never credited. Measured with a real, compiled,
        # genuinely-passing #[should_panic] test in a real container: the
        # count check just above (not a HIJACK) caught the resulting
        # credited-vs-summary mismatch before this rule existed, and
        # --require reported the test outright MISSING. `compile_fail`/
        # `no_run` decorate only the doctest binary rustdoc merges on its
        # own, which this script never sees (`cargo test --doc` does not
        # run through it); `should_panic` is an ordinary attribute reachable
        # in any of these six binaries, even though none uses it today.
        /^test [^ ]+( - should panic)? \.\.\. (ok|FAILED)$/ {
            if (pending != "") { print "HIJACK " $2 " " pending; next }
            if ($2 in seen) { print "DUPLICATE " $2 " " seen[$2] " " $NF; dup[$2] = 1; next }
            seen[$2] = $NF
            next
        }
        # `#[ignore = "reason"]` -- carried by every one of the library
        # binary 40 declared-ignored tests -- makes libtest print "ignored,
        # <reason text>" on this same line, not a bare "ignored". Matched
        # separately, with the status forced to the literal word rather than
        # read from the last field: the last word of the reason text is not
        # the outcome. Missing this rule does not go unnoticed quietly -- a
        # line like it falls through to the next rule instead, which reads
        # it as a test that is merely STARTING, and the "next test
        # announced" guard just above turns that mismatch into a false
        # HIJACK on every one of the 40 the moment the next real test
        # starts. Measured on a real log from the library binary before
        # this rule existed.
        #
        # No `( - should panic)?` here, unlike the rule above: read
        # straight from the libtest source (`TestDesc::test_mode` in
        # `library/test/src/types.rs`), whose very first line is `if
        # self.ignore { return None; }` -- an ignored test is never handed
        # the should_panic decoration, no matter what its own attributes
        # say, because the mode check that would add it never runs. Adding
        # it here would be dead on arrival, so it stays out.
        /^test [^ ]+ \.\.\. ignored(,.*)?$/ {
            if (pending != "") { print "HIJACK " $2 " " pending; next }
            if ($2 in seen) { print "DUPLICATE " $2 " " seen[$2] " ignored"; dup[$2] = 1; next }
            seen[$2] = "ignored"
            next
        }
        /^test [^ ]+( - should panic)? \.\.\. / {
            if (pending != "") { print "HIJACK " $2 " " pending; next }
            pending = $2
            next
        }
        pending != "" && /^(ok|FAILED|ignored)$/ {
            if (pending in seen) {
                print "DUPLICATE " pending " " seen[pending] " " $0
                dup[pending] = 1
                pending = ""
                next
            }
            seen[pending] = $0
            pending = ""
            next
        }
        END {
            credited = 0
            for (name in seen) credited++
            print "CREDITED " credited
            for (name in need) {
                # A name already reported DUPLICATE is not also reported
                # MISSING: "renamed, removed, or never reached ok" is the
                # wrong story for a test seen TWICE, and the DUPLICATE
                # report above already says the true one.
                if (!(name in dup) && seen[name] != "ok") print "MISSING " name
            }
        }
    ' "$log")
    credited=$(printf '%s\n' "$resolved" | sed -n 's/^CREDITED //p')
    hijacked=$(printf '%s\n' "$resolved" | sed -n 's/^HIJACK //p')
    duplicated=$(printf '%s\n' "$resolved" | sed -n 's/^DUPLICATE //p')
    missing=$(printf '%s\n' "$resolved" | sed -n 's/^MISSING //p')
    if [ -n "$duplicated" ]; then
        echo "$log resolves the same test name more than once, and a name resolved once may" \
            "never be resolved again -- a genuinely FAILED test can otherwise be whitewashed" \
            "by a second, self-contained forged line reusing its name in the ordinary gap" \
            "after its real outcome, which changes no count this script tracks (same name," \
            "same number of distinct names credited) and steals no open \`pending\` (there" \
            "is none to steal):" >&2
        while IFS=' ' read -r nm first second; do
            [ -n "$nm" ] || continue
            echo "  \"$nm\" resolved first as \"$first\", then again as \"$second\"" >&2
        done <<EOF
$duplicated
EOF
        echo "  Neither outcome is trustworthy from this log. This is not a missing-test" \
            "report either: a test that was seen twice is not a test that was never seen." >&2
        failures=$((failures + 1))
    fi
    # Only meaningful once $result itself is trustworthy: with zero or with
    # more than one `test result:` line, section 1 has already said so and
    # counted it, and comparing against a summary this run could not even
    # settle on one of would just repeat that same problem in a more
    # confusing shape ("claims 0" when the truth is "which one it claims is
    # exactly what is in question").
    if [ -n "$result" ]; then
        expected_total=$((${passed:-0} + ${failed:-0} + ${ignored:-0}))
        if [ "${credited:-0}" -ne "$expected_total" ]; then
            echo "$log: the resolver credited ${credited:-0} outcome(s), but the summary line" \
                "claims $expected_total (${passed:-0} passed + ${failed:-0} failed +" \
                "${ignored:-0} ignored). A forged \`test NAME ... \` line, dropped anywhere" \
                "\`pending\` happens to be empty -- the top of the log, or the ordinary gap" \
                "between one test resolving and the next starting -- adds a credited outcome" \
                "the summary never produced, in either direction: more credited than the" \
                "summary counts means something was forged in; fewer means the resolver" \
                "missed a real one. Either way this log cannot be trusted to credit" \
                "--require names correctly." >&2
            failures=$((failures + 1))
        fi
    fi
    if [ -n "$hijacked" ]; then
        echo "$log's own test order is broken: a fresh test announcement appeared while" \
            "another test's own outcome was still open. At --test-threads=1 libtest never" \
            "does this -- only a test's own --nocapture output sits between two control" \
            "lines -- so this log cannot be trusted to credit --require names correctly:" >&2
        while IFS=' ' read -r new old; do
            [ -n "$new" ] || continue
            echo "  \"test $new ... \" appeared before \"$old\" reported its own" \
                "ok/FAILED/ignored" >&2
        done <<EOF
$hijacked
EOF
        echo "  Neither name is trustworthy from this log. This is not a missing-test" \
            "report: fix whatever produced two overlapping test announcements before" \
            "trusting this run at all." >&2
        failures=$((failures + 1))
    fi
    if [ -n "$missing" ]; then
        echo "$log does not show a passing run of test(s) this suite is judged by --" \
            "renamed, removed, compiled out by a #[cfg], or never reached ok:" >&2
        echo "$missing" | sed 's/^/  /' >&2
        echo "  If the test was intentionally renamed or removed, update the --require name" \
            "at the run_suite call site in .github/workflows/ci.yml to match; otherwise the" \
            "suite is missing the test that is its reason for existing." >&2
        failures=$((failures + 1))
    fi
fi

if [ "$failures" -ne 0 ]; then
    echo "$log: $failures problem(s); see above" >&2
    exit 1
fi

# Say what was checked, not merely that it passed. "None skipped" reads the
# same whether the allow-list was empty or covered everything in sight, and
# those are very different runs: the first is the five system suites, where
# a skip is a failure, and the second is the library binary, where four
# named tests refuse to run as root. A pass that does not say which of the
# two it was is a pass nobody can audit.
if [ "$expected_ignored" -eq 0 ]; then
    left_out="none left out of the run"
else
    left_out="$expected_ignored left out of the run, exactly as declared"
fi
# Same reasoning as $left_out, one section down: a silent "ok" about a
# requirement nobody checked is the exact defect section 3 above exists to
# close, so the pass line says whether any --require names were declared at
# all, not just that the ones that were came back clean.
if [ "$required" = " " ]; then
    required_note="no --require names were declared for this run"
else
    required_note="$(echo "$required" | sed 's/^ //;s/ $//;s/ /, /g') confirmed present and passing"
fi
if [ $# -eq 0 ]; then
    echo "ok    $log: $passed test(s) ran, $left_out;" \
        "nothing was allowed to skip, and nothing did; $required_note"
else
    echo "ok    $log: $passed test(s) ran, $left_out; $allowed_seen skip(s), all of them among" \
        "the $# name(s) allowed on the command line: $*; $required_note"
fi
