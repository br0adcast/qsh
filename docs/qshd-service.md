# The qshd daemon as a service

`qshd serve` is the mode where `qshd` runs as a long-lived daemon: it
listens on a single UDP port and opens channels for anyone who proves their
identity with an SSH key signature — like `sshd`, rather than handing out
one predetermined shell per connection: the daemon opens a channel, and it
is the client that decides what to run inside it. It isn't installed over
SSH and doesn't update itself — unlike `transport-ensure` (which comes up
automatically when a client connects over SSH, reinstalls itself, and runs
as the one daemon per machine until a newer version replaces it or it's
stopped explicitly), this mode is started and restarted by the system's
service manager: `systemd` (Linux) or `launchd` (macOS).

Whichever way the daemon comes up — `serve` or `transport-ensure` — from
there it does the same thing: it hands out channels, and the client decides
what to run in them. These are two ways to bring up the same daemon, not
two different daemons; the only difference is who installs and restarts
it.

Both modes authenticate by signature. The daemon started over SSH
(`transport-ensure`) accepts two kinds of credentials at once: a list of
static keys handed to it over SSH at startup, and an SSH key signature
checked against the same `~/.ssh/authorized_keys`. For an address marked
`,ssh`, `qsh` registers a one-time key through SSH
and uses the allowlist for the subsequent connection. A client whose SSH key
is already in `authorized_keys` can instead authenticate directly, without
an SSH bootstrap. See [SSH startup and installation](cli-guide.md#ssh-startup-and-installation).

```bash
qsh user@host:60000
```

The port is selected by the client for that address (`serve` defaults to
60022). Both authentication methods can use the same daemon. This does not
widen the trust boundary: anyone
who can sign with a key from `authorized_keys` can already log in over SSH
and run anything, including the daemon itself.

The other way round, `qsh` with `,ssh` does not start a second daemon
next to a standing service it recognizes: before starting anything it
asks the service managers, and reports a running service (for `launchd`,
a loaded one) instead. It recognizes one only by these names:
`qshd.service` under `systemd` (the system unit or the account's own
`systemctl --user` one) and `me.qsh.qshd` under `launchd` (in the system
domain or the account's own). A service under any other name is not
seen: `qsh` runs `transport-ensure` as if there were none, and that
fails outright if the service holds the port it asks for.

This is the first `qshd` mode where client key verification is on by
default: only someone whose public SSH key is in the authorized-keys file
can connect.

`serve` itself comes in two flavors. Everything from here down to "System
mode" describes the **personal** one: the account that starts the daemon
is the only account it will ever hand out a shell for, the same as
`transport-ensure` above. **System mode** (`qshd serve --system`) is the
other one — the daemon runs as a machine-wide service instead, and any
account on the machine can log in with its own key, the way `sshd` does.
See "System mode" further down for the whole difference; until then, "the
daemon" below means the personal one.

## Command line

```
qshd serve [--port N] [--authorized-keys PATH] [--host-key PATH]
```

| Flag | Default | Meaning |
|---|---|---|
| `--port` | `60022` | UDP port the daemon listens on for connections. |
| `--authorized-keys` | `~/.ssh/authorized_keys` | File with the public keys of clients allowed to log in. |
| `--host-key` | `~/.config/qshd/host_key` | The daemon's persistent host key (created on first run, mode `0600`). |

An unknown flag, or a port that isn't a number, makes the daemon exit with
an error right away, without starting anything.

## What it does

- listens on `--port` (default `60022/udp`) on all IPv4 interfaces
  (`0.0.0.0`);
- opens a separate channel for every client request, with its own
  pseudo-terminal sized as the client asked — not a single shell for the
  whole connection; how many channels to keep open at once, and what to
  run in them, is up to the client. The `qsh` console client, in its usual
  mode, asks for one such channel with a shell, but the daemon doesn't
  limit it to that;
- keeps a persistent host key at `--host-key` (default
  `~/.config/qshd/host_key`, mode `0600`) — creates it on first run and
  reuses it afterward, so the daemon's address can be recognized again,
  the same way an SSH host key works;
- admits anyone whose public key is in `--authorized-keys` (default
  `~/.ssh/authorized_keys`) and whose signature checks out; it accepts
  Ed25519, ECDSA (P-256/P-384) and RSA keys signed with
  `rsa-sha2-256`/`rsa-sha2-512` — the legacy `ssh-rsa` (SHA-1) and DSA keys
  are rejected;
- authorized-keys lines carrying options (`command=`, `from=`, `restrict`,
  and the like) aren't accepted at all — the daemon has no way to honor
  such options, and granting access on their strength would be a false
  promise: a key on such a line stays unauthorized, even if the same key
  appears again further down without options;
- the authorized-keys file is re-read on every connection attempt, so a
  key added on the fly works right away, without a daemon restart;
- runs as a single user (whoever started it) and serves only that user's
  sessions — this mode has no shared login for multiple system users,
  unless it's started with `--system` instead; see "System mode" below.

## System mode

`qshd serve --system` is the other way to run this same daemon: one
port, one process, but instead of serving only the account that started
it, it hands a shell to any account on the machine that proves itself
with a key in *its own* `authorized_keys` — `qsh alice@host` and
`qsh bob@host` reach the same daemon on the same port, and each lands in
a shell running as themselves, the way `sshd` already works. It's for a
machine more than one person already has an account on — a shared dev
box, a small team's server — not a single-user machine, which the
personal mode above already serves without any of what follows.

### Flags

```
qshd serve --system [--port N] [--host-key PATH] \
    [--authorized-keys-template TEMPLATE] [--worker-user NAME] [--permit-root]
```

| Flag | Default | Meaning |
|---|---|---|
| `--system` | off | Turn on system mode. |
| `--port` | `60022` | same as the personal mode |
| `--host-key` | `/etc/qshd/host_key` | the machine's host key, owned by root, mode `0600` — see "The host key's move" below |
| `--authorized-keys-template` | `%h/.ssh/authorized_keys` | where an account's own keys live; `%h` expands to its home directory, `%u` to its login name |
| `--worker-user` | `qshd` | the unprivileged account the daemon's network-facing half drops to once it has split off from its root-privileged half; the `qshd` package creates this account for you on install |
| `--permit-root` | off | allow logging in as `uid 0`; refused otherwise |

`--system` only exists in a binary built with the `system` Cargo feature
(the `qshd` package's binary is; the portable release binary is not) — asking for it on a binary without the feature fails with an
explicit error rather than doing nothing. `--authorized-keys` (the
personal mode's flag, above) is refused outright together with
`--system` — a single file can't serve several accounts, and silently
reinterpreting the flag would be worse than refusing it; use
`--authorized-keys-template` instead. `--authorized-keys-template`, in
turn, is refused without `--system`, for the same reason in the other
direction: the personal mode has one account and nothing to expand.

In system mode, the expanded key path must be absolute. The helper checks every
opened directory from `/` to the file, and the file itself: each must be owned
by root or the target account and must not be writable by group or others.
The leaf must be a regular file, at most 1 MiB of UTF-8 text. Missing files admit
no keys. Directory search and file reading still run with the account's uid,
gid, and supplementary groups; a root-owned central store works only when that
account can read it. Directory listing permission is not required.

Symlinks at any level (including the home directory), relative paths, `.` or
`..` components, trailing slashes, and expanded paths of 4096 bytes or more are
refused. Repeated interior `/` separators are allowed. Configure the real,
absolute path to a safe store when replacing an older symlink-based setup.
Even a private directory below a writable ancestor such as `/tmp` is refused;
the sticky bit does not exempt a directory from the ownership/write policy.
These restrictions apply to system mode; personal-mode key loading is unchanged.

The helper walks through owned directory descriptors and reads the same opened
file it validated, so replacing a pathname cannot redirect an in-progress read.
This is not an atomic filesystem snapshot: root and the target account remain
trusted, and can change permissions, rename objects or modify bytes in place.
Use atomic file replacement for key updates. An attempt that already opened the
old file may still read it; this policy does not promise immediate revocation or
protection against a malicious filesystem or privileged mount changes.

There's no allowlist or denylist of accounts by name yet: as with a stock
`sshd`, anyone with an account on the machine and a key in their own
`authorized_keys` gets in.

### Two packages

Releases split `qshd` in two, matching the split above: the plain
**`qsh`** package is the client alone (see the top-level README), and the
**`qshd`** package carries the daemon plus everything only system mode
needs:

- `/usr/bin/qshd` — the same binary either mode runs, this time built
  with the `system` Cargo feature (`cargo build --release -p qshd
  --features system`) and linked dynamically against glibc and `libpam`
  instead of statically against musl: account lookup and PAM both load
  modules at run time, which a static binary can't do;
- `/usr/lib/systemd/system/qshd.service` — the system-wide unit, below;
- `/usr/lib/systemd/user/qshd.service` — the personal, per-user unit from
  "Linux: systemd, per-user" above, carried by the same package under a
  different systemd search path. The two files share a name on purpose:
  only one of the two search paths applies to a given `systemctl`
  invocation, so there's no clash;
- `/etc/pam.d/qshd` — the PAM service file the daemon opens once per
  login, marked so a package upgrade never overwrites an administrator's
  edits to it;
- a system account, `qshd`, created by the package's own install script
  (no home directory — `/nonexistent` — shell `/usr/sbin/nologin`): the
  identity the daemon's network-facing half drops to once it has split
  off from its root-privileged half. Removing the package does **not**
  remove this account — it may still own files written while the daemon
  ran.

The statically linked `qshd` in the Linux `.tar.gz` archives is a different
build of the same source, without the
`system` feature: it can only ever run in personal mode, and refuses
`--system` outright rather than pretending to support it (see the table
above).

Being dynamically linked means the `qshd` package has a real glibc
floor, unlike the statically linked client and portable daemon above: it
is built in dedicated containers old enough to promise that floor, for
both x86_64 and aarch64, and a build whose container turns out to carry
newer glibc than promised fails the build rather than ship a package
that quietly stops installing on the oldest systems it claims to
support. The floor itself lives in one place, `QSHD_GLIBC_FLOOR` in
`packaging/Dockerfile.build-deb` (the `.rpm` side has its own,
independently pinned) — not repeated here on purpose, so this paragraph
can't go stale against it the way a copied number could.

### Turning it on

Installing the `qshd` package does not start or enable anything — neither
unit is on after `apt install`/`dnf install` returns, on purpose: opening
a port that admits every account on the machine has to be something an
administrator asked for, not something a package decided on its own.
Turning system mode on is one command once the package is in:

```bash
sudo systemctl enable --now qshd
```

That's the *system* unit (`/usr/lib/systemd/system/qshd.service` — no
`--user`, unlike "Linux: systemd, per-user" above); it runs
`qshd serve --system --port 60022` as root. Logs go through the system
journal like any other unit — `journalctl -u qshd -f`, again with no
`--user`, since that would read the per-user unit's own log instead, a
different service under the same name.

### The host key's move

Personal mode keeps its host key at `~/.config/qshd/host_key`; system
mode keeps a separate one, at `/etc/qshd/host_key` (owned by root, mode
`0600` — same tightening rule as the personal one). The daemon never
moves a key on your own behalf: `/etc/qshd/host_key` is a different,
root-owned file, generated fresh the first time nothing is found there.

**If people already connect to this machine in personal mode and you
want them to keep trusting it without a prompt after you switch to
system mode, copy the key across yourself, before the first `--system`
start:**

```bash
sudo install -D -o root -g root -m 0600 ~/.config/qshd/host_key /etc/qshd/host_key
```

Run it as the account that ran the personal daemon, so `~` expands to
the right home directory, and run it before `systemctl enable --now
qshd`. Skip it, and the system daemon generates a brand-new key on its
first start — **everyone who already has this host pinned in their
`known_hosts` sees its fingerprint change, and to `qsh` (and to them)
that looks exactly like an impostor sitting between them and the
server**, not like routine maintenance: see the warning `qsh` itself
prints in that situation. Either carry the key across with the command
above, or be ready to tell everyone who already connects here that the
warning they're about to see is expected this one time — there's no
third way, because keeping the old fingerprint and starting from a fresh
key are mutually exclusive.

### A restart kills every session on the machine

The daemon's network-facing half holds the live state of every session
and the leading side of every session's pseudo-terminal in its own
memory — there's nowhere else for either to live between requests. In
personal mode that has always meant one person's sessions; in system
mode it means everyone's, all at once: a `systemctl restart qshd` (or a
crash that `Restart=on-failure` brings back up) drops every open shell on
the machine, not just yours. Work that has to survive a restart belongs
in `tmux` on the server, the same as it already does across a lost
connection (see "Returning to your session" above) — the daemon's own
session retention doesn't help here, because there's no session left to
return to.

**`Restart=on-failure`, the policy in the shipped unit, does *not*
restart the service after the process exits because of `SIGTERM`,
`SIGINT`, `SIGHUP` or `SIGPIPE`** — systemd counts all four as a clean
exit, not a failure. That's deliberate, not an oversight: since a restart
can't save any session anyway, there's nothing to gain from racing back
up after an administrator's own `systemctl stop` (which sends `SIGTERM`)
or a plain `kill`, and it means a stop is never silently undone a moment
later. Seeing "the service didn't come back after `kill`" should send an
administrator to this paragraph, not to a bug report.

## Path probing (multipath qsh)

The daemon can answer a path probe: on receiving one, it sends back a
reply carrying the same token **to the address the probe came from**, but,
unlike any other genuine session packet, it **does not migrate the session
itself to that address** — otherwise probing a backup path would drag live
traffic along with it, where it has no business being. The console client
uses this to keep a session reachable at more than one address, taking
backup addresses on the command line
(see `qsh --help`), and probes each of them while the session runs.

## Returning to your session, and losing the network (console client)

A session on the server is identified by a token the client picks. The
`qsh` console client keeps it on disk, at `~/.config/qsh/sessions` next to
`known_hosts`, and asks for **the same** session on the next run: you land
back in the same shell, with everything it had, even if you closed the
terminal or rebooted the computer. The server keeps a silent session
around for a day; after that the token is no longer recognized, and you
simply get a new shell, with no error at all.

Each address has several slots — the first address named on the
command line, that is, so the same addresses named in another order
reach another session. A slot is claimed with a file lock for as long
as the client runs, so a second terminal to the same server gets its
own slot and its own session, instead of taking over the first one. The
slot that frees up is exactly the session the next run returns to.

Losing the network doesn't end the client's run either. A short outage
is ridden out by the transport; after 45 seconds of silence it gives up on
the link, and the client
goes back into the same session by itself, walking its addresses again in
the background until the session is back (see [recovery](cli-guide.md#recovery-and-session-limits)). Meanwhile you can always leave with `Ctrl-]` then `.`: the session
stays on the server, and running the same `qsh` command again returns to
it.

## Terminal type

The daemon starts the shell in a pseudo-terminal and has to tell it what
terminal is reading it: that decides which escape sequences keys like Home
and End arrive as. In SSH, `pty-req` carries this; in qsh, the client
announces its terminal type in a separate record on the control stream,
before it opens its first channel.

A client that announces nothing (including a build older than this
record) gets the old default, `xterm-256color`. A console client running
inside a different terminal may need another value: Home sent as
`\e[1~` reaches a shell configured for `\eOH`, doesn't fire at all, and
leaves a stray `~` in the line.

The `qsh` console client takes the value from its own `TERM` variable. The
name is checked: only letters, digits, and `-`, `_`, `.`, `+`, no longer
than 64 characters — otherwise the record is dropped and the default value
stands.

## The authorized-keys file

This section is about the personal mode's one shared file. System mode
has no single file at all — each account's own is found through
`--authorized-keys-template` instead; see "System mode" above.

The format is the usual OpenSSH `authorized_keys`: one line per key,
`algorithm base64-public-key optional-comment`. Since the default file
name matches the regular SSH authorized-keys file, on a machine that
already has key-based login set up you likely won't need to create
anything — `qshd serve` uses the same key list.

If the file doesn't exist yet (typical for a fresh user), create it and
add the public key of the client you'll connect with, the same way you
would for regular SSH:

```bash
mkdir -p ~/.ssh
cat id_client.pub >> ~/.ssh/authorized_keys
chmod 600 ~/.ssh/authorized_keys
```

The daemon starts fine without this file — but as long as it holds no
keys, nobody can connect. On startup without the file, the daemon writes
an explicit warning about it (to the log and to standard error) — see
"Checking it" below for exactly where to look.

## Host key and the fingerprint on first connection

On every start, the daemon prints two lines to standard output:
`server-pubkey: <base64>` (the host key as-is) and
`host-key-fingerprint: SHA256:...` (the same key in the fingerprint form
SSH users are used to) — and it also writes a line with the port, the
same fingerprint, and where it's checking keys (a path to the
authorized-keys file in the personal mode, a per-account template in the
system mode) to its own log (`qshd.log`, see below), in case standard
output happens to be unavailable. The fingerprint is what a first
connection gets checked against: the first time a client sees this
daemon's host key, it will show the same fingerprint, and it should be
compared against what the daemon itself printed on startup (the same
trust-on-first-use model as regular SSH).

Don't lose access to this line — it doesn't reappear on request later,
only at daemon startup. Ways to find it after the terminal is already
closed are in "Checking it".

This section describes the personal mode's key, at `~/.config/qshd/host_key`.
System mode keeps a separate one, and switching a machine from one mode
to the other means moving it *yourself* if you want to keep it — see
"The host key's move" under "System mode" above before you do, especially
if people already connect to this machine.

## Installing the binary

The `qshd` `.deb`/`.rpm` package from the
[releases page](https://github.com/br0adcast/qsh/releases) is the normal
way to get `qshd` onto a machine that will run it as a service (see the
top-level README's "Installing" section for the exact `apt`/`dnf`
commands): it puts the binary at `/usr/bin/qshd` and the user unit at
`/usr/lib/systemd/user/qshd.service` — "Linux: systemd, per-user" below
then only needs the `systemctl` commands, no unit file to write by hand.
(The package carries the system-mode unit and PAM file too; see "Two
packages" under "System mode" above for the rest of what's in it, and
note that `qshd` is a *separate* package from `qsh`, the client — the
`qsh` `.deb`/`.rpm` doesn't carry `qshd` at all.) Packages carry no
`launchd` plist for macOS ("macOS: launchd" below is a manual step there
regardless of how the binary got onto the machine).

Building from source is the other path — useful on a platform without a
package, or for a build with local changes:

```bash
cargo build --release -p qshd
```

The command above builds the personal-mode daemon, including `serve`, for
Cargo's selected target. The Linux release archives use statically linked
musl builds; a default local build uses the host target.

Without the `system` Cargo feature, `qshd serve --system` fails with an explicit
error. System mode needs the feature named explicitly and links against glibc
and `libpam` on Linux (see "System mode" above):

```bash
cargo build --release -p qshd --features system
```

The `.deb`/`.rpm` `qshd` package ships a binary built exactly this way;
nothing else in this repository does.

The binary lands at `target/release/qshd` (from the repository root). The
service files below expect it at a specific path — put it exactly there,
or adjust `ExecStart`/`ProgramArguments` to match your own path:

```bash
# Linux — the path from the unit file below (%h/.local/bin is $HOME/.local/bin)
mkdir -p ~/.local/bin
cp target/release/qshd ~/.local/bin/qshd

# macOS — the path from the plist below
sudo cp target/release/qshd /usr/local/bin/qshd
```

## Linux: systemd, per-user

The `.deb`/`.rpm` package installs the unit already, at
`/usr/lib/systemd/user/qshd.service` — nothing to write by hand in that
case. Building from source instead, there's no package to drop a unit file
for you, so create `~/.config/systemd/user/qshd.service` pointing at
wherever you copied the binary:

```ini
[Unit]
Description=qshd — a resilient terminal daemon

[Service]
ExecStart=%h/.local/bin/qshd serve --port 60022
Restart=on-failure
RestartSec=2

[Install]
WantedBy=default.target
```

Either way:

```bash
systemctl --user daemon-reload
systemctl --user enable --now qshd
# so the daemon keeps running without an active user login:
sudo loginctl enable-linger "$USER"
```

By default, `systemd` sends the service's standard output and standard
error to the journal — there's nothing extra to configure. Log:
`journalctl --user -u qshd -f`.

This is the per-user unit, one person at a time. For a shared,
multi-account machine instead, see "System mode" above — a different
unit entirely (`systemctl enable --now qshd`, no `--user`), shipped in
the same `qshd` package.

## macOS: launchd

System mode, described above, is Linux only — macOS stays on this
personal LaunchAgent/LaunchDaemon setup no matter how many people use
the machine.

`~/Library/LaunchAgents/me.qsh.qshd.plist`:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
  "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key><string>me.qsh.qshd</string>
  <key>ProgramArguments</key>
  <array>
    <string>/usr/local/bin/qshd</string>
    <string>serve</string>
    <string>--port</string>
    <string>60022</string>
  </array>
  <key>KeepAlive</key><true/>
  <key>RunAtLoad</key><true/>
  <key>StandardOutPath</key><string>/Users/USERNAME/Library/Logs/qshd.log</string>
  <key>StandardErrorPath</key><string>/Users/USERNAME/Library/Logs/qshd.err.log</string>
</dict>
</plist>
```

Replace `USERNAME` with the real one (`echo $HOME` shows the full path) —
a plist doesn't go through a shell and doesn't expand `~`, unlike the
commands below. Without `StandardOutPath`/`StandardErrorPath`, launchd
sends all of the daemon's output to `/dev/null` — then the
`server-pubkey`/`host-key-fingerprint` lines at startup are nowhere to be
found at all, which is why these two keys in the plist aren't optional.
Don't point them at `/tmp` — it's a shared directory the system cleans out
periodically, and its file name (`qshd.log`) matches, by name if not by
directory, the daemon's own log file in the cache
(`~/Library/Caches/qsh/qshd.log`), which is easy to confuse when you go
looking for it.

```bash
launchctl bootstrap "gui/$(id -u)" ~/Library/LaunchAgents/me.qsh.qshd.plist
```

(`launchctl load -w` from older instructions still works, but is
considered deprecated in favor of `bootstrap`.)

Log: `tail -f ~/Library/Logs/qshd.log` (the path set in `StandardOutPath`
above).

**A LaunchAgent lives only as long as the user's graphical session does**:
it starts on login and stops on logout or reboot — unlike the `systemd
--user` + `loginctl enable-linger` combination on Linux, which is
explicitly meant to keep running without an active login. If the daemon
needs to stay reachable even without an open session (a headless Mac,
reachable only over the network; a locked screen doesn't count here — the
session stays open — but logging out of the account or rebooting does
close it), what's needed is a **LaunchDaemon**, not a LaunchAgent: the
file goes in `/Library/LaunchDaemons/` (root-owned), gets installed and
enabled with `sudo launchctl bootstrap system`, and runs regardless of
whether anyone is logged in. That's a separate setup (the daemon then
usually runs as root, unless the plist explicitly drops it to another
user) — it isn't spelled out in detail here.

## Port and firewall

Open the UDP port in your firewall, if you use one:

```bash
# Linux, ufw
sudo ufw allow 60022/udp
```

For other firewalls (firewalld, nftables, a router's built-in firewall),
the rule is the same in substance: allow incoming UDP packets on the
chosen port. If the daemon is running and a client can't connect from
outside the local network, the firewall is the first thing worth
checking.

## Socket buffers

qshd asks the kernel for 4 MiB of receive and send buffer on its UDP
socket and logs what it got (`udp buffers: …` in `qshd.log` or the
journal). Linux gives an unprivileged service at most `net.core.rmem_max`
and `net.core.wmem_max` — about 208 KiB by default, logged doubled. With
less than asked, bursts of output can be dropped by the kernel and wait for
a retransmit. To give qshd what it asks for:

    echo 'net.core.rmem_max = 4194304' | sudo tee /etc/sysctl.d/60-qshd.conf
    echo 'net.core.wmem_max = 4194304' | sudo tee -a /etc/sysctl.d/60-qshd.conf
    sudo sysctl --system

and restart qshd.

## Checking it

You can confirm the daemon actually came up and is listening on the port
without waiting for a client:

```bash
# the process is alive
pgrep -af 'qshd serve'

# the port is listening
ss -uln | grep 60022        # Linux
lsof -nP -iUDP:60022        # macOS

# the host key fingerprint and any warnings (e.g. a missing
# authorized_keys) are in the daemon's persistent log, regardless of what
# the system service did with standard output:
tail -f ~/.cache/qsh/qshd.log        # Linux, personal mode (or
                                      # $XDG_CACHE_HOME/qsh/qshd.log, if set)
tail -f ~/Library/Caches/qsh/qshd.log # macOS, personal mode
tail -f /var/log/qshd/qshd.log        # Linux, system mode -- a fixed,
                                      # root-owned path, not a per-account
                                      # cache directory; see "System mode" above
```

This confirms the daemon is alive and listening on the port, but not that
a real client can get past signature verification and get a shell — for
that, connect with the `qsh` client binary (see `cli/`):

```bash
qsh user@host
```

Without a client at hand, a handshake-parsing attempt can still be tested
from the transport side (with a key-discovery request, without
authentication).

### What a log line looks like

Every line of `qshd.log` has one shape — the same one the `qsh` client's
own log uses — and `qshd serve` writes every line to standard error as
well, so the journal holds the same lines (with the journal's own
timestamp in front of them):

```
2026-09-30 20:15:03.123 UTC [4242] INFO  helper: Accepted signature for alice from 203.0.113.7:2222 key ED25519 SHA256:...
2026-09-30 20:15:09.456 UTC [4242] WARN  helper: Failed signature for invalid user zzz from 203.0.113.7:2222
2026-09-30 20:15:09.460 UTC [4243] WARN  transport: session refused: no authentication record arrived in time
```

That is: the time in UTC with milliseconds; the pid of the process that
wrote the line (in system mode the privileged helper and the
network-facing worker write to the same file); the level — `INFO`,
`WARN` (a refusal, or something that failed but the daemon carries on
past) or `ERROR` (a failure that ends a process or a login), padded to
five characters; the component; and the text. The components are `qshd`
(startup, the control socket, the daemon itself), `helper` (system mode's
privileged half: every accepted and refused login), `worker` (system
mode's network-facing half), `update` (an update over qsh and the restart
that follows it) and `transport` (sessions: admission, refusals, caps,
teardown). A record of several lines repeats the whole header on each
line, and control characters in the text are replaced with `?`.

Every line means every line: in system mode the journal gets the
helper's and the worker's lines too — each accepted and refused login,
the detailed reason for each refusal, and the client-supplied login name
and address those lines carry (sanitised the same way as in the file:
a name with a space, a newline or anything unprintable is dropped whole,
and no text a client or the worker chose can start a line of its own).
`/var/log/qshd/qshd.log` is readable by root only, but the journal is
readable by the members of the `adm` and `systemd-journal` groups as
well; if that is wider than you want these details to go, keep those
groups small (as you would for `sshd`, which logs the same things
there). And as with `sshd`, the write to standard error is a blocking
one: a journal that stops reading its input stalls the daemon until it
reads again.

A `fail2ban`-style filter for the system mode's login lines anchors on
`helper: Failed signature for ... from <HOST>:\d+` after that header.
Through `qshd` 0.4.0 these lines had only the timestamp and then the
prefix `qshd helper: ` (no pid, level or component), so a filter written
for those versions needs that one edit.

## Limitations

- the *personal* mode (`qshd serve`, no `--system`) still serves only the
  one account that started it — but that's a limit of that particular
  command and build, not of the design: the same source, built with the
  `system` Cargo feature and run as `qshd serve --system`, admits any
  account on the machine, the way `sshd` does. Personal mode stays the
  right choice for a single-user machine, where system mode's extra
  moving parts (`libpam`, a service account, a privileged helper process)
  buy nothing. See "System mode" above;
- system mode has no allowlist or denylist of accounts by name: as with a
  stock `sshd`, anyone with an account on the machine and a key in their
  own `authorized_keys` can log in;
- restarting `qshd` in system mode drops every session on the machine at
  once, not just one person's — and stopping it with a plain `kill` or
  `systemctl stop` does **not** bring it back up automatically, by
  design; see "A restart kills every session on the machine" under
  "System mode" above;
- system mode never calls `pam_authenticate` — the SSH-key signature
  already proved identity — but it does run the rest of the PAM stack
  around a login: account checks (`pam_acct_mgmt`), credential
  establishment (`pam_setcred`), and a session open/close
  (`pam_open_session`/`pam_close_session`). Any module that wants to
  prompt for input (a password change, a one-time code) is refused
  outright — there's no interactive channel this early, so the prompt
  just fails the login instead of asking anything;
- one consequence of that: an account PAM considers due for a password
  change is **refused**, not asked to change it, and the client sees the
  exact same undifferentiated failure as a wrong key. But the daemon's
  own log does *not* read like a failed login: the signature really did
  check out, so it logs `Accepted signature for <name> from <addr> ...`
  first, and the refusal itself lands in a differently shaped line
  (`login session setup failed ...`), never one starting `Failed
  signature for ...`. A filter built to catch failed logins by matching
  that `Failed signature` shape catches nothing here (see "Checking it"
  for where to look instead). There is no way to change a password
  through `qsh`; fix the account another way first (console access,
  `sshd`, whatever else reaches this machine), and logging in through
  `qshd` starts working again;
- Each login starts PAM with the account's NSS supplementary groups. Every
  channel receives the exact group list left by the full PAM session opening,
  including additions, removals, or an empty list. Authorization-file access
  keeps the NSS baseline; another login cannot inherit these session groups.
- `/etc/pam.d/qshd` is a real, editable configuration file, and an
  administrator is expected to open it — but a module that decides by
  client address (`pam_access`, `pam_rhosts`) would be trusting a value
  the daemon's network-facing half chose and handed over unchecked, the
  very process the whole privilege split exists to not trust with
  anything that grants access. Don't add one of those to this file
  expecting it to hold up against a *compromised worker* — that is the
  actual threat these two lines would be defending against here, not a
  client that hasn't even logged in yet;
- an encrypted home directory (eCryptfs, a per-user `fscrypt` key, ...)
  that isn't already decrypted by the time someone logs in leaves its
  `authorized_keys` unreadable, and the login fails — the same as `sshd`
  with key-based login on the same setup; `qshd` doesn't do anything to
  help here;
- `authorized_keys` lines with options (`command=`, `from=`, `restrict`)
  are ignored outright, not partially honored;
- the daemon listens on IPv4 only (`0.0.0.0`): you can't connect to it
  over IPv6, even if the machine has one;
- the daemon answers a key-discovery request with no verification at all —
  that's how a client learns the host's public key on first connection.
  Which means a port scan can identify the service and retrieve that key:
  it isn't secret by itself (it's a public key, and its fingerprint is
  shown openly), but there's no hiding that a daemon is running on the
  port;
- macOS has no install package that bundles a `launchd` plist: unlike the
  Linux `.deb`/`.rpm`, which install the systemd unit alongside the
  binary, the plist in "macOS: launchd" above still has to be created by
  hand regardless of how `qshd` got onto the machine (package or build
  from source);
- the `qshd.log` file in the cache directory is shared by every `qshd`
  command on the machine: if `serve` and a `transport-ensure` daemon both
  run on it at the same time, their log rotation isn't coordinated with
  each other, and whichever of the two renames the file first can pull the
  log out from under the other — short entries aren't split in half
  (rotation is atomic), but a handful of lines around the rotation moment
  can get lost.
