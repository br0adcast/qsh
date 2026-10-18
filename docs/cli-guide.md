# qsh CLI guide

[Project overview](../README.md) · [Protocol](protocol.md) · [Daemon services](qshd-service.md)

## Connecting

```sh
qsh user@server.example.org
qsh user@server.example.org,ssh
qsh -i ~/.ssh/id_ed25519 user@server.example.org,ssh=2222 10.8.0.1,ssh
```

Each address has the form `host[:port]`, followed by optional comma-separated
settings: `ssh[=port]`, `nossh`, `knock=STEPS`, or `noknock`. The first example
needs an answering daemon. SSH-enabled addresses can start an installed daemon
or, with interactive approval, install one that is missing.

The `user@` prefix selects the account to claim. A personal daemon serves only
the account running it; a system daemon checks the named account through its
privileged helper and PAM. Without an explicit user, qsh reads `USER`, then
`LOGNAME`; without either, provide `user@` or `-l USER`.

All addresses in one command must identify the same server. Their pinned qsh
keys must agree before the first attempt. An unpinned address can inherit the
shared expected key after a successful authenticated handshake, and authenticated
spare paths are also remembered. Conflicting keys stop the client with exit 11;
a stored key is never silently overwritten.

qsh sessions use IPv4. The parser accepts bracketed IPv6 addresses, such as
`'[2001:db8::1]:60022,ssh'`, and SSH or knocking can use them, but the subsequent
qsh connection cannot carry a session over IPv6. The default UDP port is 60022.

## Authentication and host trust

The transport handshake is `Noise_IK_25519_ChaChaPoly_BLAKE2s`. X25519 establishes
keys; ChaCha20-Poly1305 authenticates and encrypts traffic; BLAKE2s provides the
hash. IK authenticates the server against the static key expected by the client.
The client's fresh Noise key alone does not identify a user.

Direct login proves identity with an SSH key signature. qsh tries agent keys and
usual key files, or only the file named by `-i` for direct authentication.
Supported key types include Ed25519, ECDSA P-256/P-384, and RSA with SHA-2. Legacy
RSA/SHA-1 (`ssh-rsa`) authentication is refused. A personal daemon checks
`~/.ssh/authorized_keys`; system mode checks the claimed account through a
privileged helper and PAM.

Until the signature verifies, the connection is probationary: it cannot redirect
another peer's route, overwrite its key, or evict a retained session. An SSH login
provides another authorization path: the daemon admits the current process's
Noise key after that SSH authentication. Password-based SSH is therefore also
usable. This temporary admission ends when its connection ends; later recovery
needs another valid signature or SSH authorization.

On the first direct connection, discovering the server's static key is
unauthenticated. qsh displays its fingerprint and requires confirmation. Compare
it out of band when necessary; someone controlling that first exchange could
otherwise supply their own key. The accepted key is stored in:

| Platform | qsh server-key store |
| --- | --- |
| Linux and macOS | `$XDG_CONFIG_HOME/qsh/known_hosts`, otherwise `~/.config/qsh/known_hosts`. |

Session tokens live in the adjacent `sessions` directory. XDG overrides must be
absolute paths; empty or relative values use the defaults above.

The client uses only the selected XDG store. Previous macOS files under
`~/Library/Application Support/qsh` are not imported or linked automatically;
existing files remain untouched. Server-side qshd state and host keys are unaffected.

SSH independently uses `~/.ssh/known_hosts`, including hashed entries,
`[host]:port`, and revoked keys. Unknown SSH keys need confirmation; changed
ones are refused. When that verified SSH login starts qshd, its returned daemon
key binds only the same address and the UDP port it reports. qsh compares discovery
with that key and atomically remembers it without another QSH trust question.
Conflicting existing pins, discovery keys, or session identities are refused;
Noise still proves the daemon holds the private key. Other endpoints receive no
SSH bootstrap trust grant.

Background SSH recovery additionally needs an explicit association between the
QSH server key, account, SSH endpoint, and SSH host key. After an initial SSH
bootstrap succeeds over QSH, a separate question offers to save that association.
Its default is No; declining leaves the current shell usable. An ordinary direct
QSH login does not probe SSH or create associations. To configure recovery after
a direct login, run `qsh --authorize-ssh user@server.example.org,ssh`. At least one
SSH-enabled address is required. Setup shows both fingerprints and the endpoint
before asking for consent, and verifies SSH host keys without authenticating a
user or starting a daemon. Each endpoint is authorized separately.

Associations are stored in `ssh_bindings.json` beside QSH `known_hosts`. Existing
QSH pins and SSH known-host entries are never imported as recovery grants. A
missing grant or an unreadable/corrupt binding store disables SSH recovery;
a setup or storage error leaves an established QSH session usable. Recovery
intersects explicit grants with the current SSH `known_hosts` keys before login.
Removed or revoked SSH keys cannot authenticate, even when an association remains.

Encryption does not conceal network addresses, volume, or timing. It cannot
protect either endpoint after that machine is compromised. The full threat model
and wire format are in [the protocol specification](protocol.md).

## SSH startup and installation

Use `,ssh` for port 22, `,ssh=N` for a specific SSH port, or `--ssh[=N]` to enable
SSH for addresses that do not override it. `,nossh` disables it on one address.
The initial connection follows qsh → SSH → qsh: if direct login fails, authenticate
over SSH, locate/start the daemon, then connect to the UDP port it reports.

SSH tries the `-i` identity first, then agent keys and the usual
`~/.ssh/id_ed25519`, `id_ecdsa`, and `id_rsa` files, followed by
keyboard-interactive authentication and password. A passphrase is requested only
when the server accepts the corresponding key. Questions are asked on `/dev/tty`.
`--no-password` prevents password and passphrase questions; it does not approve
host trust or installation on the user's behalf.

qsh searches the remote `PATH`, `~/.local/bin`, and the supported user-cache
locations. An existing managed service is reported and reused instead of launching a competing daemon.

If no daemon is found during an interactive connection:

1. qsh asks permission to install a daemon for the remote OS and architecture.
2. It fetches `SHA256SUMS` for the **exact client version** from GitHub Releases
   on every installation attempt. A cached archive is reused only if its bytes
   match the current checksum; otherwise qsh downloads and verifies it again.
3. It caches the verified image under `$XDG_CACHE_HOME/qsh/releases`, or
   `~/.cache/qsh/releases` when that variable is unset, on both Linux and macOS.
4. It transfers the image over SFTP to a temporary file, checks the remote bytes,
   and atomically renames it into the remote user's cache before starting it.

The installation prompt uses `[Y/n]`: press Enter to install, or type `n` to
decline. Host-key trust still requires an explicit answer. EOF or cancellation
does not approve installation. Transfer progress uses the terminal's normal text
color. When the total size is known and there is enough room, the bar fills the
available line width and adapts when the window is resized. Redirected output
uses plain text without animation.

Linux and Darwin targets support x86_64 and aarch64. Corrupt cached images are
rejected. If GitHub is temporarily unreachable, qsh can use a previously verified
cache after checking its integrity again. A missing release, invalid metadata,
checksum mismatch, unsafe redirect, or TLS verification failure stops installation
instead of allowing a stale cache. After a new checksum is received, failure to
download the matching archive also stops installation.

Upload and startup have separate deadlines and support cancellation;
time spent answering a prompt does not consume the network budget.

Declining installation ends the address ladder. Installation does not use `sudo`,
replace a system service, or update a daemon already found on the server.
There are no `--install` or `--yes` flags. Background recovery never prompts,
downloads, or installs. Without a matching published release, a usable download
or verified offline cache, and write permission, install the daemon manually.

SSH is only the bootstrap path for this console client. The terminal session
always uses qsh's UDP transport.

### Port knocking

A knock happens before SSH, using `,knock=STEPS` or shared `--knock STEPS`.
`,noknock` disables it for one address. Knocking without SSH is a command-line
error. Join steps with `+`:

```sh
qsh 'user@home.example.org,ssh=2222,knock=tcp:7000+200ms+udp:8000:open'
```

`tcp:PORT` attempts a TCP connection. `udp:PORT[:DATA]` sends a UDP datagram;
DATA may be text, including `:` but not `+` or `,`, or hex prefixed with `0x`.
Pauses such as `200ms` and `1s` need a unit and follow the previous step.
The client logs the number of knock steps, never their ports or payloads.
Replace real knock sequences before sharing a command or report.

## Keyboard controls and display

qsh uses the terminal's alternate screen. Exit, termination signals, and
suspension restore the previous screen; resuming repaints the session. The top
row normally shows qsh status, so the remote shell gets one fewer row. Mouse
coordinates are adjusted accordingly.

The status line shows the active address when there are several, latency, and
silence duration or the recovery stage. `--status off` hides it initially; a
temporary status display still appears during connection loss, recovery, or
history browsing.

Press `Ctrl-]`, then one key:

| Key | Action |
| --- | --- |
| `.` | Leave while retaining the server session. |
| `s` | Open the connection-state panel. |
| `h` | Toggle the status line and resize the remote shell. |
| `r` | Reconnect now, or remove the SSH retry delay during recovery. |
| `[` | Browse the client's scrollback. |
| `?` | Show help. |
| `Ctrl-]` | Send one literal `Ctrl-]` to the remote application. |

Other keys after the prefix are swallowed, including complete arrow and mouse
sequences. Esc cancels the pending command without swallowing the next ordinary
key. Alt-letter after the prefix has the same bytes as Esc then that letter, so
the letter is sent to the remote application. Bracketed-paste contents never
execute local prefix commands, even when a marker arrives across multiple reads.

`--escape ^X` changes the prefix; `--escape ^b` selects Ctrl-B.
Avoid `^[` and `^M` unless you intend to intercept Escape or Enter.
With `^[`, the history command `Esc [` is also the beginning of a paste marker;
it waits for another byte to distinguish the command from a paste.
`--escape none` disables the prefix; leave using the shell's `exit`, a signal,
or by closing the terminal.

The connection panel lists routes in command-line order with state and latency.
Arrows or `1`–`8` select a row; Enter switches to an answering spare route. Escape
or `q` closes the panel. Input stays local while the panel is open.

### Scrollback

`Ctrl-] [` opens the current client's emulator history. The default is 10,000
lines beyond the visible screen; `--history N` changes this and `--history 0`
disables it. With no retained lines, the client reports `no history`.

| Key | Movement |
| --- | --- |
| Up / Down | One line. |
| Page Up / Page Down | One page. |
| Home / `g` | Oldest available line. |
| End / `G` | Newest available line. |
| `q` / Escape | Return to the live terminal. |

The status reads `scroll: N/M`. New output continues arriving without moving the
selected view. Keys, paste, and mouse events stay local; prediction is disabled
while browsing. Opening history closes the help or connection panel.

This is client memory, not the outer terminal's scrollback or durable storage.
It does not survive a new client process. A server stream reset clears it and
returns to the live screen; switching paths without a reset does not clear it.

## Recovery and session limits

The silence counter measures how long it has been since authenticated traffic
arrived from the server. An idle shell still exchanges transport traffic; silence
is a connectivity signal, not a count of time since you last typed. After three
seconds of silence the status turns red. An authenticated spare path can carry
the live connection without opening another server session (the hot path).
The client keeps probing every configured path, including paths outside the
transport's eight active slots, while connected and while recovering.

Without an explicit network refusal, the transport retains its 45-second
silence deadline. A closed UDP port can accelerate recovery when the operating
system reports the refusal, after every candidate path has had an authenticated
probe window and no verified alternative remains. Firewalls and networks that
suppress ICMP still recover using the ordinary deadlines.

When the live connection ends, qsh attempts a warm resume with the previous
session token and expected QSH server key, starting at the last working address.
Every allowed QSH address in the current network generation gets an attempt
before the first SSH round is admitted. A failed or silent first address cannot
exclude the remaining addresses. DNS and key discovery have bounded waits;
their answers are candidates and never replace the expected server key.

| Recovery path | Behavior |
| --- | --- |
| UDP | Handshake packets repeat every 500 ms. Fast rounds start at least one second apart; a long round adds no extra pause. |
| SSH | Independent knock/login/startup rounds with delays of 1, 2, 4, 8, 16, then at most 30 seconds. UDP attempts continue during SSH and every pause. |

SSH can authorize the client's process key and report the daemon's current UDP
port. It does not carry terminal traffic or create a competing qsh connection.
Successful QSH recovery cancels further SSH authentication and commands; late
results cannot change the active path or server key. `Ctrl-] r` removes a pending
SSH delay without starting a duplicate login already in flight.

Background SSH requires an explicit binding between the expected QSH server,
account, SSH hostname/port, and SSH host key. An entry in ordinary OpenSSH
`known_hosts` alone does not grant that permission. The bound key must also
remain trusted there, and `@revoked` entries still block it. A direct QSH login
creates no SSH binding automatically. Use `--authorize-ssh` during a foreground
login to review both fingerprints and grant the selected pair.

Background recovery asks no questions and never installs or updates qshd.
Missing bindings or credentials leave QSH recovery running; skipped SSH steps
are explained in the log. Explicit foreground setup can provide the missing
permission. The initial foreground connection retains its sequential address
ladder and strict handling of conflicting QSH keys.

A foreign QSH key or rejected SSH login fails that path for the attempt. It does
not replace trust, end background recovery, or permanently ban the address.
Retries continue across network A → B → A, so the original server can return at
the same address without deleting trust records or restarting the client. Old
DNS, discovery, UDP, and SSH results cannot authorize work in a newer generation.

During an outage the entire top row turns red, including while viewing local
scrollback or hiding the normal status line. Its fixed text lists every configured
hostname in command-line order, without ports, for example
`reconnecting: host-a [QSH/SSH], host-b [QSH]`. Protocol labels
are bright white while being tried and gray otherwise; hostnames remain gray.
Warm probes can check several paths at once. New QSH handshakes currently try
addresses in sequence. Gray labels indicate no current attempt; recovery can
try eligible targets again. SSH can finish starting the daemon before QSH
finishes checking whether the original session still exists.
Monochrome terminals use
bold versus regular reverse video. The text stays in place as activity changes.
The help hint stays in its usual left-hand columns; recovery text ends at the
rightmost terminal cell, with at least one space separating it from the hint.
Very narrow rows omit the hint to leave room for clipped recovery text.
Overflow is clipped with an ellipsis, without rotating the text.

`Ctrl-] s` opens read-only recovery details. Use the arrow keys to scroll through
elapsed outage time and all configured addresses, including unresolved names
and aliases of the same socket. Details show available QSH endpoints and effective
ports, configured SSH hosts and ports, and resolving, queued, or retry states.
QSH continues while SSH is active or waiting to retry. The details close when the
session returns.

The transport retransmits unacknowledged input while it can recover. After ten
seconds without a link, the server stops retaining unlimited output and repaints
its current screen on return. Output that scrolled away during the outage may
therefore be lost even though the shell survives.

A completely silent server session stays live and routable for a day, then its
backend remains retained for another hour for warm recovery. The daemon allows
at most sixteen live and retained sessions together. tmux provides persistence
beyond these bounds; qsh alone does not promise it.

Leaving with `Ctrl-] .` keeps the server session. Running the same command returns
to it. Local session records are scoped by the effective login, the first
configured host's exact spelling, and its QSH port. Different logins have separate
tokens and numbered locks. Reordering addresses, changing the login or port, or
using another spelling or alias for the host can select a different session;
qsh does not resolve or normalize host names when choosing a local record.

The login-scoped storage format uses `v2-<hash>-<slot>` filenames. Older host-only
records remain untouched and are never automatically imported or claimed: they
contain no trustworthy login attribution. After upgrading from that format, qsh
starts with a fresh local record and cannot automatically resume a detached
session through its old record. This transition does not terminate the old
server session.

A key conflict during foreground login exits with code 11. During recovery, a
foreign server is retried as a failed path while the expected key remains unchanged. When the expected server authenticates but
confirms that the old session no longer exists, for example after a daemon
restart, or an authenticated resume no longer lists the tracked shell, qsh restores the terminal, explains the loss, and asks
`Start a new session? [Y/n]`. Enter, `yes`, or `y` starts a fresh shell
in the same invocation. `no`, EOF, or no controlling terminal exits with
code 13; Ctrl-C cancels with code 130. The new shell uses the same locked local
session slot with a new persisted resume token, so detach and resume work as
usual. Consent preserves the expected server identity and SSH recovery bindings;
a changed endpoint continues retrying without another trust question. Replacement
first tries the authenticated road that confirmed the loss, then the other
configured roads if needed.

## Options and exit codes

| Option | Meaning |
| --- | --- |
| `-l USER` | Account to claim unless supplied as `user@`. |
| `-p, --port N` | Default qsh UDP port; an explicit `host:port` takes precedence. |
| `-i, --identity PATH` | The only identity for direct qsh authentication; first choice for SSH. |
| `--ssh[=N]` | Enable SSH for addresses without their own override. |
| `--authorize-ssh` | After QSH login, explicitly configure SSH recovery for the authenticated QSH server. |
| `--knock STEPS` | Shared pre-SSH knock sequence. |
| `--no-password` | Do not ask for passwords or passphrases. |
| `--predict adaptive\|always\|never` | Local input prediction; default `adaptive`. |
| `--escape ^X\|none` | Client command prefix; default Ctrl-]. |
| `--status on\|off` | Initial status-line visibility. |
| `--history N` | Client scrollback lines; default 10000, zero disables. |
| `--verbose` | More detail in the already-enabled client log. |
| `-h, --help` | Command-line help. |
| `-V, --version` | Version information. |

Before the session starts, messages go to stderr with the `qsh:` prefix;
questions use `/dev/tty`, even when stdout/stderr is redirected. A remote shell
exit is returned as its own exit code. Client-generated failures use:

| Code | Meaning |
| --- | --- |
| 1 | Trust or installation declined, session startup failure, or leaving with Ctrl-] . while retaining the session. |
| 2 | Invalid command line. |
| 10 | Authentication keys could not be loaded. |
| 11 | A server key changed during foreground login, or supplied addresses have conflicting server keys. |
| 12 | All addresses failed during login. |
| 13 | Recovery confirmed session loss and a replacement was declined or could not be confirmed. |
| 130 | An interrupted operation, such as cancelling an installation with Ctrl-C. |

### Prediction

`adaptive` enables local input prediction when latency warrants it and disables
it on fast links. `always` predicts unconditionally; `never` disables prediction.
The client reconciles the predicted display with the authoritative server frame.
On applications with unusual redraw behavior, disabling prediction may avoid
visible corrections.

## Logs and troubleshooting

The client log is enabled without `--verbose`:

| Platform | Location |
| --- | --- |
| Linux and macOS | `$XDG_CACHE_HOME/qsh/log`, otherwise `~/.cache/qsh/log`. |

New logs use the XDG cache directory. Previous macOS logs under
`~/Library/Caches/qsh` are left in place; they are not copied or removed.
Downloaded release archives already use the XDG cache directory.

After exceeding 1 MiB, `log` becomes `log.1` and a new log starts; one prior file
is retained. Directories use mode 0700 and files 0600. Logging failures do not
end the session or overwrite its screen.

Records contain a UTC timestamp with milliseconds, PID, level, and component:

```text
2026-09-30 20:15:03.123 UTC [4242] INFO  qsh: qsh exiting with code 12
```

Normally the project's code logs at INFO and dependencies at WARN. `--verbose`
changes project logging to DEBUG and `russh` to INFO. Startup records include
version/build, OS/architecture, and addresses; exit records include the code.
While rendering, stderr is redirected to the log under component `stderr`.
Some final lines can arrive after the exit marker as the reader drains.

Diagnostics distinguish send failures with their OS error, no UDP answer, a key
response without login, incompatible replies, and IPv6-only addresses. Login
refusal names the claimed account and offered key fingerprints; server-side
reasons such as authorized-key or PAM rejection are in the daemon log. On macOS,
applicable local-address errors include a hint about Local Network permission.

A useful bug report includes version/build, platform, the visible error and its
time, reproduction steps, relevant `log`/`log.1` excerpts, and a matching
server-log excerpt. See [daemon logging](qshd-service.md#what-a-log-line-looks-like)
for locations and journald integration.

Passwords, passphrases, private-key material, and knock payloads/ports are not
logged intentionally. Addresses, account names, paths, and public fingerprints
may appear. Review logs and redact real connection details before sharing them;
never paste private keys, passwords, or a real knock sequence into an issue.
