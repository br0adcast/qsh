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
ones are refused. Trusting an SSH key does not implicitly trust a different qsh
server key.

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
2. It downloads the **exact client version** from GitHub Releases and verifies
   the archive against that release's `SHA256SUMS`.
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
rejected. Upload and startup have separate deadlines and support cancellation;
time spent answering a prompt does not consume the network budget.

Declining installation ends the address ladder. Installation does not use `sudo`,
replace a system service, or update a daemon already found on the server.
There are no `--install` or `--yes` flags. Background recovery never prompts,
downloads, or installs. Without a matching published release, network access, or
write permission, install the daemon manually.

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

Other keys after the prefix are swallowed, including complete arrow/Alt
sequences. `--escape ^X` changes the prefix; `--escape ^b` selects Ctrl-B.
Avoid `^[` and `^M` unless you intend to intercept Escape or Enter.
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

Short outages are handled by the transport. After three seconds of silence the
status turns red; after 45 seconds the transport gives up the connection. The
client then tries to recover the same server session, starting with the last
working address.

| Recovery path | Behavior |
| --- | --- |
| UDP | No increasing round delay. Handshake packets repeat every 500 ms; an immediately failing round cannot restart sooner than one second after its start. |
| SSH | Independent knock/login/startup rounds with delays of 1, 2, 4, 8, 16, then 30 seconds. |

A separate changed-key check retains its five-second wait without holding up the
next UDP attempt. SSH delivers the reported port and process-key authorization
to UDP recovery rather than opening a competing qsh connection. Successful UDP
recovery cancels SSH work. `Ctrl-] r` removes a pending SSH delay without starting
a duplicate login already in flight.

Background recovery asks no questions. Unknown keys, passwords, or passphrases
require starting the client again; skipped steps are explained in the log.
The initial foreground connection still uses the sequential address ladder.

The transport retransmits unacknowledged input while it can recover. After ten
seconds without a link, the server stops retaining unlimited output and repaints
its current screen on return. Output that scrolled away during the outage may
therefore be lost even though the shell survives.

A completely silent server session stays live and routable for a day, then its
backend remains retained for another hour for warm recovery. The daemon allows
at most sixteen live and retained sessions together. tmux provides persistence
beyond these bounds; qsh alone does not promise it.

Leaving with `Ctrl-] .` keeps the server session. Running the same command returns
to it; the first address is the local session-record key, so reordering addresses
can select a different session. A changed server key ends recovery with exit 11.
A daemon that no longer has the session, for example after restart, causes exit
13. Start qsh again to create a new session in that case.

## Options and exit codes

| Option | Meaning |
| --- | --- |
| `-l USER` | Account to claim unless supplied as `user@`. |
| `-p, --port N` | Default qsh UDP port; an explicit `host:port` takes precedence. |
| `-i, --identity PATH` | The only identity for direct qsh authentication; first choice for SSH. |
| `--ssh[=N]` | Enable SSH for addresses without their own override. |
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
| 11 | A server key changed, or supplied addresses have conflicting server keys. |
| 12 | All addresses failed during login. |
| 13 | Recovery found that the server session no longer exists. |
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
