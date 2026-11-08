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
spare paths are also remembered. Pins for different endpoints that disagree stop
the client with exit 11; a stored key is never silently overwritten. Ambiguous
records for one equivalent endpoint are refused as described below.

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
Both QSH signing and SSH authentication read private keys only from regular
files, with a 1 MiB input limit (including comments and padding). This is a
resource limit, not a maximum defined by key formats. On Unix, the opened file
must belong to the effective user or root and grant no group or other permissions
(including execute): `0400` and `0600` work. The same descriptor is checked before
and after the bounded read, before decoding or asking for a passphrase. Unsafe
files are refused without changing their permissions or ownership.

Symbolic links to safe final files and hardlinks remain supported. Parent paths
use ordinary OS resolution, without additional ancestor ownership or mode rules.
These Unix owner/mode checks do not audit extended ACLs, including macOS ACLs,
and do not provide an atomic content snapshot or continuous permission monitor.
Agent keys, platform signers and keys supplied in memory do not use this file
policy. An explicit QSH identity failure stops selection; unsafe discovered QSH
files are skipped with a reason, while SSH keeps its method fallback behavior.

For a file identity, a passphrase unlocks the key selected before the prompt.
Replacing or editing its path during that attempt does not select another key;
a later selection attempt can read the changed file normally.
Direct QSH login supports Ed25519, ECDSA P-256/P-384, and RSA with SHA-2
signatures. It refuses RSA/SHA-1 signatures (`ssh-rsa` as a signature
algorithm), but accepts RSA public keys whose type is `ssh-rsa` when the
signature uses SHA-2. SSH negotiates its own signatures and refuses RSA/SHA-1
the same way, in both directions: an RSA host key is used only through
`rsa-sha2-512` or `rsa-sha2-256`, and an RSA key file, agent key or platform key
signs only with one of those. When a server advertises only legacy `ssh-rsa`
for RSA keys, qsh skips the RSA key, says why, and goes on with the next one. A
server that advertises no RSA algorithm, or no signature algorithms at all, gets
one `rsa-sha2-512` attempt. A server whose host-key offer is only `ssh-rsa`
fails the handshake with that offer named. Ed25519 and ECDSA keys are
unaffected. There is no option to allow SHA-1. A personal daemon checks
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

Pin identifiers must be nonempty, contain no whitespace or control characters,
and not start with `#` (the store's comment syntax). Rejected identifiers are
never trimmed or rewritten into a different identity. Ordinary ASCII DNS names
match without regard to letter case; standard IP literals match by value within
the same address family. Trailing-dot presence remains significant: `host` and
`host.` can resolve differently through a search list. IPv6 zone text remains
exact, so `%eth0`, `%ETH0`, `%2`, and no zone are distinct. Unicode names and
other safe opaque identifiers retain exact spelling; no IDNA, resolver or
interface-based equivalence is inferred. Stored spelling is not migrated.

### Names in trust questions

Two different names must not be shown as the same text where you decide
whether to trust them. The QSH first-use question and changed-key refusal, the SSH unknown and
changed host-key messages and the qshd installation question therefore show account names, host names, key types and
fingerprints by a stricter rule than other text. Only the presentation changes:
the connection, the known-hosts lookup and the stored pins use the name exactly
as given.

A character that is invisible on its own, or that rearranges the text around
it, is shown as `\u{XXXX}` with its code point, and a backslash as `\\`, so the
shown text maps back to exactly one name. That covers terminal controls, line
separators, direction controls, format characters such as the zero-width space,
the word joiner, the soft hyphen and the interlinear annotation controls U+FFF9
to U+FFFB, spaces other than the ordinary space (and an ordinary space at either
end), default-ignorable characters such as the Hangul fillers, and unassigned,
private-use and noncharacter code points. Joiners, variation selectors and tag
characters are shown as they are only in the sequences below, and escaped
elsewhere:

- ZWJ and ZWNJ after a virama, ZWNJ between joining letters (the contexts
  RFC 5892 allows), and ZWJ inside an emoji ZWJ sequence;
- a variation selector that forms a variation sequence registered in Unicode
  17.0 (`StandardizedVariants.txt` or `emoji-variation-sequences.txt`) with
  the character before it, where an emoji or text selector on `0`-`9`, `#` or
  `*` counts only in a keycap such as `1️⃣`. Ideographic variation sequences
  are registered separately, in the Ideographic Variation Database, and are
  escaped;
- tag characters only in the RGI emoji tag sequences, the flags of England,
  Scotland and Wales.

Whether a sequence is drawn as intended still depends on the terminal and its
fonts; the rule decides only which text is written.

Every script, combining mark and emoji is otherwise shown as it is. When a
question shows an escape it adds a line saying so. A name whose presentation
would exceed 512 bytes is cut and ends with `\[+N more characters, sha256 H]`:
the number of characters left out and the first 64 bits of the SHA-256 of the
whole name. No name is shown as such a marker, since its backslashes are
doubled; H tells apart long names that agree in the part shown, barring a
collision of those 64 bits. Look-alike letters from different scripts, such as
Cyrillic `а` and Latin `a`, are not marked. Error messages, server text and the
status line keep the general rule, which replaces controls with `?` or a space
and leaves other characters unchanged.

Every equivalent record must agree on one key. Conflicting keys, including
duplicate rows with the exact same spelling, make that endpoint ambiguous and
cause a pin-store error. Appending a correction no longer selects the last row:
inspect the store and remove stale conflicting entries before retrying. qsh
does not select a matching offered key from conflicts or repair them silently.
A unique stored key that differs from the offered key still produces the
ordinary changed-key refusal. This QSH pin format is separate from OpenSSH's
host-list syntax; the CLI still owns comma-separated address settings.

On Unix, QSH pins are read only through validated paths owned by root or the
current effective account. Ordinary directories and regular pin files must not
be writable by group or others; trusted sticky directories may be traversed.
This rule also rejects a nonsticky `0775` ancestor when its group is intended
for only one user: group membership is not used to establish filesystem
integrity. A private child does not make an unsafe ancestor trustworthy. An
administrator can choose a suitable authority route with non-group-writable
ancestors, such as `0755` or `0700`; do not recursively change a shared project
or home directory to satisfy this check.

Safe public files such as `0644` pins, trusted aliases, and public-data hardlinks
are supported. Unsafe, unreadable, dangling, special, or invalid UTF-8 sources
cause a pin-store error, never an empty-store first-use prompt. A genuinely
missing ordinary store remains empty, and checking it creates nothing.

Writers retain the configured store's permanent sibling lock. That lock must be
a regular, singly linked `0600` file owned by the current account; existing
objects are never repaired with chmod or chown. A trusted root-owned source may
be read, and an existing account-owned lock permits a true no-op in a read-only
trusted directory. Publishing a pin requires a current-account-owned directory
that is not writable by others. New directories use `0700`; new pins use `0600`.

A trusted final alias may supply the initial pins, but publication replaces the
configured entry under its original sibling lock and leaves the alias target
and other hardlinks unchanged. Observed route, source, lock, or temporary-name
replacement causes refusal. Updates write and sync a complete sibling temporary
file before atomic rename; failed cleanup removes only its own still-named
inode, never a collision or substituted entry. This does not add a file-size
limit, lock timeout, directory-fsync durability, or an atomic snapshot against
concurrent edits by root or the same account. These rules apply to the QSH store;
OpenSSH's separate host-key store is not changed by them.

Session tokens live in the adjacent `sessions` directory. XDG overrides must be
absolute paths; empty or relative values use the defaults above.

`~` is `$HOME`, or the account database's home directory when `HOME` is unset
or empty. When neither names one, qsh never uses the current directory instead.
Without an absolute `XDG_CONFIG_HOME` it exits with an error. Without an
absolute `XDG_CACHE_HOME` it runs without a log file and without the release
cache: a daemon image is still downloaded and verified, but not kept. SSH then
tries no default key files and reads only `/etc/ssh/ssh_known_hosts`, so an
accepted SSH host key is not saved.

The CLI treats its sessions directory as dedicated private storage. It validates
the directory route and each regular, single-linked, same-user slot before use,
and can tighten initial directory/file permissions after locking a free slot.
It never changes shared ancestors or occupied slots. A later displaced path or
unsafe permission change prevents token replacement; the held token and lock
remain intact. Generic library callers do not authorize directory repair.

Token files accept the existing trimmed 32-digit hexadecimal form within 4096
bytes. Damaged or oversized contents can be replaced with a fresh token. A read
I/O error leaves that file untouched and falls back to another slot or an
in-memory token. Initial saving is best effort; replacement reports errors.
Writes retain the locked inode and do not promise crash-atomic persistence.
There is no automatic local token expiration. A token alone does not authorize
reattachment: the server still requires account authentication.

The client uses only the selected XDG store. Previous macOS files under
`~/Library/Application Support/qsh` are not imported or linked automatically;
existing files remain untouched. Server-side qshd state and host keys are unaffected.

SSH independently reads `~/.ssh/known_hosts` and `/etc/ssh/ssh_known_hosts`,
including hashed entries, `[host]:port`, and revoked keys. Both configured stores
must be readable or ordinarily absent; an unsafe or unreadable store stops SSH
before a connection starts. Public regular files owned by root or the current
user are accepted when neither group nor others can write them. Trusted parent
and file aliases, public hardlinks, and safe searchable directories remain
supported; observed path or metadata changes are refused. Malformed lines and
invalid UTF-8 lines remain ignored individually, without hiding valid neighbors.

Unknown SSH keys need confirmation; changed ones are refused. Saving an accepted
key requires a current-user-owned file and reads its complete tail through the
same descriptor used for append. A trusted final alias appends to its actual
target; hardlink names share the change. Existing modes are preserved. Creating
entries requires a current-user-owned safe parent; no permissions are repaired.
Dangling aliases or a new entry appearing during creation cause a save error.
If saving fails, qsh warns and may still connect using the specifically approved
key for this attempt. Append does not serialize other writers or roll back a
partial write. When that verified SSH login starts qshd, its returned daemon
key binds only the same address and the UDP port it reports. qsh compares discovery
with that key and atomically remembers it without another QSH trust question.
Conflicting existing pins, discovery keys, or session identities are refused;
Noise still proves the daemon holds the private key. Other QSH endpoints do not
inherit this daemon-key grant; the SSH recovery key has the separate scope below.

Recovery SSH accepts keys already approved for the attempted SSH hostname and
port in the configured OpenSSH `known_hosts` files. This works after either a
direct QSH login or an SSH bootstrap, without a separate association question,
key query or persistent recovery grant. Unapproved or revoked keys cannot trigger
recovery authentication or remote commands. The removed `--authorize-ssh`
option is rejected; old `ssh_bindings.json` files are ignored and left untouched.

After verified SSH bootstrap and successful QSH authentication, the checked SSH
host key is also retained in memory for this client connection, bound to the
actual QSH server and account. A same-connection shell replacement retains this
evidence; a new client starts afresh. An explicitly SSH-enabled alias absent from
ordinary known-hosts files may use this memory key. Before each attempt, fresh
origin trust checks and target revocations determine whether memory remains
eligible. An origin conflict, revocation or read failure suppresses only that
memory authority; independently approved target keys remain usable. A different approved target key does not veto eligible memory evidence; when
origin and target are the same endpoint, its origin conflict still suppresses
memory. A matching target revocation always excludes the affected key. An unreadable target trust
store fails closed. These checks never overwrite known-host entries or import
unrelated keys, and are per-attempt checks rather than a global revocation service.

The actual restricted SSH handshake proves possession before authentication.
After SSH startup, QSH must still prove the original authenticated daemon identity
before the session can continue. Initial SSH host verification is unchanged.

Encryption does not conceal network addresses, volume, or timing. It cannot
protect either endpoint after that machine is compromised. The full threat model
and wire format are in [the protocol specification](protocol.md).

## Client installation and updates

These commands describe `main` and require a later installer-capable release.
No published release has `--self-install` or `--self-update`, and neither did
the withdrawn `0.6.0-rc1`; the bootstrap refuses an older executable rather than
falling back to another release.

The [README installer instructions](../README.md#installing) download
`scripts/install.sh` directly from official GitHub HTTPS. The script selects the
latest stable release by default. `--version VERSION` selects an exact version,
including an RC such as `0.6.0-rc.2`; this example is syntax, not an availability
claim. It downloads only a temporary bootstrap client and invokes:

```sh
qsh --self-install [--version VERSION] [--prefix PATH]
```

The default prefix is `$HOME/.local`; the client is `<prefix>/bin/qsh`. The
prefix must be inside the user's home. Installation needs no sudo and installs
no daemon. The engine authenticates the final selected release with compiled
release roots before publishing a complete generation and its active link.
The [bootstrap trust boundary](release-security.md#client-bootstrap-trust)
explains why this does not authenticate the temporary executable before execution.

A different `qsh` on PATH causes the default installation to refuse. An explicit
`--prefix` acknowledges a separate installation and reports both paths; it does
not edit PATH. An existing unregistered destination is never overwritten.
Manual copies and package-owned clients cannot acquire managed status merely by
being in a particular directory. Keep DEB/RPM installations under their package
manager, using local release packages; qsh provides no apt/dnf repository,
Homebrew formula, or `cargo install qsh` channel.

For a registered managed installation:

```sh
qsh --self-update
qsh --self-update --version VERSION
```

The default selects a newer stable release. Exact selection allows an RC but
never downgrades the installed client. Update validates the actual running
executable, its receipt and binary digest before downloading. Running from a
checkout does not change an installed client's provenance; copying a developer
binary elsewhere does not make it eligible. Source builds, including release
profile builds, never download, install, or switch console clients. Manual,
package-owned, modified and unregistered copies refuse self-update.

On connection and reconnect, qsh independently asks the pinned server for its
running daemon version and supported session protocols. This authenticated
discovery runs alongside ordinary admission. A legacy daemon that does not
answer remains unknown and adds no admission delay. On an attached connection,
the discovery process generation must match the authenticated session reply.

A newer eligible server release can offer a managed client update. Enter or
Escape postpones; choose the explicit update option to consent. A compatible
connection can continue after postponement. An authenticated incompatible server
cannot open a shell. Source builds only show manual rebuild guidance for
incompatibility, and package-owned copies use their package manager. The offer
requests the exact eligible server release from the official release source;
it never uses a server-supplied download location. After installation, relaunch
qsh explicitly. Updating does not promise to preserve the remote terminal.
Termination during an approved update cancels its network work and is checked
again before atomic activation. Cancellation observed before activation leaves
the previous active client in place. A signal after activation commits does not
undo the installation; relaunch is still explicit.

If UDP discovery is unavailable, an already configured and trusted SSH route
may execute read-only `qshd server-info --challenge HEX64`. Its response must
echo the fresh challenge and match the pinned qsh key. Discovery never accepts
a new SSH host key, installs a daemon, or authorizes a client. Unsupported
legacy commands and daemon modes without an available local control socket
remain unknown; the executable's `--version` is not running-server evidence.

Release authentication, destination validation or cancellation failures before
publication leave the prior active generation in place. Updates retain the old
generation and report the exact executable path to run next. They never replace
the running process, restart a session, or run automatically after a connection
failure. Different client/server versions alone do not establish incompatibility;
compatible peers remain usable. Unsupported protocol or capability combinations
produce a diagnostic and require an explicit update through the client's normal
installation channel.

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

Before executing a discovered daemon, qsh checks ownership and Unix permissions
from `/` through its canonical path, including symlink inodes and targets. Every
object must belong to root or the SSH command's effective account. The executable
must be a regular executable file without group/other write or setuid/setgid bits.
Reachable directories must deny group/other write. A trusted private directory
that denies group/other search permits writable inner directories; this exemption
does not carry across symlinks or exempt executable permissions. Trusted sticky
directories such as `/tmp` permit traversal through existing trusted-owned
children, but are not installation destinations. Symlink and path traversal are
bounded; missing metadata tools or malformed responses cause refusal.

An unsafe selected daemon stops startup with a verification error. qsh does not
try a lower-priority candidate, request installation approval, or download a
replacement. Correct the reported ownership/permissions or install qshd in a
private directory owned by your account. Custom builds do not need a published
release hash or a matching filename version: cache filenames only rank candidates,
and the running command reports its actual version. Protocol and capability
negotiation still determine compatibility.

Managed installation separately checks its destination before reading, changing,
or replacing files, creates missing cache directories with private permissions,
and refuses an existing final symlink or unsafe file without repairing it. A safe
cache-directory symlink is supported. Callers that explicitly request a bundled
image verify and install that image at their own trusted destination instead of
executing a discovered candidate.

These checks assume the server, root, account, shell and OS tools are trusted,
Unix permissions are enforced, and ACLs do not grant additional access. Rechecks
narrow races but do not atomically bind pathname execution or protect against
concurrent changes by trusted writers.

If no daemon is found during an interactive connection:

1. qsh asks permission to install a daemon for the remote OS and architecture.
2. It fetches `SHA256SUMS` and `SHA256SUMS.sigstore.json` for the **exact client
   version** from GitHub Releases. It authenticates the original manifest under
   the compiled qsh repository/workflow policy before selecting an archive hash.
3. It retains the signed evidence, verified archive and image under
   `$XDG_CACHE_HOME/qsh/releases`, or `~/.cache/qsh/releases` when that variable
   is unset, on both Linux and macOS. Every offline load authenticates the
   original evidence again and rechecks the archive and extracted image.
4. It transfers the image over SFTP to a temporary file, checks the remote bytes,
   and atomically renames it into the remote user's cache before starting it.

The installation prompt uses `[Y/n]`: press Enter to install, or type `n` to
decline. Host-key trust still requires an explicit answer. EOF or cancellation
does not approve installation. Transfer progress uses the terminal's normal text
color. When the total size is known and there is enough room, the bar fills the
available line width and adapts when the window is resized. Redirected output
uses plain text without animation.

Linux and Darwin targets support x86_64 and aarch64. Automatic downloads require
signed metadata; unsigned releases, including the existing v0.5.0, are refused.
Old unsigned cache generations are misses, without trusting or migrating their
checksum receipts. Older released clients remain unchanged. A daemon already
found on the server follows its existing source policy and is not a signing-error
fallback. See [release authentication](release-security.md) for the trust boundary.

If the manifest request fails temporarily before receiving any body bytes, qsh
may use a fully reauthenticated cache for that exact version and target. A
manifest transfer interrupted after body bytes fails. If the complete manifest
arrives but its bundle transfer is interrupted or temporarily unavailable, cache
reuse requires byte-identical authenticated manifest evidence. Missing assets,
TLS rejection, size limits, malformed or unauthenticated metadata, and archive
hash/download failures stop installation even when another cache exists.

Both metadata downloads share one 20-second network deadline covering DNS,
connection, redirects, headers and body. Bounded local signature verification
checks cancellation and its own budget before and after the synchronous call;
it cannot be preempted mid-call. Archive download, upload and startup retain
separate deadlines. Ctrl-C cancels the wait; cancellation does not select the
offline cache or approve installation. Prompt time does not use a network budget.

Historical signed evidence does not establish current revocation status, latest
version or that a release has not been withdrawn. Offline authentication uses
this client's compiled roots at verified signing times; a leaf certificate's
present-day expiry alone does not invalidate valid historical evidence. Unknown
roots require an updated client. There is no network root refresh or trust-policy
override.

Cache reuse still requires trusted root- or current-account-owned directories
and public data without group or other write access, plus a private current-account
lock. Safe 0755 directories, 0644 public files and trusted cache-root aliases remain
supported; aliases below the cache root are refused. Refused storage does not prevent
installation from freshly downloaded, authenticated bytes. Existing permissions
are not repaired. A cache operation retains its original directory and lock
identities and refuses observed replacement rather than adopting another route.
These filesystem checks do not provide atomic pathname publication against root
or processes controlling the same account; signed evidence must still verify.

Release HTTPS uses bundled WebPKI CA roots. Adding a private or enterprise CA to
the operating system's trust store does not automatically add it to this client's
release trust store. A TLS verification failure stops installation even when a
cache exists; qsh does not disable certificate verification to use it.

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
Name resolution has its own 10-second limit. After it, the knock with its
pauses and the TCP connection share one 10-second limit: a sequence that does
not fit stops there, and no connection is attempted.
The client logs the number of knock steps, never their ports or payloads.
Replace real knock sequences before sharing a command or report.

## Keyboard controls and display

qsh uses the terminal's alternate screen. Exit, termination signals, and
suspension restore the previous screen; resuming repaints the session. The top
row normally shows qsh status, so the remote shell gets one fewer row. Mouse
coordinates are adjusted accordingly.

The status line shows the active address, including for a single-server command,
latency, and silence duration or the recovery stage. `--status off` hides it
initially; a temporary status display still appears during connection loss,
recovery, or history browsing. A resize refusal also stays visible while the
connection is live, even with status hidden. The notice does not take another
remote row.

Window changes request a new remote size. Until the server confirms it, qsh
keeps parsing output at the last committed dimensions and crops or pads that
screen into the physical window. A refusal leaves the remote PTY and model
unchanged and names the reason. While this client keeps the same channel,
repainting or reconnecting does not retry that refused request. Change the
window size to retry; moving away and back also counts as a new request.
Zero-sized windows suspend resize requests. SSH sessions can only
report that `window-change` was sent, not that the remote PTY applied it.

QSH requires protocol 2 with channel geometry. The published v0.5.0 protocol-1
client and daemon cannot open a QSH session with these peers; update the peer
through its normal installation path. An unanswered UDP attempt does not prove
which version is at the address. Configured SSH recovery remains available.

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

If the terminal sends a paste-start marker without its matching end marker,
qsh keeps treating subsequent input as literal paste, including `Ctrl-] .`.
Waiting does not restore local commands. If you know the original input source
has finished and no input remains queued, a terminal action that sends a complete
bracketed paste can supply the missing end marker. Its content and markers still
go to the remote application; local commands become available after the end
marker. This depends on your terminal sending those markers. qsh cannot confirm
that an input source has finished, and this is not a universal recovery method.

To leave anyway, close the terminal or use another terminal to send a signal
to the identified qsh process. During a session, `SIGHUP`, which closing a
terminal usually sends, leaves the way `Ctrl-] .` does: qsh exits with code 1
and the server keeps the session, also inside an unfinished paste. qsh sends
nothing more to the remote application, so after you return it may still be
waiting for the paste's end marker. `SIGTERM`, `SIGINT` and `SIGQUIT` end the
client and close the remote session. When a closing signal and `SIGHUP` are
both seen before qsh has decided how to leave, the close wins; a signal that
arrives after that decision changes nothing. Which signals a closing terminal
or a logout sends, and in what order, depends on the terminal and the system.
Before a session is attached (while connecting, or at a trust or password
question), any of these signals cancels with code 130. If the login was already
admitted when the signal arrived, a hangup still leaves its session on the
server, and a closing signal ends it. Typing `Ctrl-C` or
`Ctrl-Z` in raw mode does not send these operating-system signals to qsh.

After a lost terminal, restoring its settings and printing the closing notice
are best effort, as there may be nowhere left to write them; the client log
records the hangup. Coming back needs the session token to have been saved
(see below) and the server to still keep the session.

`--escape ^X` changes the prefix; `--escape ^b` selects Ctrl-B.
Avoid `^[` and `^M` unless you intend to intercept Escape or Enter.
With `^[`, the history command `Esc [` is also the beginning of a paste marker;
it waits for another byte to distinguish the command from a paste.
`--escape none` disables the prefix. Closing the terminal or sending `SIGHUP`
leaves and keeps the remote session; the shell's `exit`, `SIGTERM`, `SIGINT` and
`SIGQUIT` end it.

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
Recovery sends one shared handshake to all eligible resolved endpoints, with
at most eight handshake datagrams per 50 ms scheduling interval. Each endpoint
gets its own send and failure evidence; aliases of one socket share that work.
The first authenticated response selects one transport and one proof producer.
If it cannot finish authentication, unfinished endpoints get another selection
opportunity before the next credential is tried. Every applicable endpoint and
credential check must finish before the first SSH round is admitted. A failed
or silent first address cannot exclude the remaining addresses. DNS and key
discovery have bounded waits;
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

Background SSH uses applicable ordinary known-host approval or eligible
connection-local bootstrap evidence, as described above. A refused key affects
only that attempt; it does not erase evidence, permanently ban an address or stop
all-address QSH recovery. Background recovery asks no questions. Missing approval
or credentials leaves QSH recovery running; bounded, deduplicated explanations
appear in the active terminal notice area.

Background recovery asks no questions and never installs or updates qshd. It only
reuses or restarts an installed daemon with its existing identity; a missing
executable or identity refuses that SSH attempt while other paths remain eligible.
Consenting to a replacement shell in the same client run does not permit installation
or binary replacement. Initial connection installation remains available.
The initial foreground connection retains its sequential address
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
Warm probes and shared recovery handshakes can check several paths at once.
A QSH label lights up after an actual send; queued work stays gray. Recovery can
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

Leaving with `Ctrl-] .`, or by a terminal hangup, keeps the server session.
Running the same command can return to it while the server keeps it. Local session records are scoped by the effective login, the first
configured host's exact spelling, and its QSH port. Different logins have separate
tokens and numbered locks. Reordering addresses, changing the login or port, or
using another spelling or alias for the host can select a different session;
qsh does not resolve or normalize host names when choosing a local record.

If the local session store cannot be opened or written, qsh prints one warning
before drawing the terminal. The current connection remains usable, but future
recovery may be unavailable because its token was not saved. The notice printed
on leaving then says the session is kept but that another run cannot return to
it. The warning names
the failing path and condition without printing the token. Inspect the reported
component's ownership, permissions, and available space; qsh does not repair an
unsafe ancestor or replace another account's file.

The login-scoped storage format uses `v2-<hash>-<slot>` filenames. Older host-only
records remain untouched and are never automatically imported or claimed: they
contain no trustworthy login attribution. After upgrading from that format, qsh
starts with a fresh local record and cannot automatically resume a detached
session through its old record. This transition does not terminate the old
server session.

Current application peers require explicit authentication acceptance as well as
ordered channel geometry. A completed transport handshake or successful SSH
bootstrap alone does not start application work: qsh waits for the server's
committed admission record. Missing capabilities are an incompatibility; elapsed
time and unrelated output never substitute for acceptance. A resumed record
still needs usable channel evidence, while a fresh record during recovery does
not open a shell before the existing consent question.

A key conflict during foreground login exits with code 11. During recovery, a
foreign server is retried as a failed path while the expected key remains unchanged. When the expected server authenticates but
confirms that the old session no longer exists, for example after a daemon
restart, or an authenticated resume no longer lists the tracked shell, qsh restores the terminal, explains the loss, and asks
`Start a new session? [Y/n]`. Enter, `yes`, or `y` starts a fresh shell
in the same invocation. `no`, EOF, or no controlling terminal exits with
code 13; Ctrl-C cancels with code 130. The new shell uses the same locked local
session slot with a new persisted resume token, so detach and resume work as
usual. Consent preserves the expected server identity and connection-local SSH recovery evidence;
a changed endpoint continues retrying without another trust question. Replacement
first tries the authenticated road that confirmed the loss, then the other
configured roads if needed.

## Options and exit codes

| Option | Meaning |
| --- | --- |
| `--self-install` | Install an official client under a home prefix; requires an installer-capable release. |
| `--self-update` | Explicitly update the registered running client; requires an installer-capable release. |
| `--version VERSION` | Exact release selection with either self-installation flag. |
| `--prefix PATH` | Installation prefix with `--self-install`; default `$HOME/.local`. |
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
| 1 | Trust or installation declined, session startup failure, or leaving with Ctrl-] . or a terminal hangup (SIGHUP) while retaining the session. |
| 2 | Invalid command line. |
| 10 | Authentication keys could not be loaded. |
| 11 | A server key changed during foreground login, or supplied addresses have conflicting server keys. |
| 12 | All addresses failed during login. |
| 13 | Recovery confirmed session loss and a replacement was declined or could not be confirmed. |
| 130 | An interrupted operation, such as cancelling an installation with Ctrl-C, or a termination or hangup signal before a session is attached. |

### Prediction

`adaptive` enables local input prediction when latency warrants it and disables
it on fast links. `always` shows available predictions regardless of latency;
`never` disables prediction.

Prediction has per-episode limits on speculative memory, pending cursors and
work. A large paste or delayed echo can reach a limit; the client then displays
authoritative output until echo acknowledgement catches up. Every input byte
still goes to the remote application. Prediction can resume after that
acknowledgement. Resizing or changing the prediction display mode does not
bypass this wait.

The client reconciles the predicted display with the authoritative server frame.
On applications with unusual redraw behavior, disabling prediction may avoid
visible corrections.

### Ordinary output presentation

The console keeps ingesting server output and evaluating the terminal model
immediately. During a burst it can retain the latest ordinary-output snapshot
until 16 ms after the last changed presentation. New output does not extend
that deadline, and quiet final output is presented when the deadline arrives.

Input, echo acknowledgements, synchronized-output boundaries, input-mode changes,
geometry and visible UI changes bypass this pacing. Normal exit and suspension
flush already-executed pending output before restoring the local terminal.
This interval is not a global frame-rate limit.

## Logs and troubleshooting

The client log is enabled without `--verbose`:

| Platform | Location |
| --- | --- |
| Linux and macOS | `$XDG_CACHE_HOME/qsh/log`, otherwise `~/.cache/qsh/log`. |

New logs use the XDG cache directory. Previous macOS logs under
`~/Library/Caches/qsh` are left in place; they are not copied or removed.
Downloaded release archives already use the XDG cache directory.

Before the next complete record would exceed 1 MiB, `log` becomes `log.1`
and a new log starts; one prior file is retained. A record larger than 1 MiB
including its newline is dropped whole. If rotation or reopening fails, that
record is dropped and later records retry, instead of growing an old file.
Existing oversized files are not silently truncated. Independent clients can
race their size checks: with N cooperating writers and maximum record size L,
the conservative per-inode bound is the larger of its initial size and
1 MiB + (N - 1) × L, at worst the larger of its initial size and N MiB; this
excludes outside writes. Directories use mode 0700 and files 0600. Logging
failures do not end the session or overwrite its screen. Initial file-log
failure produces one startup warning naming the path and condition. Personal
daemon startup carries its log warning through the successful SSH bootstrap;
a reused daemon reports the retained warning again to its next connecting
caller. During SSH recovery, the warning appears in the active terminal notice
area and is retained after reconnection; repeated identical warnings are suppressed. Service-mode startup reports it on stderr for the service manager.

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
