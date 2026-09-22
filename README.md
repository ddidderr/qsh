# qsh

A small SSH replacement built on QUIC. Version 1.0 does three things, and
nothing else:

* **shell** — an interactive login shell with a real PTY, window resizing and
  signals,
* **exec** — run a command remotely with stdin/stdout/stderr passed through
  byte for byte,
* **rsync** — because of the above, `rsync -e qsh` just works.

Everything runs over a single QUIC connection: TLS 1.3 by construction, one
UDP port, no head-of-line blocking between sessions, and connection migration
if your laptop changes network.

```
rsync -e qsh -av ./data/ server:/backup/data/
qsh server                     # interactive shell
qsh server uptime              # remote command
```

## Why QUIC, and why quinn

SSH multiplexes its own channels over one TCP stream, so a stalled channel
stalls everything. QUIC gives us streams, flow control, encryption, and
0-RTT-style fast reconnects for free, and it survives the client's IP address
changing. What is left for qsh to implement is only the part that is actually
about remote execution.

Among the Rust QUIC stacks, [quinn](https://github.com/quinn-rs/quinn) is the
one that fits this program. qsh's entire authentication model is a pair of
custom rustls certificate verifiers, and quinn accepts a `rustls::ClientConfig`
and `rustls::ServerConfig` directly, so they drop straight in. It is
tokio-native, its streams are `AsyncRead`/`AsyncWrite`, and it is pure Rust —
no C toolchain to cross-compile around.

[quiche](https://github.com/cloudflare/quiche) is sans-I/O: you drive the
socket loop, timers and loss recovery yourself, and it builds against
BoringSSL. Its centre of gravity is HTTP/3, which qsh does not want.
[s2n-quic](https://github.com/aws/s2n-quic) would work, and has a good mTLS
story, but custom certificate verification goes through a provider
indirection rather than rustls directly.

## Install

```
cargo install --path .          # installs qsh and qsh-server
```

Requires a Unix-like system (Linux is what it is tested on) and Rust 1.88+,
which is what the pinned dependency graph in `Cargo.lock` needs. CI builds
both that version and current stable with `--locked`.

## Setup

Three commands on each side, once.

### On the server

```
sudo qsh-server keygen
sudo qsh-server serve            # or run it under systemd, see below
```

`keygen` writes `/etc/qsh/server.crt`, `/etc/qsh/server.key` (mode 0600), a
default `/etc/qsh/qsh-server.toml`, and creates `/etc/qsh/authorized/`. It
prints the host key fingerprint.

Without root, everything moves to `~/.config/qsh-server` and the server can
only run sessions as the account it runs under.

### On the client

```
qsh keygen
```

This writes `~/.config/qsh/id.crt` and `~/.config/qsh/id.key` (mode 0600) and
prints your fingerprint.

### Authorize the client

Copy `id.crt` to the server, then:

```
sudo qsh-server authorize alice-laptop.crt --user alice
```

That maps this key to the local account `alice`. It takes effect within a
second — no restart. Useful variations:

```
# rsync-only key: no interactive shell, no other programs
sudo qsh-server authorize backup.crt --user backup --no-shell --command rsync

sudo qsh-server list
sudo qsh-server revoke alice-laptop
```

### First connection

```
qsh server
The authenticity of host 'server:2222' cannot be established.
Key fingerprint is sha256:1f0c….
Are you sure you want to continue connecting (yes/no)? yes
```

The fingerprint is stored in `~/.config/qsh/known_hosts`. To skip the prompt
(and the guesswork), pin it in advance with the value `qsh-server keygen`
printed:

```
qsh known-hosts add server:2222 sha256:1f0c…
```

## rsync

`rsync` needs a transport that starts a program on the far side and connects
its stdin/stdout. That is exactly qsh's exec mode:

```
rsync -e qsh -av ./data/ server:/backup/data/
rsync -e 'qsh -p 4242' -av ./data/ server:/backup/data/
```

rsync invokes `qsh [-l user] host rsync --server …`. qsh forwards those
arguments as a **structured argument list** — the remote side executes the
program directly with `execvp`, never `sh -c` on a re-joined string. There is
no quoting layer to get wrong and nothing for a crafted filename to escape
from. Nothing in the data path translates newlines or touches encodings.

Note that this also means the remote command is *not* shell-expanded. If you
want globbing or redirection, ask for it explicitly:

```
qsh server sh -c 'echo hello > /tmp/out'
```

## Security model

There is no password authentication, no PKI, and no CA. Both sides hold a
long-lived self-signed **Ed25519** certificate.

| Direction | What is checked |
|---|---|
| Client → server | The server's public key must match the pinned fingerprint in `known_hosts`, and the certificate must be inside its validity window. |
| Server → client | The client's public key must be present in `authorized/`, and its certificate must be inside its validity window. |

* Fingerprints are `sha256:` over the certificate's SubjectPublicKeyInfo, so
  renewing a certificate for the same key does not invalidate a pin.
* A certificate outside its validity window is refused in both directions,
  including on a client's very first connection to an unknown host.
* **Certificate expiry is not what bounds an authorization.** Because the
  server pins a public key, anyone holding the matching private key can
  self-issue a fresh certificate with a later `notAfter` and the fingerprint
  still matches. If you want an authorization to lapse, give it a deadline the
  server owns:

  ```
  sudo qsh-server authorize alice-laptop.crt --user alice --expires-in-days 90
  ```

  That deadline is recorded in `authorized/<name>.toml` and enforced
  independently of whatever certificate the client presents. `qsh-server list`
  shows the remaining time.
* Deleting `authorized/<name>.crt` (or `qsh-server revoke <name>`) takes
  effect within a second, without a restart.
* Private keys are written 0600 and refused at load time if they are group- or
  world-readable.
* Client authentication is mandatory; TLS 1.3 only. Unvalidated peer addresses
  are made to complete a QUIC retry before the server does any work for them.
* A key restricted with `--command` is matched against the whole of `argv[0]`,
  never its basename: the authorized account can write files, so permitting
  `/tmp/rsync` because it ends in `rsync` would make an rsync-only key a
  general-purpose one. A bare name is resolved through the server's own fixed
  `PATH`; to allow a program elsewhere, authorize its absolute path.
* A session is torn down with its connection. If the client is killed, the
  server notices when the QUIC idle timeout expires (60s by default, with
  15-second keep-alives) and signals the session's process group `SIGHUP`, then
  `SIGTERM`, then `SIGKILL`. That watch stays up for the whole session,
  including while the last of the output is still draining, so a descendant
  that outlives the command it was started from is cleaned up too.

  What this does **not** reach is a process that has left the session's process
  group — one you backgrounded with `&` in an interactive shell (job control
  gives it a group of its own), or that called `setsid` itself, or that you
  started under `nohup`. Those survive the session, exactly as they do under
  ssh, and deliberately: leaving a long job running after you log out is a
  thing people do on purpose. If you want the stricter behaviour, that is what
  a session cgroup is for — `systemd-logind`'s `KillUserProcesses=yes` — and
  it is off by default there for the same reason it is not qsh's default.
* Work is bounded before anyone has authenticated: peers must complete a QUIC
  retry to prove their address, a handshake has 5 seconds to finish, and a
  session stream has 10 seconds to say what it wants. Handshakes in flight
  (32) are budgeted separately from established connections (256), so
  half-open attempts cannot eat the budget that established sessions run on.
  Within the handshake budget, no single source address may hold more than 4
  slots at once, which is what keeps one address from filling the pool and
  locking out everyone else — separate budgets alone would not do that.
  Over-limit connections are dropped silently rather than answered, and
  failures before authentication are counted and reported in batches rather
  than logged one line per attempt.

  This is a fairness reservation, not a rate limit: nothing is remembered
  after an attempt ends, so there is no per-address table to grow or expire.
  It bounds concurrency, not attempt rate, and it says nothing about a
  distributed flood from many addresses — for that, put the port behind
  whatever the host already uses for the rest of its services.
* A key's policy is re-read for every session, not captured when the
  connection was made, so revoking a key also cuts off the connections it
  already has.
* The client cannot set arbitrary environment variables. Only `TERM`, `LANG`,
  `COLORTERM`, `LC_*` and `QSH_*` survive; `PATH` is fixed by the server. The
  remote process gets a fresh session (`setsid`) and, when root, a full
  privilege drop with `setgroups`/`setgid`/`setuid`, verified before `exec`.
  The supplementary groups are resolved *before* the fork: looking them up
  afterwards would mean calling NSS in a forked child, which is not
  async-signal-safe and deadlocks under LDAP or SSSD.

What 1.0 does **not** have, on purpose: port forwarding, agent forwarding, X11
forwarding, `sftp`, jump hosts, certificate authorities, host key rotation
helpers, or Windows support.

## Configuration

`/etc/qsh/qsh-server.toml`:

```toml
listen = "0.0.0.0:2222"     # QUIC is UDP; this does not collide with sshd
idle_timeout_secs = 60      # also how quickly a killed client is cleaned up
keepalive_secs = 15
```

An absent default configuration file uses the built-in defaults. An explicitly
selected `qsh-server serve --config FILE` must exist and be readable and valid;
otherwise startup fails.

QUIC uses the smaller of the two peers' idle timeouts. The qsh client currently
offers 60 seconds, so increasing the server value above 60 does not extend a
qsh connection's outage tolerance. Lower server values still take effect.
Keep-alives keep a reachable, otherwise quiet session active.

`/etc/qsh/authorized/<name>.toml`, written by `authorize` and editable by hand:

```toml
user = "alice"
allow_shell = true
allow_exec = true
allowed_commands = []       # empty means "any program"; entries match argv[0] exactly
key_fingerprint = "sha256:…" # the key this policy was written for
# expires_at_unix = 1793491200   # optional; set by --expires-in-days
```

An authorization is two files — `<name>.crt` and `<name>.toml` — and each is
written atomically. `key_fingerprint` ties them together: if a crash or a
half-finished edit ever left a certificate paired with a policy written for a
different key, the entry is refused rather than applied.

Environment overrides for both binaries: `QSH_HOME` (client directory) and
`QSH_SERVER_HOME` (server directory); `qsh-server --dir` and `qsh -i` do the
same per invocation.

## Client reference

```
qsh [options] [user@]host [command [args...]]
```

| Option | Meaning |
|---|---|
| `-p, --port PORT` | UDP port, default 2222 |
| `-l USER` | Log in as USER; must match what the server authorized |
| `-i, --identity DIR` | Directory holding `id.crt`/`id.key` |
| `-t` / `-T` | Force / forbid a remote terminal |
| `-E, --setenv K=V` | Send one environment variable |
| `--accept-new` | Pin an unknown host key without asking |
| `--refuse-new` | Never pin automatically |
| `-4` / `-6` | Restrict to IPv4 / IPv6 |
| `--connect-timeout SECS` | Deadline per address, default 10 |
| `-o OPTION` | Ignored, for ssh compatibility; `StrictHostKeyChecking=accept-new\|yes` is honoured |
| `-q`, `-v`, `-C` | Accepted for ssh compatibility |

Subcommands: `qsh keygen`, `qsh fingerprint`, `qsh known-hosts list|add|remove`.

A host name that resolves to several addresses is tried in turn, IPv6 first,
each with its own connect timeout — so a dual-stack name still works when only
one family is reachable.

In an interactive session, `~.` at the start of a line hangs up (the remote
session gets `SIGHUP`, so it exits `129` rather than being orphaned), and `~~`
sends a literal tilde — as in ssh. The escape is disabled whenever there is no
terminal, so binary streams are never interpreted.

`qsh -t host cat < file` works: a terminal has no half to close, so end of
input is delivered as the line discipline's EOF character — twice, because the
first one only flushes a partial last line. A program that puts the terminal
into raw mode sees those as data, exactly as it would under ssh.

Like ssh, a command that leaves a background process holding its stdout keeps
the session open until that process exits — the output still belongs to you.
Detach it explicitly if you do not want to wait:

```
qsh server sh -c 'nohup ./daemon >/dev/null 2>&1 &'
```

An interactive session is different, because a terminal has no equivalent of
"the last writer closed it": a job you background with `&` keeps the terminal
open after the shell exits. There the session waits two seconds for the rest of
the output and then finishes anyway, so `sleep 300 &` followed by `exit` still
returns you to your prompt.

qsh exits with the remote command's exit status, `128+n` if it died from
signal `n`, and `255` for its own failures — the same convention as ssh, which
is what makes it a drop-in for scripts and for rsync.

## Running under systemd

```ini
[Unit]
Description=qsh server
After=network.target

[Service]
ExecStart=/usr/local/bin/qsh-server serve
Restart=on-failure
# The server must start as root to switch to the target user.
User=root

[Install]
WantedBy=multi-user.target
```

Open the port with `ufw allow 2222/udp` (or the nftables equivalent) — UDP,
not TCP. This is the single most common reason a first connection times out.

## Protocol

One QUIC bidirectional stream per session. Frames are
`[kind: u8][length: u32 big-endian][payload]`:

| Kind | Payload |
|---|---|
| `Request` | version, user, argv (or none for a login shell), PTY request, environment |
| `Started` / `Error` | server's verdict on the request |
| `Stdin` / `Stdout` / `Stderr` | raw bytes, never transformed |
| `StdinEof` | close the remote stdin |
| `Resize` | new terminal geometry |
| `Signal` | signal name, delivered to the remote process group |
| `Exit` | exit code and signal |

Structured payloads use [postcard](https://docs.rs/postcard); the three data
kinds carry raw bytes. ALPN is `qsh/1`.

## Development

```
just            # list every recipe
just check      # fmt-check + pedantic clippy + all tests
just demo-setup # a throwaway server and client under target/sandbox
just demo-serve # run it; then `just demo-shell` or `just demo-run uname -a`
```

The end-to-end tests start a real `qsh-server` on a loopback UDP port and
drive the real `qsh` binary against it, including a binary round trip and, if
`rsync` is installed, an actual `rsync -e qsh` transfer.

### Continuous integration

`.github/workflows/ci.yml` runs rustfmt, pedantic clippy as errors, the tests
on both stable and the declared MSRV with `--locked`, an end-to-end run with
rsync installed, a **root** end-to-end run (without it the privilege-drop path
is never executed, since an unprivileged server never switches account), a
check that the declared MSRV still matches the lockfile, and `cargo audit
--deny warnings` so an unmaintained dependency fails the build rather than
waiting to be noticed.

`actionlint` runs over the workflow itself, because a workflow that does not
parse runs nothing and reports no failure — which is exactly how an earlier
version of this file sat there doing nothing.

### Lints

The crate builds clean under `clippy::pedantic` with warnings as errors, and
`unwrap`, `expect`, `panic!`, `todo!`, slice indexing and integer division are
**denied** outside of tests — a remote-shell daemon should not carry panic
paths that a lazy `unwrap` put there. Lock poisoning is handled rather than
unwrapped (the `sync` helpers in `src/lib.rs`), so a panic inside a dependency
cannot lock every future session out.

`unsafe_code` is denied crate-wide. It cannot be avoided altogether — PTY
ioctls, raw-fd reads and writes, `kill(2)`, and the `pre_exec` hook that runs
`setsid` plus `setgroups`/`setgid`/`setuid` between fork and exec have no safe
equivalents — so each of the eleven exceptions carries its own
`#[allow(unsafe_code, reason = ...)]`. They live in exactly two modules, `pty`
and `child`, and `just audit-unsafe` prints every one of them:

```
$ just audit-unsafe
unsafe_code is denied crate-wide; every exception is justified:
  - TIOCSWINSZ is an ioctl with no safe wrapper
  - kill(2) has no safe wrapper; pid comes from our own child
  - pre_exec is inherently unsafe: its closure runs between fork and exec
  ...
unsafe blocks per file:
src/pty.rs:8
src/child.rs:4
```

## License

MIT.
