# qsh end-to-end test plan

This plan says what qsh's multi-host end-to-end suite checks and why. It is
meant to grow with qsh: when a feature, a fix or a documented promise
changes, the scenarios here change with it.

How to run the suite and how the environment works is in
[README.md](README.md). The unit tests and the loopback suite in
`tests/e2e.rs` stay the first line of defence; this suite covers what they
cannot reach:

- **separate machines**: different hosts, accounts, addresses and file
  systems on each side, so nothing passes by accident because client and
  server share a disk, a user or a `/etc/passwd`;
- **the documented deployment**: `qsh-server` as root under the shipped
  systemd unit, with a delegated cgroup v2 subtree;
- **real networks**: loss, delay, jitter, reordering, duplication, outages,
  NAT rebinding and address changes, through a relay that behaves the same
  on every kernel;
- **real tools and data**: rsync, tar, interactive terminals, gigabytes;
- **the threat model's actors** acting from where they would really be: a
  stranger on the network, an impostor at a pinned name, another local user
  on either host.

## Conventions

Each scenario has an ID (`AREA-NN`), never reused once published, and:

- **Status**
  - `automated`: a test tagged `@pytest.mark.plan("ID")` implements it;
  - `planned`: worth automating, not done yet;
  - `manual`: checked by hand, for example because it needs hardware;
  - `blocked`: needs something the reference environment lacks (stated).
- **Priority**: `P0` protects a documented promise or a security boundary;
  `P1` a realistic workflow or failure mode; `P2` an edge case or a
  convenience.
- **Needs**: environment features beyond the defaults (`netsim`, `server2`,
  `cgroup-v2`, `pty`, `two-clients`, `ipv6`).

`e2e/run plan` (CI runs it) fails when a test names an ID this file does not
have, when an `automated` scenario has no test, or when a test implements a
scenario not marked `automated`.

Expected behaviour cites the README, `THREAT_MODEL.md` or the code. When a
scenario found a bug, the [findings log](#findings-log) records it and the
commit that fixed it.

A scenario whose expected behaviour qsh does not meet yet is still
`automated`: its test asserts the expected behaviour and is marked
`@pytest.mark.xfail(strict=True, reason="F<n>: …")`, naming the open
finding. It reports as an expected failure until the fix lands, and then
fails until the mark is removed, so a fix cannot go unnoticed.

## Areas

| Area | What it covers | Scenarios |
|---|---|---|
| [EXEC](#exec--remote-commands) | one remote command: status, streams, argv, environment | 23 |
| [PTY](#pty--interactive-sessions) | login shells and forced terminals | 16 |
| [XFER](#xfer--data-transfer) | rsync, tar and large streams | 14 |
| [NET](#net--network-conditions) | impairment, outages, migration, addressing | 12 + 3 planned, 2 blocked |
| [AUTH](#auth--authorization-and-policy) | who may do what, and how changes take effect | 18 + 2 planned |
| [LIFE](#life--process-lifecycle) | what happens to remote processes when sessions end | 8 + 3 planned |
| [OPS](#ops--running-the-server) | installation, systemd, configuration, keys | 11 + 7 planned |
| [SEC](#sec--threat-model-boundaries) | the boundaries THREAT_MODEL.md promises | 12 + 2 planned |
| [LOAD](#load--concurrency-and-budgets) | many sessions, per-key budgets, leaks | 5 + 2 planned |
| [CLI](#cli--client-conventions) | the client's own subcommands and conventions | 6 + 1 planned |

---

## EXEC — remote commands

### EXEC-01 — The remote exit status reaches the caller
- **Status:** automated · **Priority:** P0 · **Needs:** —
- **Why:** scripts and rsync act on qsh's status (README: "qsh exits with the remote command's exit status").
- **Steps:** run `sh -c 'exit N'` for N in 0, 1, 42, 254.
- **Expected:** qsh exits N.

### EXEC-02 — Death by signal is reported as 128+n
- **Status:** automated · **Priority:** P0 · **Needs:** —
- **Steps:** the remote shell kills itself with TERM, KILL, SEGV.
- **Expected:** 143, 137, 139 (README: "`128+n` if it died from signal `n`").

### EXEC-03 — stdout and stderr stay separate and intact
- **Status:** automated · **Priority:** P0 · **Needs:** —
- **Steps:** interleave writes to both streams, with and without trailing newlines.
- **Expected:** each local stream receives exactly its own bytes.

### EXEC-04 — Arguments arrive verbatim, without a shell
- **Status:** automated · **Priority:** P0 · **Needs:** —
- **Why:** README: the remote side executes argv with `execvp`, "no quoting layer to get wrong".
- **Steps:** pass spaces, quotes, `$HOME`, backticks, `;|&`, `*`, newlines, tabs, an empty string, `-n`, non-ASCII and backslashes to a remote `python3` that prints its argv as JSON.
- **Expected:** the remote argv equals the local one, element for element.

### EXEC-05 — 64 MiB of stdin streams byte for byte
- **Status:** automated · **Priority:** P0 · **Needs:** —
- **Expected:** the remote `sha256sum` of stdin equals the local digest.

### EXEC-06 — 64 MiB of stdout streams byte for byte
- **Status:** automated · **Priority:** P0 · **Needs:** —
- **Expected:** a remote `cat` of a random file arrives with the same digest.

### EXEC-07 — Every byte value survives a round trip
- **Status:** automated · **Priority:** P0 · **Needs:** —
- **Steps:** send all 256 byte values, `~.`, `~~`, CR LF, NUL, ^D and ^C through a remote `cat`.
- **Expected:** identical bytes back; nothing is interpreted without a terminal (README: escapes are "disabled whenever there is no terminal").

### EXEC-08 — End of stdin reaches the remote process
- **Status:** automated · **Priority:** P0 · **Needs:** —
- **Expected:** `printf abc | qsh server wc -c` prints 3.

### EXEC-09 — `-n` never reads local stdin
- **Status:** automated · **Priority:** P1 · **Needs:** —
- **Steps:** call `qsh -n` inside a `while read` loop fed by a pipe.
- **Expected:** every loop iteration runs; qsh consumed none of the loop's input.

### EXEC-10 — The session runs as the mapped account
- **Status:** automated · **Priority:** P0 · **Needs:** —
- **Expected:** user alice, groups alice and project, cwd and `HOME` `/home/alice`, `USER`/`LOGNAME` alice, `SHELL` from passwd, `PATH` the server's fixed one (`src/child.rs` `DEFAULT_PATH`).

### EXEC-11 — The environment is filtered by the server
- **Status:** automated · **Priority:** P0 · **Needs:** —
- **Steps:** `-E` LANG, LC_TIME, QSH_TRACE, FOO, LD_PRELOAD, PATH, HOME.
- **Expected:** only LANG, LC_*, QSH_* arrive; PATH and HOME stay the server's (README: "The client cannot set arbitrary environment variables").

### EXEC-12 — A program that cannot run fails like a shell
- **Status:** automated · **Priority:** P1 · **Needs:** —
- **Expected:** a missing program exits 127 with a "command not found" message naming it; a file that is not executable exits 126 (README: "the same convention as ssh", which runs commands through a shell). Found F11.

### EXEC-13 — Exec has a terminal only when asked
- **Status:** automated · **Priority:** P1 · **Needs:** —
- **Expected:** without `-t`, stdin is not a tty; with `-t`, `tty` prints `/dev/pts/N`.

### EXEC-14 — A remote reader that stops early ends the session
- **Status:** automated · **Priority:** P1 · **Needs:** —
- **Expected:** `yes | qsh server head -n1` prints `y` and qsh exits 0 within seconds.

### EXEC-15 — A local reader that stops early ends qsh quietly
- **Status:** automated · **Priority:** P1 · **Needs:** —
- **Steps:** `qsh server sh -c 'exec yes X' | head -n1`.
- **Expected:** qsh exits 141 like a local writer killed by SIGPIPE, prints nothing, and the remote `yes` is gone. Found F3.

### EXEC-16 — 1,000 arguments and a 16 KiB argument
- **Status:** automated · **Priority:** P1 · **Needs:** —
- **Expected:** both arrive intact (README limits: 1,024 arguments, 16 KiB each).

### EXEC-17 — A request over the limits is refused clearly
- **Status:** automated · **Priority:** P1 · **Needs:** —
- **Steps:** a 16 KiB + 1 argument; five 15,000-byte arguments (over 64 KiB); 1,025 arguments.
- **Expected:** non-zero status (126 from the server or 255 from the client) with a message naming the limit; the next session works. Found F4.

### EXEC-18 — The requested account must match the authorization
- **Status:** automated · **Priority:** P0 · **Needs:** —
- **Expected:** `alice@server` and `-l alice` work; `bob@server` with alice's key is refused with a message naming bob.

### EXEC-19 — Output order is preserved
- **Status:** automated · **Priority:** P1 · **Needs:** —
- **Expected:** `seq 1 200000` arrives complete and in order.

### EXEC-20 — ssh-compatible options are accepted
- **Status:** automated · **Priority:** P1 · **Needs:** —
- **Steps:** `-q -v -C -o BatchMode=yes -o StrictHostKeyChecking=yes -T`.
- **Expected:** the command runs normally (README client reference).

### EXEC-21 — A closed local stderr ends qsh quietly
- **Status:** automated · **Priority:** P1 · **Needs:** —
- **Steps:** `qsh server sh -c 'yes err >&2' 2>&1 | head -n1`.
- **Expected:** status 141, no panic (a panic exits 101). Found F10.

### EXEC-22 — INT and TERM are relayed without a terminal
- **Status:** automated · **Priority:** P1 · **Needs:** —
- **Steps:** send INT or TERM to a local qsh running a remote shell that traps it.
- **Expected:** the remote trap runs and its status (130, 143) becomes qsh's (`src/client.rs` `forward_signals`: without a terminal "local Ctrl-C must be relayed as a signal").

### EXEC-23 — An argument that is not UTF-8 is refused cleanly
- **Status:** automated · **Priority:** P1 · **Needs:** —
- **Why:** qsh/1 carries arguments as text; file names in other encodings exist, and rsync passes them on its command line unless given `-s`.
- **Expected:** status 255 and a message saying the argument is not valid UTF-8 (with the `-s` hint), never a panic. Found F18.

## PTY — interactive sessions

### PTY-01 — A login shell on a real terminal
- **Status:** automated · **Priority:** P0 · **Needs:** pty
- **Expected:** `tty` is `/dev/pts/N`, `$0` is `-bash`, `login_shell` is set, cwd is home, `TERM` is forwarded, `exit` gives 0.

### PTY-02 — The initial window size is the local one
- **Status:** automated · **Priority:** P1 · **Needs:** pty
- **Expected:** `stty size` reports the local 31×101.

### PTY-03 — A local resize reaches the remote program
- **Status:** automated · **Priority:** P1 · **Needs:** pty
- **Steps:** trap WINCH remotely; resize the local terminal.
- **Expected:** the trap fires with the new size; `stty size` agrees.

### PTY-04 — Ctrl-C interrupts the foreground job only
- **Status:** automated · **Priority:** P0 · **Needs:** pty
- **Expected:** `sleep 100` is interrupted (`$?` 130); the shell survives.

### PTY-05 — The shell's exit status becomes qsh's
- **Status:** automated · **Priority:** P1 · **Needs:** pty
- **Expected:** `exit 7` makes qsh exit 7.

### PTY-06 — `~.` disconnects at once and the server cleans up
- **Status:** automated · **Priority:** P0 · **Needs:** pty
- **Expected:** qsh exits 255 within 3 s while a remote job runs; the job is gone on the server within seconds (README: `~.` "does not wait for the remote process").

### PTY-07 — `~~` sends one literal tilde
- **Status:** automated · **Priority:** P1 · **Needs:** pty
- **Expected:** a remote `cat` echoes `~hello` for `~~hello`.

### PTY-08 — Raw-mode programs receive control bytes as data
- **Status:** automated · **Priority:** P1 · **Needs:** pty
- **Expected:** a remote program in raw mode reads ^A ^C ^Z `z` as bytes `01 03 1a 7a`.

### PTY-09 — A forced terminal for a command uses the local size
- **Status:** automated · **Priority:** P2 · **Needs:** pty
- **Expected:** `qsh -t server stty size` prints the local 33×99.

### PTY-10 — `-T` runs the shell without a terminal
- **Status:** automated · **Priority:** P2 · **Needs:** pty
- **Expected:** `tty` says "not a tty"; `exit 3` gives 3.

### PTY-11 — A background job does not hold the session open
- **Status:** automated · **Priority:** P1 · **Needs:** pty
- **Expected:** after `sleep 300 &` and `exit`, qsh exits 0 within 8 s (README: "waits two seconds for the rest of the output and then finishes anyway").

### PTY-12 — A large burst of terminal output arrives complete
- **Status:** automated · **Priority:** P1 · **Needs:** pty
- **Expected:** `seq 1 200000` ends with `200000`; the shell stays responsive.

### PTY-13 — The local terminal is restored after the session
- **Status:** automated · **Priority:** P0 · **Needs:** pty
- **Steps:** from a plain local `sh`, `stty -g` before and after `qsh server`, ending with `exit` and with `~.`. (Not an interactive bash: it restores the modes itself after a job dies of a signal.)
- **Expected:** identical settings both times.

### PTY-14 — A resize during session setup is not lost
- **Status:** automated · **Priority:** P2 · **Needs:** pty, netsim
- **Steps:** connect across 1.5 s each way; resize as soon as the server logs the login, while its answer is still on the way back.
- **Expected:** the remote `stty size` is the new size. Found F12.

### PTY-15 — A signal from outside still restores the terminal
- **Status:** automated · **Priority:** P1 · **Needs:** pty
- **Steps:** `pkill -INT|-USR1|-HUP|-TERM qsh` during an interactive session started from a plain local `sh`.
- **Expected:** the local terminal's settings are as before. Found F14.

### PTY-16 — `~.` returns promptly over a long round trip
- **Status:** automated · **Priority:** P2 · **Needs:** pty, netsim
- **Steps:** a session across 600 ms RTT, then `~.`; then a plain `qsh netsim true`.
- **Expected:** the prompt is back within 2 s of `~.`, and the short command does not linger seconds after finishing (README: `~.` "does not wait for the remote process or server"). Found F19.

## XFER — data transfer

### XFER-01 — rsync push reproduces a tree exactly
- **Status:** automated · **Priority:** P0 · **Needs:** —
- **Steps:** `rsync -e qsh -aHS` a tree with many small files, a 5 MiB file, an empty file, a 64 MiB sparse file, hard and symbolic links, odd modes and times, and names with spaces, quotes, newlines and non-ASCII.
- **Expected:** names, types, modes, sizes, file mtimes, link targets, link counts and contents match (directory times are rsync's business; see the manifest note in the test).

### XFER-02 — rsync pull reproduces a tree exactly
- **Status:** automated · **Priority:** P0 · **Needs:** —
- **Expected:** as XFER-01, server to client. Found F6.

### XFER-03 — rsync resync sends only the changes
- **Status:** automated · **Priority:** P1 · **Needs:** —
- **Steps:** change, add, delete and touch files; resync with `--delete --stats`.
- **Expected:** exactly the three changed regular files transferred; trees match.

### XFER-04 — `rsync -s` handles awkward remote paths
- **Status:** automated · **Priority:** P0 · **Needs:** —
- **Why:** rsync 3.2.4+ escapes remote paths for a remote shell, which qsh does not have; `-s` (`--secluded-args`) sends them through the rsync protocol (README rsync section).
- **Expected:** a remote path with spaces, quotes, `$HOME`, `*?` and non-ASCII is used literally, both directions. Found F5.

### XFER-05 — rsync over an impaired link
- **Status:** automated · **Priority:** P0 · **Needs:** netsim
- **Steps:** push and pull a tree with 1% loss, 15 ms delay, 10 ms jitter, 1% reordering and 1% duplication.
- **Expected:** both directions intact; the relay really dropped packets both ways.

### XFER-06 — An interrupted rsync resumes with `--partial`
- **Status:** automated · **Priority:** P1 · **Needs:** netsim, server2
- **Steps:** black-hole the link part way through a 200 MiB upload; once both ends have given up, restore it and rerun.
- **Expected:** the rerun sends less than the whole file and the result matches.

### XFER-07 — tar pipes in both directions
- **Status:** automated · **Priority:** P1 · **Needs:** —
- **Expected:** `tar c | qsh server tar x` and the reverse reproduce the tree (POSIX format, so sub-second times survive).

### XFER-08 — rsync as another account from another machine
- **Status:** automated · **Priority:** P1 · **Needs:** two-clients
- **Expected:** bob on client2, with `bob@server` and `-e 'qsh -l bob'`, creates files owned by bob.

### XFER-09 — A gigabyte each way with checksums
- **Status:** automated · **Priority:** P1 · **Needs:** — (marked `slow`)
- **Expected:** identical digests on both ends; throughput printed for the record.

### XFER-10 — Six rsyncs at once from two machines
- **Status:** automated · **Priority:** P1 · **Needs:** two-clients
- **Expected:** all exit 0 and every tree matches.

### XFER-11 — A download over a slow link is complete
- **Status:** automated · **Priority:** P0 · **Needs:** netsim
- **Steps:** `qsh netsim cat` a 16 MiB file across 40 ms delay and 1% loss.
- **Expected:** every byte arrives, then status 0. Output still in flight when the remote command exits must be delivered, not abandoned. Found F1.

### XFER-12 — git over qsh through a `sh -c` wrapper
- **Status:** automated · **Priority:** P2 · **Needs:** —
- **Why:** git passes its remote command as one shell string (`git-upload-pack '/path'`), which qsh does not split. The README documents a wrapper that runs that string with `sh -c`.
- **Expected:** with the README's wrapper and `GIT_SSH_VARIANT=ssh`, clone (`server:repo.git`, relative to the remote home), push, clone of an `ssh://server:2222/...` URL and fetch all work. Found F20.

### XFER-13 — rsync under a `--kill-session-processes` key
- **Status:** automated · **Priority:** P2 · **Needs:** cgroup-v2
- **Expected:** push and pull complete; rsync's generator outlives its receiver child, so the cgroup kill at leader exit finds nothing to cut.

### XFER-14 — Revoking a key in the middle of a large rsync
- **Status:** automated · **Priority:** P1 · **Needs:** netsim
- **Expected:** the transfer stops on both sides within 10 s (README: revocation normally takes effect within two seconds); rsync reports an error, not success.

## NET — network conditions

### NET-01 — Latency, loss, reordering and duplicates do not corrupt a session
- **Status:** automated · **Priority:** P0 · **Needs:** netsim
- **Steps:** 150 ms RTT, 20 ms jitter, 3% loss, 3% reordering, 2% duplicates; a ticking command and a 512 KiB upload.
- **Expected:** every line in order, the right digest, status 0.

### NET-02 — A short outage is survived
- **Status:** automated · **Priority:** P0 · **Needs:** netsim, server2
- **Steps:** black-hole the link for half the idle timeout mid-session.
- **Expected:** the session completes with all output and status 0.

### NET-03 — An outage past the idle timeout ends both sides
- **Status:** automated · **Priority:** P0 · **Needs:** netsim, server2
- **Expected:** the client exits 255 within the idle timeout plus a margin; the server kills the remote job (README: cleanup bounded by the idle timeout).

### NET-04 — NAT rebinding mid-session
- **Status:** automated · **Priority:** P0 · **Needs:** netsim
- **Steps:** move the flow to a new source port twice during a 12 s command.
- **Expected:** the session continues; all output, status 0 (README: "connection migration"). Found F1 and F2.

### NET-05 — The client changes address mid-session
- **Status:** automated · **Priority:** P0 · **Needs:** —
- **Steps:** reconnect client1 to the network with a new IP during a 12 s command.
- **Expected:** as NET-04.

### NET-06 — The relay's source address changes mid-session
- **Status:** automated · **Priority:** P1 · **Needs:** netsim
- **Expected:** as NET-04, with a new source IP rather than a new port.

### NET-07 — `--connect-timeout` against a silent peer
- **Status:** automated · **Priority:** P1 · **Needs:** netsim
- **Expected:** status 255 with "timed out" after about 3 s for `--connect-timeout 3`.

### NET-08 — Nothing listening fails within the timeout
- **Status:** automated · **Priority:** P2 · **Needs:** —
- **Expected:** status 255 within 10 s for `--connect-timeout 3`.

### NET-09 — An unknown host name fails fast
- **Status:** automated · **Priority:** P2 · **Needs:** —
- **Expected:** status 255 naming the host, within seconds.

### NET-10 — A server restart ends the session promptly
- **Status:** automated · **Priority:** P0 · **Needs:** —
- **Steps:** `systemctl restart qsh-server` during a session on the default 60 s idle timeout.
- **Expected:** the client exits 255 within 10 s, the job is gone, new sessions work with the same host key. Found F8.

### NET-11 — A dead first address falls back to a live one
- **Status:** automated · **Priority:** P1 · **Needs:** —
- **Steps:** a name with an unreachable and a live address.
- **Expected:** connects in under 5 s (README: 250 ms stagger, per-address timeout).

### NET-12 — IPv6
- **Status:** blocked · **Priority:** P2 · **Needs:** ipv6
- **Why:** the compose network has no IPv6 (it needs `enable_ipv6` and a ULA subnet, and the development host's kernel has no IPv6 at all), and the server listens on `0.0.0.0` by default.
- **Expected:** with an IPv6 network and the server on `[::]:2222`, `-6` connects.

### NET-13 — Handshakes over a very lossy link vs the 5 s handshake deadline
- **Status:** planned · **Priority:** P2 · **Needs:** netsim
- **Expected:** document the loss level up to which a handshake reliably completes and the message when it does not.

### NET-14 — Outage tolerance with the default timeouts
- **Status:** automated · **Priority:** P1 · **Needs:** netsim (marked `slow`)
- **Expected:** a 30 s outage is survived; a 90 s one ends both sides. Detection takes idle timeout plus up to one keep-alive interval (60–75 s).

### NET-16 — One-way outages
- **Status:** planned · **Priority:** P1 · **Needs:** netsim with per-direction black holes
- **Expected:** both sides give up within about twice the idle timeout; the side that still hears its peer does not stay up indefinitely.

### NET-17 — The path MTU drops mid-session
- **Status:** planned · **Priority:** P2 · **Needs:** netsim with a datagram size limit
- **Expected:** bulk output recovers after the drop; a path below QUIC's 1,200-byte minimum fails clearly.

### NET-15 — A dual-stack listen address
- **Status:** blocked · **Priority:** P2 · **Needs:** ipv6
- **Why:** the reference host kernel has no IPv6. Expected: `listen = "[::]:2222"` serves `-4` and `-6`.

## AUTH — authorization and policy

### AUTH-01 — An unauthorized key is refused
- **Status:** automated · **Priority:** P0 · **Needs:** —
- **Expected:** status 255, a handshake or authorization message, no `authenticated as` line on the server.

### AUTH-02 — `authorize` takes effect without a restart
- **Status:** automated · **Priority:** P0 · **Needs:** —
- **Expected:** works within the reload interval; the daemon's PID is unchanged (README: "within a second — no restart").

### AUTH-03 — `revoke` cuts off new and running sessions
- **Status:** automated · **Priority:** P0 · **Needs:** —
- **Expected:** a running session ends with 255 within 6 s, its job is gone, new connections fail (THREAT_MODEL actor 3).

### AUTH-04 — `--no-shell` allows commands only
- **Status:** automated · **Priority:** P0 · **Needs:** pty
- **Expected:** commands run; a login shell is refused with a message.

### AUTH-05 — `--no-exec` allows the shell only
- **Status:** automated · **Priority:** P0 · **Needs:** pty
- **Expected:** commands get 126; a login shell works.

### AUTH-06 — A command filter matches argv[0] exactly
- **Status:** automated · **Priority:** P0 · **Needs:** —
- **Steps:** a key with `--command /usr/bin/uptime`.
- **Expected:** `/usr/bin/uptime -p` runs; `id`, bare `uptime`, a planted look-alike and `sh -c uptime` get 126 naming the program (README: "matched against the whole of `argv[0]`, never its basename").

### AUTH-07 — A server-side deadline expires the authorization
- **Status:** automated · **Priority:** P0 · **Needs:** —
- **Steps:** `--expires-in-days 30` (listed with 29–30 days left), then bring `expires_at_unix` forward by hand.
- **Expected:** the running session ends shortly after the deadline; new attempts fail.

### AUTH-08 — An expired client certificate is refused
- **Status:** automated · **Priority:** P0 · **Needs:** —
- **Expected:** a `--days 0` certificate fails with "Expired" even though authorized.

### AUTH-09 — A revoked key can be authorized again
- **Status:** automated · **Priority:** P1 · **Needs:** —
- **Expected:** works again after a fresh `authorize` (tombstone removed).

### AUTH-10 — One key under two names fails closed
- **Status:** automated · **Priority:** P0 · **Needs:** —
- **Steps:** copy an entry by hand under a second name mapping to bob.
- **Expected:** the key is refused; `list` shows a conflict; `revoke` removes both aliases.

### AUTH-11 — A hand-edited policy applies to the next session
- **Status:** automated · **Priority:** P1 · **Needs:** —
- **Expected:** `allow_exec = false` gives 126 on the next command.

### AUTH-12 — The identity is the key, not the machine
- **Status:** automated · **Priority:** P2 · **Needs:** two-clients
- **Expected:** alice's key directory copied to client2 logs in as alice from there.

### AUTH-13 — Narrowing a policy ends sessions it no longer allows
- **Status:** automated · **Priority:** P0 · **Needs:** pty
- **Expected:** setting `allow_shell = false` ends a running shell within seconds; commands still work.

### AUTH-14 — A bare command name runs from the server's fixed PATH
- **Status:** automated · **Priority:** P1 · **Needs:** —
- **Steps:** `--command uptime`, with a fake `uptime` planted in the account's home.
- **Expected:** `uptime` runs the real `/usr/bin/uptime`; `/usr/bin/uptime` is refused (exact match).

### AUTH-15 — A legacy policy without `key_fingerprint` still works, with a warning
- **Status:** automated · **Priority:** P1 · **Needs:** pty
- **Expected:** accepted, with a journal warning naming the file; re-running `authorize --force` with the same flags binds it to the key and keeps the restrictions. (`authorize` builds the policy from its own flags only, so flags left off that command line are dropped.)

### AUTH-16 — `authorize --force` rotates a client key
- **Status:** automated · **Priority:** P1 · **Needs:** —
- **Expected:** the old key is cut off, including its live sessions; the new one works.

### AUTH-17 — A revocation tombstone blocks hand-restored files
- **Status:** automated · **Priority:** P1 · **Needs:** —
- **Expected:** copying the revoked `.crt` and `.toml` back does not restore access; `authorize` does.

### AUTH-18 — Narrowing a policy tells the user why
- **Status:** planned · **Priority:** P2 · **Needs:** —
- **Why:** today the client only sees `stream reset by peer: error 2` and the server writes no line. Open: decide the message and the audit line, then test them.

### AUTH-19 — Account controls outside qsh do not gate it
- **Status:** automated · **Priority:** P1 · **Needs:** —
- **Why:** admins coming from sshd with PAM expect an expired account or `/etc/nologin` to stop logins; qsh has no PAM (README security model).
- **Expected:** with carol's account expired (`chage -E 0`) and `/etc/nologin` present, carol's key still logs in; revoking the key ends access. Found F21.

### AUTH-20 — Directory-backed accounts and a directory outage
- **Status:** planned · **Priority:** P1 · **Needs:** server2 as an LDAP server
- **Why:** session preparation resolves users and groups through NSS and holds the session budget while it waits.
- **Expected:** groups come from the directory; an outage fails sessions with a clear message and releases their budget; `systemctl stop` is not held up by stuck lookups.

## LIFE — process lifecycle

### LIFE-01 — A killed client does not strand its remote job
- **Status:** automated · **Priority:** P0 · **Needs:** server2
- **Expected:** after `kill -9` of the local qsh, the remote job is gone within the idle timeout plus a margin.

### LIFE-02 — An ordinary key may leave a detached job
- **Status:** automated · **Priority:** P1 · **Needs:** —
- **Expected:** a `setsid` job survives the session (a decided trade-off in THREAT_MODEL.md).

### LIFE-03 — A background writer keeps the session open, like ssh
- **Status:** automated · **Priority:** P1 · **Needs:** —
- **Expected:** `(sleep 3; echo late) & echo early` returns both lines after about 3 s.

### LIFE-04 — A restricted key kills every descendant at session end
- **Status:** automated · **Priority:** P0 · **Needs:** cgroup-v2
- **Expected:** with `--kill-session-processes`, a `setsid`, double-forked `sleep` is gone after a successful session, and no `session-*` cgroup is left behind.

### LIFE-05 — A restricted key kills descendants when the client vanishes
- **Status:** automated · **Priority:** P0 · **Needs:** cgroup-v2, server2
- **Expected:** after `kill -9` of the client, the detached job is gone within the idle timeout plus a margin.

### LIFE-06 — Restricted sessions cannot gain privileges
- **Status:** automated · **Priority:** P0 · **Needs:** cgroup-v2
- **Expected:** `NoNewPrivs: 1` for a restricted key, 0 for an ordinary one.

### LIFE-07 — A restricted session runs in its own cgroup
- **Status:** automated · **Priority:** P0 · **Needs:** cgroup-v2
- **Expected:** `/proc/self/cgroup` shows `…/qsh-restricted/session-…`.

### LIFE-08 — Revoking mid-session kills the process group
- **Status:** automated · **Priority:** P0 · **Needs:** —
- **Expected:** the leader and its same-group background child are gone.

### LIFE-09 — Interactive exit with a chatty background job
- **Status:** planned · **Priority:** P2 · **Needs:** pty
- **Why:** README promises the session "waits two seconds … and then finishes anyway"; with a background job that keeps writing, the lab measured about 10 s and status 255. Open: decide whether the promise or the drain changes.

### LIFE-10 — Client exits that send no close
- **Status:** planned · **Priority:** P2 · **Needs:** pty, server2
- **Why:** a closed terminal window (SIGHUP) or another fatal signal ends qsh without a CONNECTION_CLOSE, so the server keeps the session until its idle timeout.
- **Expected:** document the delay, or send a close before exiting and check the remote job ends at once.

### LIFE-11 — rsync `-P` cut by an outage and re-run at once
- **Status:** planned · **Priority:** P2 · **Needs:** netsim
- **Why:** the old receiver lives on until the idle timeout; on SIGHUP it moves its partial file into place, possibly over the retry's result.
- **Expected:** the retried transfer's result survives the old receiver's cleanup.

## OPS — running the server

### OPS-01 — Root `keygen` lays out `/etc/qsh`
- **Status:** automated · **Priority:** P0 · **Needs:** —
- **Expected:** `server.key` 0600 root, the configuration, `authorized/` not group- or world-writable, `fingerprint` matches, a second `keygen` refuses without `--force`.

### OPS-02 — The shipped unit runs the server
- **Status:** automated · **Priority:** P0 · **Needs:** —
- **Expected:** active, `User=root`, `Delegate=yes`, `KillMode=control-group`, `Restart=on-failure`; journal says `listening on 0.0.0.0:2222`.

### OPS-03 — Logins are logged with peer, key and account
- **Status:** automated · **Priority:** P1 · **Needs:** —
- **Expected:** `<client1 IP>:<port> authenticated as `alice` (key `alice-client1`)`.

### OPS-04 — `systemctl stop` ends sessions and tells clients at once
- **Status:** automated · **Priority:** P0 · **Needs:** —
- **Expected:** the unit stops within 10 s, the job is gone, the client exits 255 within 10 s saying the server is shutting down (not after the 60 s idle timeout). Found F8.

### OPS-05 — A crashed daemon is restarted and its sessions cleaned
- **Status:** automated · **Priority:** P0 · **Needs:** server2
- **Expected:** after `kill -9` of the main process, systemd starts a new one; the old session's job is gone (`KillMode=control-group`); new sessions work.

### OPS-06 — The configured listen address is used
- **Status:** automated · **Priority:** P1 · **Needs:** server2
- **Expected:** `listen = "0.0.0.0:2400"` serves on 2400 after a restart.

### OPS-07 — An invalid configuration stops startup with a reason
- **Status:** automated · **Priority:** P1 · **Needs:** server2
- **Expected:** the unit fails; the journal says "`listen` is not a socket address".

### OPS-08 — An explicit missing configuration fails before startup
- **Status:** automated · **Priority:** P1 · **Needs:** —
- **Expected:** non-zero status naming the file (README: "must exist").

### OPS-09 — A second daemon on a busy port fails clearly
- **Status:** automated · **Priority:** P2 · **Needs:** —
- **Expected:** a message that the address is already in use; the service is unaffected.

### OPS-10 — A non-root server serves only its own account
- **Status:** automated · **Priority:** P1 · **Needs:** —
- **Expected:** alice's own daemon from `~/.config/qsh-server` serves alice; a session as bob fails.

### OPS-11 — Rotating the host key is refused until re-pinned
- **Status:** automated · **Priority:** P0 · **Needs:** server2
- **Expected:** after `keygen --force` and a restart the client refuses with status 255, naming both the pinned and the presented `sha256:` fingerprints and how to remove the old pin; after re-pinning it works. Found F9.

### OPS-12 — SIGHUP is not a reload
- **Status:** automated · **Priority:** P2 · **Needs:** server2
- **Why:** administrators send SIGHUP to daemons out of habit, to reload them. qsh-server re-reads authorizations every second by itself and its configuration only at startup, and the README does not say what SIGHUP does.
- **Steps:** `systemctl reload`; then `kill -HUP` the main process during a session.
- **Expected:** pinned: `systemctl reload` is refused (`CanReload=no`: the unit has no `ExecReload=`) and leaves the daemon alone. SIGHUP ends the daemon, since only INT and TERM are handled (`shutdown_signal` in `src/bin/qsh-server.rs`); systemd counts death by SIGHUP as a clean exit, so the unit ends `inactive (dead)` with `Result=success` and `Restart=on-failure` does not start it again (checked past `RestartSec=2`); the session's job is gone (`KillMode=control-group`). Like a stop (OPS-04), SIGHUP should also close every connection and log `shutting down`. It does neither: the client reported `connection lost: timed out` 7.7 s later, server2's idle timeout (60 s with the defaults), and qsh-server wrote no line at all. Found FXX-OPS-12.

### OPS-13 — A stalled journald does not stop serving or revocation
- **Status:** automated · **Priority:** P1 · **Needs:** server2
- **Why:** THREAT_MODEL: "a blocked or failing stderr/journald must never block serving". README: a bounded queue and a dedicated writer; "a full log pipe cannot block session handling or authorization reload".
- **Steps:** `SIGSTOP` journald on server2. The daemon's stream socket to journald has a 16 MiB send buffer (systemd's 8 MiB, doubled), about 11,000 lines, which logins would take minutes to fill against journald's 3-minute watchdog; the test shrinks that one socket's buffer to 8 KiB through a `pidfd_getfd` copy of the descriptor, then makes 320 logins, half of them with a session the server refuses. Before and after the checks, the `qsh-diagnostics` thread is asleep in a system call on descriptor 2 and the socket's queued memory is at its send buffer. Checks: three new sessions; revoking a key with a running session. Then `SIGCONT`, and the buffer is put back.
- **Expected:** the sessions answer in under 5 s (measured 0.2 s); the revocation ends the running session within 6 s (as AUTH-03; measured 0.8–1.8 s) and the key's next session is refused; after `SIGCONT` the writer catches up and the lines the full queue dropped are counted (`suppressed N diagnostic message(s)`: 186 of the 320 logins were logged, 227 lines counted). A restart during the stall should also complete at once. It hangs until journald recovers (`systemctl restart` still waiting after 15 s): the blocked writer holds Rust's stderr lock, the shutdown path's `eprintln!("qsh-server: shutting down")` on the runtime's main thread waits for it before the endpoint is closed, the accept loop stops, and the unit sits in `deactivating (stop-sigterm)` until journald runs again or systemd's 90 s stop timeout kills the daemon. Found FXX-OPS-13.

### OPS-14 — The upgrade path: replace the binary and restart
- **Status:** planned · **Priority:** P1 · **Needs:** —
- **Expected:** keys, authorizations and pins keep working across a restart with a new binary.

### OPS-15 — A host reboot
- **Status:** planned · **Priority:** P1 · **Needs:** —
- **Expected:** the enabled unit comes back with its state; a listen address that appears late (DHCP, a floating IP) does not leave the unit failed for good under systemd's start limits.

### OPS-16 — Version skew and rollback
- **Status:** planned · **Priority:** P1 · **Needs:** two builds
- **Expected:** a previous build's client and server interoperate with the current one, or refuse clearly; a rolled-back server still fails closed on state the newer build wrote.

### OPS-17 — A large authorization store
- **Status:** automated · **Priority:** P2 · **Needs:** server2 (marked `slow`)
- **Why:** the daemon re-reads the whole store every second on a runtime worker (`spawn_store_refresher` in `src/server.rs`), and `qsh-server authorize` reads it whole too.
- **Steps:** back up server2's `authorized/`; measure 15 logins, the delay from `qsh-server authorize` returning to a newcomer's first session (retrying from before the authorization), and the time from `revoke` to the end of a running session; add 2,000 keys (`qsh keygen` and `qsh-server authorize` loops on server2: 76–82 s); measure again, and the idle daemon's CPU; put the directory back under its lock and restart.
- **Expected:** the median login within 0.25 s of the small store's and every login under 2 s (measured 0.10–0.12 s with either store, at most 0.18 s); an authorization in effect within 2.5 s (README: "within a second"; 0.2–0.6 s, then 0.7–0.9 s); a revocation within 4 s (README: "normally within two seconds"; 0.7–0.8 s with either store); the idle daemon under half a CPU (5%); the store restored byte for byte.

### OPS-18 — A wildcard listen address on a host with a secondary address
- **Status:** automated · **Priority:** P2 · **Needs:** server2
- **Why:** on an unconnected socket bound to `0.0.0.0` the kernel picks a reply's source address by route, which is the primary address; a QUIC client drops datagrams from an address it did not dial.
- **Steps:** add a secondary address from the subnet to server2's `eth0` (the daemon listens on `0.0.0.0:2222`); run a session to the secondary address and one to the primary, while an AF_PACKET socket on client1 records each datagram's addresses.
- **Expected:** both sessions work; every datagram to a client port comes from the address that port dialed (quinn reads each datagram's destination address and answers from it). A wildcard UDP server that does not do this answers from the primary address, which the capture shows and a connected socket never receives.

## SEC — threat-model boundaries

### SEC-01 — An impostor under a pinned name is refused
- **Status:** automated · **Priority:** P0 · **Needs:** server2
- **Actor:** 2, on-path attacker.
- **Steps:** pin `bank` to the real server, then point `bank` at server2.
- **Expected:** status 255 naming both fingerprints; the pin is unchanged. server2 has the victim's key authorized, yet logs no login: the client refused before presenting its identity. Found F9.

### SEC-02 — First contact asks, and "no" pins nothing
- **Status:** automated · **Priority:** P0 · **Needs:** pty
- **Expected:** the prompt shows the fingerprint; "no" exits 255 with nothing pinned; "yes" pins and connects; the next connection does not ask.

### SEC-03 — First-contact policies without a terminal
- **Status:** automated · **Priority:** P0 · **Needs:** —
- **Expected:** `--refuse-new` and `StrictHostKeyChecking=yes` refuse and pin nothing; `--accept-new` and `StrictHostKeyChecking=accept-new` pin and connect.

### SEC-04 — Local users on the server cannot reach its secrets
- **Status:** automated · **Priority:** P0 · **Needs:** —
- **Actor:** 4, local user on the server host.
- **Expected:** bob cannot read `server.key`, cannot write `authorized/`, cannot open the lock file (0600 root).

### SEC-05 — Local users on the client cannot reach alice's identity
- **Status:** automated · **Priority:** P0 · **Needs:** —
- **Actor:** 5, local user on the client host.
- **Expected:** `id.key` is 0600; bob can neither read it nor append to alice's `known_hosts`.

### SEC-06 — A readable private key is refused
- **Status:** automated · **Priority:** P1 · **Needs:** —
- **Expected:** with `id.key` 0640, qsh exits 255 naming the file.

### SEC-07 — A root daemon's session keeps no privilege
- **Status:** automated · **Priority:** P0 · **Needs:** —
- **Actor:** 3, authenticated client.
- **Expected:** real, effective, saved and filesystem UID and GID all alice's; groups alice and project; inheritable, permitted, effective and ambient capabilities empty.

### SEC-08 — A session inherits only its standard streams
- **Status:** automated · **Priority:** P0 · **Needs:** —
- **Expected:** with and without `-t`, the remote process has descriptors 0, 1, 2 only.

### SEC-09 — A session's terminal belongs to its user alone
- **Status:** automated · **Priority:** P1 · **Needs:** pty
- **Expected:** the PTY is alice:tty 0620 as sshd leaves it; alice can open it by name (screen, pinentry, `write`); bob cannot write to it. Found F7.

### SEC-10 — Unauthenticated noise does not disturb service
- **Status:** automated · **Priority:** P0 · **Needs:** two-clients
- **Actor:** 1, unauthenticated network peer.
- **Steps:** 3,000 junk datagrams and 20 concurrent unauthorized handshakes from client2.
- **Expected:** alice is served within seconds meanwhile; every stranger gets 255; failures appear as a few summary lines, not one per attempt.

### SEC-11 — The first-contact answer is not case-sensitive
- **Status:** automated · **Priority:** P2 · **Needs:** pty
- **Expected:** `YES`, `Yes` and `y` accept the key, as ssh accepts any case. Found F17.

### SEC-12 — Capabilities added to the unit never reach sessions
- **Status:** automated · **Priority:** P1 · **Needs:** server2
- **Steps:** a unit drop-in with `AmbientCapabilities=CAP_NET_RAW CAP_SYS_ADMIN`; check that the daemon really has them.
- **Expected:** sessions start and have no inheritable, permitted, effective or ambient capabilities (THREAT_MODEL actor 3).

### SEC-13 — A spoofed-source Initial flood is absorbed by Retry
- **Status:** planned · **Priority:** P0 · **Needs:** a raw-packet sender
- **Actor:** 1, unauthenticated network peer.
- **Expected:** spoofed Initials cost only stateless Retry work: no handshake slots, no amplification, legitimate logins unaffected.

### SEC-14 — The global handshake pool filled from many addresses
- **Status:** planned · **Priority:** P1 · **Needs:** several client addresses
- **Actor:** 1.
- **Expected:** established sessions are unaffected; every slot is released after the 5 s handshake deadline. (Keeping the pool full from many addresses is documented as not promised.)

## LOAD — concurrency and budgets

### LOAD-01 — Concurrent sessions from two machines
- **Status:** automated · **Priority:** P0 · **Needs:** two-clients
- **Expected:** 16 simultaneous 4 MiB round trips all succeed byte for byte.

### LOAD-02 — One key is capped and other keys keep working
- **Status:** automated · **Priority:** P0 · **Needs:** two-clients
- **Steps:** 40 simultaneous connections on one key.
- **Expected:** exactly 32 run; the server closes the other 8 with "key connection limit reached" once they authenticate, and they exit 255; bob is served promptly meanwhile.

### LOAD-03 — Hundreds of short sessions leak nothing
- **Status:** automated · **Priority:** P1 · **Needs:** —
- **Expected:** after 300 sessions the daemon's descriptor count is within 4 of where it started; no zombies.

### LOAD-04 — A long transfer survives alongside churn
- **Status:** automated · **Priority:** P1 · **Needs:** two-clients
- **Expected:** a 256 MiB upload completes while bob opens and closes 50 sessions.

### LOAD-05 — The global session budget (128) across five keys
- **Status:** automated · **Priority:** P1 · **Needs:** —
- **Steps:** 26 sessions on each of five keys, launched slightly staggered so the per-source handshake cap does not interfere.
- **Expected:** exactly 128 sessions run; the other two are refused (status 255).

### LOAD-06 — Many clients behind one address against the per-source handshake cap
- **Status:** planned · **Priority:** P1 · **Needs:** netsim
- **Expected:** document how a burst from one NAT address behaves (4 handshakes at a time).

### LOAD-07 — Throughput on a long fat path
- **Status:** planned · **Priority:** P2 · **Needs:** a faster relay than netsim
- **Expected:** bulk throughput is set by the 8 MiB stream window, as `src/net.rs` intends, not by quinn's default window or the output queue.

## CLI — client conventions

### CLI-01 — Usage, help and version
- **Status:** automated · **Priority:** P2 · **Needs:** —
- **Expected:** bare `qsh` prints usage and exits 255; `--help` exits 0; `--version` prints `qsh …`.

### CLI-02 — `keygen` writes a private key and refuses to overwrite
- **Status:** automated · **Priority:** P1 · **Needs:** —
- **Expected:** `id.key` 0600; a second `keygen` refuses without `--force`; `fingerprint` matches.

### CLI-03 — `known-hosts` add, list, remove, with normalization
- **Status:** automated · **Priority:** P1 · **Needs:** —
- **Expected:** a pin added as `SERVER:2222` serves `server` under `--refuse-new`; after `remove` the connection is refused.

### CLI-04 — Adding a pin replaces the old one and fails closed
- **Status:** automated · **Priority:** P1 · **Needs:** server2
- **Expected:** `known-hosts add` for an equivalent spelling (`SERVER:2222`) replaces the existing pin under the canonical name, as `list` shows; a connection to the real server then refuses its key. (Whether `add` should refuse to replace silently is an open item.)

### CLI-05 — `-q` silences qsh's own messages
- **Status:** automated · **Priority:** P2 · **Needs:** —
- **Expected:** "permanently added" appears without `-q` and nothing with it.

### CLI-06 — `QSH_HOME` selects the identity directory
- **Status:** automated · **Priority:** P2 · **Needs:** —
- **Expected:** the session authenticates with that directory's key.

### CLI-07 — Divergences from OpenSSH that scripts may hit
- **Status:** planned · **Priority:** P2 · **Needs:** —
- **Why:** `-o 'Key Value'`, options after the host, `UserKnownHostsFile`, `ConnectTimeout` and `BatchMode` differ from ssh. Decide which to support or document, then pin them.

---

## Findings log

Bugs this suite found, and what became of them. IDs are stable; the commit
that fixed each one carries its ID.

| ID | Severity | Finding | Scenario | Status |
|---|---|---|---|---|
| F1 | P0 | Output still in flight when the remote command exits was abandoned after 2 s + 2 s: truncated output and status 255 on slow or briefly interrupted paths | XFER-11, NET-04–06 | fixed |
| F2 | P1 | After a NAT rebinding or address change a quiet client sends nothing until its 15 s keep-alive, so the session stalls that long | NET-04–06 | open, see below |
| F3 | P2 | `qsh host cmd \| head` printed "Broken pipe" and exited 255 | EXEC-15 | fixed |
| F4 | P2 | An oversized request failed with the encoder's "serialize buffer is full" | EXEC-17 | fixed |
| F5 | P1 | rsync escapes remote paths for a shell; through qsh they arrived with literal backslashes | XFER-04 | fixed (docs) |
| F6 | P0 | rsync pulls failed: rsync gives the remote shell non-blocking pipes, and qsh treated `EAGAIN` as fatal | XFER-02 | fixed |
| F7 | P1 | A root daemon left the session's terminal owned by root, so the user could not open it by name | SEC-09 | fixed |
| F8 | P1 | Stopping or restarting the server sent no close, so clients hung for the idle timeout | OPS-04, NET-10 | fixed |
| F9 | P1 | A changed host key was reported as Rust debug output with decimal bytes, not fingerprints | OPS-11, SEC-01 | fixed |
| F10 | P1 | A closed stderr made qsh panic (status 101) | EXEC-21 | fixed |
| F11 | P2 | A missing remote program exited 126; shells and ssh say 127 | EXEC-12 | fixed |
| F12 | P2 | A resize during session setup was never sent | PTY-14 | fixed |
| F14 | P1 | An external SIGINT, SIGUSR1, SIGUSR2 or SIGALRM left the local terminal raw | PTY-15 | fixed |
| F17 | P2 | The first-contact prompt rejected `YES` | SEC-11 | fixed |
| F18 | P1 | An argument that is not valid UTF-8 made qsh panic (status 101), also under rsync | EXEC-23 | fixed |
| F19 | P2 | Every exit, `~.` included, waited out QUIC's draining period: seconds on a long round trip | PTY-16 | fixed |
| F20 | P2 | git cannot use qsh directly: it sends one command string for a shell; no documented way around | XFER-12 | fixed (docs) |
| F21 | P2 | Undocumented: account expiry, locking and `/etc/nologin` do not gate qsh (no PAM) | AUTH-19 | fixed (docs) |

### Open items

Observed while building the suite and left for a maintainer decision. They
are not security findings under THREAT_MODEL.md.

- **F2, migration stall.** QUIC migration works, but the server learns a
  quiet client's new address only from the client's next packet, which can be
  up to a keep-alive interval (15 s) away. With F1 fixed the session survives
  the stall. A shorter client keep-alive would shorten it at the cost of more
  idle traffic.
- **Narrowed policies are silent** (AUTH-18): no reason for the client, no
  journal line on the server.
- **A chatty background job at interactive exit** (LIFE-09).
- **Idle detection takes the idle timeout plus up to one keep-alive** (60–75 s
  by default), not exactly the idle timeout the README states.
- **A home directory root cannot enter** (NFS `root_squash`): the server
  changes directory before dropping privileges, so every session for that
  user fails.
- **`known-hosts add` overwrites an existing, different pin silently**, and
  `authorize` accepts certificates outside their validity window.
- **The "QUIC needs UDP" hint is unreachable**: it needs quinn's 60 s
  handshake timeout to fire before `--connect-timeout`.
- **rsync does not expand `~`** in `server:~/path` (neither qsh nor
  `rsync --server` does; ssh's remote shell did). Paths relative to the
  remote home work without it.
- **A restart kills detached jobs.** Sessions live in the service's cgroup,
  so `systemctl restart qsh-server` (a package upgrade, say) ends `nohup`
  work that ordinary keys may otherwise leave running.
- **A crash still leaves clients waiting for the idle timeout**: the new
  process's stateless-reset key is random, so it cannot reset the old
  process's connections. A key derived from the host key would let it.
- **SIGTERM sent to qsh while the network is down** is relayed and waits
  for the remote side, so a supervisor's TERM does not end qsh until the
  idle timeout.
- **`keygen` under umask 000** creates group- and world-writable state
  directories. THREAT_MODEL.md treats that as an administrator mistake;
  refusing such a store would be a cheap fail-closed hardening.
- **`--no-shell` refuses login-shell requests**, not interactive programs:
  `qsh -t server bash` still works. The flag's help says "interactive
  shells".
