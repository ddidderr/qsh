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
  `cgroup-v2`, `pty`, `two-clients`, `ipv6`, `two-builds` for the previous
  release next to the current one, `ldap` for the directory server and NSS
  client in the image).

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
| [NET](#net--network-conditions) | impairment, outages, migration, addressing | 15 + 2 blocked |
| [AUTH](#auth--authorization-and-policy) | who may do what, and how changes take effect | 20 |
| [LIFE](#life--process-lifecycle) | what happens to remote processes when sessions end | 11 |
| [OPS](#ops--running-the-server) | installation, systemd, configuration, keys | 18 |
| [SEC](#sec--threat-model-boundaries) | the boundaries THREAT_MODEL.md promises | 13 + 1 blocked |
| [LOAD](#load--concurrency-and-budgets) | many sessions, per-key budgets, leaks | 7 |
| [CLI](#cli--client-conventions) | the client's own subcommands and conventions | 7 |

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

### EXEC-20 — qsh's own flags combine
- **Status:** automated · **Priority:** P1 · **Needs:** —
- **Steps:** `-q -T`, and the same bundled as `-qT`.
- **Expected:** the command runs normally (README client reference). ssh's flags are not qsh's; CLI-07 checks that they are refused.

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
- **Steps:** `pkill -INT|-USR1|-HUP|-TERM|-VTALRM|-PROF qsh` during an interactive session started from a plain local `sh`.
- **Expected:** the local terminal's settings are as before. Found F14 (fixed). VTALRM and PROF, as strict xfails, still leave it raw: qsh catches only TERM, HUP, QUIT, INT, USR1, USR2 and ALRM (`FatalSignals::install`, `src/client.rs`), and any other terminating signal (XCPU under `ulimit -t`, say) kills it before the terminal is restored. Found F27.

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
- **Why:** git passes its remote command as one shell string (`git-upload-pack '/path'`), which qsh does not split. The README documents a wrapper that runs that string with `sh -c` and drops the `-o SendEnv=GIT_PROTOCOL` git adds for `GIT_SSH_VARIANT=ssh`, since qsh has no `-o`.
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
- **Status:** automated · **Priority:** P2 · **Needs:** netsim
- **Why:** the server gives a handshake 5 s from the first Initial that passed its Retry check (`HANDSHAKE_GRACE` in `src/server.rs`; README: "a handshake has 5 seconds to finish"), the client 10 s from its first datagram (`--connect-timeout`, default 10). A lost flight costs a retransmission timeout that starts near 1 s and doubles. The client finishes its side of the handshake one flight before the server does.
- **Measured:** pinned logins (`qsh netsim echo …`, so handshake, command and exit) over 50 ms each way with independent loss in each direction, a link with its own `--seed` per attempt, default timeouts:

  | Loss each way | Logins | Median, slowest | Failures |
  |---|---|---|---|
  | 10% | 50/50 | 0.8 s, 4.8 s | — |
  | 15% | 40/40 | 1.3 s, 4.0 s | — |
  | 20% | 50/50 | 1.8 s, 12.2 s | — |
  | 30% | 9/10 | 4.1 s, 25.6 s | 1 (c) |
  | 40% | 6/10 | 4.3 s, 7.4 s | 3 (a), 1 (c) |
  | 50% | 5/10 | 6.9 s, 19.5 s | 4 (a), 1 (c) |
  | 60% | 2/10 | 6.7 s, 11.5 s | 6 (a), 1 (b), 1 (d) after 61 s |
  | 70% | 0/10 | — | 7 (a), 1 (d) after 61 s, 2 still running at 90 s |
  | 80% | 0/10 | — | 9 (a), 1 (b) after 6.3 s |
  | 90% | 0/10 | — | 10 (a) |

  (a) `connecting to netsim (ADDR) timed out after 10s`: the client's deadline. (b) `cannot connect to netsim (ADDR): aborted by peer: the application or application protocol caused the connection to be closed during the handshake`: the server's 5 s deadline dropped the handshake (quinn closes a dropped connection with application error 0) and the close got through. (c) the same text after `connection lost:`, when the client had already finished its side and sent its request. (d) `connection lost: timed out` at the client's 60 s idle timeout: as (c), with the close lost too. From 60% on, a login whose handshake did complete can crawl for minutes, because any datagram that gets through restarts the idle timer: a rerun of one 70% attempt that outlived 90 s ended after 225 s, and the server had logged the login. A second sweep at 50 ms each way, other seeds: 10% 30/30 (slowest 3.8 s), 20% 20/20 (slowest 4.1 s), 50% 5/10.
- **Steps:** (1) 10% loss each way and 50 ms each way, seeds 1 to 8; (2) 90% loss, seed 1; (3) two paths on which every handshake outlives the server's deadline, without randomness: "slow", 3 s each way with `--connect-timeout 20` (the client's Finished arrives 6 s after the deadline started), and "big", which drops datagrams over 1,150 bytes towards the client only (the server's padded first flight never arrives, its short close does). One login per path, shared by the pinned test and the xfail test.
- **Expected:** (1) all eight log in (measured 0.7 to 4.6 s each over several runs: a seed fixes netsim's draws, not which datagrams they fall on, so a failure names a seed to retry with, not a pattern that repeats). (2) Status 255 with `timed out after 10s` within 15 s (measured 10.1 s). (3) Status 255, no output at all, no `authenticated as` line on the server, and the server's deadline, not the client's timer, ended it: no `timed out after Ns`, "big" over within 8 s, before the client's own 10 s (measured 5.1 s), "slow" within 25 s (measured 17.3 to 17.5 s). A server built with a 30 s deadline lets the "slow" login in, and fails "big" only at the client's 10 s, so the test catches both. The round trip that still logs in is exact: 2,400 ms each way logs in after 14.8 s, even with the default `--connect-timeout`; 2,600 ms each way fails, at the client's 10 s with the default timeout and with (c) after 15.8 s with `--connect-timeout 30`. The client needs two round trips (the Retry, then the handshake), so its default 10 s excludes a 5 s round trip as well, and a longer `--connect-timeout` cannot help past it, because the server's deadline, one round trip after the Retry, binds. The message should say that the server ended a handshake that took too long; today it is quinn's generic text, (b) or (c). The strict xfail asks that stderr name the deadline ("5 s", "5 seconds", "deadline", "too slow" or "too long") and not say "connection lost": a session that never started was not lost. quinn's text may stay. Found F33.

### NET-14 — Outage tolerance with the default timeouts
- **Status:** automated · **Priority:** P1 · **Needs:** netsim (marked `slow`)
- **Expected:** a 30 s outage is survived; a 90 s one ends both sides. Detection takes idle timeout plus up to one keep-alive interval (60–75 s).

### NET-16 — One-way outages
- **Status:** automated · **Priority:** P1 · **Needs:** netsim, server2
- **Steps:** a session on server2 (8 s idle timeout, 2 s keep-alives) whose client writes a line to stdin every 0.25 s, into `cat` beside `sleep MARKER`; then netsim drops one direction only (`blackhole_up`, client to server, or `blackhole_down`). The relay's counters confirm that the other direction kept carrying traffic.
- **Expected:** the client exits 255 with "timed out" and the remote job is gone, both within twice the idle timeout plus 8 s. The deaf side's idle timer runs from the last packet it received, so it gives up after one idle timeout and falls silent; the side that still hears its peer hears it until then and gives up one idle timeout later. QUIC restarts the idle timer on every packet received but on a send only for the first ack-eliciting packet since the last receipt (RFC 9000, section 10.1), so talking does not keep a side alive. Measured: client to server dropped, remote job gone after 9.8 s and client exit after 17.7 to 18.2 s; server to client dropped, client exit after 8.3 s and remote job gone after 18.0 s (two runs each). Against `server` (60 s idle timeout), neither side gives up within that bound, which is the failure the test catches.
- **Why the stdin lines:** QUIC acknowledges only ack-eliciting packets, so with a quiet `sleep` session a server-to-client cut leaves the client silent too, and the server hears nothing either (measured: both sides about 8 s).

### NET-17 — The path MTU drops mid-session
- **Status:** automated · **Priority:** P2 · **Needs:** netsim, server2
- **Why:** quinn starts at QUIC's 1,200-byte minimum and probes up to its 1,452-byte ceiling right after the handshake (`netsim --trace`: 1,326, 1,389, 1,420 and 1,452-byte probes within 10 ms, then 1,452-byte datagrams). A path whose MTU later shrinks without sending ICMP is a black hole that quinn must infer from losses (quinn-proto `connection/mtud.rs`: more than three suspicious loss bursts send it back to 1,200 bytes). netsim's `max_datagram` settings drop larger datagrams silently; they count UDP payload bytes.
- **Steps:** (1) 30.9 MB (`seq 1 4000000`) from the server and, separately, to it, over 5 ms each way; after 3,000 datagrams at 1,452 bytes, that direction's limit drops to 1,252 bytes (a 1,280-byte IPv4 MTU). (2) A new connection over a link limited to 1,150 bytes, `--connect-timeout 3`. (3) On server2, bulk output (`seq 1 48480250`, 450 MB, so it is still flowing at the cut, which the test checks) whose path drops to 1,150 bytes mid-transfer.
- **Expected:** (1) the digest matches and the status is 0; netsim counted datagrams over the new limit after the drop, so the drop really cut the size in use. Measured: the black hole is detected within about 0.2 s, after which every datagram is 1,200 bytes; the remaining 26 MB took 1.4 to 4.0 s down and up, and 1,298 to 8,483 datagrams were lost to the limit (eight runs). (Before netsim had 16 MiB socket buffers: 2.8 to 3.9 s and 200 to 350 datagrams; the bigger buffers let more of the old size be in flight at the cut.) The whole 30.9 MB takes 2.9 s without a drop. With a qsh built with `min_mtu(1452)`, so that the fallback cannot go below the old size, both directions stall and the test fails. (2) Status 255 with `timed out after 3s` within 8 s, and not one datagram reached the server: a client pads its Initials to 1,200 bytes (RFC 9000, section 14.1). A path too small only towards the client lets the client's Initials through but not the server's padded reply; the server's 5 s deadline then ends the attempt with quinn's generic message (NET-13 "big"). (3) The client exits 255 with `connection lost: timed out` one idle timeout after the drop (measured 8.0 s, the job gone 0.1 s later) and the server removes the job: QUIC cannot tell a path below its minimum from an outage, so the session ends like one. Measured by hand, not pinned: a session whose packets stay small (a line every 0.25 s) carries on across such a path.

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
- **Why:** the connection and each of its sessions check the key once a second, each on its own tick. When a session's check saw the reload first, it ended the session itself and reset its stream ahead of the connection's close: the client printed only `stream reset by peer: error 2` and closed the connection, sometimes before the withdrawal was logged (3 of 96 revocations by hand).
- **Steps:** revoke the key of a running `sleep`. By hand, twice: 12 rounds of revoking 8 running sessions at once, each with a key and a connection of its own.
- **Expected:** the session ends with 255 within 6 s, its job is gone, new connections fail (THREAT_MODEL actor 3). The client prints `closed by peer: authorization withdrawn or expired`, with no stream reset, and the journal has `<peer> is no longer authorized; closing the connection` for its connection exactly once: a session's own check leaves a withdrawn key to the connection's. By hand: 192 of 192 withdrawn, each line once, in 0.43–2.15 s (median 1.3 s); the build before the fix, 3 resets and 2 missing lines in 192, in the same times. `a_revoked_session_always_ends_with_the_withdrawal` in `tests/e2e.rs` spreads its sessions' ticks over the second so that one of them always sees the reload before its connection does; it failed every run before the fix. Found F30.

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
- **Status:** automated · **Priority:** P2 · **Needs:** pty, two-clients
- **Why:** a narrowed key keeps its connection, so unlike a revocation no connection close carries a reason. The client saw only `stream reset by peer: error 2`, and the server wrote no line.
- **Steps:** with a session running a distinctive `sleep` (in a login shell for the shell grant, `qsh server sleep …` otherwise), change the key's policy: `allow_shell = false`, `allow_exec = false`, `allowed_commands = ["/usr/bin/true"]`, `user = "bob"` or `kill_session_processes = true` in its `.toml`, or `authorize --force --no-shell`. Then `allow_exec = false` under three running commands while bob's `--no-exec` key fails sessions from client2 in four loops, about 40 a second against the peer budget of 16 (skipped if no "suppressed" report shows that the budget ran out, before and after the change).
- **Expected:** every session ends with status 255 within 2 s + 2 s of the change, and its job is gone. The client prints `qsh: the server ended this session: this key's permissions changed`, with no "stream reset"; the details are for the administrator (decided 2026-10-17). The journal gets one line per session on the audit lane, `<peer> (key `<name>`): ended a session its authorization no longer allows: <what>`, for example `login shells are no longer allowed` or `` `sleep` is no longer an allowed command``, and all three survive the flood. Found F22.

### AUTH-19 — Account controls outside qsh do not gate it
- **Status:** automated · **Priority:** P1 · **Needs:** —
- **Why:** admins coming from sshd with PAM expect an expired account or `/etc/nologin` to stop logins; qsh has no PAM (README security model).
- **Expected:** with carol's account expired (`chage -E 0`) and `/etc/nologin` present, carol's key still logs in; revoking the key ends access. Found F21.

### AUTH-20 — Directory-backed accounts and a directory outage
- **Status:** automated · **Priority:** P1 · **Needs:** server2, ldap
- **Why:** sites with central accounts get them from LDAP or SSSD, which can be slow or down. qsh resolves the account and its supplementary groups through NSS as it prepares each session, off the async workers (`spawn_blocking` in `handle_session`, src/server.rs; README: groups are resolved before the fork), and a session holds its budget while that blocking work runs (README: 128 sessions in total and 32 per key "can be preparing, running, or cleaning up"). THREAT_MODEL actor 3: one key cannot degrade others beyond the per-key limits or block the async workers.
- **Steps:** slapd on server2, run as a transient unit, serves a directory the scenario creates: erin (uid 3001, not in /etc/passwd) with groups erin (3001) and dir-ops (3100), and dir-dev (3101) with the local alice as a member. On `server`, nslcd points at it with its timeouts set explicitly: `bind_timelimit 10`, `timelimit 10`, `reconnect_sleeptime 1`, `reconnect_retrytime 10`, `threads 5` (nslcd's defaults, except `timelimit`, which by default waits for ever); nsswitch.conf gets `files ldap` for passwd and group. qsh-server is not restarted. The outage is a blackhole route on server2 for server's address: server's packets arrive and nothing comes back. (The route on server itself would make its sends fail at once with EINVAL.) Everything is put back in `finally`: nsswitch.conf, nslcd.conf, nslcd and slapd stopped, the route, erin's home, qsh-server running.
- **Expected:**
  - erin's key logs in: `id` prints `uid=3001(erin) gid=3001(erin) groups=3001(erin),3100(dir-ops)`, and HOME, USER and SHELL come from the directory. alice's session has alice, project and dir-dev. A `memberUid` added with `ldapmodify` shows in erin's next session. The daemon's PID never changes.
  - Outage, 40 sessions at once on erin's key: 8 are refused at once, ending within 10 s of the launch with 255 and "key connection limit reached" (measured 1.2 s). The other 32 wait in preparation, then fail with 126 and ``qsh: looking up user `erin`: ENOENT: No such file or directory`` (glibc's report of an unavailable NSS source, not "no such local user"), all within the NSS module's 60 s read timeout plus 15 s. Measured: 20 to 35 s. The journal says ``session from … ended: looking up user `erin` ``. Meanwhile a key mapped to root logs in within 5 s (measured 0.2 s). Root's preparation makes no lookup that reaches the directory: it is in /etc/passwd, and needing no identity switch it has no group lookup (`prepare_identity`, src/child.rs). So this shows that the stuck lookups leave the async workers free, not that other local accounts are unaffected (they are not; see below). Once the directory answers again (nslcd retries it within about 10 s), 32 sessions on erin's key run at once: the failures gave the whole budget back.
  - `systemctl stop` with 16 sessions waiting on erin's lookup (queued behind nslcd's threads, they would fail about 30 s later): the clients hear "server shutting down" at once (255), and the stop must finish within 10 s, as in OPS-04 (measured with no directory: 0.3 s). Found F31: the process stays until the last lookup has returned, 27 to 30 s. systemd logs "Deactivated successfully" 6 ms after nslcd fails the last lookup, and until then nothing listens on 2222, so a restart during an outage locks out every key, root included.
  - Measured, not asserted (NSS, not qsh): during the outage a session of the local alice waited 36 s behind the queued lookups and started without dir-dev, because glibc's `getgrouplist` skips a source that does not answer. While the directory is silent, `journalctl -u` on server also waits out an LDAP lookup, of the systemd-coredump account.

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

### LIFE-09 — Interactive exit returns at once past background jobs
- **Status:** automated · **Priority:** P2 · **Needs:** pty
- **Why:** a background job holds the terminal open, so the session waited two seconds for it after the shell exited, and with a job that kept writing the lab measured up to 10 s and status 255. Decided 2026-10-17: `exit` and Ctrl-D end the session at once. The server now ends a PTY session once the terminal has been quiet for 100 ms after the shell exits, and at the latest after `DRAIN_GRACE` (2 s, `src/server.rs`).
- **Steps:** leave a quiet job (`sleep`) or a chatty one (a line every 300 ms) in the background, then `echo bye; exit 7`. Then `exit 5` past a job that writes 20 lines a second, read throughout, and past `yes`, with the local terminal reading nothing for 2.5 s after `exit`, as one that cannot keep up would.
- **Expected:** `bye` arrives and qsh exits 7 within 1.5 s; the job is still running, because a normal exit does not end it (README). The 20-lines-a-second job never leaves the terminal quiet, so it ends at the 2 s cap, with status 5 and no error (within 2 s + 3 s). Proposed, as a strict xfail: the flood also exits 5 without an error and without staying more than 1.5 s after its last output. Today it gives 255 after about 6.4 s: the output queue is full at the cap, so the pump holds a chunk it cannot queue (`CutoffPending`), the session counts as incomplete, and the shell's process group gets SIGHUP, 2 s, SIGTERM, 2 s before the status goes out; the explanation, "the remote output could not be delivered in full", is `try_send`'s into that same full queue and is mostly lost. Found F24 (fixed) and F25.

### LIFE-10 — Client exits that send no close
- **Status:** automated · **Priority:** P2 · **Needs:** pty, server2
- **Why:** a closed terminal window (SIGHUP) or another fatal signal can end qsh without a QUIC CONNECTION_CLOSE, and the server then keeps the session until its idle timeout. In a terminal qsh catches TERM, HUP, QUIT, INT, USR1, USR2 and ALRM, restores the terminal and calls `process::exit` without closing (`restore_on_fire`, `src/client.rs`); without one it catches only INT and TERM, to relay them (EXEC-22). Every other terminating signal takes its default action. ssh closes its TCP connection on HUP, INT, QUIT and TERM, and the kernel closes it on any other death, so sshd ends the session at once. The relay has the opposite problem on a dead path: `forward_signals` queues each INT as a frame and never ends qsh, so Ctrl-C does nothing until the idle timeout, where ssh exits on the first INT.
- **Steps:** on server2 (8 s idle timeout), a session whose job is a distinctive `sleep`: a login shell with it in the foreground, or `qsh server2 sleep …`. Send qsh a signal: in a terminal HUP, TERM, INT, QUIT, USR1, USR2, ALRM, and VTALRM for those it does not catch; without one HUP and USR1. Then `qsh server2 sleep …` through a netsim link that goes dark, and INT three times, a second apart, as a user pressing Ctrl-C until something happens.
- **Expected:** after HUP qsh exits 129 within 2 s (measured 0.2 s) and the job is gone within the idle timeout plus a margin, as after `kill -9` (LIFE-01). Proposed: qsh sends a close before it exits, still with 128+n, so that after each of these signals the job is gone within 3 s. Measured 8.8–9.3 s for every one, the idle timeout, with 128+n. Found F26. Proposed for the dead path: an INT or TERM that arrives while an earlier one is unanswered ends qsh locally with 128+n, within 5 s of the first. Measured 8.1 s and status 255 "connection lost: timed out" (60.1 s against `server`'s default idle timeout). A prototype that ends qsh, with a close, on a second relayed signal passed: 2.2 s after the first INT, status 130, EXEC-22 unchanged. Found F34.

### LIFE-11 — rsync `-P` cut by an outage and re-run at once
- **Status:** automated · **Priority:** P2 · **Needs:** netsim, server2
- **Why:** an rsync hazard on every transport whose server side outlives a silently lost client, which qsh bounds. The old receiver cannot tell that its client has gone: under qsh it lives until the server's idle timeout, then gets end of input and SIGHUP (README: "signals the session's process group `SIGHUP`…"), and rsync's `--partial` cleanup renames the temporary file it was writing to the destination name, over whatever is there by then. Under ssh the same receiver lives until sshd's TCP connection gives up, about 15 minutes with data unacknowledged or hours with only TCP keep-alives (OpenSSH and Linux defaults, not measured here), so a retry is exposed far longer; qsh's 60 s by default is the shorter window.
- **Steps:** `rsync -P --bwlimit=2m` a 32 MiB file through a netsim link to server2, throttled so that the outage lands part way whatever the host's speed. Once the receiver's temporary file passes 4 MiB, black-hole the link and press Ctrl-C (SIGINT to rsync's process group, qsh included). At once rerun `rsync` with the same options at full speed, straight to server2, while the old receiver still runs (skipped otherwise). Wait until the old receiver and the old qsh are gone. With `-P`, and with `-P --partial-dir=.rsync-partial`.
- **Expected:** pinned, as the README is to describe it (F39): the interrupted rsync fails (measured status 20); the retry exits 0 with the source's digest; the old receiver is gone within the idle timeout plus 10 s of the outage (measured 8.6–10.8 s). With `-P` alone the destination is then the old receiver's partial, smaller than 32 MiB with another digest (measured 5.0–5.3 MiB): rsync says nothing about it. With `--partial-dir` the destination keeps the retry's digest and the partial is left in `.rsync-partial/large.bin`.

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
- **Expected:** the unit does not come up, and the journal says "`listen` is not a socket address". It does not end `failed` either: qsh-server exits 1 at every start, and the shipped unit tries again every 2 s for as long as the configuration stays invalid, because five gaps of more than 2 s never fit systemd's default start limit of 5 starts in 10 s (see OPS-15).

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
- **Expected:** pinned: `systemctl reload` is refused (`CanReload=no`: the unit has no `ExecReload=`) and leaves the daemon alone. SIGHUP ends the daemon, since only INT and TERM are handled (`shutdown_signal` in `src/bin/qsh-server.rs`). systemd counts death by SIGHUP as a clean exit: it logs the unit's success once ("Deactivated successfully", matched by its catalogue message ID) and no failure, and `Restart=on-failure` does not start it again (checked past `RestartSec=2`). The unit, disabled and referenced by nothing, is then unloaded, so it reads `inactive (dead)` rather than `failed`. The session's job is gone (`KillMode=control-group`). Nothing documents what SIGHUP should do, so the rest is a proposed decision: SIGHUP shuts down like SIGTERM, which since F8 (OPS-04) closes every connection and logs `shutting down`. Today it does neither: the client reported `connection lost: timed out` 7.7 s later, server2's idle timeout (60 s with the defaults), and qsh-server wrote no line at all. Found F35.

### OPS-13 — A stalled journald does not stop serving or revocation
- **Status:** automated · **Priority:** P1 · **Needs:** server2
- **Why:** THREAT_MODEL: "a blocked or failing stderr/journald must never block serving". README: a bounded queue and a dedicated writer; "a full log pipe cannot block session handling or authorization reload".
- **Steps:** `SIGSTOP` journald on server2. The daemon's stream socket to journald has a 16 MiB send buffer (systemd's 8 MiB, doubled), about 11,000 lines, which logins would take minutes to fill against journald's 3-minute watchdog; the test shrinks that one socket's buffer to 8 KiB through a `pidfd_getfd` copy of the descriptor, then makes 320 logins, half of them with a session the server refuses. Before and after the checks, the `qsh-diagnostics` thread is asleep in a system call on descriptor 2 and the socket's queued memory is at its send buffer. Checks: three new sessions; revoking a key with a running session. Then `SIGCONT`, and the buffer is put back.
- **Expected:** the sessions answer in under 5 s (measured 0.2–0.3 s); the revocation ends the running session within 6 s (as AUTH-03; measured 0.8–1.8 s) and the key's next session is refused. The client says the authorization was withdrawn (AUTH-03). After `SIGCONT` the writer catches up, and every line dropped during the stall is counted (`suppressed N diagnostic message(s)`; `src/server/diagnostics.rs`: "lines that do not fit are counted"): the login lines, the refused sessions' lines, the other sessions' login lines and the revoked connection's one withdrawal line missing from the journal add up to at most the count, and the count exceeds them by at most 3 lines not tallied one by one: the admission summary for the revoked key's refused connection, and room for two more (measured: 180–190 of 320 logins and 68–78 of 160 refusals logged; 227 lines missing, 228 counted). Against a build that leaves every other dropped audit line uncounted, this check failed (227 lines missing, 158 counted), where counting against the lost logins alone passed it. A restart during the stall should also complete at once. It hangs until journald recovers (`systemctl restart` still waiting after 15 s): the blocked writer holds Rust's stderr lock, and the shutdown path's `eprintln!("qsh-server: shutting down")` on the runtime's main thread waits for it before the endpoint is closed. New connections are no longer accepted, none is closed, and the process does not exit; the unit sits in `deactivating (stop-sigterm)` until journald runs again or systemd's 90 s stop timeout kills the daemon. Running sessions are ended by systemd's SIGTERM to the control group, and their exit status still reaches the client. Checked by hand outside systemd: with stderr on a pipe nobody reads, the same SIGTERM hung for 43 s until the pipe was drained, and a session already running was served to the end meanwhile. Found F28.

### OPS-14 — The upgrade path: replace the binary and restart
- **Status:** automated · **Priority:** P1 · **Needs:** server2, two-builds
- **Why:** an upgrade replaces the binary under the unit and restarts it. Neither 1.0's README nor the current one has upgrade notes; the current one says only that policies written "before `key_fingerprint` existed remain accepted with a warning for upgrade compatibility" (THREAT_MODEL lists the same trade-off). 1.0 shipped contrib/qsh-server.service with `ProtectSystem=full`; the unit 1.0's README printed never set it, and the current contrib unit dropped it on purpose ("ProtectSystem=full would make /usr and /etc read-only *inside user sessions*"). An upgrade that replaces only the binary keeps whichever unit the host had.
- **Steps:** server2 set up from scratch by qsh-server 1.0 (`keygen`, `authorize`) with three keys: one made by the current client; one made and pinned by qsh 1.0 itself, held to `--no-shell --command id`; one that 1.0's `authorize --force` left under two names. Replace `/usr/local/bin/qsh-server` as a package manager does (a new file renamed over the old one), check that the running 1.0 daemon still serves, `systemctl restart`. Rebind a 1.0 policy with `authorize`. Then the same upgrade on a host that kept 1.0's contrib unit file.
- **Expected:** the host fingerprint is unchanged and no client re-pins: the current client, qsh 1.0, and the current client on the identity 1.0 wrote (`id.crt`, `id.key`, `known_hosts`) all log in. The 1.0 policy still refuses `sh`, and now also `/usr/bin/id`, because `argv[0]` is matched whole (1.0 matched the basename; THREAT_MODEL: "exact match, never basename"). The key under two names gets neither policy: refused, both names listed as `CONFLICT`, the journal names both. Each 1.0 policy is accepted with the warning "does not record which key it is for; re-run `qsh-server authorize`", at startup and from `list`. A plain re-run of `authorize` is refused ("pass --force"); with `--force` and the same options it writes `key_fingerprint`, the warning stops and the policy still restricts. Measured: about 9 s.
- **Expected, 1.0's contrib unit:** proposed: the upgraded server starts and serves the same keys although `ProtectSystem=full` makes /etc read-only for it (1.0 never writes there while serving). It never starts: "opening /etc/qsh/authorized.lock: Read-only file system", four restarts, then "Start request repeated too quickly"; the same with a lock file that already exists. Found F36, a decision: either the server serves from a state directory it cannot write (the strict xfail tests that), or upgrade notes require replacing the unit, and that test goes.

### OPS-15 — A host reboot
- **Status:** automated · **Priority:** P1 · **Needs:** server2
- **Why:** after a reboot nobody is at the console: the server must come back by itself and as it was, or the machine is out of reach. The shipped unit is `WantedBy=multi-user.target`, and everything the daemon needs lives under `/etc/qsh`. A listen address the host does not have yet (a DHCP lease, a floating IP) makes the bind fail with `EADDRNOTAVAIL` and qsh-server exit 1; `Restart=on-failure` then retries under systemd's start limit, by default 5 starts within 10 s before the unit fails for good.
- **Steps:** enable the unit on server2, run a session, and reboot server2 with `docker restart` (systemd shuts down and boots again; `/etc` and `/var` survive, `/run` and `/tmp` do not). Then set `listen` to a spare address server2 lacks, restart the unit with its start counter reset as on a fresh boot, and add the address 25 s later. This runs three times: under the shipped unit; under the shipped unit with two `systemctl restart`s, each right after a failed try; and under the unit the README shows, installed beside it. The journal's monotonic timestamps of the bind errors give each try's time.
- **Expected:** pinned: the session ends at once with `shutting down` (F8). Reboot and boot take about 2 s, and the unit comes up with the boot at the first attempt (`NRestarts=0`) without anyone starting it. `/etc/qsh` is byte for byte the same, `qsh-server fingerprint` and alice's pin still match, and her authorization still lets her in. `/sys/fs/cgroup` is cgroup v2 again, and a `--kill-session-processes` session still gets its own cgroup and takes a setsid'd job with it. On a cgroup v2 host node-entrypoint.sh has nothing to remount, so this checks that systemd and the delegated subtree came back. Under the shipped unit: 11 restarts in 25 s (12 tries), and the unit never fails: each of the five gaps between starts is `RestartSec=2` plus the try and timer slack (measured 2.05–2.26 s), so the sixth start always falls past the 10 s window (10.2–11.3 s after the first) and the window starts over; serving 1.8–2.5 s after the address appeared (bound 10 s). Every start counts towards the limit, an administrator's too, and the unit should also come up after one restarts it while it waits, and under the README's unit. It does not. A restart m seconds after a try puts the sixth start four gaps plus m after the first, inside the window when m is under 1.0–1.8 s. The test restarts twice, right after failed tries (tries at 0, 0.04, 0.09, 2.21 and 4.44 s), so the sixth start comes at about 6.7 s whatever the host's pace; systemd logs "Start request repeated too quickly", and the unit is still failed after the address appears. Found F29. The README's unit has no `RestartSec=`, so systemd retries after its default 100 ms; the five tries took about a second (0 to 0.97 s), and the unit stays failed. Found F29. With `StartLimitIntervalSec=0` added to both units, and `RestartSec=2` and network-online ordering added to the README's, all four tests pass.

### OPS-16 — Version skew and rollback
- **Status:** automated · **Priority:** P1 · **Needs:** server2, two-builds
- **Why:** clients and servers are upgraded separately, and a bad upgrade is rolled back. Both builds speak qsh/1, protocol version 1 (README "Protocol"), so a mixed pair must behave as a matched one. A rollback must not undo what the newer build refused (THREAT_MODEL actor 3: revocation and expiry hold for every session).
- **Steps:** servers run by hand on server2, each with its own state directory and port. (1) qsh 1.0's client against the current server, and the current client against qsh-server 1.0: 1 MiB of every byte value through a remote `cat` on stdin without a terminal, with a line on stderr and `exit 7`; a shell killing itself with TERM; argv and `-E` passed verbatim; a forced terminal (`-t`) opened at 33x91, resized to 40x100, whose shell exits 3 from its WINCH trap; a local TERM to a client without a terminal, which the remote shell traps and answers with `exit 44`; a request as `bob`; a key the server does not know; the current server stopped under a 1.0 client. A key held to 200 programs (`--command` 200 times) asks for `sh`: from the current server to a 1.0 client in the same test, from a 1.0 server to the current client in its own. (2) A store 1.0 set up, then changed by the current build (a new key, the revocation of a 1.0 key, a passed `--expires-in-days 0` deadline, a 1.0 policy narrowed to `--no-exec`), served by the current build, by 1.0, and by the current build again after 1.0 authorized the revoked key anew. (3) The current build's `revoke` of a 1.0 key killed as it deletes the certificate (strace fault injection), then served by the current build and by 1.0.
- **Expected:** (1) the same results as a matched pair: the stream byte for byte, status 7, stderr apart, 143, `[a b][*][$HOME][][v 16]`; `tty-33 91`, then `WINCH-40 100` and status 3 (the request carries the size, a Resize frame the change); the trap's `got-TERM`, status 44 and the remote job gone (a Signal frame); 126 with "not `bob`"; 255 with a message for the unknown key; 255 with "server shutting down" within 10 s. The key held to 200 programs gets 126 and "may not execute `sh`" both ways. From the current server it does (refusals are bounded to 512 characters). From a 1.0 server, whose refusal lists every permitted program (5,041 bytes here; 1.0's own client shows it and exits 126), the current client exits 255 with "frame payload of 5041 exceeds limit 4096": it caps Error frames at 4096 bytes, where 1.0 allowed 1 MiB for every frame. A program name of 5,000 bytes does the same (by hand: 1.0 refuses it in 5,051 bytes; the current server says "program name is too long"). Found F32. Not checked: 1.0's server sends no close when it stops (F8), so a current client waits out its idle timeout there. Measured: about 9 s and 3 s.
- **Expected, rollback:** (2) Under 1.0 only the untouched 1.0 policy works: the revoked key's files are gone, and every policy the current build wrote is refused whole, 1.0 saying "unknown field `key_fingerprint`", so the narrowed key does not fall back to its broad 1.0 policy. Forward again the key 1.0 re-authorized stays refused and listed as `DENIED`: 1.0's `authorize` leaves the current build's tombstone. `authorized.lock` is 0600 root after the current build's management commands and again after its server and `list` reopened it at the end (1.0 never opens it). (3) The current build refuses the key, `list` says "DENIED: interrupted mutation", and `revoke` again finishes the job (README: "a denial marker keeps that key inactive"). Rolled back to 1.0 the key must stay refused; it logs in, because 1.0 knows no denial markers and the key's 1.0 files are intact. Found F37, a decision on whether a rollback to 1.0 is supported at all: 1.0 reads no tombstones, so legacy files restored from a backup after a complete `revoke` are refused by the current build (AUTH-17) and granted by 1.0 (by hand, not asserted: nothing in the current build can change that). Documentation is the complete fix (rollback unsupported, or only after every `DENIED` entry is finished, and tombstones do not survive it); the strict xfail tests the optional partial mitigation, a `revoke` that makes a legacy policy unreadable to 1.0 before it deletes anything. Measured: about 10, 2 and 2 s.

### OPS-17 — A large authorization store
- **Status:** automated · **Priority:** P2 · **Needs:** server2 (marked `slow`)
- **Why:** the daemon re-reads the whole store every second on a runtime worker (`spawn_store_refresher` in `src/server.rs`), and `qsh-server authorize` reads it whole too.
- **Steps:** back up server2's `authorized/`; measure 15 logins, the delay from `qsh-server authorize` returning to the start of a newcomer's first session that works (retrying from before the authorization, so at most one refused try, about 0.1 s, late), and the time from `revoke` to the end of a running session; add 2,000 keys (`qsh keygen` and `qsh-server authorize` loops on server2: 69–89 s, bounded at 400 s); measure again, and the idle daemon's CPU; stop any fill loop left over, put the directory back under its lock and restart.
- **Expected:** the median login within 0.25 s of the small store's and every login under 2 s (measured 0.10–0.12 s with either store, at most 0.25 s); an authorization in effect within 1.5 s (README: "within a second": one reload interval, the reload itself, about 50 ms at 2,000 keys, and one refused try, plus room for a busy host; measured 0.2–0.9 s with either store, depending on the phase of the once-a-second reload); a revocation within 3 s (README: "normally within two seconds": the reload, then the connection's own once-a-second check; 0.7–0.8 s with either store, ending with the withdrawal); the idle daemon under a quarter of a CPU (5%; a reload of 250 ms would reach it); the store restored byte for byte. Against a build whose reload took 0.7 ms per key (1.4 s at 2,000 keys), the test failed on the authorization (2.1 s), which the earlier bounds of 2.5 s and 4 s let through (2.1–2.4 s, revocation 2.8 s).

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
- **Expected:** `--refuse-new` refuses and pins nothing; `--accept-new` pins and connects.

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
- **Status:** blocked · **Priority:** P0 · **Needs:** a raw-packet sender
- **Actor:** 1, unauthenticated network peer.
- **Blocked:** the suite has no spoofed-source packet sender, and this round did not build one. SEC-14 covers the handshake pool from many real addresses.
- **Expected:** spoofed Initials cost only stateless Retry work: no handshake slots, no amplification, legitimate logins unaffected.

### SEC-14 — The global handshake pool filled from many addresses
- **Status:** automated · **Priority:** P1 · **Needs:** netsim (several source addresses)
- **Actor:** 1, unauthenticated network peer.
- **Why:** the server takes at most 32 handshakes at once (`MAX_HANDSHAKES`), 4 from one address (`MAX_HANDSHAKES_PER_SOURCE`), for at most 5 s each (`HANDSHAKE_GRACE`, all in `src/server.rs`), in a pool separate from established connections. THREAT_MODEL.md: actor 1 "cannot hold server resources beyond the pre-authentication budgets"; "Not promised: surviving a distributed flood from many addresses".
- **Steps:** netsim takes 8 extra addresses and runs 8 links, each with its own source address and a 1,150-byte limit towards the client, so the server's padded first flight never arrives while its Retry and its close do. An identity authorized nowhere, on client2, starts 4 handshakes per link within milliseconds (32); 1 s later the links drop everything towards the server too, so the strangers fall silent and not even their clients' closes can free a slot. alice's session (a line every 0.25 s for 15 s, direct to the server) runs throughout. At that same second alice tries a new login with `--connect-timeout 2`; once the strangers have ended, another.
- **Expected:** the precondition, that the pool is full: the probe exits 255 with `timed out after 2s` (measured: it ended 3.1 to 3.5 s into the flood, before the deadline), the documented non-promise, and the server counts exactly 32 `failed to authenticate`. Then: each stranger exits 255, ended by the server's deadline, not its own 10 s timer (measured 5.0 to 5.1 s after the flood started); a login right after them takes under 2 s (measured 0.2 to 0.3 s); the established session prints all 60 lines with no gap over 1.5 s; the journal has summary lines only, fewer than the 32 attempts, none naming a stranger's address; the server stays active. A server built with a 30 s deadline keeps every slot taken: the strangers run into their own 10 s timeout, and a login after them fails after 10 s, which the test catches. With a per-source limit of 32 the test still passes, as it should: 4 per address is all it uses.

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
- **Status:** automated · **Priority:** P1 · **Needs:** netsim
- **Why:** one address may hold 4 of the 32 handshake slots at once (`MAX_HANDSHAKES_PER_SOURCE` in `src/server.rs`; README: "no single source address may hold more than 4 slots at once"). The server ignores an Initial over the limit without answering ("Refusing would send a packet per attempt", `incoming.ignore()` in `src/server.rs`), and the client sends it again when quinn's retransmission timer fires: about 1 s after the first (quinn's initial RTT estimate is 333 ms), then 2, 4 and 8 s later. quinn's Retry tokens last 15 s (quinn-proto `ServerConfig::retry_token_lifetime`), and an Initial with an expired token is refused with `INVALID_TOKEN`.
- **Steps:** one key starts 32 `qsh netsim echo CROWD-n` within milliseconds, through one link with 100 ms each way, so the server sees them all from netsim's address; the client's Finished takes 200 ms to free a slot, much longer than the crowd takes to start. 0.3 s in, alice logs in directly from client1, another address. Once with the default `--connect-timeout 10`, once with 20.
- **Expected:** alice is served at once (under 2 s; measured 0.21 to 0.27 s): the cap is what keeps one address from taking the whole pool. The crowd gets in at most 4 at a time, once per attempt (the first and three resends), and exactly 16 of the 32 log in (measured: waves at 0.9, 1.9, 3.9 and 7.9 s, five runs). The other 16 exit 255: with the default timeout with `timed out after 10s` (measured 10.0 to 10.1 s); with 20 s before their own timer, at 15.4 s, with `aborted by peer: received an invalid Retry Token in a client Initial`, because the next resend, the fifth attempt, comes after the token expired. So no `--connect-timeout` lets more than 16 of a simultaneous crowd in. The server logs one `authenticated as` line per login and the refusals as at most one line a second. Measured by hand: the same 16 of 32 at 25, 50, 100 and 150 ms each way, while a crowd of 16 all got in; on the LAN without delay handshakes finish fast enough that slots come free during the burst, and 32 of 32 got in within 7.3 s. A server built with a per-source limit of 32 lets all 32 in at once (and alice then waited 1.2 s for a slot), which the test catches. The README does not say any of this. Found F38.

### LOAD-07 — Throughput on a long fat path
- **Status:** automated · **Priority:** P2 · **Needs:** netsim
- **Why:** `src/net.rs` raises the stream window to 8 MiB and the connection windows to 32 MiB so that "a single rsync stream can saturate a fast link". quinn-proto 0.11's default stream window is 1.25 MB (12,500 kB/s at an expected 100 ms round trip), and a sender never has more than a window of a stream in flight, so on a 400 ms round trip the default caps a stream at 3.1 MB/s.
- **Steps:** 124 MB (`seq 1 15000000`) from the server and, separately, to it, through a link with 200 ms each way. The receiving end hashes the stream and notes when each quarter arrived; netsim counts the most bytes its delay held at once (`max_delayed`), all of them in flight.
- **Expected:** the digest matches and the status is 0; the delay held more than 2.5 MB at once, twice what a default window allows; the last three quarters ran faster than the default window's 3.1 MB/s ceiling, which a default window can never beat. Measured over the last three quarters, in fresh environments on a shared host: down 10.4 to 13.9 MB/s with 4.9 to 6.4 MB in the delay at most, up 7.5 to 14.8 MB/s with 4.6 to 7.2 MB; with the host at a load average of 10, down 4.9 and up 3.7 MB/s, with 4.0 and 4.3 MB in the delay. The rate depends on the host, the bytes in the delay do not. With quinn's default windows (a qsh built without the three window lines): 2.7 to 2.8 MB/s and at most 1.25 to 1.28 MB in the delay, so the test fails; the download goes through the server's output queue, and it is no slower than the upload. The relay sets the top speed here, not the window: 8 MiB per 400 ms would allow 21 MB/s, so the test shows that the window is not quinn's default, not that it is the bottleneck. It needs netsim's 16 MiB socket buffers: with the kernel's default 208 KiB the relay itself dropped thousands of datagrams in bursts and capped the same transfer at 4.6 to 6.8 MB/s.

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
- **Status:** automated · **Priority:** P2 · **Needs:** —
- **Why:** qsh is not an ssh clone and takes no ssh options for compatibility (decided 2026-10-17; README). It used to accept every `-o` and honour only `StrictHostKeyChecking=…` in the `=` spelling, so `UserKnownHostsFile=/dev/null`, `ConnectTimeout`, `BatchMode`, `User`, `Port` and `-o 'Key Value'` were silently ignored, as were `-v`, `-C`, `-a` and `-x`. Found F23.
- **Expected:** any `-o`, attached or separate, and `-v`, `-C`, `-a`, `-x` fail with status 255 and `unknown option: …` before contacting the host, pinning nothing; `--accept-new`/`--refuse-new` are the host-key policy. Everything after the host is the remote command: `qsh server echo -p 2222 -o x` prints `-p 2222 -o x`, and `-p 2222`, `-l alice`, `-t`, `-n`, `-o BatchMode=yes` or `--` before `true` after the host give 127 naming the word, before anything runs, unlike ssh (README client reference). Tools that hand ssh its options (`scp -O -S`, Ansible's ssh connection, git with `GIT_SSH_VARIANT=ssh`) need a wrapper, as the README's git section shows.

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
| F22 | P2 | A narrowed policy ended sessions with `stream reset by peer: error 2` and no journal line | AUTH-18 | fixed |
| F23 | P2 | `-o` accepted any ssh option and silently ignored all but `StrictHostKeyChecking=…`, including `UserKnownHostsFile`; `-v`, `-C`, `-a`, `-x` were no-ops | CLI-07 | fixed (all removed) |
| F24 | P2 | An interactive `exit` waited two seconds for any background job on the terminal, and a chatty one could make it end with 255 | LIFE-09 | fixed |
| F25 | P2 | A job that writes faster than the client reads still turns an interactive `exit` into status 255 after about 6 s | LIFE-09 | open |
| F26 | P2 | A signal that ends qsh (a closed terminal window, `kill`) sends no close, so the remote job runs on until the idle timeout | LIFE-10 | open |
| F27 | P2 | Terminating signals qsh does not catch (VTALRM, PROF, XCPU, …) still leave the local terminal raw | PTY-15 | open |
| F28 | P2 | A stop or restart while the log sink is blocked hangs: the shutdown line waits on the blocked log writer before the endpoint is closed | OPS-13 | open |
| F29 | P2 | Restarting the shipped unit while it waits for a late listen address trips systemd's start limit for good; the README's unit gives up within a second | OPS-15 | open |
| F30 | P2 | A revoked session sometimes ends with only `stream reset by peer: error 2`, and its withdrawal line can be missing | AUTH-03, OPS-13 | open |
| F31 | P2 | Stopping or restarting the server during a directory outage waits for every stuck account lookup; the README does not say what a slow directory does | AUTH-20 | open |
| F32 | P2 | The client rejects a 1.0 server's refusal over 4096 bytes (`frame payload of N exceeds limit 4096`, 255) instead of showing it (126) | OPS-16 | open |
| F33 | P2 | A login ended by the server's 5 s handshake deadline is reported with quinn's generic text, sometimes as "connection lost"; the README does not say which paths the deadline excludes | NET-13 | open (decision) |
| F34 | P2 | On a dead path, Ctrl-C without a terminal, or a supervisor's TERM, does nothing until the idle timeout | LIFE-10 | open (decision) |
| F35 | P2 | SIGHUP kills qsh-server without a word and the service stays down; the README does not say there is no reload | OPS-12 | open (decision) |
| F36 | P2 | Under 1.0's contrib unit (`ProtectSystem=full`) an upgraded server never starts; there are no upgrade notes, and the legacy-policy advice fails as given | OPS-14 | open (decision) |
| F37 | P2 | Rolling back to 1.0 re-enables a legacy key whose revoke was interrupted, or whose files were restored from a backup | OPS-16 | open (decision) |
| F38 | P2 | Undocumented: of a burst from one NAT address over a WAN path, about 16 get in, whatever `--connect-timeout` says | LOAD-06 | open (docs) |
| F39 | P2 | Undocumented rsync hazard: after an outage the old receiver's `--partial` cleanup replaces a quick retry's file | LIFE-11 | open (docs) |

### Open items

Observed while building the suite and left for a maintainer decision. They
are not security findings under THREAT_MODEL.md.

- **F2, migration stall.** QUIC migration works, but the server learns a
  quiet client's new address only from the client's next packet, which can be
  up to a keep-alive interval (15 s) away. With F1 fixed the session survives
  the stall. A shorter client keep-alive would shorten it at the cost of more
  idle traffic.
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
- **`keygen` under umask 000** creates group- and world-writable state
  directories. THREAT_MODEL.md treats that as an administrator mistake;
  refusing such a store would be a cheap fail-closed hardening.
- **Both builds call themselves 1.0.0**, so neither an administrator nor
  the upgrade scenarios' pin can tell the previous release from this one
  by `--version`.
- **`--no-shell` refuses login-shell requests**, not interactive programs:
  `qsh -t server bash` still works. The flag's help says "interactive
  shells".
