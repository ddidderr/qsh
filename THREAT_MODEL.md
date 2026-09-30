# qsh threat model

This is the reference for security reviews of qsh. It says who the attacker
is, which boundaries qsh promises to hold, and which trade-offs are already
decided. The README's "Security model" section describes the mechanisms; this
file decides what counts as a finding.

A security finding is a way for an actor in the **in scope** list to cross
one of that actor's **boundaries**. Anything else is a hardening idea or a
bug report, and is handled as such (see [Rules for reviews](#rules-for-reviews)).

## Actors in scope

### 1. Unauthenticated network peer

Anyone who can send UDP to the server. They hold no authorized key.

Boundaries qsh must hold:

- They cannot authenticate, open a session stream, or reach any code that
  parses a session request.
- They cannot hold server resources beyond the pre-authentication budgets:
  32 handshakes in flight, at most 4 from one source address, a 5 s
  handshake deadline, QUIC address validation (retry) before work is done.
- They cannot make the server write one log line per attempt. Failures are
  counted and reported in batches.

Not promised: surviving a distributed flood from many addresses. That is the
host firewall's job, as the README states.

### 2. On-path network attacker

Can read, drop, and inject packets between client and server.

Boundaries:

- Once a client has pinned a host key, it cannot be made to talk to a
  different key under that pin. Mismatches fail hard.
- Session contents stay confidential and integrity-protected (TLS 1.3 only,
  mutual authentication).
- Certificates outside their validity window are refused in both directions.

### 3. Authenticated client

Holds a private key that `authorized/` maps to a local account, with the
policy in `<name>.toml`.

Boundaries:

- It runs only as the mapped account, with that account's supplementary
  groups, and with no daemon privileges. That means no leftover real, saved,
  or effective IDs, inheritable or ambient capabilities, file descriptors, or
  environment beyond the allowlist. A non-root daemon can serve only its own
  account and keeps the groups it started with; the README documents that
  deployment's limits.
- Policy is enforced for every session: `allow_shell`, `allow_exec`, the
  `argv[0]` filter (exact match, never basename), expiry, and revocation.
  Revocation and expiry also end existing connections within about two
  seconds.
- Session cleanup, at two levels:
  - Ordinary sessions: disconnect, expiry, or revocation terminates the
    session's initial process group with SIGHUP, then SIGTERM, then SIGKILL,
    including while output is still draining. A normal exit does not signal
    it, and work that moved to another process group may survive; see
    "Decided trade-offs".
  - With `kill_session_processes`, under the preconditions the README lists
    (root daemon, non-root target, delegated cgroup v2): the session runs in
    its own cgroup, or does not run at all. At the end, qsh kills everything
    still in that cgroup. If the kill itself fails, the session ends in
    failure and the failure is logged. If a standalone daemon is killed
    abruptly, its in-process cleanup cannot run; the supplied systemd unit's
    `KillMode=control-group` is the crash boundary.
- It cannot degrade other keys beyond the per-key limits: 32 connections and
  32 sessions per key, 128 sessions and 256 connections in total. It cannot
  crash the server or block its async workers. Request parsing enforces the
  documented payload size, field lengths, and collection counts before it
  allocates for them.
- It cannot suppress the log lines for logins and withdrawn authorizations
  by exhausting the peer diagnostic budget with failing sessions. Those lines
  still share a bounded, best-effort queue; see "Trusted, or out of scope".

Not boundaries, by design:

- Anything the mapped account can do on its own. A full-shell key has that
  account's full authority, including forking until `TasksMax`, filling its
  disk quota, or starting work outside the session through cron or user
  services.
- What an allowed executable does with its arguments. `--command` filters
  `argv[0]` only and is documented as not being a sandbox. `rsync -e` runs
  arbitrary programs.
- Resource use within its quotas.

### 4. Local unprivileged user on the server host

A different, non-root account on the machine where `qsh-server` runs.

Boundaries:

- They cannot read the host private key.
- They cannot alter the authorization store.
- They cannot control what qsh synchronizes on. For example, lock files must
  not be openable by them, because holding one would stall the server's
  authorization reload or the management commands.
- They cannot reach another account's session PTY or pipes. Descriptors are
  close-on-exec.

### 5. Local unprivileged user on the client host

A different account on the client machine.

Boundaries: they cannot read the client's private key, alter its
`known_hosts`, or stall the client through its lock files.

## Trusted, or out of scope

- **root, and anyone who can write the server state directory**
  (`/etc/qsh` or `~/.config/qsh-server`) or the systemd unit. Administrator
  mistakes, such as hand-copied duplicate entries or a policy edited to
  contradict itself, should fail closed when that is cheap. They are not
  security findings.
- **The account a non-root server runs as.** Sessions of that same account
  can rewrite its state. This is documented, and the README gives the
  supported deployment.
- **The client user's own choices**: which host spelling they type, answering
  the first-connection prompt, `--accept-new`.
- **A pinned server**: its session output reaches the terminal byte for byte,
  as with ssh.
- **The log sink.** Logging is best effort: a blocked or failing
  stderr/journald must never block serving, but lines may be lost, and the
  loss is counted where possible.
- **Kernel, libc, NSS, and dependency correctness** (rustls, quinn, ring),
  beyond using their APIs as documented. Hardware, timing, and other side
  channels.

## Decided trade-offs

These are known and accepted. Do not re-report them without a new fact that
changes the analysis.

- Trust on first use for unknown hosts, as in ssh.
- Host pins normalize DNS case, IP address text, and ports. They do not merge
  aliases: another DNS name, the bare IP, or another IPv6 zone spelling
  (`%eth0` versus `%2`) is a separate pin.
- `--command` is an `argv[0]` filter, not a sandbox.
- Ordinary keys may leave detached jobs running after a session. Only
  `--kill-session-processes` promises cleanup.
- Certificate expiry does not bound an authorization. `--expires-in-days`
  does.
- Legacy policies without `key_fingerprint` are accepted with a warning, for
  upgrades.
- Request limits: 64 KiB per request, 1,024 arguments, 16 KiB per argument
  or environment value. Commands larger than that are refused.
- Logging is best effort; there is no retry and no durable audit log.
- Revocation latency is about two seconds, not immediate. A management
  command holding the authorization lock delays the reload until it
  finishes.
- Lock files that pre-release builds created with the default mode are
  tightened to 0600 on next use, but a descriptor opened before that keeps
  working. No release ever shipped the default mode.
- `authorize --force` and `revoke` cannot repair duplicate entries whose file
  names are not valid UTF-8 or not valid entry names. The key stays denied
  until a trusted state-directory writer removes the files by hand.

## Rules for reviews

1. **Every finding names its actor and its boundary.** State which actor
   above performs the attack, what they control, which boundary they cross,
   and the code path or reproduction. If you cannot name both the actor and
   the boundary, it is not a security finding.
2. **Everything else goes in a separate "hardening ideas" list.** Do not
   implement it in the same pass. The maintainer decides which ideas, if any,
   become work.
3. **Fix the cause with the smallest change.** Prefer removing or
   restructuring the thing that caused the problem over adding a layer that
   compensates for it. Documenting a limitation is a valid fix when the
   boundary was never promised.
4. **Check every new mechanism against actors 3 and 4.** A new file, lock,
   thread, queue, socket, or protocol field is new attack surface. On
   2026-09-30, a fail-closed fix added a world-readable lock file. It let any
   local user stall authorization reloads, so revocation stopped working.
5. **A fix to a recent fix is a signal to stop.** If a finding exists only
   because of machinery added in an earlier round, reconsider or revert that
   machinery rather than adding more. Example: the logging retry and priority
   lanes, reverted in `bdbb39b`.
6. **A clean review is done.** A review that finds no in-scope finding ends
   the loop. By default, a later review concentrates on code changed since
   the last one, rather than re-auditing unchanged code with fresh eyes. A
   concrete new fact, such as an exploit, a dependency advisory, or a changed
   deployment, justifies looking at unchanged code again.
