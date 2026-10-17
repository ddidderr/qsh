# qsh multi-host end-to-end suite

`tests/e2e.rs` drives the real binaries on one machine over loopback. This
suite runs them the way they are deployed: on separate machines with their
own accounts and addresses, the server under systemd as the README says, and
a network in between that can lose, delay, reorder, duplicate, black-hole and
re-address traffic. It moves real data with real tools (rsync, tar) and
drives interactive sessions through a real terminal.

What it tests, and why, is in [TEST_PLAN.md](TEST_PLAN.md). This file is about
running it and extending it.

## Running it

Needs Docker with BuildKit and the compose plugin, and Python 3.10 or later
with `venv`. Nothing else is installed on the host.

```
e2e/run test                     # build the image, run every scenario
e2e/run test -k rsync            # any pytest arguments pass through
e2e/run test -m "not slow"       # skip the slowest: 1 GiB each way, default-timeout outages
QSH_E2E_SKIP_BUILD=1 e2e/run test scenarios/test_pty.py   # reuse the image
e2e/run plan                     # check TEST_PLAN.md against the scenarios
```

or `just e2e` / `just e2e-plan` from the repository root.

A run builds the image (about 90 s cold, seconds when only qsh's sources
changed), starts a fresh environment, runs the scenarios, and removes the
environment again. The full suite takes around 25 minutes, most of it in a
handful of scenarios that wait out timeouts or move a gigabyte.

Results land in `target/e2e/`: `junit.xml`, and in `artifacts/` the compose
logs and both servers' complete journals. A failing scenario's report also
carries the qsh-server journal lines both servers wrote while it ran.

To look around by hand:

```
e2e/run up                       # start and provision an environment
e2e/run shell client1 alice      # then, for example: qsh server
e2e/run shell server             # root on the server: journalctl -u qsh-server
e2e/run down
```

### Behind a proxy

The image build downloads Debian packages and crates. If `https_proxy` is
set, `e2e/run build` builds with the host's network so a proxy on
`localhost` is reachable, switches apt to HTTPS, and, when
`QSH_E2E_CA_BUNDLE` (or else `SSL_CERT_FILE`) names a CA bundle, trusts it
during the build only. The test containers themselves never need the
internet.

A proxy that refuses Debian's mirrors can still build the suite on another
apt-based release: `QSH_E2E_BASE_IMAGE=ubuntu:26.04 e2e/run build`. The
binaries are still compiled on Debian, so the base needs the same or a newer
glibc. CI and the scenarios' expectations assume the pinned Debian.

## The environment

```
  client1 (alice) ─┐                    ┌─ server   qsh-server under systemd
  client2 (bob)   ─┼── lan ─────────────┼─ server2  short timeouts; impostor
                   └─ netsim (relay) ───┘
```

All five containers run one image, built by
[docker/Dockerfile](docker/Dockerfile): qsh compiled from this checkout inside
the image's Debian release, the shipped
[systemd unit](../contrib/qsh-server.service), rsync, git, python3, and the
accounts `alice` (with supplementary group `project`), `bob`, `carol` and
`dave`.

- **server** boots systemd as PID 1 and runs `qsh-server` exactly as the
  README's setup describes: `keygen` as root into `/etc/qsh`, the unit
  started with `systemctl`. It sees a pure cgroup v2 hierarchy (see
  [node-entrypoint.sh](docker/node-entrypoint.sh)), so
  `--kill-session-processes` works the way it does on a modern host.
- **server2** is a second machine: a server with an 8 s idle timeout for the
  scenarios that wait for a peer to be declared dead, the impostor in the
  host-key scenarios, and the victim of the crash, reconfiguration and
  key-rotation scenarios. (NET-10 and OPS-04 restart and stop `server`
  itself, on purpose: they need its default 60 s idle timeout.)
- **client1** and **client2** are where qsh runs, as `alice` and `bob`.
- **netsim** runs [netsim.py](netsim/netsim.py), a UDP relay with a control
  socket. One relay process is one link, created per scenario on its own
  port: `client → netsim:PORT → server`. It applies loss, delay, jitter,
  reordering, duplication, a black hole in both directions or in one, and a
  datagram size limit (a path MTU that shrinks without ICMP), and can move a
  flow to a new source port or address (what a NAT rebinding or a roaming
  client looks like to the server). `--trace` logs every datagram with its
  size. Userspace, not `tc netem`, so it behaves the same on every kernel
  Docker runs on. Its sockets have 16 MiB buffers, so the kernel does not
  drop a fast sender's burst before the relay gets to it, and its counters
  say how many bytes its delay held at once: on a long path, how far the
  sender's window opened.

The compose project name and subnet are chosen per run, so several runs can
coexist on one Docker host.

## Writing a scenario

1. Add it to [TEST_PLAN.md](TEST_PLAN.md) first: an ID, what it protects,
   the steps and the expected behaviour, citing the README, the threat
   model, or the code.
2. Implement it in the matching `scenarios/test_*.py` and tag it with
   `@pytest.mark.plan("ID")`. Set its status in the plan to `automated`.
3. `e2e/run plan` checks the two agree; CI runs it.

The fixtures in [conftest.py](conftest.py) provide the shared machines:
`server` and `fast_server` (`server2`), `alice` and `bob` (authorized,
pinned identities), `alice_fast` (alice's key on server2), `make_client`
(a fresh identity with its own policy, revoked afterwards) and `make_link`
(a netsim relay, closed afterwards). The helpers in [harness/](harness/)
run commands on nodes (`Node.run`, `Node.sh`, `Node.wait_for`), drive qsh
(`QshServer`, `QshClient`, `NetLink`), and drive terminals (`Terminal`).

Scenarios share the environment, as tests on real machines would. Leave
shared state as you found it: use your own identity from `make_client`, a
unique name from `harness.qsh.unique`, and clean up in `finally`. Give
remote processes a distinctive argument (`sleep 4242.25`) so `pgrep -f`
finds exactly yours.

Some lessons the first scenarios taught:

- A terminal echoes the command line. Match a result the command line
  cannot contain: `echo CMP-$?` and expect `CMP-(\d)`, not `echo SAME`.
- `pkill -f PATTERN` also matches the shell that runs it when the pattern
  is in its command line. Stop processes by PID file, or anchor the pattern
  (`^qsh server2 sleep 61`).
- `docker exec` starts with umask 0000; the harness sets 022 like a login.
- `qsh-server authorize` takes effect at the next reload, within about a
  second; the helpers wait `RELOAD_SETTLE` after changing authorizations.
- A first connection to an unknown host makes an anonymous probe first,
  which the server counts as an authentication failure. That is by design.
- An interactive bash saves the terminal's modes and restores them when a
  foreground job dies of a signal. Check that qsh restores the terminal
  from a plain `sh`, or a broken qsh passes.
- A regression test is only one if it fails without its fix. Run new
  scenarios against an image built from the commit before the fix.
- Put shared state back in `finally`: a scenario that fails half way
  through (a rotated host key, an edited configuration) must not take
  later scenarios down with it.
- QUIC acknowledges only packets that ask for it, and a quiet client asks
  for nothing. To test what one side does while it still hears the other
  (a one-way outage), give that other side something to send.
