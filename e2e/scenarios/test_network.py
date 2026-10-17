"""NET: what the network does to a session, and what qsh does about it.

Impaired paths go through netsim (see e2e/netsim/netsim.py). Scenarios that
need a peer to be declared dead use server2, whose idle timeout is 8 s.
"""

from __future__ import annotations

import hashlib
import ipaddress
import re
import shlex
import subprocess
import time

import pytest

from conftest import FAST_IDLE_TIMEOUT
from harness.qsh import NetLink


def ticker(count: int, interval: float = 0.25) -> tuple[str, ...]:
    """A remote command that prints 1..count, one line every `interval`."""
    return ("sh", "-c", f"for i in $(seq 1 {count}); do echo $i; sleep {interval}; done")


def lines_ok(out: bytes, count: int) -> bool:
    return out.decode().split() == [str(i) for i in range(1, count + 1)]


def start(client, host, *command, port=None, options=()):
    argv = client.argv(host, *command, port=port, options=options)
    return client.node.popen(argv, user=client.user)


def pipeline(client, script: str):
    """Start a local bash pipeline as the client's account; it fails if any part does."""
    return client.node.popen(["bash", "-o", "pipefail", "-c", script], user=client.user)


@pytest.mark.plan("NET-01")
def test_interactive_latency_and_loss_do_not_corrupt_a_session(alice, server, make_link):
    """A long session across 150 ms RTT, 3% loss, jitter, reordering and duplicates."""
    link = make_link("server:2222", delay_ms=75, jitter_ms=20, loss=0.03, reorder=0.03, duplicate=0.02)
    alice.pin(link.host, server.fp, port=link.port)
    r = alice.run("netsim", *ticker(40, 0.1), port=link.port, timeout=120)
    assert r.rc == 0, r.describe()
    assert lines_ok(r.out, 40)
    data = bytes(range(256)) * 2048
    r = alice.run("netsim", "sha256sum", port=link.port, input=data, timeout=120)
    assert r.stdout.split()[0] == hashlib.sha256(data).hexdigest()


@pytest.mark.plan("NET-02")
def test_a_short_outage_is_survived(alice_fast, fast_server, make_link):
    link = make_link("server2:2222")
    alice_fast.pin(link.host, fast_server.fp, port=link.port)
    proc = start(alice_fast, "netsim", *ticker(40), port=link.port)
    time.sleep(2)
    link.blackhole(True)
    time.sleep(FAST_IDLE_TIMEOUT / 2)
    link.blackhole(False)
    out, err = proc.communicate(timeout=60)
    assert proc.returncode == 0, err.decode()
    assert lines_ok(out, 40)


@pytest.mark.plan("NET-03")
def test_an_outage_past_the_idle_timeout_ends_both_sides(alice_fast, fast_server, make_link):
    link = make_link("server2:2222")
    alice_fast.pin(link.host, fast_server.fp, port=link.port)
    marker = "4242.25"
    proc = start(alice_fast, "netsim", "sleep", marker, port=link.port)
    fast_server.node.wait_running(f"sleep {marker}", timeout=10)
    link.blackhole(True)
    cut = time.monotonic()
    _, err = proc.communicate(timeout=FAST_IDLE_TIMEOUT + 30)
    gone = time.monotonic() - cut
    assert proc.returncode == 255, err.decode()
    assert gone < FAST_IDLE_TIMEOUT + 10, f"the client took {gone:.1f}s to give up"
    # The server reached the same verdict and cleaned up the remote process.
    fast_server.node.wait_gone(f"sleep {marker}", timeout=FAST_IDLE_TIMEOUT + 10)


@pytest.mark.plan("NET-04")
def test_nat_rebinding_mid_session(alice, server, make_link):
    """The relay moves the flow to a new source port, as a NAT would."""
    link = make_link("server:2222")
    alice.pin(link.host, server.fp, port=link.port)
    proc = start(alice, "netsim", *ticker(60, 0.2), port=link.port)
    time.sleep(2)
    link.rebind()
    time.sleep(3)
    link.rebind()
    out, err = proc.communicate(timeout=90)
    assert proc.returncode == 0, err.decode()
    assert lines_ok(out, 60)


@pytest.mark.plan("NET-05")
def test_client_address_change_mid_session(alice, server, env):
    """client1 moves to a new IP address, as a laptop changing networks does."""
    proc = start(alice, "server", *ticker(60, 0.2))
    try:
        time.sleep(2)
        env.reconnect("client1", env.spare_ip(10))
        out, err = proc.communicate(timeout=90)
        assert proc.returncode == 0, err.decode()
        assert lines_ok(out, 60)
    finally:
        env.reconnect("client1", env.spare_ip(11))


@pytest.mark.plan("NET-06")
def test_relay_source_address_change_mid_session(alice, server, env, make_link):
    """The flow reaches the server from a different IP address part way through."""
    link = make_link("server:2222")
    alice.pin(link.host, server.fp, port=link.port)
    second = env.spare_ip(20)
    env.node("netsim").run(["ip", "addr", "replace", f"{second}/{env.subnet().prefixlen}", "dev", "eth0"], check=True)
    proc = start(alice, "netsim", *ticker(60, 0.2), port=link.port)
    time.sleep(2)
    link.rebind(source_ip=second)
    out, err = proc.communicate(timeout=90)
    assert proc.returncode == 0, err.decode()
    assert lines_ok(out, 60)


@pytest.mark.plan("NET-07")
def test_connect_timeout_against_a_silent_peer(alice, server, make_link):
    link = make_link("server:2222", blackhole=True)
    alice.pin(link.host, server.fp, port=link.port)
    begin = time.monotonic()
    r = alice.run("netsim", "true", port=link.port, options=("--connect-timeout", "3"), timeout=60)
    took = time.monotonic() - begin
    assert r.rc == 255, r.describe()
    assert "timed out" in r.stderr, r.describe()
    assert 2.5 < took < 10, f"took {took:.1f}s"


@pytest.mark.plan("NET-08")
def test_nothing_listening_fails_within_the_timeout(alice):
    begin = time.monotonic()
    r = alice.run("server", "true", port=2999, options=("--connect-timeout", "3", "--accept-new"), timeout=60)
    assert r.rc == 255, r.describe()
    assert time.monotonic() - begin < 10


@pytest.mark.plan("NET-09")
def test_an_unknown_host_name_fails_fast(alice):
    begin = time.monotonic()
    r = alice.run("no-such-host.invalid", "true", timeout=60)
    assert r.rc == 255, r.describe()
    assert "no-such-host.invalid" in r.stderr
    assert time.monotonic() - begin < 15


@pytest.mark.plan("NET-10")
def test_a_server_restart_ends_the_session_promptly(alice, server):
    """`server` has the default 60 s idle timeout: notice must not wait for it."""
    marker = "4343.25"
    proc = start(alice, "server", "sleep", marker)
    server.node.wait_running(f"sleep {marker}", timeout=10)
    begin = time.monotonic()
    server.restart()
    _, err = proc.communicate(timeout=90)
    assert proc.returncode == 255, err.decode()
    assert time.monotonic() - begin < 10, f"the client noticed after {time.monotonic() - begin:.0f}s"
    # systemd's KillMode=control-group took the session with the old daemon.
    assert not server.node.pids(f"sleep {marker}")
    # And the restarted server serves new sessions with the same identity.
    assert alice.run("server", "true").rc == 0


@pytest.mark.plan("NET-11")
def test_a_dead_first_address_falls_back_to_a_live_one(alice, server, env):
    """A name with two addresses, the first one dead, still connects quickly.

    The client tries addresses in sorted order, so the dead one must sort
    first: the network's gateway, where nothing answers on UDP 2222.
    """
    dead = str(env.subnet().network_address + 1)
    live = server.node.ip
    assert ipaddress.ip_address(dead) < ipaddress.ip_address(live)
    alice.node.edit_hosts(add=f"{dead} multihomed")
    alice.node.edit_hosts(add=f"{live} multihomed")
    try:
        alice.pin("multihomed", server.fp)
        begin = time.monotonic()
        r = alice.run("multihomed", "hostname", timeout=60)
        assert r.rc == 0, r.describe()
        assert r.stdout.strip() == "server"
        assert time.monotonic() - begin < 5
    finally:
        alice.node.edit_hosts(remove="multihomed")


# The server gives a handshake 5 s from the first Initial that passed its
# address check (HANDSHAKE_GRACE in src/server.rs, after the Retry round trip),
# the client 10 s from its first datagram (--connect-timeout). Lost datagrams
# cost a handshake time through QUIC's retransmission timer, which starts near
# 1 s and doubles. TEST_PLAN.md has the measured success rates.
LOSSY_DELAY_MS = 50
CONNECT_TIMEOUT = 10  # the client's default


def timed_login(client, link, *options):
    begin = time.monotonic()
    r = client.run("netsim", "echo", "LOGIN-OK", port=link.port, options=options, timeout=120)
    return r, time.monotonic() - begin


@pytest.mark.plan("NET-13")
def test_handshakes_complete_over_a_lossy_link(alice, server, make_link):
    """10% loss each way and 50 ms each way: every one of eight logins completes.

    Each login has a link of its own with its own seed, so a failure names a
    seed to retry with. A seed fixes netsim's random draws, not which
    datagrams they fall on: that depends on quinn's timers.
    """
    times = []
    for seed in range(1, 9):
        link = make_link("server:2222", seed=seed, loss=0.1, delay_ms=LOSSY_DELAY_MS)
        alice.pin(link.host, server.fp, port=link.port)
        r, took = timed_login(alice, link)
        assert r.rc == 0 and r.stdout == "LOGIN-OK\n", f"seed {seed}: {r.describe()}"
        times.append(round(took, 1))
    print(f"logins took {times} s")


@pytest.mark.plan("NET-13")
def test_a_hopeless_link_fails_within_the_connect_timeout(alice, server, make_link):
    """90% loss each way: no handshake, and qsh says so when its timeout expires."""
    link = make_link("server:2222", seed=1, loss=0.9, delay_ms=LOSSY_DELAY_MS)
    alice.pin(link.host, server.fp, port=link.port)
    r, took = timed_login(alice, link)
    print(f"status {r.rc} after {took:.1f}s: {r.stderr.strip()}")
    assert r.rc == 255, r.describe()
    assert f"timed out after {CONNECT_TIMEOUT}s" in r.stderr, r.describe()
    assert took < CONNECT_TIMEOUT + 5, f"took {took:.1f}s"


# Two paths on which every handshake outlives the server's 5 s deadline, with
# no randomness. "slow": 3 s each way, so the client's Finished reaches the
# server 6 s after the deadline started; the client, done with its side of the
# handshake at 12 s, has already sent its request when the server's close
# arrives. "big": the path drops datagrams over 1,150 bytes towards the client
# only, so the server's padded first flight never arrives but its short close
# does, 5 s after the Retry round trip. On "big" the client's own 10 s timer
# would end the login too, so it must have failed well before that timer: a
# server without its deadline still fails a "big" login, at 10 s.
DEADLINE_PATHS = {
    # impairment, client options, the most seconds the failure may take
    "slow": ({"delay_ms": 3000}, ("--connect-timeout", "20"), 25),
    "big": ({"max_datagram_down": 1150}, (), CONNECT_TIMEOUT - 2),
}


@pytest.fixture(scope="module")
def deadline_logins(env, alice, server):
    """A login over each DEADLINE_PATHS path, made once for the tests that judge it.

    Nothing random decides how one ends, and they take 5 and 17 s, so the
    pinned test and the xfail test share them.
    """
    links, done = [], {}

    def login(path):
        if path not in done:
            impairment, options, _ = DEADLINE_PATHS[path]
            link = NetLink(env.node("netsim"), "server:2222", **impairment)
            links.append(link)
            alice.pin(link.host, server.fp, port=link.port)
            since = server.cursor()
            r, took = timed_login(alice, link, *options)
            print(f"{path}: status {r.rc} after {took:.1f}s: {r.stderr.strip()}")
            done[path] = (r, took, server.journal(since))
        return done[path]

    yield login
    for link in links:
        link.close()


@pytest.mark.plan("NET-13")
@pytest.mark.parametrize("path", sorted(DEADLINE_PATHS))
def test_a_handshake_past_the_server_deadline_fails(path, deadline_logins):
    """The server's 5 s handshake deadline ends a handshake that is too slow.

    HANDSHAKE_GRACE in src/server.rs keeps a half-open attempt from holding
    an admission slot: the login fails, nothing runs, nobody is logged in,
    and it ends at the server's deadline, not at the client's.
    """
    r, took, journal = deadline_logins(path)
    limit = DEADLINE_PATHS[path][2]
    assert r.rc == 255, r.describe()
    assert r.stdout == "", r.describe()
    assert took < limit, f"took {took:.1f}s, more than {limit}s"
    assert not re.search(r"timed out after \d+s", r.stderr), r.describe()
    assert "authenticated as" not in journal, journal


@pytest.mark.plan("NET-13")
@pytest.mark.parametrize("path", sorted(DEADLINE_PATHS))
@pytest.mark.xfail(strict=True, reason="FXX-NET-13: the server's handshake deadline is reported as quinn's generic application close")
def test_a_handshake_past_the_server_deadline_is_named(path, deadline_logins):
    """The user learns that the server ended a handshake that took too long.

    Today the client prints quinn's text for a peer's application close during
    the handshake ("the application or application protocol caused the
    connection to be closed during the handshake"), prefixed with "connection
    lost" when the client had finished its side: it reads like a refusal or a
    dropped session, not like a path too slow for the 5 s deadline. quinn's
    text may stay, as long as qsh says what ended the login; a session that
    never started was not lost.
    """
    r, _, _ = deadline_logins(path)
    assert r.rc == 255, r.describe()
    assert re.search(r"\b5 ?s(econds)?\b|deadline|too (slow|long)", r.stderr), r.describe()
    assert "connection lost" not in r.stderr, r.describe()


@pytest.mark.plan("NET-14")
@pytest.mark.slow
def test_outage_tolerance_with_the_default_timeouts(alice, server, make_link):
    """Default 60 s idle timeout: 30 s of silence is survived, 90 s is not."""
    link = make_link("server:2222")
    alice.pin(link.host, server.fp, port=link.port)
    proc = start(alice, "netsim", *ticker(60, 1), port=link.port)
    time.sleep(5)
    link.blackhole(True)
    time.sleep(30)
    link.blackhole(False)
    out, err = proc.communicate(timeout=120)
    assert proc.returncode == 0, err.decode()
    assert lines_ok(out, 60)

    marker = "4545.25"
    proc = start(alice, "netsim", "sleep", marker, port=link.port)
    server.node.wait_running(f"sleep {marker}", timeout=10)
    link.blackhole(True)
    _, err = proc.communicate(timeout=120)
    assert proc.returncode == 255, err.decode()
    # Idle timeout plus up to one keep-alive interval, then the HUP/TERM/KILL ladder.
    server.node.wait_gone(f"sleep {marker}", timeout=60)


# A one-way outage leaves one side deaf while the other still hears it. The
# deaf side's idle timer runs from the last packet it received, so it gives up
# after one idle timeout and falls silent; the other side hears it until then
# and gives up one idle timeout later. QUIC restarts the idle timer on every
# packet received, but on a send only for the first ack-eliciting packet since
# the last receipt (RFC 9000, section 10.1): talking cannot keep a side alive.
ONE_WAY_LIMIT = 2 * FAST_IDLE_TIMEOUT + 8


def seconds(elapsed: float | None) -> str:
    return "never" if elapsed is None else f"{elapsed:.1f}s"


@pytest.mark.plan("NET-16")
@pytest.mark.parametrize("dead", ["up", "down"])
def test_a_one_way_outage_ends_both_sides(dead, alice_fast, fast_server, make_link):
    """Only one direction of the path dies: "up" (client -> server) or "down".

    Both directions carry traffic until the cut: the client streams a tick on
    stdin every 0.25 s and server2 sends keep-alives every 2 s. So the side
    that still hears its peer really goes on hearing it, and must still give up.
    """
    link = make_link("server2:2222")
    alice_fast.pin(link.host, fast_server.fp, port=link.port)
    marker = {"up": "4646.25", "down": "4646.5"}[dead]
    remote = alice_fast.argv("netsim", "sh", "-c", f"cat >/dev/null & exec sleep {marker}", port=link.port)
    proc = pipeline(alice_fast, f"while :; do echo tick; sleep 0.25; done | {shlex.join(remote)}")
    try:
        fast_server.node.wait_running(f"sleep {marker}", timeout=10)
        time.sleep(1)
        before = link.stats()["stats"]
        link.blackhole(True, direction=dead)
        cut = time.monotonic()
        client_gone = server_gone = None
        while client_gone is None or server_gone is None:
            now = time.monotonic() - cut
            if client_gone is None and proc.poll() is not None:
                client_gone = now
            if server_gone is None and not fast_server.node.pids(f"sleep {marker}"):
                server_gone = now
            if now > ONE_WAY_LIMIT + 10:
                break
            time.sleep(0.2)
        after = link.stats()["stats"]
    finally:
        if proc.poll() is None:
            alice_fast.node.kill_command(alice_fast.user, remote)
        _, err = proc.communicate(timeout=30)
    times = f"client gone after {seconds(client_gone)}, remote job after {seconds(server_gone)}"
    print(f"{dead} dead: {times}")
    heard = "down" if dead == "up" else "up"
    assert after[dead]["dropped"] > before[dead]["dropped"], after
    # The open direction kept carrying the hearing side's peer: one-way, really.
    assert after[heard]["forwarded"] > before[heard]["forwarded"], after
    assert client_gone is not None and client_gone < ONE_WAY_LIMIT, times
    assert server_gone is not None and server_gone < ONE_WAY_LIMIT, times
    assert proc.returncode == 255, err.decode()
    assert "timed out" in err.decode(), err.decode()


# quinn's path-MTU discovery starts at QUIC's 1,200-byte minimum and probes up
# to its 1,452-byte ceiling within milliseconds of the handshake (`netsim
# --trace` shows the 1,326, 1,389, 1,420 and 1,452-byte probes on this
# network). A path that then shrinks to 1,252-byte datagrams, a 1,280-byte IPv4
# MTU, cuts the size in use but still carries QUIC's minimum. netsim drops the
# oversized datagrams silently, as a router that sends no ICMP does.
QUIC_MIN_DATAGRAM = 1200
SHRUNK_DATAGRAM = 1252
SEQ_COUNT = 4_000_000  # `seq 1 4000000` writes 30.9 MB


@pytest.mark.plan("NET-17")
@pytest.mark.parametrize("direction", ["down", "up"])
def test_bulk_data_survives_a_path_mtu_drop(direction, alice, server, make_link):
    """30.9 MB in one direction; part way through, that direction's path MTU shrinks.

    The sender must notice the black hole from its losses alone, fall back to
    1,200-byte datagrams and finish the stream intact.
    """
    link = make_link("server:2222", delay_ms=5)
    alice.pin(link.host, server.fp, port=link.port)
    if direction == "down":
        remote = alice.argv("netsim", "seq", "1", str(SEQ_COUNT), port=link.port)
        script = f"{shlex.join(remote)} | sha256sum"
    else:
        remote = alice.argv("netsim", "sha256sum", port=link.port)
        script = f"seq 1 {SEQ_COUNT} | {shlex.join(remote)}"
    proc = pipeline(alice, script)
    try:
        # A few MB at full size first: 3,000 of the transfer's 22,000 datagrams.
        deadline = time.monotonic() + 30
        while (moved := link.stats()["stats"][direction])["forwarded"] < 3000:
            assert proc.poll() is None, proc.communicate()[1].decode()
            assert time.monotonic() < deadline, moved
            time.sleep(0.05)
        assert moved["largest"] > SHRUNK_DATAGRAM, f"datagrams never grew past {SHRUNK_DATAGRAM} bytes: {moved}"
        link.set(**{f"max_datagram_{direction}": SHRUNK_DATAGRAM})
        cut = time.monotonic()
        assert proc.poll() is None, "the transfer ended before the path shrank"
        try:
            out, err = proc.communicate(timeout=60)
        except subprocess.TimeoutExpired:
            pytest.fail(f"the transfer stalled after the path shrank: {link.stats()['stats']}")
        took = time.monotonic() - cut
    finally:
        if proc.poll() is None:
            alice.node.kill_command(alice.user, remote)
    after = link.stats()["stats"][direction]
    print(f"{direction}: {moved['largest']}-byte datagrams before the drop, the rest took {took:.1f}s, {after}")
    assert proc.returncode == 0, err.decode()
    assert out.decode().split()[0] == alice.shell(f"seq 1 {SEQ_COUNT} | sha256sum").stdout.split()[0]
    # Datagrams of the old size really were sent into the shrunken path.
    assert after["oversized"] > 0, after


@pytest.mark.plan("NET-17")
def test_a_path_below_the_quic_minimum_fails_to_connect_clearly(alice, server, make_link):
    """1,150-byte datagrams at most: no QUIC handshake fits through.

    A client pads every datagram that carries its Initial to 1,200 bytes
    (RFC 9000, section 14.1), so not one of them reaches the server.
    """
    link = make_link("server:2222", max_datagram=QUIC_MIN_DATAGRAM - 50)
    alice.pin(link.host, server.fp, port=link.port)
    begin = time.monotonic()
    r = alice.run("netsim", "true", port=link.port, options=("--connect-timeout", "3"), timeout=60)
    took = time.monotonic() - begin
    assert r.rc == 255, r.describe()
    assert "timed out after 3s" in r.stderr, r.describe()
    assert took < 8, f"took {took:.1f}s"
    up = link.stats()["stats"]["up"]
    assert up["oversized"] > 0 and up["forwarded"] == 0, up


@pytest.mark.plan("NET-17")
def test_bulk_output_on_a_path_that_falls_below_the_minimum_ends_at_the_idle_timeout(
    alice_fast, fast_server, make_link
):
    """An established session whose path shrinks to 1,150-byte datagrams mid-output.

    quinn falls back to 1,200 bytes, which still do not fit, and nothing tells
    it why: every full datagram is lost, and only the idle timeout ends the
    session, on both sides, as an outage would. It must end, not stall.
    """
    link = make_link("server2:2222")
    alice_fast.pin(link.host, fast_server.fp, port=link.port)
    # 450 MB, far more than the path carries before the cut: the output is
    # still flowing when the path shrinks. The count doubles as the marker.
    producer = "seq 1 48480250"
    remote = alice_fast.argv("netsim", *producer.split(), port=link.port)
    proc = pipeline(alice_fast, f"{shlex.join(remote)} >/dev/null")
    try:
        deadline = time.monotonic() + 30
        while link.stats()["stats"]["down"]["forwarded"] < 3000:
            assert proc.poll() is None, proc.communicate()[1].decode()
            assert time.monotonic() < deadline
            time.sleep(0.05)
        link.set(max_datagram=QUIC_MIN_DATAGRAM - 50)
        cut = time.monotonic()
        assert proc.poll() is None, "the output ended before the path shrank"
        _, err = proc.communicate(timeout=FAST_IDLE_TIMEOUT + 30)
        gone = time.monotonic() - cut
    finally:
        if proc.poll() is None:
            alice_fast.node.kill_command(alice_fast.user, remote)
    assert proc.returncode == 255, err.decode()
    assert "timed out" in err.decode(), err.decode()
    assert gone < FAST_IDLE_TIMEOUT + 10, f"the client took {gone:.1f}s to give up"
    fast_server.node.wait_gone(producer, timeout=FAST_IDLE_TIMEOUT + 10)
    print(f"client gone after {gone:.1f}s, remote job after {time.monotonic() - cut:.1f}s")
