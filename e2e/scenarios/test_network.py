"""NET: what the network does to a session, and what qsh does about it.

Impaired paths go through netsim (see e2e/netsim/netsim.py). Scenarios that
need a peer to be declared dead use server2, whose idle timeout is 8 s.
"""

from __future__ import annotations

import hashlib
import ipaddress
import time

import pytest

from conftest import FAST_IDLE_TIMEOUT


def ticker(count: int, interval: float = 0.25) -> tuple[str, ...]:
    """A remote command that prints 1..count, one line every `interval`."""
    return ("sh", "-c", f"for i in $(seq 1 {count}); do echo $i; sleep {interval}; done")


def lines_ok(out: bytes, count: int) -> bool:
    return out.decode().split() == [str(i) for i in range(1, count + 1)]


def start(client, host, *command, port=None, options=()):
    argv = client.argv(host, *command, port=port, options=options)
    return client.node.popen(argv, user=client.user)


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
    reproducible loss pattern.
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
# does, after 5 s.
DEADLINE_PATHS = {
    "slow": ({"delay_ms": 3000}, ("--connect-timeout", "20")),
    "big": ({"max_datagram_down": 1150}, ()),
}


def login_past_the_deadline(path, alice, server, make_link):
    impairment, options = DEADLINE_PATHS[path]
    link = make_link("server:2222", **impairment)
    alice.pin(link.host, server.fp, port=link.port)
    since = server.cursor()
    r, took = timed_login(alice, link, *options)
    print(f"{path}: status {r.rc} after {took:.1f}s: {r.stderr.strip()}")
    return r, took, server.journal(since)


@pytest.mark.plan("NET-13")
@pytest.mark.parametrize("path", sorted(DEADLINE_PATHS))
def test_a_handshake_past_the_server_deadline_fails(path, alice, server, make_link):
    r, took, journal = login_past_the_deadline(path, alice, server, make_link)
    assert r.rc == 255, r.describe()
    assert "LOGIN-OK" not in r.stdout
    assert took < 25, f"took {took:.1f}s"
    assert "authenticated as" not in journal, journal


@pytest.mark.plan("NET-13")
@pytest.mark.parametrize("path", sorted(DEADLINE_PATHS))
@pytest.mark.xfail(strict=True, reason="FXX-NET-13: the server's handshake deadline is reported as quinn's generic application close")
def test_a_handshake_past_the_server_deadline_is_named(path, alice, server, make_link):
    """The user learns that the server ended a handshake that took too long.

    Today the client prints quinn's text for a peer's application close during
    the handshake ("the application or application protocol caused the
    connection to be closed during the handshake"), prefixed with "connection
    lost" when the client had finished its side: it reads like a refusal or a
    dropped session, not like a path too slow for the 5 s deadline.
    """
    r, _, _ = login_past_the_deadline(path, alice, server, make_link)
    assert r.rc == 255, r.describe()
    assert "the application or application protocol" not in r.stderr, r.describe()
    assert "connection lost" not in r.stderr, r.describe()
    assert "handshake" in r.stderr, r.describe()


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
