"""LOAD: many sessions, the per-key budgets, and staying healthy afterwards."""

from __future__ import annotations

import hashlib
import json
import re
import shlex
import time

import pytest

from harness.env import Burst


def daemon_fds(server) -> int:
    pid = server.main_pid()
    return int(server.node.run(["sh", "-c", f"ls /proc/{pid}/fd | wc -l"], check=True).stdout)


@pytest.mark.plan("LOAD-01")
def test_concurrent_sessions_from_two_machines(alice, bob):
    """16 sessions at once, each moving 4 MiB both ways, from two clients."""
    procs = []
    for client in (alice, bob):
        for i in range(8):
            script = f"head -c 4M /dev/urandom | tee /tmp/load-{i}.in | qsh server cat | sha256sum; sha256sum < /tmp/load-{i}.in"
            procs.append(client.node.popen(["bash", "-c", script], user=client.user))
    for proc in procs:
        out, err = proc.communicate(timeout=180)
        assert proc.returncode == 0, err.decode()
        sums = {line.split()[0] for line in out.decode().splitlines()}
        assert len(sums) == 1, out


@pytest.mark.plan("LOAD-02")
def test_one_key_is_capped_and_others_keep_working(make_client, bob, server):
    """40 simultaneous connections on one key: 32 are served, the rest refused.

    The server closes the excess connections with "key connection limit
    reached" once they authenticate. Another key is unaffected.
    """
    greedy = make_client("alice", authorize_as="alice")
    procs = [
        greedy.node.popen(greedy.argv("server", "sleep", "12", options=("--connect-timeout", "4")), user="alice")
        for _ in range(40)
    ]
    try:
        time.sleep(6)
        begin = time.monotonic()
        r = bob.run("server", "echo", "fair")
        assert r.rc == 0 and r.stdout.strip() == "fair", r.describe()
        assert time.monotonic() - begin < 5
        codes = [proc.wait(timeout=60) for proc in procs]
    finally:
        for proc in procs:
            proc.kill()
    assert codes.count(0) == 32, codes
    assert codes.count(255) == 8, codes


@pytest.mark.plan("LOAD-03")
def test_hundreds_of_short_sessions_leak_nothing(alice, server):
    before = daemon_fds(server)
    script = "for i in $(seq 1 300); do qsh server true || exit 1; done"
    alice.shell(script, timeout=600)
    time.sleep(3)
    after = daemon_fds(server)
    assert after <= before + 4, f"daemon descriptors grew from {before} to {after}"
    zombies = server.node.run(["sh", "-c", "ps -eo stat= | grep -c '^Z' || true"]).stdout.strip()
    assert zombies == "0", f"{zombies} zombie processes on the server"


@pytest.mark.plan("LOAD-04")
def test_a_long_session_survives_alongside_churn(alice, bob):
    """A transfer keeps going while another client opens and closes sessions."""
    data_cmd = "head -c 256M /dev/zero | qsh server sha256sum"
    long = alice.node.popen(["bash", "-c", data_cmd], user="alice")
    churn = bob.shell("for i in $(seq 1 50); do qsh server true || exit 1; done", timeout=300)
    assert churn.rc == 0
    out, err = long.communicate(timeout=300)
    assert long.returncode == 0, err.decode()
    want = hashlib.sha256(b"\0" * 256 * 1024 * 1024).hexdigest()
    assert out.decode().split()[0] == want


@pytest.mark.plan("LOAD-05")
def test_the_global_session_budget_across_five_keys(make_client, bob):
    """130 sessions from five keys (26 each): 128 run, the rest are refused."""
    keys = [make_client("alice", authorize_as="alice") for _ in range(5)]
    procs = []
    # Staggered, so the handshakes do not all queue on the four slots one
    # source address may hold at once: that cap is not what this measures.
    for _ in range(26):
        for key in keys:
            procs.append(key.node.popen(key.argv("server", "sleep", "25"), user="alice"))
            time.sleep(0.03)
    try:
        codes = [proc.wait(timeout=90) for proc in procs]
    finally:
        for proc in procs:
            proc.kill()
    assert codes.count(0) == 128, sorted(codes)
    assert codes.count(0) + codes.count(255) == len(codes), sorted(codes)


# LOAD-06. One address may hold 4 of the server's 32 handshake slots at once
# (MAX_HANDSHAKES_PER_SOURCE in src/server.rs). The server ignores an Initial
# over that limit without a word, and the client sends it again when its
# retransmission timer fires: about 1 s later (quinn's first RTT estimate is
# 333 ms), then 2, 4 and 8 s after that. A crowd behind one NAT therefore gets
# in four at a time, once per resend: four resends fit in the default 10 s
# --connect-timeout. The fifth comes after quinn's 15 s Retry token lifetime,
# and the server refuses it as an invalid token, so a longer timeout does not
# let more in.
PER_SOURCE_HANDSHAKES = 4
RESENDS_THAT_COUNT = 4  # at about 1, 3, 7 and 15 s: the first four
CROWD = 32  # one key's connection limit
# Each way: the client's Finished takes a 200 ms round trip to free a slot,
# far longer than the crowd takes to start, so a slot cannot serve two
# members of one wave.
CROWD_DELAY_MS = 100


def waves(times: list[float], gap: float = 0.5) -> list[list[float]]:
    """Group sorted times into runs separated by more than `gap` seconds."""
    groups: list[list[float]] = []
    for t in sorted(times):
        if groups and t - groups[-1][-1] <= gap:
            groups[-1].append(t)
        else:
            groups.append([t])
    return groups


@pytest.mark.plan("LOAD-06")
@pytest.mark.parametrize("connect_timeout", [10, 20])
def test_a_crowd_behind_one_address_gets_in_four_at_a_time(connect_timeout, make_client, alice, server, make_link):
    """32 logins at the same moment from behind one NAT address, 100 ms each way.

    The cap is what keeps one address from taking every handshake slot, so
    another address is served at once meanwhile. The crowd sees the cost:
    16 of the 32 get in, in four waves of four, and the rest fail with
    status 255, whatever --connect-timeout says.
    """
    crowd = make_client("alice", authorize_as="alice")
    link = make_link("server:2222", delay_ms=CROWD_DELAY_MS)
    crowd.pin(link.host, server.fp, port=link.port)
    options = ("--connect-timeout", str(connect_timeout))
    since = server.cursor()
    burst = Burst(
        crowd.node,
        [crowd.argv("netsim", "echo", f"CROWD-{i}", port=link.port, options=options) for i in range(CROWD)],
        user=crowd.user,
    )
    burst.wait_launched()
    time.sleep(0.3)  # the first four are in their handshakes now
    begin = time.monotonic()
    r = alice.run("server", "echo", "ELSEWHERE")
    elsewhere = time.monotonic() - begin
    results = burst.wait(timeout=connect_timeout + 30)
    time.sleep(1.5)  # the last batch of refusals reaches the journal
    journal = server.journal(since)

    logged_in = [x.took for i, x in enumerate(results) if x.rc == 0 and x.out == f"CROWD-{i}\n"]
    failed = [x for x in results if x.rc != 0]
    groups = waves(logged_in)
    print(
        f"timeout {connect_timeout}s: in at {[[round(t, 2) for t in g] for g in groups]}; "
        f"{len(failed)} failed after {sorted({round(x.took, 1) for x in failed})}s: "
        f"{sorted({x.err.strip() for x in failed})}; another address served in {elsewhere:.2f}s"
    )
    assert r.rc == 0 and r.stdout == "ELSEWHERE\n", r.describe()
    assert elsewhere < 2, f"another address waited {elsewhere:.1f}s"
    assert all(len(g) <= PER_SOURCE_HANDSHAKES for g in groups), groups
    assert len(logged_in) == PER_SOURCE_HANDSHAKES * RESENDS_THAT_COUNT, groups
    assert len(logged_in) + len(failed) == CROWD, results
    for x in failed:
        assert x.rc == 255 and x.out == "", x
        if connect_timeout == 10:
            assert f"timed out after {connect_timeout}s" in x.err, x
        else:
            # The server refused the expired token: the client's own timer had not run out.
            assert x.took < connect_timeout - 2 and f"timed out after {connect_timeout}s" not in x.err, x
    assert journal.count(f"(key `{crowd.entry}`)") == len(logged_in), journal
    # Refusals come in batches, at most one line a second.
    refused = [int(n) for n in re.findall(r"refused (\d+) connection\(s\) over the concurrency limit", journal)]
    assert sum(refused) >= len(failed) and len(refused) <= connect_timeout + 3, journal


# quinn-proto 0.11's default stream receive window: 12,500 kB/s at an expected
# 100 ms round trip (TransportConfig::default). src/net.rs raises it to 8 MiB
# (STREAM_WINDOW), and the connection's windows to 32 MiB, so that one stream
# can fill a long fat path. A sender can never have more than a window of a
# stream in flight, so a window caps a stream at window / RTT.
QUINN_DEFAULT_STREAM_WINDOW = 1_250_000
LONG_FAT_DELAY_MS = 200  # each way: a 400 ms round trip
LONG_FAT_RTT = 2 * LONG_FAT_DELAY_MS / 1000
DEFAULT_WINDOW_CEILING = QUINN_DEFAULT_STREAM_WINDOW / LONG_FAT_RTT  # 3.1 MB/s
LONG_FAT_COUNT = 15_000_000  # `seq 1 15000000` writes 123.9 MB

# Reads a stream to its end, hashes it, and notes when the first byte and each
# quarter arrived, so the rate can be measured after slow start is over.
METER = """
import hashlib, json, sys, time
total = int(sys.argv[1])
digest, got, marks = hashlib.sha256(), 0, []
while chunk := sys.stdin.buffer.read1(1 << 20):
    if not marks:
        marks.append(time.monotonic())
    digest.update(chunk)
    got += len(chunk)
    while len(marks) < 5 and got >= total * len(marks) / 4:
        marks.append(time.monotonic())
print(json.dumps({"bytes": got, "sha256": digest.hexdigest(), "marks": marks}))
"""


def seq_bytes(count: int) -> int:
    """How many bytes `seq 1 COUNT` writes."""
    total, digits, low = 0, 1, 1
    while low <= count:
        high = min(count, 10**digits - 1)
        total += (high - low + 1) * (digits + 1)
        low, digits = 10**digits, digits + 1
    return total


@pytest.mark.plan("LOAD-07")
@pytest.mark.parametrize("direction", ["down", "up"])
def test_throughput_on_a_long_fat_path_beats_the_default_window(direction, alice, server, make_link):
    """124 MB across a 400 ms round trip: more in flight than quinn's default window allows.

    With the default 1.25 MB stream window no sender can have more than
    1.25 MB in flight, so no stream can beat 3.1 MB/s on this path however
    fast the path is. Everything in netsim's delay is in flight, so the most
    it ever held shows how far the window really opened. "down" goes through
    the server's output queue, "up" through the remote process's stdin.
    """
    link = make_link("server:2222", delay_ms=LONG_FAT_DELAY_MS)
    alice.pin(link.host, server.fp, port=link.port)
    total = seq_bytes(LONG_FAT_COUNT)
    want = alice.shell(f"seq 1 {LONG_FAT_COUNT} | sha256sum").stdout.split()[0]
    meter = ("python3", "-c", METER, str(total))
    if direction == "down":
        remote = alice.argv("netsim", "seq", "1", str(LONG_FAT_COUNT), port=link.port)
        script = f"{shlex.join(remote)} | {shlex.join(meter)}"
    else:
        remote = alice.argv("netsim", *meter, port=link.port)
        script = f"seq 1 {LONG_FAT_COUNT} | {shlex.join(remote)}"
    r = alice.shell(script, timeout=180, check=False)
    assert r.rc == 0, r.describe()
    got = json.loads(r.stdout)
    assert got["bytes"] == total and got["sha256"] == want, got
    marks = got["marks"]
    # The last three quarters: slow start on a 400 ms path takes seconds.
    steady = total * 3 / 4 / (marks[4] - marks[1])
    held = link.stats()["stats"][direction]["max_delayed"]
    print(
        f"{direction}: {total / (marks[4] - marks[0]) / 1e6:.1f} MB/s overall, {steady / 1e6:.1f} MB/s"
        f" over the last three quarters, at most {held / 1e6:.2f} MB in netsim's delay at once"
    )
    # Twice what a default window could ever put there, QUIC's overhead and all.
    assert held > 2 * QUINN_DEFAULT_STREAM_WINDOW, f"at most {held} bytes in flight one way"
    # A default window ran at 90% of its ceiling; a busy host slows this one.
    assert steady > 1.3 * DEFAULT_WINDOW_CEILING, f"{steady / 1e6:.1f} MB/s"
