"""LOAD: many sessions, the per-key budgets, and staying healthy afterwards."""

from __future__ import annotations

import hashlib
import time

import pytest


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
