"""LIFE: what happens to remote processes when sessions end, cleanly or not."""

from __future__ import annotations

import re
import time

import pytest

from conftest import FAST_IDLE_TIMEOUT
from harness.terminal import Terminal

CGROUP_ROOT = "/sys/fs/cgroup/system.slice/qsh-server.service"


@pytest.mark.plan("LIFE-01")
def test_a_killed_client_does_not_strand_its_remote_job(alice_fast, fast_server):
    marker = "6161.25"
    proc = alice_fast.node.popen(alice_fast.argv("server2", "sleep", marker), user="alice")
    fast_server.node.wait_running(f"sleep {marker}", timeout=10)
    # SIGKILL the qsh process itself, inside the client container: no goodbye.
    alice_fast.node.run(["pkill", "-KILL", "-u", "alice", "-f", f"^qsh server2 sleep {marker}"], check=True)
    proc.wait(timeout=10)
    begin = time.monotonic()
    fast_server.node.wait_gone(f"sleep {marker}", timeout=FAST_IDLE_TIMEOUT + 15)
    assert time.monotonic() - begin < FAST_IDLE_TIMEOUT + 10


@pytest.mark.plan("LIFE-02")
def test_an_ordinary_key_may_leave_a_detached_job(alice, server):
    """Documented trade-off: work that left the session's process group survives."""
    marker = "6262.25"
    r = alice.run("server", "sh", "-c", f"setsid sleep {marker} > /dev/null 2>&1 < /dev/null & echo started")
    assert r.rc == 0 and r.stdout.strip() == "started", r.describe()
    try:
        time.sleep(2)
        assert server.node.pids(f"sleep {marker}"), "the detached job did not survive"
    finally:
        server.node.run(["pkill", "-f", f"^sleep {marker}$"])


@pytest.mark.plan("LIFE-03")
def test_a_background_writer_keeps_the_session_open_like_ssh(alice):
    """A job still holding stdout is still producing the caller's output."""
    begin = time.monotonic()
    r = alice.run("server", "sh", "-c", "(sleep 3; echo late) & echo early")
    took = time.monotonic() - begin
    assert r.rc == 0, r.describe()
    assert r.stdout.split() == ["early", "late"]
    assert took >= 3


@pytest.mark.plan("LIFE-04")
def test_restricted_key_kills_every_descendant_at_session_end(make_client, server):
    """--kill-session-processes: even setsid'd, double-forked work dies."""
    restricted = make_client("alice", authorize_as="alice", options=("--kill-session-processes",))
    marker = "6363.25"
    script = f"setsid sh -c 'sleep {marker} & exit' > /dev/null 2>&1 < /dev/null; echo detached"
    r = restricted.run("server", "sh", "-c", script)
    assert r.rc == 0 and r.stdout.strip() == "detached", r.describe()
    server.node.wait_gone(f"sleep {marker}", timeout=10)
    # And nothing is left behind in the delegated cgroup tree, which must
    # exist, or the check below would pass for a wrong path.
    assert server.node.exists(f"{CGROUP_ROOT}/qsh-restricted"), "no qsh-restricted cgroup"
    server.node.wait_for(f"! ls -d {CGROUP_ROOT}/qsh-restricted/session-* 2>/dev/null", timeout=10)


@pytest.mark.plan("LIFE-05")
def test_restricted_key_kills_descendants_when_the_client_vanishes(make_client, fast_server):
    restricted = make_client("alice", authorize_as="alice", options=("--kill-session-processes",), on=fast_server)
    marker = "6464.25"
    script = f"setsid sleep {marker} > /dev/null 2>&1 < /dev/null & exec sleep {marker}1"
    proc = restricted.node.popen(restricted.argv("server2", "sh", "-c", script), user="alice")
    fast_server.node.wait_running(f"sleep {marker}1", timeout=10)
    restricted.node.run(["pkill", "-KILL", "-u", "alice", "-f", f"^qsh -i {restricted.identity} server2"], check=True)
    proc.wait(timeout=10)
    fast_server.node.wait_gone(f"sleep {marker}", timeout=FAST_IDLE_TIMEOUT + 15)


@pytest.mark.plan("LIFE-06")
def test_restricted_sessions_cannot_gain_privileges(make_client, alice, server):
    restricted = make_client("alice", authorize_as="alice", options=("--kill-session-processes",))
    r = restricted.run("server", "grep", "NoNewPrivs", "/proc/self/status")
    assert r.stdout.split() == ["NoNewPrivs:", "1"], r.describe()
    r = alice.run("server", "grep", "NoNewPrivs", "/proc/self/status")
    assert r.stdout.split() == ["NoNewPrivs:", "0"], r.describe()


@pytest.mark.plan("LIFE-07")
def test_restricted_session_runs_in_its_own_cgroup(make_client, server):
    restricted = make_client("alice", authorize_as="alice", options=("--kill-session-processes",))
    r = restricted.run("server", "cat", "/proc/self/cgroup")
    assert r.rc == 0, r.describe()
    assert "/qsh-restricted/session-" in r.stdout, r.stdout


@pytest.mark.plan("LIFE-09")
@pytest.mark.parametrize(
    "job",
    ["sleep 6666.25", "sh -c 'while :; do echo tick-6667; sleep 0.3; done'"],
    ids=["quiet", "chatty"],
)
def test_an_interactive_exit_returns_at_once_past_background_jobs(alice, server, job):
    """`exit` ends the session with the shell's status; the job keeps running."""
    running = job.replace("'", "")  # its command line, as pgrep sees it
    term = Terminal(alice, "server")
    try:
        term.set_prompt()
        term.sendline(f"{job} &")
        server.node.wait_running(running, timeout=10)
        begin = time.monotonic()
        term.sendline("echo bye; exit 7")
        term.expect(r"\nbye\r")
        assert term.wait_exit() == 7
        took = time.monotonic() - begin
    finally:
        term.close()
    try:
        assert took < 1.5, f"exit took {took:.2f}s"
        assert server.node.pids(running), "a normal exit ended the background job"
    finally:
        server.node.run(["pkill", "-f", "^" + re.escape(running)])


@pytest.mark.plan("LIFE-08")
def test_revoking_mid_session_kills_the_process_group(make_client, server):
    member = make_client("alice", authorize_as="alice")
    marker = "6565.25"
    proc = member.node.popen(member.argv("server", "sh", "-c", f"sleep {marker} & sleep {marker}1"), user="alice")
    server.node.wait_running(f"sleep {marker}1", timeout=10)
    server.revoke(member.entry, settle=False)
    proc.wait(timeout=30)
    # Both the leader and its same-group background child.
    server.node.wait_gone(f"sleep {marker}", timeout=10)
