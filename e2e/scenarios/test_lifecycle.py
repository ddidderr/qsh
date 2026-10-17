"""LIFE: what happens to remote processes when sessions end, cleanly or not."""

from __future__ import annotations

import re
import signal
import time
from contextlib import contextmanager

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


# ---------------------------------------------------------------- LIFE-09
#
# How long the server reads a PTY after the shell has exited (DRAIN_GRACE in
# src/server.rs), and what the README promises for it: "the session waits two
# seconds for the rest of the output and then finishes anyway".
PTY_DRAIN_GRACE = 2


def exit_past_a_chatty_job(
    client, server, job: str, output: str, process: str, *, stall: float = 0
) -> tuple[int, float, float, str]:
    """`job &` in an interactive shell, then `exit 5`.

    Returns qsh's status, the seconds from `exit` until it ended, the seconds
    it stayed after its last output, and the tail of that output. `output` is
    a line the job prints and its echoed command line cannot contain;
    `process` is the job's command line on the server, which is stopped
    afterwards: an ordinary key may leave it running, and nothing else ends
    it. For `stall` seconds after `exit` the local terminal reads nothing.
    """
    term = Terminal(client, server.host, timeout=30)
    try:
        term.set_prompt()
        term.sendline(f"{job} &")
        term.expect(rf"\n{re.escape(output)}\r?\n")
        begin = time.monotonic()
        term.sendline("exit 5")
        time.sleep(stall)
        status, tail, quiet = term.drain_exit(timeout=60)
        return status, time.monotonic() - begin, quiet, tail
    finally:
        term.close()
        server.node.run(["pkill", "-u", client.user, "-f", "^" + re.escape(process)])


@pytest.mark.plan("LIFE-09")
def test_interactive_exit_past_a_background_job_that_keeps_writing(alice, server):
    """The shell exits while a job it put in the background writes on.

    The job keeps the terminal open, so the server stops reading it after
    the drain grace and reports the shell's status. Twenty lines a second:
    every chunk is on its way to the client long before the next one.
    """
    status, took, _, tail = exit_past_a_chatty_job(
        alice,
        server,
        "sh -c 'while :; do printf \"chatter-%s\\n\" 9090; sleep 0.05; done'",
        "chatter-9090",
        'sh -c while :; do printf "chatter-%s\\n" 9090;',
    )
    assert status == 5, tail
    assert "could not be delivered" not in tail, tail
    assert took < PTY_DRAIN_GRACE + 3, f"exit took {took:.1f}s"


@pytest.mark.plan("LIFE-09")
@pytest.mark.xfail(
    strict=True,
    reason="FXX-LIFE-09: a job that outwrites the terminal turns the exit into status 255 after 6-10 s",
)
def test_interactive_exit_past_a_background_job_that_floods_the_terminal(alice, server):
    """The same, with a job that writes faster than the terminal reads.

    The terminal reads nothing until the drain grace is over, as one that
    cannot keep up would, so the server's output queue is full when the grace
    runs out and it holds a chunk read but not yet queued. That is output
    after the shell's exit, which the README says the session does not wait
    for: it must not turn into a failed session, nor keep qsh after the
    output already on its way has arrived.
    """
    status, took, quiet, tail = exit_past_a_chatty_job(
        alice, server, "yes chatter-$((9190 + 1))", "chatter-9191", "yes chatter-9191", stall=PTY_DRAIN_GRACE + 0.5
    )
    print(f"exit took {took:.1f}s, {quiet:.1f}s of it after the last output")
    assert "could not be delivered" not in tail, tail[-300:]
    assert status == 5, tail[-300:]
    assert quiet < 1.5, f"qsh stayed {quiet:.1f}s after its last output"


# ---------------------------------------------------------------- LIFE-10


@contextmanager
def a_session_running(client, server, marker: str, *, terminal: bool):
    """A session on `server` whose remote job is `sleep <marker>`.

    Yields the local qsh's command line and a function that waits for it to
    exit and returns its status. With `terminal`, it is an interactive shell
    with the job in the foreground; otherwise a plain `qsh host sleep ...`.
    """
    if terminal:
        term = Terminal(client, server.host, timeout=30)
        argv, wait = term.argv, term.wait_exit
    else:
        argv = client.argv(server.host, "sleep", marker)
        proc = client.node.popen(argv, user=client.user)

        def wait(timeout: float) -> int:
            return proc.wait(timeout=timeout)

    try:
        if terminal:
            term.set_prompt()
            term.sendline(f"sleep {marker}")
        server.node.wait_running(f"sleep {marker}", timeout=15)
        yield argv, wait
    finally:
        if terminal:
            term.close()
        else:
            client.node.kill_command(client.user, argv)
            proc.wait(timeout=10)
        server.node.run(["pkill", "-u", client.user, "-f", f"^sleep {marker}$"])


@pytest.mark.plan("LIFE-10")
@pytest.mark.parametrize("terminal", [True, False], ids=["terminal", "command"])
def test_a_hangup_ends_qsh_at_once_and_the_idle_timeout_ends_its_job(alice_fast, fast_server, terminal):
    """A closed terminal window: SIGHUP for qsh, interactive or not.

    qsh exits at once with 128+1 (the terminal case restores the local
    terminal first, PTY-15), and the server cleans up the remote job within
    its idle timeout, as for a killed client (LIFE-01).
    """
    marker = "7070.25" if terminal else "7070.5"
    with a_session_running(alice_fast, fast_server, marker, terminal=terminal) as (argv, wait):
        begin = time.monotonic()
        assert alice_fast.node.kill_command("alice", argv, "HUP"), "no qsh to signal"
        assert wait(timeout=10) == 128 + signal.SIGHUP
        assert time.monotonic() - begin < 2, "qsh did not exit at once"
        fast_server.node.wait_gone(f"sleep {marker}", timeout=FAST_IDLE_TIMEOUT + 15)
        assert time.monotonic() - begin < FAST_IDLE_TIMEOUT + 10


@pytest.mark.plan("LIFE-10")
@pytest.mark.xfail(
    strict=True,
    reason="FXX-LIFE-10: qsh ends on a signal without a CONNECTION_CLOSE; the job lives on for the idle timeout",
)
@pytest.mark.parametrize(
    "terminal,name",
    [
        *(pytest.param(True, n, id=f"terminal-{n}") for n in ("HUP", "TERM", "INT", "QUIT", "USR1", "USR2", "ALRM", "VTALRM")),
        *(pytest.param(False, n, id=f"command-{n}") for n in ("HUP", "USR1")),
    ],
)
def test_a_signal_that_ends_qsh_ends_the_remote_job_at_once(alice_fast, fast_server, terminal, name):
    """qsh tells the server it is leaving, so the job does not wait out the idle timeout.

    In a terminal qsh catches TERM, HUP, QUIT, INT, USR1, USR2 and ALRM,
    restores the terminal and exits (src/client.rs `restore_on_fire`);
    VTALRM stands for the terminating signals it does not catch. Without a
    terminal only INT and TERM are caught, and relayed (EXEC-22); HUP and
    USR1 take their default action. ssh closes its TCP connection on all of
    these, and sshd ends the session at once.
    """
    number = signal.Signals[f"SIG{name}"].value
    marker = f"{7171 if terminal else 7272}.{number:02d}5"
    with a_session_running(alice_fast, fast_server, marker, terminal=terminal) as (argv, wait):
        assert alice_fast.node.kill_command("alice", argv, name), "no qsh to signal"
        wait(timeout=10)
        # Well under server2's 8 s idle timeout: a close arrives at once.
        fast_server.node.wait_gone(f"sleep {marker}", timeout=3)
