"""LIFE: what happens to remote processes when sessions end, cleanly or not."""

from __future__ import annotations

import re
import signal
import time
from contextlib import contextmanager

import pytest

from conftest import FAST_IDLE_TIMEOUT
from harness.qsh import unique
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

    The job keeps the terminal open and never leaves it quiet for the 100 ms
    that would end the session at once, so the server stops reading it at
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
    reason="F25: a job that outwrites the terminal turns the exit into status 255 after about 6 s",
)
def test_interactive_exit_past_a_background_job_that_floods_the_terminal(alice, server):
    """The same, with a job that writes faster than the terminal reads.

    `yes` outwrites the path whatever reads it: with this terminal read at
    full speed the exit already failed in most runs. Here the terminal reads
    nothing until the drain grace is over, as one that cannot keep up would,
    which makes it fail every time: the server's output queue is full when
    the grace runs out and it holds a chunk read but not yet queued. That is
    output after the shell's exit, which the README says the session does
    not wait for: it must not turn into a failed session, nor keep qsh after
    the output already on its way has arrived.
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
        # With SIGHUP at its default, as a login shell leaves it: `docker exec`
        # now and then starts a process with it ignored (e2e/README.md).
        proc = client.node.popen(["env", "--default-signal=HUP", *argv], user=client.user)

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
def test_a_hangup_ends_qsh_and_its_job_at_once(alice_fast, fast_server, terminal):
    """A closed terminal window: SIGHUP for qsh, interactive or not.

    qsh exits at once with 128+1 (the terminal case restores the local
    terminal first, PTY-15). It closes the connection on its way out, so the
    server ends the remote job at once, not at its idle timeout as for a
    killed client (LIFE-01).
    """
    marker = "7070.25" if terminal else "7070.5"
    with a_session_running(alice_fast, fast_server, marker, terminal=terminal) as (argv, wait):
        begin = time.monotonic()
        assert alice_fast.node.kill_command("alice", argv, "HUP"), "no qsh to signal"
        assert wait(timeout=10) == 128 + signal.SIGHUP
        assert time.monotonic() - begin < 2, "qsh did not exit at once"
        fast_server.node.wait_gone(f"sleep {marker}", timeout=3)


@pytest.mark.plan("LIFE-10")
@pytest.mark.parametrize(
    "terminal,name",
    [
        *(pytest.param(True, n, id=f"terminal-{n}") for n in ("HUP", "TERM", "INT", "QUIT", "USR1", "USR2", "ALRM", "VTALRM")),
        *(pytest.param(False, n, id=f"command-{n}") for n in ("HUP", "QUIT", "USR1", "ALRM", "VTALRM")),
    ],
)
def test_a_signal_that_ends_qsh_ends_the_remote_job_at_once(alice_fast, fast_server, terminal, name):
    """qsh tells the server it is leaving, so the job does not wait out the idle timeout.

    qsh catches every signal whose default action would end it, except the
    faults and TRAP (src/client.rs `FatalSignals`). The session then ends
    the ordinary way: the terminal is restored and the connection closed
    before qsh exits. Without a terminal, INT and TERM are relayed instead
    (EXEC-22), so they are not here. ssh closes its TCP connection on HUP,
    INT, QUIT and TERM, and the kernel closes it on any other death, so sshd
    ends the session at once too.
    """
    number = signal.Signals[f"SIG{name}"].value
    marker = f"{7171 if terminal else 7272}.{number:02d}5"
    with a_session_running(alice_fast, fast_server, marker, terminal=terminal) as (argv, wait):
        begin = time.monotonic()
        assert alice_fast.node.kill_command("alice", argv, name), "no qsh to signal"
        # Still 128+n, the status the README gives a death by signal n.
        assert wait(timeout=10) == 128 + number
        # Well under server2's 8 s idle timeout: a close arrives at once.
        fast_server.node.wait_gone(f"sleep {marker}", timeout=3)
        print(f"the job was gone {time.monotonic() - begin:.1f}s after SIG{name}")


@pytest.mark.plan("LIFE-10")
@pytest.mark.xfail(
    strict=True,
    reason="F34: without a terminal qsh only relays INT, so on a dead path Ctrl-C waits out the idle timeout",
)
def test_ctrl_c_ends_a_command_whose_path_has_gone_dark(alice_fast, fast_server, make_link):
    """Ctrl-C, pressed until something happens, ends qsh even when the server cannot hear it.

    Without a terminal qsh relays INT and TERM to the remote command instead
    of exiting (EXEC-22), so that the command can clean up and its status
    becomes qsh's. When the path has gone dark the relayed signal never
    arrives, and nothing else ends qsh before its idle timeout: 8 s on
    server2, 60 s on a default server. ssh exits on the first INT. Proposed:
    an INT or TERM that arrives while an earlier one is still unanswered
    ends qsh locally, with 128+n, so pressing Ctrl-C again gets the user out.
    """
    link = make_link("server2:2222")
    alice_fast.pin(link.host, fast_server.fp, port=link.port)
    marker = "7373.25"
    argv = alice_fast.argv(link.host, "sleep", marker, port=link.port)
    proc = alice_fast.node.popen(argv, user="alice")
    try:
        fast_server.node.wait_running(f"sleep {marker}", timeout=15)
        link.blackhole(True)
        begin = time.monotonic()
        assert alice_fast.node.kill_command("alice", argv, "INT"), "no qsh to signal"
        for _ in range(2):
            time.sleep(1)
            if proc.poll() is None:
                alice_fast.node.kill_command("alice", argv, "INT")
        status = proc.wait(timeout=FAST_IDLE_TIMEOUT + 15)
        took = time.monotonic() - begin
    finally:
        if proc.poll() is None:
            alice_fast.node.kill_command("alice", argv)
            proc.wait(timeout=10)
        alice_fast.subcommand("known-hosts", "remove", f"{link.host}:{link.port}")
        fast_server.node.run(["pkill", "-u", "alice", "-f", f"^sleep {marker}$"])
    print(f"qsh ended {took:.1f}s after the first Ctrl-C, status {status}")
    # Well before server2's 8 s idle timeout, and before a fourth Ctrl-C would come.
    assert took < 5, f"qsh ended {took:.1f}s after the first Ctrl-C"
    assert status == 128 + signal.SIGINT


@pytest.mark.plan("LIFE-10")
def test_nohup_keeps_a_command_and_its_job_through_a_hangup(alice_fast, fast_server):
    """`nohup qsh host cmd`: a hangup that qsh was started to ignore stays ignored.

    Without a terminal qsh ends on HUP like on the other signals above, but
    only when HUP was not ignored when it started.
    """
    marker = "7474.25"
    argv = alice_fast.argv("server2", "sleep", marker)
    proc = alice_fast.node.popen(["nohup", *argv], user="alice")
    try:
        fast_server.node.wait_running(f"sleep {marker}", timeout=15)
        assert alice_fast.node.kill_command("alice", argv, "HUP"), "no qsh to signal"
        time.sleep(2)
        assert proc.poll() is None, f"qsh ended with {proc.returncode} on a hangup it was told to ignore"
        assert fast_server.node.pids(f"sleep {marker}"), "the remote job ended"
    finally:
        alice_fast.node.kill_command("alice", argv)
        proc.wait(timeout=10)
        fast_server.node.run(["pkill", "-u", "alice", "-f", f"^sleep {marker}$"])


# ---------------------------------------------------------------- LIFE-11


# What LIFE-11 sends, and what is left of it when an outage cuts it.
RSYNC_SIZE = 32 * 1024 * 1024


@pytest.mark.plan("LIFE-11")
@pytest.mark.parametrize(
    "partial,survives",
    [
        pytest.param(("-P",), False, id="partial"),
        pytest.param(("-P", "--partial-dir=.rsync-partial"), True, id="partial-dir"),
    ],
)
def test_an_rsync_retried_at_once_meets_the_old_receivers_cleanup(alice_fast, fast_server, make_link, partial, survives):
    """An upload is cut by an outage, stopped with Ctrl-C, and re-run at once.

    The old receiver on server2 cannot hear that its client is gone: it lives
    until the idle timeout, then gets SIGHUP and an end of input, and rsync's
    `--partial` cleanup moves the file it was writing to the destination
    name, or with `--partial-dir` into that directory. That is rsync's doing,
    on any transport whose server side outlives its client: under ssh the old
    receiver lives until TCP gives up, minutes to hours later. What qsh adds
    is the bound, the idle timeout, which this pins, together with what the
    README is to say about it: with `-P` alone the partial replaces a retry
    that finished in the meantime; with `--partial-dir` the retry's result
    stays. A change that ended abandoned sessions some other way, or never,
    fails one of the two. The first run is throttled so that the outage lands
    part way through, whatever the host's speed; the retry runs at full speed.
    """
    name = unique("retry")
    local, remote = f"/home/alice/{name}-local", f"/home/alice/{name}-remote"
    link = make_link("server2:2222")
    alice_fast.pin(link.host, fast_server.fp, port=link.port)
    qsh = f"{alice_fast.qsh_command} -p {link.port}"
    # The first run passes --bwlimit to its receiver, which tells it apart.
    old_receiver = f"^rsync --server .*--bwlimit=.* {re.escape(remote)}/$"
    first = None
    try:
        alice_fast.shell(f"mkdir -p {local} && head -c {RSYNC_SIZE} /dev/urandom > {local}/large.bin")
        fast_server.node.run(["mkdir", "-p", remote], user="alice", check=True)
        want = alice_fast.node.run(["sha256sum", f"{local}/large.bin"], check=True).stdout.split()[0]
        # In a session of its own, so that a Ctrl-C reaches rsync and its qsh
        # alike, as a terminal's would.
        first = alice_fast.node.popen(
            ["setsid", "--wait", "rsync", "-e", qsh, *partial, "--bwlimit=2m", f"{local}/large.bin", f"netsim:{remote}/"],
            user="alice",
        )
        fast_server.node.wait_for(f"find {remote} -maxdepth 1 -name '.large.bin.*' -size +4M | grep -q .", timeout=60)
        link.blackhole(True)
        outage = time.monotonic()
        (leader,) = alice_fast.node.pids(f"rsync -e {qsh} ")
        alice_fast.node.run(["kill", "-INT", "--", f"-{leader}"], check=True)
        _, err = first.communicate(timeout=30)
        assert first.returncode != 0, f"the interrupted rsync reported success: {err.decode()}"

        out = alice_fast.node.run(
            ["rsync", "-e", alice_fast.qsh_command, *partial, f"{local}/large.bin", f"server2:{remote}/"],
            user="alice",
            timeout=120,
        )
        assert out.rc == 0, out.describe()
        if fast_server.node.run(["pgrep", "-u", "alice", "-f", old_receiver]).rc != 0:
            pytest.skip("the old receiver was gone before the retry finished; nothing to race")
        got = fast_server.node.run(["sha256sum", f"{remote}/large.bin"], check=True).stdout.split()[0]
        assert got == want, "the retry did not produce the file"

        fast_server.node.wait_for(f"! pgrep -u alice -f '{old_receiver}'", timeout=FAST_IDLE_TIMEOUT + 15)
        cleaned = time.monotonic() - outage
        print(f"the old receiver was cleaned up {cleaned:.1f}s after the outage")
        assert cleaned < FAST_IDLE_TIMEOUT + 10, f"the old receiver lived {cleaned:.1f}s after the outage"
        # And the first qsh, which waits out its own idle timeout.
        alice_fast.node.wait_gone(f"qsh -p {link.port} netsim rsync", timeout=FAST_IDLE_TIMEOUT + 15)
        size = int(fast_server.node.run(["stat", "-c", "%s", f"{remote}/large.bin"], check=True).stdout)
        got = fast_server.node.run(["sha256sum", f"{remote}/large.bin"], check=True).stdout.split()[0]
        if survives:
            assert got == want, f"after the old receiver's cleanup the destination has {size} of {RSYNC_SIZE} bytes"
            kept = fast_server.node.run(["stat", "-c", "%s", f"{remote}/.rsync-partial/large.bin"])
            assert kept.rc == 0 and 0 < int(kept.stdout) < RSYNC_SIZE, f"no partial in .rsync-partial/: {kept.describe()}"
        else:
            # The hazard the README is to describe: the old partial, in place
            # of the retry's complete file.
            assert got != want and 0 < size < RSYNC_SIZE, f"the destination has {size} of {RSYNC_SIZE} bytes"
    finally:
        if first is not None and first.poll() is None:
            alice_fast.node.run(["pkill", "-u", "alice", "-f", f"^rsync -e {re.escape(qsh)} "])
            first.wait(timeout=10)
        alice_fast.node.run(["rm", "-rf", local])
        fast_server.node.run(["rm", "-rf", remote])
