"""OPS: installing, configuring and running qsh-server the documented way."""

from __future__ import annotations

import contextlib
import json
import re
import statistics
import subprocess
import time
from collections import Counter

import pytest

from conftest import FAST_IDLE_TIMEOUT
from harness.env import REPO_DIR, Unmet, docker
from harness.qsh import (
    PORT,
    PREVIOUS_QSH_SERVER,
    PREVIOUS_VERSION,
    RELOAD_SETTLE,
    QshClient,
    QshServer,
    parse_fingerprint,
    unique,
)
from harness.terminal import Terminal


def stat(node, path: str) -> str:
    """`mode owner group` of a path, e.g. `600 root root`."""
    return node.run(["stat", "-c", "%a %U %G", path], check=True).stdout.strip()


@pytest.mark.plan("OPS-01")
def test_root_keygen_lays_out_etc_qsh(server):
    node = server.node
    assert stat(node, "/etc/qsh/server.key") == "600 root root"
    assert stat(node, "/etc/qsh/server.crt").endswith("root root")
    assert node.exists("/etc/qsh/qsh-server.toml")
    mode = stat(node, "/etc/qsh/authorized").split()[0]
    assert int(mode, 8) & 0o022 == 0, f"authorized/ is group/world writable: {mode}"
    assert server.fingerprint() == server.fp
    again = server.admin("keygen", check=False)
    assert again.rc != 0 and "--force" in again.stderr, again.describe()


@pytest.mark.plan("OPS-02")
def test_the_shipped_unit_runs_the_server(server):
    show = server.node.run(
        ["systemctl", "show", server.unit, "--property=ActiveState,User,Delegate,KillMode,Restart"], check=True
    ).stdout
    props = dict(line.split("=", 1) for line in show.split())
    assert props == {
        "ActiveState": "active",
        "User": "root",
        "Delegate": "yes",
        "KillMode": "control-group",
        "Restart": "on-failure",
    }
    assert "listening on 0.0.0.0:2222" in server.journal()


@pytest.mark.plan("OPS-03")
def test_logins_are_logged_with_peer_key_and_account(alice, server, env):
    since = server.cursor()
    assert alice.run("server", "true").rc == 0
    ip = alice.node.ip
    server.wait_journal(rf"{ip.replace('.', '[.]')}:\d+ authenticated as `alice` \(key `alice-client1`\)", since)


@pytest.mark.plan("OPS-04")
def test_stop_ends_sessions_and_tells_clients_at_once(alice, server):
    """`systemctl stop` with a live session: the job dies and the client knows.

    `server` keeps the default 60 s idle timeout, so a client that is not told
    would sit on the dead session for a minute or more.
    """
    marker = "7171.25"
    proc = alice.node.popen(alice.argv("server", "sleep", marker), user="alice")
    server.node.wait_running(f"sleep {marker}", timeout=10)
    since = server.cursor()
    begin = time.monotonic()
    server.stop()
    try:
        assert time.monotonic() - begin < 10, "stopping the unit took too long"
        assert not server.node.pids(f"sleep {marker}")
        _, err = proc.communicate(timeout=60)
        assert proc.returncode == 255
        assert time.monotonic() - begin < 10, f"the client waited {time.monotonic() - begin:.0f}s to notice"
        assert "shutting down" in err.decode(), err.decode()
    finally:
        server.start()
    assert "shutting down" in server.journal(since)


@pytest.mark.plan("OPS-05")
def test_a_crashed_daemon_is_restarted_and_its_sessions_cleaned(alice_fast, fast_server):
    marker = "7272.25"
    proc = alice_fast.node.popen(alice_fast.argv("server2", "sleep", marker), user="alice")
    fast_server.node.wait_running(f"sleep {marker}", timeout=10)
    old = fast_server.main_pid()
    fast_server.node.run(["kill", "-KILL", str(old)], check=True)
    fast_server.node.wait_for(
        f"p=$(systemctl show -p MainPID --value {fast_server.unit}); [ \"$p\" != 0 ] && [ \"$p\" != {old} ]",
        timeout=20,
    )
    fast_server.wait_listening()
    # KillMode=control-group is the crash boundary for the session's job.
    assert not fast_server.node.pids(f"sleep {marker}")
    proc.kill()
    assert alice_fast.run("server2", "true").rc == 0


@pytest.mark.plan("OPS-06")
def test_the_configured_listen_address_is_used(alice_fast, fast_server):
    conf = "/etc/qsh/qsh-server.toml"
    original = fast_server.node.read(conf)
    fast_server.node.write(conf, original.replace(b"0.0.0.0:2222", b"0.0.0.0:2400"))
    try:
        fast_server.node.run(["systemctl", "restart", fast_server.unit], check=True)
        fast_server.wait_listening(port=2400)
        alice_fast.pin(fast_server.host, fast_server.fp, port=2400)
        r = alice_fast.run("server2", "hostname", port=2400)
        assert r.rc == 0 and r.stdout.strip() == "server2", r.describe()
    finally:
        fast_server.node.write(conf, original)
        fast_server.restart()


@pytest.mark.plan("OPS-07")
def test_an_invalid_configuration_stops_startup_with_a_reason(fast_server):
    conf = "/etc/qsh/qsh-server.toml"
    original = fast_server.node.read(conf)
    since = fast_server.cursor()
    fast_server.node.write(conf, b"listen = \"not an address\"\n")
    try:
        fast_server.node.run(["systemctl", "restart", fast_server.unit])
        # Type=exec reports a successful start; the failure follows at once.
        fast_server.node.wait_for(f"! systemctl is-active --quiet {fast_server.unit}", timeout=20)
        journal = fast_server.journal(since)
        assert "`listen` is not a socket address" in journal, journal
    finally:
        fast_server.node.write(conf, original)
        fast_server.node.run(["systemctl", "reset-failed", fast_server.unit])
        fast_server.start()


@pytest.mark.plan("OPS-08")
def test_an_explicit_missing_config_fails_before_startup(server):
    r = server.node.run(["qsh-server", "serve", "--config", "/nonexistent.toml", "--listen", "127.0.0.1:0"], timeout=20)
    assert r.rc != 0, r.describe()
    assert "/nonexistent.toml" in r.stderr


@pytest.mark.plan("OPS-09")
def test_a_second_daemon_on_a_busy_port_fails_clearly(server):
    r = server.node.run(["qsh-server", "serve", "--listen", f"0.0.0.0:{PORT}"], timeout=20)
    assert r.rc != 0, r.describe()
    assert "in use" in r.stderr.lower(), r.describe()
    assert server.is_active()


@pytest.mark.plan("OPS-10")
def test_a_non_root_server_serves_only_its_own_account(make_client, server):
    """alice runs her own qsh-server from ~/.config/qsh-server on port 2300."""
    node = server.node
    own = QshServer(node, state_dir="/home/alice/.config/qsh-server")
    out = node.run(["qsh-server", "keygen"], user="alice", check=True).stdout
    fp = parse_fingerprint(out, "Host key: ")
    assert stat(node, "/home/alice/.config/qsh-server/server.key") == "600 alice alice"
    proc = node.popen(["qsh-server", "serve", "--listen", "0.0.0.0:2300"], user="alice")
    try:
        own.wait_listening(port=2300)
        mine = make_client("alice", pin=False)
        mine.pin("server", fp, port=2300)
        cert = mine.cert()
        node.write("/home/alice/mine.crt", cert, user="alice")
        node.run(["qsh-server", "authorize", "/home/alice/mine.crt", "--user", "alice", "--name", "mine"], user="alice", check=True)
        node.run(["qsh-server", "authorize", "/home/alice/mine.crt", "--user", "bob", "--name", "as-bob"], user="alice")
        time.sleep(2.5)
        r = mine.run("server", "id", "-un", port=2300)
        assert r.rc == 0 and r.stdout.strip() == "alice", r.describe()
        r = mine.run("bob@server", "id", "-un", port=2300)
        assert r.rc != 0, r.describe()
    finally:
        proc.kill()
        node.run(["pkill", "-u", "alice", "-f", "^qsh-server serve --listen 0.0.0.0:2300"])
        node.run(["rm", "-rf", "/home/alice/.config/qsh-server", "/home/alice/mine.crt"])


@pytest.mark.plan("OPS-11")
def test_rotating_the_host_key_is_refused_until_repinned(alice_fast, fast_server):
    old_fp = fast_server.fp
    new_fp = fast_server.keygen("--force")
    assert new_fp != old_fp
    fast_server.fp = new_fp
    fast_server.restart()
    try:
        r = alice_fast.run("server2", "true")
        assert r.rc == 255, r.describe()
        # Both keys, in the form `qsh-server fingerprint` prints, so the user
        # can compare them with one obtained out of band.
        assert old_fp in r.stderr and new_fp in r.stderr, r.describe()
        assert "known-hosts" in r.stderr and "remove" in r.stderr, r.describe()
    finally:
        # Later scenarios use alice's pin for server2: re-pin even on failure.
        alice_fast.subcommand("known-hosts", "remove", "server2:2222", check=False)
        alice_fast.pin("server2", new_fp)
    assert alice_fast.run("server2", "true").rc == 0


def unit_state(server: QshServer, *names: str) -> dict[str, str]:
    """Properties of the server's unit, as `systemctl show` reports them."""
    out = server.node.run(["systemctl", "show", server.unit, "--property=" + ",".join(names)], check=True).stdout
    return dict(line.split("=", 1) for line in out.splitlines() if "=" in line)


def bring_back(server: QshServer) -> None:
    """Start the unit again after a scenario stopped it, from whatever state it is in."""
    server.node.run(["systemctl", "reset-failed", server.unit])
    server.start()


# systemd's catalogue IDs for "<unit>: Deactivated successfully." and "<unit>:
# Failed with result ...", stable across versions and languages.
UNIT_SUCCESS = "7ad2d189f7e94e70a38c781354912448"
UNIT_FAILED = "d9b373ed55a64feb8242e02dbe79a49c"


def unit_verdicts(server: QshServer, since: str) -> Counter:
    """How often systemd logged each of those two verdicts on the unit after `since`."""
    out = server.node.run(
        ["journalctl", "--after-cursor", since, "-o", "export", f"UNIT={server.unit}.service"], check=True
    ).stdout
    found = re.findall(rf"^MESSAGE_ID=({UNIT_SUCCESS}|{UNIT_FAILED})$", out, re.M)
    return Counter("success" if message == UNIT_SUCCESS else "failed" for message in found)


SIGHUP_LINE = (
    "qsh-server: ignoring SIGHUP: there is nothing to reload; authorized/ is re-read every second, "
    "and other settings take effect on restart"
)


@pytest.mark.plan("OPS-12")
def test_sighup_is_logged_and_the_daemon_keeps_serving(alice_fast, fast_server):
    """SIGHUP is not a reload: qsh-server says so and carries on.

    qsh-server has nothing to reload on a signal: authorized/ is re-read
    every second, and qsh-server.toml, the host key and the command line
    only at startup. Decided 2026-10-18: SIGHUP is ignored, with one journal
    line that says so. An administrator's habitual `kill -HUP` must neither
    take the service down nor end a session. The unit has no `ExecReload=`,
    so `systemctl reload` is refused rather than turned into a signal.
    """
    node, unit = fast_server.node, fast_server.unit
    pid = fast_server.main_pid()
    r = node.run(["systemctl", "reload", unit])
    assert r.rc != 0, r.describe()
    assert unit_state(fast_server, "CanReload") == {"CanReload": "no"}
    assert fast_server.main_pid() == pid, "a refused reload must leave the daemon alone"

    # Longer than server2's idle timeout: a client left on a dead connection
    # would have given up by then.
    marker = f"{FAST_IDLE_TIMEOUT + 1}.7373"
    argv = alice_fast.argv("server2", "sh", "-c", f"sleep {marker}; echo still-served")
    proc = alice_fast.node.popen(argv, user="alice")
    since = fast_server.cursor()
    try:
        node.wait_running(f"sleep {marker}", timeout=10)
        node.run(["kill", "-HUP", str(pid)], check=True)
        fast_server.wait_journal(re.escape(SIGHUP_LINE), since, timeout=10)
        out, err = proc.communicate(timeout=30)
        assert proc.returncode == 0 and out.decode().strip() == "still-served", err.decode()
    finally:
        proc.kill()
        alice_fast.node.kill_command("alice", argv)
        if fast_server.main_pid() != pid:
            bring_back(fast_server)
    assert fast_server.main_pid() == pid, "SIGHUP replaced the daemon"
    assert unit_state(fast_server, "ActiveState", "SubState") == {"ActiveState": "active", "SubState": "running"}
    # systemd saw no exit at all, clean or not.
    assert unit_verdicts(fast_server, since) == Counter(), unit_verdicts(fast_server, since)
    assert alice_fast.run("server2", "true").rc == 0
    journal = fast_server.journal(since)
    assert journal.count(SIGHUP_LINE) == 1, journal
    assert "shutting down" not in journal, journal


# How a revoked key's running session ends on the client. The connection's
# once-a-second check closes it with the reason, "authorization withdrawn or
# expired", and logs the withdrawal. The session runs its own check on its
# own one-second tick, though, and when that one sees the reload first, the
# session is abandoned and its stream reset with RESET_ABANDONED (error 2)
# before the close: the client then reports only the reset, and if it closes
# the connection before the connection's check comes round, the withdrawal
# is never logged. Measured: 3 of 96 revocations. Either way the session
# ends. F30.
REVOKED = re.compile(r"withdrawn|stream reset by peer: error 2")


# OPS-13 reaches into the daemon's log socket from outside: pidfd_getfd
# (Linux 5.6) copies another process's descriptor, and the copy is the same
# socket, so a send buffer set through it is the daemon's own. SO_SNDBUFFORCE
# (32) goes past net.core.wmem_max, as systemd itself does for this socket.
SOCKET_BUFFER = r"""
import ctypes, os, socket, sys
pid, fd = int(sys.argv[1]), int(sys.argv[2])
libc = ctypes.CDLL(None, use_errno=True)
copy = libc.syscall(438, os.pidfd_open(pid), fd, 0)  # SYS_pidfd_getfd
if copy < 0:
    raise OSError(ctypes.get_errno(), "pidfd_getfd")
sock = socket.socket(fileno=copy)
if len(sys.argv) > 3:
    sock.setsockopt(socket.SOL_SOCKET, 32, int(sys.argv[3]))
print(sock.getsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF))
"""


class JournalStall:
    """systemd-journald stopped on a server, and qsh-server's log stream full.

    systemd connects the daemon's stdout and stderr to journald through a
    stream socket with an 8 MiB send buffer, which the kernel doubles. Each
    line is two writes (the text, then the newline) of about 770 bytes of
    socket memory each, so the buffer holds about 11,000 lines: filling it
    with logins would take a couple of minutes, close to journald's 3-minute
    watchdog. A stopped journald leaves that socket just as full whatever its
    size, so the stall shrinks this one socket's buffer to 8 KiB, and a few
    hundred lines then fill it and the daemon's 256-line queue behind it.
    Leaving puts the buffer back and resumes journald, whatever happened.
    Every step taken during a stall is bounded well inside the watchdog, so
    that a qsh that does block fails the scenario before journald is killed.
    """

    def __init__(self, server: QshServer) -> None:
        self.server = server
        self.node = server.node

    def __enter__(self) -> JournalStall:
        node = self.node
        self.pid = self.server.main_pid()
        task = node.run(["sh", "-c", f"grep -lx qsh-diagnostics /proc/{self.pid}/task/*/comm"], check=True).stdout
        self.writer = int(task.split("/")[4])
        link = node.run(["readlink", f"/proc/{self.pid}/fd/2"], check=True).stdout.strip()
        match = re.fullmatch(r"socket:\[(\d+)\]", link)
        assert match, f"qsh-server's stderr is {link}, not journald's stream socket"
        self.inode = match.group(1)
        self.journald = node.run(["pidof", "systemd-journald"], check=True).stdout.strip()
        node.run(["kill", "-STOP", self.journald], check=True)
        try:
            self.buffer = int(self._send_buffer().stdout)
            self._send_buffer(4096)
        except BaseException:
            node.run(["kill", "-CONT", self.journald])
            raise
        return self

    def __exit__(self, *exc) -> None:
        try:
            if self.node.exists(f"/proc/{self.pid}/task/{self.writer}"):
                # The kernel doubles what it is given.
                self._send_buffer(self.buffer // 2)
        finally:
            if self.node.run(["kill", "-CONT", self.journald]).rc != 0:
                # journald's watchdog killed it and systemd started another.
                # The daemon's stream died with the old one: give it a new
                # one, or later scenarios find nothing in server2's journal.
                self.server.restart()
                raise AssertionError("journald stayed stopped past its 3-minute watchdog")

    def _send_buffer(self, size: int | None = None):
        argv = ["python3", "-c", SOCKET_BUFFER, str(self.pid), "2"]
        return self.node.run([*argv, str(size)] if size else argv, check=True)

    def writer_blocked(self) -> tuple[bool, str]:
        """Whether the diagnostics writer is stuck writing to journald, and the evidence.

        Asleep in a system call on descriptor 2, with the socket's queued
        memory at its send buffer: a full stream, not an idle writer (which
        waits on its queue, a futex).
        """
        task = f"/proc/{self.pid}/task/{self.writer}"
        state = self.node.read(f"{task}/stat").decode().rsplit(")", 1)[1].split()[0]
        syscall = self.node.read(f"{task}/syscall").decode().split()
        wchan = self.node.read(f"{task}/wchan").decode()
        sockets = self.node.run(["ss", "-xmH"], check=True).stdout
        match = re.search(rf"\*\s+{self.inode}\s+\*\s+\d+.*?skmem:\(r\d+,rb\d+,t(\d+),tb(\d+)", sockets)
        queued, limit = (int(n) for n in match.groups()) if match else (0, 0)
        evidence = (
            f"qsh-diagnostics thread {self.writer}: state {state}, syscall {' '.join(syscall[:2])}, "
            f"wchan {wchan}; stderr socket {queued} of {limit} bytes queued"
        )
        return state == "S" and syscall[1:2] == ["0x2"] and limit > 0 and queued >= limit, evidence


def login_burst(client: QshClient, host: str, rounds: int, parallel: int = 4) -> tuple[int, int]:
    """Log in 2 x `rounds` times in each of `parallel` loops; half the sessions are refused.

    Every connection writes a login line before its session is judged, and
    each refusal (the key is alice's, the request is for bob) adds a session
    error under the 16-a-second peer budget. Returns how many connections
    authenticated and how many of their sessions were refused. Four loops,
    because one address may hold only four handshakes at once. Bounded at a
    minute, which is ten times what it takes.
    """
    qsh = client.qsh_command
    script = (
        f"for j in $(seq {parallel}); do ( for i in $(seq {rounds}); do "
        f"{qsh} {host} true >/dev/null 2>&1; echo $?; "
        f"{qsh} -l bob {host} true >/dev/null 2>&1; echo $?; "
        "done ) & done; wait"
    )
    # Plain bash, not `shell`: a refused session must not end its loop.
    r = client.node.run(["bash", "-c", script], user=client.user, timeout=60, check=True)
    codes = Counter(r.stdout.split())
    assert set(codes) <= {"0", "126"}, f"sessions failed during the burst: {codes}"
    return codes["0"] + codes["126"], codes["126"]


# Lines the daemon's queue may drop that OPS-13 does not tally one by one:
# the once-a-second admission summary for the revoked key's refused
# connection, and the withdrawal line for the revoked connection, which is
# not written at all when the session's own check wins (see REVOKED).
UNTALLIED_LINES = 4


@pytest.mark.plan("OPS-13")
def test_a_stalled_journald_does_not_stop_serving_or_revocation(alice_fast, fast_server, make_client):
    """journald stops reading; sessions and revocation carry on regardless.

    THREAT_MODEL.md: "a blocked or failing stderr/journald must never block
    serving". README: a bounded queue and a dedicated writer, so "a full log
    pipe cannot block session handling, authorization reload, or a stop"
    (the stop is the next scenario's). The writer is shown stuck in write(2)
    before and after the checks, so they ran while the log was blocked;
    afterwards, every line the full queue dropped must be counted ("lines
    that do not fit are counted and reported as suppressed",
    src/server/diagnostics.rs).
    """
    node = fast_server.node
    noisy = make_client("alice", authorize_as="alice", on=fast_server)
    victim = make_client("alice", authorize_as="alice", on=fast_server)
    since = fast_server.cursor()
    marker = "7474.25"
    with JournalStall(fast_server) as stall:
        logins, refusals = login_burst(noisy, "server2", rounds=40)
        blocked, evidence = stall.writer_blocked()
        assert blocked, evidence
        sessions = []
        for i in range(3):
            begin = time.monotonic()
            r = alice_fast.run("server2", "echo", f"served-{i}", timeout=15)
            sessions.append(time.monotonic() - begin)
            assert r.rc == 0 and r.stdout.strip() == f"served-{i}", r.describe()
            assert sessions[-1] < 5, f"a session took {sessions[-1]:.1f}s"
        proc = victim.node.popen(victim.argv("server2", "sleep", marker), user="alice")
        try:
            node.wait_running(f"sleep {marker}", timeout=10)
            begin = time.monotonic()
            fast_server.revoke(victim.entry, settle=False)
            _, err = proc.communicate(timeout=30)
            took = time.monotonic() - begin
        finally:
            proc.kill()
        assert proc.returncode == 255 and REVOKED.search(err.decode()), err.decode()
        # AUTH-03's bound: "normally within two seconds", plus the revoke command and a margin.
        assert took < 6, f"revocation took {took:.1f}s to reach a running session"
        node.wait_gone(f"sleep {marker}", timeout=10)
        assert victim.run("server2", "true").rc == 255
        blocked, evidence = stall.writer_blocked()
        assert blocked, f"the writer recovered before the checks were done: {evidence}"

    # The writer catches up. Each line the daemon produced during the stall
    # is now either in the journal or counted in a once-a-second
    # `suppressed N diagnostic message(s)` summary, so the lines missing from
    # the journal add up to what is counted, give or take UNTALLIED_LINES:
    # the logins (audit lines, which only a full queue drops), the refusals
    # (also over the peer budget), and the other sessions' logins.
    login, refusal = f"(key `{noisy.entry}`)", f"key `{noisy.entry}` is authorized for `alice`, not `bob`"
    produced = {
        login: logins,
        refusal: refusals,
        "(key `alice-client1`)": len(sessions),
        f"(key `{victim.entry}`)": 1,
    }

    def tally() -> tuple[dict[str, int], int, int]:
        journal = fast_server.journal(since)
        seen = {text: journal.count(text) for text in produced}
        assert all(seen[text] <= n for text, n in produced.items()), f"produced {produced}, logged {seen}"
        missing = sum(n - seen[text] for text, n in produced.items())
        suppressed = sum(int(n) for n in re.findall(r"suppressed (\d+) diagnostic message", journal))
        return seen, missing, suppressed

    deadline = time.monotonic() + 20
    while True:
        seen, missing, suppressed = tally()
        if seen[login] and suppressed >= missing:
            break
        assert time.monotonic() < deadline, f"{missing} missing, {suppressed} counted: produced {produced}, logged {seen}"
        time.sleep(0.5)
    # A count still held back comes with the next summary.
    time.sleep(RELOAD_SETTLE)
    seen, missing, suppressed = tally()
    print(
        f"sessions {', '.join(f'{t:.2f}s' for t in sessions)}; revocation {took:.2f}s; "
        f"{seen[login]} of {logins} logins and {seen[refusal]} of {refusals} refusals logged; "
        f"{missing} lines missing, {suppressed} counted as suppressed"
    )
    assert seen[login] < logins, "nothing was dropped: the queue never filled"
    assert suppressed >= missing, f"{missing - suppressed} dropped lines were not counted: {produced} {seen}"
    assert suppressed <= missing + UNTALLIED_LINES, f"{suppressed} lines counted, but only {missing} are missing"
    # And the daemon's log stream works again.
    since = fast_server.cursor()
    assert alice_fast.run("server2", "true").rc == 0
    fast_server.wait_journal(r"authenticated as `alice` \(key `alice-client1`\)", since)


@pytest.mark.plan("OPS-13")
def test_a_restart_during_a_journald_stall_is_not_held_up(alice_fast, fast_server, make_client):
    """A restart while journald is stalled must still restart.

    The writer thread holds Rust's stderr lock while it is blocked in
    write(2), so nothing on the shutdown path may write to stderr directly.
    The daemon closes the endpoint first, then queues "shutting down" for
    the writer like any other line, and gives the closes and the line the
    same bounded wait (SHUTDOWN_GRACE in src/server.rs). With journald
    stopped the line never gets out, and the old daemon exits once that
    bound is up. F28: the line used to be printed with `eprintln!` before
    the close, which waited for the lock until journald ran again or
    systemd's 90 s stop timeout killed the daemon.
    """
    noisy = make_client("alice", authorize_as="alice", on=fast_server)
    try:
        with JournalStall(fast_server) as stall:
            login_burst(noisy, "server2", rounds=40)  # fills the queue, as above
            blocked, evidence = stall.writer_blocked()
            assert blocked, evidence
            begin = time.monotonic()
            r = fast_server.node.run(["systemctl", "restart", fast_server.unit], timeout=15)
            took = time.monotonic() - begin
            print(f"`systemctl restart` took {took:.2f}s")
            assert r.rc == 0 and took < 10, f"`systemctl restart` exited {r.rc} after {took:.1f}s"
            fast_server.wait_listening()
            r = alice_fast.run("server2", "echo", "restarted", timeout=15)
            assert r.rc == 0 and r.stdout.strip() == "restarted", r.describe()
    finally:
        # A restart cut short by the timeout carries on once journald runs again.
        bring_back(fast_server)


@pytest.mark.plan("OPS-15")
def test_an_enabled_unit_comes_back_after_a_reboot_with_its_state(alice_fast, fast_server, make_client):
    """server2 reboots; the enabled unit starts by itself, with the same key, store and pins.

    The shipped unit is `WantedBy=multi-user.target`, so `systemctl enable`
    is what brings the server back after a reboot. Everything it needs lives
    under /etc/qsh, and clients pin its host key: after the reboot it must
    present the same key and accept the same authorizations without anyone
    touching it. A session running across the reboot is told, as by a stop
    (F8). The second boot must also give systemd its cgroup v2 tree again
    (node-entrypoint.sh) and the unit its delegated subtree, or every
    `--kill-session-processes` session fails closed.
    """
    node, unit = fast_server.node, fast_server.unit
    restricted = make_client("alice", authorize_as="alice", options=("--kill-session-processes",), on=fast_server)

    def contained(marker: str) -> None:
        # Its own cgroup under the unit's subtree, and a setsid'd, double-forked
        # job dies with the session (LIFE-04, LIFE-07).
        script = f"cat /proc/self/cgroup; setsid sh -c 'sleep {marker} & exit' >/dev/null 2>&1 </dev/null; echo detached"
        r = restricted.run("server2", "sh", "-c", script, timeout=30)
        assert r.rc == 0 and r.stdout.split()[-1:] == ["detached"], r.describe()
        assert "/qsh-restricted/session-" in r.stdout, r.stdout
        node.wait_gone(f"sleep {marker}", timeout=10)

    contained("7676.25")
    enabled = node.run(["systemctl", "is-enabled", unit]).stdout.strip()
    state = tree_listing(node, "/etc/qsh")
    started = docker("inspect", "-f", "{{.State.StartedAt}}", node.container).stdout
    marker = "7677.25"
    argv = alice_fast.argv("server2", "sleep", marker)
    proc = None
    try:
        node.run(["systemctl", "enable", unit], check=True)
        proc = alice_fast.node.popen(argv, user="alice")
        node.wait_running(f"sleep {marker}", timeout=10)
        begin = time.monotonic()
        node.reboot()
        booted = time.monotonic() - begin
        assert docker("inspect", "-f", "{{.State.StartedAt}}", node.container).stdout != started
        # systemd stopped the unit on the way down, which closes every connection.
        _, err = proc.communicate(timeout=30)
        assert proc.returncode == 255 and "shutting down" in err.decode(), err.decode()
        # Nobody started it: it came up with the boot, at the first attempt.
        after = unit_state(fast_server, "ActiveState", "SubState", "UnitFileState", "NRestarts")
        assert after == {"ActiveState": "active", "SubState": "running", "UnitFileState": "enabled", "NRestarts": "0"}, after
        fast_server.wait_listening()
        assert tree_listing(node, "/etc/qsh") == state, "/etc/qsh changed across the reboot"
        assert fast_server.fingerprint() == fast_server.fp
        # alice's pin for server2 and her authorization: the daemon presents the same key.
        r = alice_fast.run("server2", "hostname", timeout=30)
        assert r.rc == 0 and r.stdout.strip() == "server2", r.describe()
        assert node.run(["stat", "-fc", "%T", "/sys/fs/cgroup"], check=True).stdout.strip() == "cgroup2fs"
        contained("7678.25")
        print(f"rebooted and booted in {booted:.1f}s; server2 is at {node.ip}")
    finally:
        if proc is not None:
            proc.kill()
            alice_fast.node.kill_command("alice", argv)
        if enabled != "enabled":
            node.run(["systemctl", "disable", unit])
        if not fast_server.is_active():
            bring_back(fast_server)


# A listen address the host does not have yet: a DHCP lease, or a floating IP
# (keepalived, a cloud's reassignable address), which can take this long to
# arrive. Once it is there, the unit must be serving on it within the bound:
# RestartSec=2, systemd's timer slack, a start, and room for a busy host.
LATE_ADDRESS_DELAY = 25
LATE_ADDRESS_BOUND = 10


def serve_on_a_late_address(server: QshServer, address: str, prefix: int, *, restarts: int = 0) -> dict:
    """Start the server's unit with `listen` on a missing address, then add the address.

    The configuration must already name `address`. The rate limit is reset
    first, as on a fresh boot. With `restarts`, an administrator runs
    `systemctl restart` that many times, each once the last try has failed,
    to see whether it helps. Returns the unit's state after
    LATE_ADDRESS_DELAY seconds without the address, how long after it
    appeared the unit was active and listening on it (None: not within
    LATE_ADDRESS_BOUND), when each failed try came (seconds after the first),
    and the unit's journal.
    """
    node, unit = server.node, server.unit
    since = server.cursor()
    node.run(["systemctl", "reset-failed", unit])
    script = f"systemctl restart {unit}"
    for _ in range(restarts):
        # From inside the node, as soon as systemd has scheduled the next
        # automatic try (the last one failed), so the restarts come at once.
        script += (
            f" && until [ \"$(systemctl show -p SubState --value {unit})\" = auto-restart ]; do sleep 0.05; done"
            f" && systemctl restart {unit}"
        )
    failure = rf"binding UDP {re.escape(address)}:{PORT}: Cannot assign requested address"
    begin = time.monotonic()
    node.sh(script, timeout=30)
    server.wait_journal(failure, since)
    time.sleep(max(0.0, begin + LATE_ADDRESS_DELAY - time.monotonic()))
    waiting = unit_state(server, "ActiveState", "NRestarts", "StartLimitBurst")
    node.run(["ip", "addr", "add", f"{address}/{prefix}", "dev", "eth0"], check=True)
    added = time.monotonic()
    serving = None
    while serving is None and time.monotonic() < added + LATE_ADDRESS_BOUND:
        listening = node.run(["ss", "-Hlun", f"sport = :{PORT}"]).stdout
        if server.is_active() and f"{address}:{PORT}" in listening:
            serving = round(time.monotonic() - added, 2)
        else:
            time.sleep(0.25)
    # Each failed try logs the bind error; the journal's monotonic clock says when.
    timed = node.run(["journalctl", "-u", unit, "--after-cursor", since, "-o", "short-monotonic"], check=True).stdout
    times = [float(t) for t in re.findall(rf"^\[\s*([\d.]+)\].*{failure}", timed, re.M)]
    tries = [round(t - times[0], 2) for t in times]
    return {"waiting": waiting, "serving": serving, "tries": tries, "journal": server.journal(since)}


def listen_on(server: QshServer, address: str) -> bytes:
    """Point server2's configuration at `address`; returns the original to put back."""
    conf = "/etc/qsh/qsh-server.toml"
    original = server.node.read(conf)
    changed = original.replace(f"0.0.0.0:{PORT}".encode(), f"{address}:{PORT}".encode())
    assert changed != original, original
    server.node.write(conf, changed)
    return original


def put_back(server: QshServer, original: bytes, address: str, prefix: int) -> None:
    """Undo `listen_on` and `serve_on_a_late_address`: the address, the configuration, the daemon."""
    server.node.run(["ip", "addr", "del", f"{address}/{prefix}", "dev", "eth0"])
    server.node.write("/etc/qsh/qsh-server.toml", original)
    # Restart, not start: a unit that came up is still bound to the address.
    server.node.run(["systemctl", "reset-failed", server.unit])
    server.restart()


@pytest.mark.plan("OPS-15")
def test_the_shipped_unit_waits_for_a_late_listen_address(make_client, fast_server, env):
    """`listen` names an address that arrives 25 s late; the shipped unit retries until it does.

    Binding an address the host does not have fails (EADDRNOTAVAIL) and
    qsh-server exits 1. The shipped unit's `Restart=on-failure` and
    `RestartSec=2` try again every two seconds, and systemd's default start
    limit (5 starts within 10 s, then the unit fails for good) never trips
    on that loop alone: each of the five gaps is RestartSec plus the try plus
    timer slack, more than 2 s, so the sixth start always falls past the
    window, which then starts over. When the address appears, the next try
    binds it and serves.
    """
    node = fast_server.node
    address, prefix = env.spare_ip(40), env.subnet().prefixlen
    client = make_client("alice", authorize_as="alice", on=fast_server)
    client.pin(address, fast_server.fp)
    # Or a bind to a missing address would succeed and prove nothing.
    assert node.read("/proc/sys/net/ipv4/ip_nonlocal_bind").strip() == b"0"
    original = listen_on(fast_server, address)
    try:
        seen = serve_on_a_late_address(fast_server, address, prefix)
        waiting = seen["waiting"]
        print(
            f"after {LATE_ADDRESS_DELAY}s without the address: {waiting}; tries at {seen['tries']}; "
            f"serving after {seen['serving']}s"
        )
        assert waiting["ActiveState"] != "failed", f"the unit gave up: {waiting}, tries at {seen['tries']}"
        # More tries than the start limit's burst: the limit was really in play.
        assert int(waiting["NRestarts"]) > int(waiting["StartLimitBurst"]), waiting
        assert seen["serving"] is not None, f"not serving {LATE_ADDRESS_BOUND}s after the address appeared"
        r = client.run(address, "hostname", timeout=30)
        assert r.rc == 0 and r.stdout.strip() == "server2", r.describe()
    finally:
        put_back(fast_server, original, address, prefix)


@pytest.mark.plan("OPS-15")
@pytest.mark.xfail(strict=True, reason="F29: restarting the unit while it waits for its address trips the start limit for good")
def test_restarting_while_waiting_for_the_address_does_not_give_up(make_client, fast_server, env):
    """An administrator restarts the waiting unit; it must still come up with the address.

    Alone, the retry loop never reaches the start limit (see above). Every
    start counts towards it, though, the administrator's too: a `systemctl
    restart` m seconds after a try, to see whether it helps, moves the sixth
    start to 4 gaps + m after the window opened, inside the 10 s if m is
    under 1.0-1.8 s (gaps of 2.25-2.05 s). systemd refuses that
    start ("Start request repeated too quickly") and the unit stays failed,
    also once the address is there. Here the administrator restarts twice,
    each right after a failed try: the sixth start then comes about 7 s
    after the first, so the outcome does not hang on how fast this host
    runs the loop (one restart leaves about 1 s to spare over four gaps,
    two leave 3 s over three). Proposed: `StartLimitIntervalSec=0` in the
    unit's [Unit] section, so that it keeps trying.
    """
    address, prefix = env.spare_ip(40), env.subnet().prefixlen
    client = make_client("alice", authorize_as="alice", on=fast_server)
    client.pin(address, fast_server.fp)
    original = listen_on(fast_server, address)
    try:
        seen = serve_on_a_late_address(fast_server, address, prefix, restarts=2)
        print(f"after {LATE_ADDRESS_DELAY}s without the address: {seen['waiting']}; tries at {seen['tries']}")
        assert seen["serving"] is not None, f"the unit gave up: {seen['waiting']}, tries at {seen['tries']}"
        r = client.run(address, "hostname", timeout=30)
        assert r.rc == 0 and r.stdout.strip() == "server2", r.describe()
    finally:
        put_back(fast_server, original, address, prefix)


def readme_unit() -> str:
    """The unit README.md's "Running under systemd" shows administrators."""
    _, heading, section = (REPO_DIR / "README.md").read_text().partition("## Running under systemd")
    assert heading, 'README.md has no "Running under systemd" section'
    match = re.search(r"```ini\n(.*?)```", section, re.S)
    assert match and "ExecStart=" in match.group(1), "README.md shows no systemd unit"
    return match.group(1)


@pytest.mark.plan("OPS-15")
@pytest.mark.xfail(strict=True, reason="F29: the README's unit restarts every 100 ms, so a late address trips the start limit at once")
def test_the_readme_unit_waits_for_a_late_listen_address(make_client, fast_server, env):
    """The same late address, under the unit the README shows instead of the shipped one.

    The README's unit has `Restart=on-failure` but no `RestartSec=`, so
    systemd retries after its default 100 ms: five tries take about a
    second, the start limit trips, and the unit stays failed for good, also
    once the address is there. It is also ordered only after
    `network.target`, which waits for no address at all. Proposed: show the
    shipped unit (`RestartSec=2`, `After=network-online.target`) in the
    README, with `StartLimitIntervalSec=0` as for F29.
    """
    node = fast_server.node
    address, prefix = env.spare_ip(41), env.subnet().prefixlen
    readme = QshServer(node, unit=unique("qsh-readme"))
    path = f"/etc/systemd/system/{readme.unit}.service"
    client = make_client("alice", authorize_as="alice", on=fast_server)
    client.pin(address, fast_server.fp)
    original = listen_on(fast_server, address)
    try:
        node.write(path, readme_unit())
        node.run(["systemctl", "daemon-reload"], check=True)
        # The shipped unit holds 0.0.0.0:2222, which the new address's port would collide with.
        fast_server.stop()
        seen = serve_on_a_late_address(readme, address, prefix)
        print(f"after {LATE_ADDRESS_DELAY}s without the address: {seen['waiting']}; tries at {seen['tries']}")
        assert seen["serving"] is not None, f"the unit gave up: {seen['waiting']}, tries at {seen['tries']}"
        r = client.run(address, "hostname", timeout=30)
        assert r.rc == 0 and r.stdout.strip() == "server2", r.describe()
    finally:
        node.run(["systemctl", "stop", readme.unit])
        node.run(["systemctl", "reset-failed", readme.unit])
        node.run(["rm", "-f", path])
        node.run(["systemctl", "daemon-reload"])
        put_back(fast_server, original, address, prefix)


# Timing helpers that run on a client node, so that what they measure is the
# session and not `docker exec`.
TIMED_RUNS = r"""
import json, subprocess, sys, time
n, argv = int(sys.argv[1]), sys.argv[2:]
runs = []
for _ in range(n):
    begin = time.monotonic()
    rc = subprocess.run(argv, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode
    runs.append((rc, time.monotonic() - begin))
print(json.dumps(runs))
"""

FIRST_SUCCESS = r"""
import json, subprocess, sys, time
deadline, argv = time.monotonic() + float(sys.argv[1]), sys.argv[2:]
print("polling", flush=True)
tries, longest = 0, 0.0
while time.monotonic() < deadline:
    tries += 1
    at, begin = time.time(), time.monotonic()
    rc = subprocess.run(argv, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode
    if rc == 0:
        print(json.dumps({"at": at, "tries": tries, "longest_refusal": longest}))
        break
    longest = max(longest, time.monotonic() - begin)
"""


def login_times(client: QshClient, host: str, n: int = 15) -> list[float]:
    """Seconds each of `n` consecutive `qsh host true` took, end to end."""
    argv = ["python3", "-c", TIMED_RUNS, str(n), *client.argv(host, "true")]
    r = client.node.run(argv, user=client.user, timeout=120, check=True)
    runs = json.loads(r.stdout)
    assert all(rc == 0 for rc, _ in runs), runs
    return [took for _, took in runs]


def authorization_delay(server: QshServer, newcomer: QshClient) -> float:
    """Seconds from `qsh-server authorize` returning to the start of the newcomer's first session.

    The newcomer retries from the moment before the authorization, so the
    authorization took effect at most one refused try (about 0.1 s) before
    the first try that worked began; both clocks are the one kernel clock
    every container shares.
    """
    poller = newcomer.node.popen(
        ["python3", "-c", FIRST_SUCCESS, "30", *newcomer.argv(server.host, "true")], user=newcomer.user
    )
    try:
        assert poller.stdout.readline().strip() == b"polling"
        path = f"/tmp/{newcomer.entry}.crt"
        server.node.write(path, newcomer.cert())
        done = server.node.sh(
            f"qsh-server authorize {path} --user {newcomer.user} --name {newcomer.entry} >/dev/null"
            f" && date +%s.%N && rm -f {path}"
        )
        out, _ = poller.communicate(timeout=60)
    finally:
        poller.kill()
    assert out.strip(), "the newcomer was not let in within 30 s"
    result = json.loads(out)
    assert result["tries"] > 1, "the newcomer was let in before it was authorized"
    assert result["longest_refusal"] < 1, f"a refused try took {result['longest_refusal']:.2f}s"
    return result["at"] - float(done.stdout)


def revocation_delay(server: QshServer, victim: QshClient, marker: str) -> float:
    """Seconds from `qsh-server revoke` starting to the victim's running session ending."""
    proc = victim.node.popen(victim.argv(server.host, "sleep", marker), user=victim.user)
    try:
        server.node.wait_running(f"sleep {marker}", timeout=10)
        begin = time.monotonic()
        server.revoke(victim.entry, settle=False)
        _, err = proc.communicate(timeout=30)
        took = time.monotonic() - begin
    finally:
        proc.kill()
    assert proc.returncode == 255 and REVOKED.search(err.decode()), err.decode()
    server.node.wait_gone(f"sleep {marker}", timeout=10)
    return took


def daemon_cpu(server: QshServer, seconds: float = 5.0) -> float:
    """The daemon's CPU use while idle, as a fraction of one CPU."""
    pid = server.main_pid()
    hz = int(server.node.run(["getconf", "CLK_TCK"], check=True).stdout)

    def ticks() -> int:
        fields = server.node.read(f"/proc/{pid}/stat").decode().rsplit(")", 1)[1].split()
        return int(fields[11]) + int(fields[12])  # utime + stime

    before = ticks()
    time.sleep(seconds)
    return (ticks() - before) / hz / seconds


def tree_listing(node, path: str) -> str:
    """Every entry under `path` with its type, mode, owner, size and content digest."""
    return node.sh(
        f"cd {path} && find . -mindepth 1 -printf '%P %y %m %U:%G %s\\n' | sort"
        " && find . -type f -print0 | sort -z | xargs -0r sha256sum"
    ).stdout


@pytest.mark.plan("OPS-17")
@pytest.mark.slow
def test_a_large_authorization_store_keeps_its_bounds(make_client, fast_server):
    """2,000 authorized keys: logins, the reload and revocation stay within bounds.

    README: an authorization "takes effect within a second", a revocation
    "normally within two seconds". The store is re-read whole, every second,
    on a runtime worker (`spawn_store_refresher` in src/server.rs), and
    `qsh-server authorize` reads it whole too. The same three measurements
    are taken on the store as it is and with 2,000 more keys. server2's store
    is put back exactly as it was: revoking 2,000 keys would leave 2,000
    tombstones. Against a build whose reload took 0.7 ms per key (1.4 s with
    the large store), the authorization bound below failed at 2.1 s.
    """
    node = fast_server.node
    store = "/etc/qsh/authorized"
    backup = "/var/tmp/ops17-authorized"
    keys = "/var/tmp/ops17-keys"
    before = tree_listing(node, store)
    node.sh(f"rm -rf {backup} && cp -a {store} {backup}")
    try:
        member = make_client("alice", authorize_as="alice", on=fast_server)
        newcomers = [make_client("alice", on=fast_server) for _ in range(2)]
        victims = [make_client("alice", authorize_as="alice", on=fast_server) for _ in range(2)]
        small = {
            "login": login_times(member, "server2"),
            "authorize": authorization_delay(fast_server, newcomers[0]),
            "revoke": revocation_delay(fast_server, victims[0], "7575.25"),
        }

        prefix = unique("ops17")
        begin = time.monotonic()
        node.sh(
            f"mkdir -p {keys} && for i in $(seq 2000); do qsh keygen --identity {keys}/$i >/dev/null; done"
            f" && for i in $(seq 2000); do"
            f" qsh-server authorize {keys}/$i/id.crt --user dave --name {prefix}-$i >/dev/null; done",
            # Well inside pytest's 600 s, so that this ends the loop in the
            # node, not just the local `docker exec`.
            timeout=400,
        )
        filled = time.monotonic() - begin
        listed = fast_server.list().count(f"{prefix}-")
        assert listed == 2000, f"{listed} of the 2,000 keys are listed"
        time.sleep(RELOAD_SETTLE)

        large = {
            "login": login_times(member, "server2"),
            "authorize": authorization_delay(fast_server, newcomers[1]),
            "revoke": revocation_delay(fast_server, victims[1], "7576.25"),
            "cpu": daemon_cpu(fast_server),
        }
        report = (
            f"filling took {filled:.0f}s; logins {statistics.median(small['login']):.3f}s -> "
            f"{statistics.median(large['login']):.3f}s (max {max(large['login']):.3f}s); authorize "
            f"{small['authorize']:.2f}s -> {large['authorize']:.2f}s; revoke {small['revoke']:.2f}s -> "
            f"{large['revoke']:.2f}s; idle daemon {large['cpu']:.0%} of a CPU"
        )
        print(report)
        # Logins: no documented bound, so against the small store's, with room for a busy host.
        assert statistics.median(large["login"]) < statistics.median(small["login"]) + 0.25, report
        assert max(large["login"]) < 2, report
        # "Within a second": up to one reload interval, the reload itself
        # (about 50 ms here) and one refused try, plus 0.35 s for a busy host.
        assert large["authorize"] < 1.5, report
        # "Normally within two seconds": the reload, then the connection's
        # own once-a-second check; plus the revoke command and a margin.
        assert large["revoke"] < 3, report
        # The reload of 2,000 entries every second must not eat the server
        # (5% of a CPU here): a reload of 250 ms would.
        assert large["cpu"] < 0.25, report
    finally:
        # A fill loop cut short must not go on adding keys to the restored store.
        node.run(["pkill", "-f", f"[{keys[0]}]{keys[1:]}"])
        # Under the store's lock, so no reload sees it half restored.
        node.sh(f"flock {store}.lock sh -c 'rm -rf {store} && cp -a {backup} {store}' && rm -rf {backup} {keys}")
        fast_server.restart()
    assert tree_listing(node, store) == before


# A capture of the UDP datagrams to or from one port on a node's eth0, both
# directions, until a stop file appears: counts per flow, as JSON.
CAPTURE = r"""
import json, os, socket, struct, sys, time
iface, port, stop = sys.argv[1], int(sys.argv[2]), sys.argv[3]
sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0003))  # ETH_P_ALL
sock.bind((iface, 0))
sock.settimeout(0.2)
open(stop + ".ready", "w").close()
flows = {}
deadline = time.monotonic() + 120
while not os.path.exists(stop) and time.monotonic() < deadline:
    try:
        frame = sock.recv(65535)
    except socket.timeout:
        continue
    if len(frame) < 42 or frame[12:14] != b"\x08\x00" or frame[23] != 17:  # IPv4, UDP
        continue
    ihl = (frame[14] & 0x0F) * 4
    sport, dport = struct.unpack("!HH", frame[14 + ihl:18 + ihl])
    if port in (sport, dport):
        key = f"{socket.inet_ntoa(frame[26:30])}:{sport} {socket.inet_ntoa(frame[30:34])}:{dport}"
        flows[key] = flows.get(key, 0) + 1
print(json.dumps(flows))
"""


class UdpCapture:
    """What a node's network interface carried to and from one UDP port.

    An AF_PACKET socket sees the datagrams as they leave and arrive, with the
    addresses they really carry; Docker gives every container CAP_NET_RAW.
    """

    def __init__(self, node, port: int) -> None:
        self.node = node
        self.port = port
        self.flows: dict[tuple[str, int, str, int], int] = {}

    def __enter__(self) -> UdpCapture:
        self.stop = f"/tmp/{unique('capture')}.stop"
        self.proc = self.node.popen(["python3", "-c", CAPTURE, "eth0", str(self.port), self.stop])
        deadline = time.monotonic() + 10
        while not self.node.exists(f"{self.stop}.ready"):
            if self.proc.poll() is not None or time.monotonic() > deadline:
                self.proc.kill()
                raise AssertionError(f"the capture did not start: {self.proc.communicate()[1].decode()}")
            time.sleep(0.1)
        return self

    def __exit__(self, *exc) -> None:
        self.node.run(["touch", self.stop])
        out, err = self.proc.communicate(timeout=30)
        self.node.run(["rm", "-f", self.stop, f"{self.stop}.ready"])
        assert self.proc.returncode == 0, err.decode()
        for flow, count in json.loads(out).items():
            src, dst = (end.rsplit(":", 1) for end in flow.split())
            self.flows[(src[0], int(src[1]), dst[0], int(dst[1]))] = count


@pytest.mark.plan("OPS-18")
def test_a_wildcard_listener_answers_from_the_address_dialed(make_client, fast_server, env):
    """server2 gains a second address; replies leave from whichever one the client used.

    The daemon listens on 0.0.0.0:2222, so the kernel would pick the source
    of an unconnected reply by route: the primary address. A QUIC client
    drops datagrams from an address it did not dial, so a reply from the
    wrong one would never connect. quinn learns each datagram's destination
    (IP_PKTINFO) and answers from it. The capture on client1 shows, per
    client port, where its datagrams went and where the answers came from.
    """
    node = fast_server.node
    primary = node.ip
    secondary = env.spare_ip(30)
    listening = node.run(["ss", "-Hlun", f"sport = :{PORT}"], check=True).stdout
    assert f"0.0.0.0:{PORT}" in listening, listening
    client = make_client("alice", authorize_as="alice", on=fast_server)
    for address in (primary, secondary):
        client.pin(address, fast_server.fp)
    node.run(["ip", "addr", "add", f"{secondary}/{env.subnet().prefixlen}", "dev", "eth0"], check=True)
    try:
        with UdpCapture(client.node, PORT) as capture:
            for address in (secondary, primary):
                r = client.run(address, "hostname", timeout=30)
                assert r.rc == 0 and r.stdout.strip() == "server2", r.describe()
    finally:
        node.run(["ip", "addr", "del", f"{secondary}/{env.subnet().prefixlen}", "dev", "eth0"])
    me = client.node.ip
    dialed: dict[int, set[str]] = {}
    answered: dict[int, set[str]] = {}
    for (src, sport, dst, dport), _ in capture.flows.items():
        if src == me and dport == PORT:
            dialed.setdefault(sport, set()).add(dst)
        elif dst == me and sport == PORT:
            answered.setdefault(dport, set()).add(src)
    for address in (secondary, primary):
        ports = [port for port, dests in dialed.items() if dests == {address}]
        assert ports, f"no datagrams to {address}: {capture.flows}"
        for port in ports:
            assert answered.get(port) == {address}, f"client port {port} dialed {address}: {capture.flows}"


# ---------------------------------------------------------------- upgrades
#
# The previous release is installed next to the current binaries as qsh-1.0
# and qsh-server-1.0 (e2e/run pins its commit). OPS-14 upgrades a server that
# 1.0 set up; OPS-16 mixes the two builds and rolls a server back.

UNIT_BINARY = "/usr/local/bin/qsh-server"
UNIT_FILE = "/etc/systemd/system/qsh-server.service"
PREVIOUS_UNIT_FILE = f"/usr/local/share/qsh-e2e/qsh-server-{PREVIOUS_VERSION}.service"
SAVED = "/var/lib/qsh-e2e-saved"
PAYLOAD = bytes(range(256)) * 4096  # 1 MiB with every byte value


def replace_binary(node, source: str, target: str = UNIT_BINARY) -> None:
    """Install `source` at `target` the way a package manager does.

    The new file is written beside the old one and renamed over it: a running
    daemon keeps the image it started from, the next start runs the new one.
    """
    node.sh(f"install -m 0755 {source} {target}.new && mv -f {target}.new {target}")


def legacy_warning(name: str) -> str:
    """What this build says about a policy written before `key_fingerprint`."""
    return f"{name}.toml does not record which key it is for; re-run `qsh-server authorize` for `{name}`"


def listed(listing: str, name: str, fingerprint: str, rest: str) -> bool:
    """Whether `qsh-server list` has a line for `name` as alice, then `rest`."""
    return re.search(rf"^{re.escape(name)} +alice +{fingerprint}{rest}", listing, re.M) is not None


@contextlib.contextmanager
def set_up_by_previous_release(server: QshServer, unit_file: str | None = None):
    """server2 freshly installed with qsh-server 1.0, until the block ends.

    The unit runs 1.0 from the unit's own path, with an empty state directory
    for the scenario to `keygen` and `authorize` into as 1.0's administrator
    did; `unit_file` replaces the unit file as well. Afterwards server2 gets
    back the current binary, its own state directory and configuration and
    its unit, and runs again, whatever the scenario left behind.
    """
    node = server.node
    try:
        node.run(["systemctl", "stop", server.unit], check=True)
        node.sh(
            f"mkdir -p {SAVED}\n"
            f"cp -p {UNIT_BINARY} {SAVED}/qsh-server\n"
            f"cp -p {UNIT_FILE} {SAVED}/qsh-server.service\n"
            f"mv {server.state_dir} {SAVED}/state\n"
        )
        replace_binary(node, f"/usr/local/bin/{PREVIOUS_QSH_SERVER}")
        if unit_file is not None:
            node.sh(f"cp {unit_file} {UNIT_FILE} && systemctl daemon-reload")
        yield
    finally:
        node.run(["systemctl", "stop", server.unit])
        node.sh(
            f"if [ -e {SAVED}/qsh-server ]; then\n"
            f"    install -m 0755 {SAVED}/qsh-server {UNIT_BINARY}.new\n"
            f"    mv -f {UNIT_BINARY}.new {UNIT_BINARY}\n"
            f"fi\n"
            f"if [ -e {SAVED}/qsh-server.service ]; then cp -p {SAVED}/qsh-server.service {UNIT_FILE}; fi\n"
            f"if [ -d {SAVED}/state ]; then rm -rf {server.state_dir} && mv {SAVED}/state {server.state_dir}; fi\n"
            f"rm -rf {SAVED}\n"
            f"systemctl daemon-reload\n"
            f"systemctl reset-failed {server.unit} || true\n"
        )
        server.start()


@pytest.mark.plan("OPS-14")
def test_an_upgrade_keeps_keys_authorizations_and_pins(make_client, fast_server):
    """Upgrade a server that qsh 1.0 set up: replace the binary, restart.

    1.0's administrator ran its `keygen` and `authorize`. One client made its
    identity with this build's qsh; one made and pinned it with qsh 1.0
    (`id.crt`, `id.key` and `known_hosts` all written by 1.0) and is held to
    `--no-shell --command id`; one key 1.0's `authorize --force` left under
    two names. After the upgrade the host key, every pin and every policy
    must hold, and 1.0's policies must still restrict what they restricted.
    """
    node = fast_server.node
    with set_up_by_previous_release(fast_server):
        host_key = fast_server.keygen()
        modern = make_client("alice", pin=False)
        veteran = make_client("alice", pin=False, previous=True)
        twice = make_client("alice", pin=False)
        restricted = ("--no-shell", "--command", "id")
        fast_server.authorize(modern.cert(), user="alice", name=modern.entry, settle=False)
        fast_server.authorize(veteran.cert(), user="alice", name=veteran.entry, options=restricted, settle=False)
        # 1.0's `--force` under a new name adds an entry and keeps the old one.
        aliases = (f"{twice.entry}-a", f"{twice.entry}-b")
        fast_server.authorize(twice.cert(), user="alice", name=aliases[0], settle=False)
        fast_server.authorize(twice.cert(), user="alice", name=aliases[1], options=("--force",), settle=False)
        for client in (modern, veteran, twice):
            client.pin("server2", host_key)
        fast_server.start()
        assert modern.run("server2", "id", "-un").stdout == "alice\n"
        # 1.0 compared a command filter with the basename of argv[0].
        assert veteran.run("server2", "/usr/bin/id", "-un").rc == 0
        assert twice.run("server2", "true").rc == 0

        replace_binary(node, f"{SAVED}/qsh-server")
        r = modern.run("server2", "true")
        assert r.rc == 0, f"the running daemon stopped serving when its file was replaced\n{r.describe()}"
        since = fast_server.cursor()
        fast_server.restart()

        assert fast_server.fingerprint() == host_key
        # 1.0's identity files, read by this build's client, and 1.0's client.
        upgraded = QshClient(veteran.node, "alice", identity=veteran.identity)
        for client in (modern, upgraded, veteran):
            r = client.run("server2", "id", "-un")
            assert r.rc == 0 and r.stdout == "alice\n", f"{client.program}: {r.describe()}"
        # 1.0's policy still restricts: no shell, no other program...
        r = upgraded.run("server2", "sh", "-c", "true")
        assert r.rc == 126 and "may not execute `sh`" in r.stderr, r.describe()
        # ... and argv[0] is now compared whole, so a path no longer passes.
        r = upgraded.run("server2", "/usr/bin/id")
        assert r.rc == 126 and "may not execute `/usr/bin/id`" in r.stderr, r.describe()
        # A key 1.0 left under two names gets neither policy.
        r = twice.run("server2", "true")
        assert r.rc == 255, r.describe()
        journal = fast_server.wait_journal(
            re.escape(f"refusing duplicate authorizations for {twice.fingerprint}: {aliases[0]}, {aliases[1]}"), since
        )
        # Policies 1.0 wrote are accepted, each with a warning that names it.
        for name in (modern.entry, veteran.entry):
            assert legacy_warning(name) in journal, journal
        listing = fast_server.admin("list")
        assert listed(listing.stdout, modern.entry, modern.fingerprint, "$"), listing.stdout
        assert listed(listing.stdout, veteran.entry, veteran.fingerprint, r"  \[no-shell commands=id\]$"), listing.stdout
        for name in aliases:
            assert listed(listing.stdout, name, twice.fingerprint, r"  \[CONFLICT"), listing.stdout
        assert legacy_warning(veteran.entry) in listing.stderr, listing.stderr

        # Binding a 1.0 policy to its key: running `authorize` again needs
        # --force, and rewrites the policy from the options given.
        cert = f"{fast_server.state_dir}/authorized/{veteran.entry}.crt"
        rebind = ("authorize", cert, "--user", "alice", "--name", veteran.entry, *restricted)
        again = fast_server.admin(*rebind, check=False)
        assert again.rc != 0 and "pass --force" in again.stderr, again.describe()
        fast_server.admin(*rebind, "--force")
        policy = node.read(f"{fast_server.state_dir}/authorized/{veteran.entry}.toml").decode()
        assert f'key_fingerprint = "{veteran.fingerprint}"' in policy, policy
        time.sleep(RELOAD_SETTLE)
        assert legacy_warning(veteran.entry) not in fast_server.admin("list").stderr
        r = upgraded.run("server2", "id", "-un")
        assert r.rc == 0 and r.stdout == "alice\n", r.describe()
        r = upgraded.run("server2", "sh", "-c", "true")
        assert r.rc == 126 and "may not execute `sh`" in r.stderr, r.describe()


@pytest.mark.plan("OPS-14")
@pytest.mark.xfail(
    strict=True,
    raises=Unmet,
    reason="F36 (decision): under 1.0's contrib unit (ProtectSystem=full) the upgraded server "
    "cannot open /etc/qsh/authorized.lock for writing and never starts",
)
def test_an_upgrade_keeps_serving_under_the_unit_1_0_shipped(make_client, fast_server):
    """The same upgrade on a host that kept the unit file 1.0 shipped.

    Replacing the binary is what a package or `cargo install` does; a unit
    file installed from 1.0's contrib/qsh-server.service stays. It has
    `ProtectSystem=full`, which makes /etc read-only for the daemon, and 1.0
    never writes there while serving. (The unit 1.0's README printed never
    set ProtectSystem, and neither README has upgrade notes; this build's
    unit dropped it because it also made /etc and /usr read-only inside
    every session.) Proposed here: the upgraded server starts and serves the
    same keys from a state directory it cannot write. If the maintainer
    decides instead that upgrading from 1.0 means replacing the unit, the
    upgrade notes are the fix and this test goes.
    """
    with set_up_by_previous_release(fast_server, unit_file=PREVIOUS_UNIT_FILE):
        host_key = fast_server.keygen()
        client = make_client("alice", pin=False)
        fast_server.authorize(client.cert(), user="alice", name=client.entry, settle=False)
        client.pin("server2", host_key)
        fast_server.start()
        assert client.run("server2", "true").rc == 0, "1.0 does not serve under its own unit"
        replace_binary(fast_server.node, f"{SAVED}/qsh-server")
        since = fast_server.cursor()
        fast_server.node.run(["systemctl", "restart", fast_server.unit], check=True)
        try:
            fast_server.wait_listening(timeout=15)
        except AssertionError as exc:
            raise Unmet(f"the upgraded server never listened:\n{fast_server.journal(since)[-3000:]}") from exc
        r = client.run("server2", "true")
        if r.rc != 0:
            raise Unmet(r.describe())


# ---------------------------------------------------------------- version skew
#
# Servers run by hand on server2, each with its own state directory and port,
# so the unit and the shared /etc/qsh stay as they are.

SKEW_PORTS = {
    "current": 2416,
    "previous": 2417,
    "rollback": 2418,
    "interrupted": 2419,
    "interrupted-1.0": 2420,
    "refusal": 2421,
}

# A key held to 200 programs. Refusing any other, 1.0's server lists them all,
# some 5 KB; this build's server keeps a refusal to 512 characters.
MANY_COMMANDS = tuple(arg for i in range(200) for arg in ("--command", f"/opt/ops16/bin/tool-{i:03d}"))

# Under a terminal: report the size, then the size after a resize, and exit 3.
WINCH_SCRIPT = (
    "trap 'echo WINCH-$(stty size); exit 3' WINCH; "
    "[ -t 0 ] && echo tty-$(stty size); while :; do sleep 0.1; done"
)


@contextlib.contextmanager
def standalone_servers(node):
    """A factory for servers with new state directories under /var/tmp.

    `new(program, label)` makes one and its host key with `program`. Every
    directory made, and its log, is removed when the block ends, also when
    setting one up failed half way.
    """
    made: list[QshServer] = []

    def new(program: str, label: str) -> QshServer:
        server = QshServer(node, state_dir=f"/var/tmp/{unique(label)}", program=program)
        made.append(server)
        server.fp = server.keygen()
        return server

    try:
        yield new
    finally:
        for server in made:
            node.run(["rm", "-rf", server.state_dir, f"{server.state_dir}.log"])


@contextlib.contextmanager
def serving_by_hand(server: QshServer, port: int):
    """`server` run by hand as root, outside systemd, listening on `port`.

    Yields a function that stops it with SIGTERM, as `systemctl stop` does;
    the block's end stops it in any case. Its stderr is appended to
    `<state dir>.log`.
    """
    node = server.node
    argv = [server.program, "--dir", server.state_dir, "serve", "--listen", f"0.0.0.0:{port}"]
    command = " ".join(argv)
    proc = node.popen(
        ["sh", "-c", 'exec "$@" 2>>"$0"', f"{server.state_dir}.log", *argv],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )

    def stop() -> None:
        node.run(["pkill", "-TERM", "-f", "^" + re.escape(command) + "$"])
        node.wait_gone(command)

    try:
        server.wait_listening(port=port)
        yield stop
    finally:
        stop()
        proc.wait(timeout=20)


@pytest.mark.plan("OPS-16")
def test_the_previous_release_and_this_one_interoperate(make_client, fast_server):
    """qsh 1.0's client against this server, and this client against a 1.0 server.

    The wire protocol is still qsh/1, version 1 (README "Protocol"), so a
    mixed pair has to work as a matched one does: the exit status and death
    by signal, stdin and stdout byte for byte without a terminal, stderr
    apart, argv and the environment verbatim; a terminal of the local size
    that follows a local resize; a local TERM relayed to the remote process.
    A refusal must arrive as a message and a status, never as a hang: a
    policy refusal, a key the server does not know, and this server shutting
    down under a 1.0 client. This server's refusal of a key held to many
    programs reaches a 1.0 client too; 1.0's long refusal and this client
    are the strict xfail below.
    """
    node = fast_server.node
    marker, relayed = "7373.25", "7373.5"
    try:
        with standalone_servers(node) as new_server:
            current = new_server("qsh-server", "ops16-current")
            previous = new_server(PREVIOUS_QSH_SERVER, "ops16-previous")
            pairs = []
            skews = ((current, SKEW_PORTS["current"], True), (previous, SKEW_PORTS["previous"], False))
            for server, port, old_client in skews:
                client = make_client("alice", pin=False, previous=old_client)
                stranger = make_client("alice", pin=False, previous=old_client)  # authorized nowhere
                server.authorize(client.cert(), user="alice", name=client.entry, settle=False)
                for each in (client, stranger):
                    each.pin("server2", server.fp, port=port)
                pairs.append((client, stranger, server, port))
            narrow = make_client("alice", pin=False, previous=True)
            current.authorize(narrow.cert(), user="alice", name=narrow.entry, options=MANY_COMMANDS, settle=False)
            narrow.pin("server2", current.fp, port=SKEW_PORTS["current"])

            for client, stranger, server, port in pairs:
                pair = f"{client.program} against {server.program}"
                with serving_by_hand(server, port) as stop:
                    r = client.run(
                        "server2", "sh", "-c", "cat; echo e-ops16 >&2; exit 7", port=port, input=PAYLOAD, timeout=30
                    )
                    assert (r.rc, r.err) == (7, b"e-ops16\n"), f"{pair}: {r.describe()}"
                    assert r.out == PAYLOAD, f"{pair}: stdout differs, {len(r.out)} bytes of {len(PAYLOAD)}"
                    r = client.run("server2", "sh", "-c", "kill -TERM $$", port=port, timeout=30)
                    assert r.rc == 128 + 15, f"{pair}: {r.describe()}"
                    r = client.run(
                        "server2", "sh", "-c", 'printf "[%s]" "$@" "$QSH_OPS16"', "sh", "a b", "*", "$HOME", "",
                        port=port, options=("-E", "QSH_OPS16=v 16"), timeout=30,
                    )
                    assert (r.rc, r.stdout) == (0, "[a b][*][$HOME][][v 16]"), f"{pair}: {r.describe()}"

                    # A terminal: the request carries the local size, a Resize
                    # frame the new one. (Terminal.expect waits for ever unless
                    # given a timeout.)
                    term = Terminal(
                        client, "server2", "sh", "-c", WINCH_SCRIPT, options=("-t", "-p", str(port)), rows=33, cols=91
                    )
                    try:
                        term.expect(r"tty-33 91", timeout=20)
                        term.resize_and_wait(40, 100)
                        term.expect(r"WINCH-40 100", timeout=20)
                        status = term.wait_exit()
                    except AssertionError as exc:
                        raise AssertionError(f"{pair}: {exc}") from None
                    finally:
                        term.close()
                    assert status == 3, f"{pair}: the terminal session exited {status}"

                    # Without a terminal a local TERM goes over as a Signal frame:
                    # the remote trap runs, and its status comes back.
                    script = f"trap 'echo got-TERM; kill $!; exit 44' TERM; echo ready; sleep {relayed} & wait"
                    argv = client.argv("server2", "sh", "-c", script, port=port)
                    proc = client.node.popen(argv, user="alice")
                    node.wait_running(f"sleep {relayed}", timeout=10)
                    client.node.kill_command("alice", argv, signal="TERM")
                    try:
                        out, err = proc.communicate(timeout=30)
                    except subprocess.TimeoutExpired:
                        proc.kill()
                        raise AssertionError(f"{pair}: a local TERM did not end the remote command") from None
                    assert (proc.returncode, out.split()) == (44, [b"ready", b"got-TERM"]), f"{pair}: {err.decode()}"
                    node.wait_gone(f"sleep {relayed}", timeout=10)

                    r = client.run("bob@server2", "true", port=port, timeout=30)
                    assert r.rc == 126 and "not `bob`" in r.stderr, f"{pair}: {r.describe()}"
                    r = stranger.run("server2", "true", port=port, timeout=30)
                    assert r.rc == 255 and r.stderr.startswith("qsh: "), f"{pair}: {r.describe()}"
                    if server is current:
                        r = narrow.run("server2", "sh", "-c", "true", port=port, timeout=30)
                        assert r.rc == 126 and "may not execute `sh`" in r.stderr, f"{pair}: {r.describe()}"
                        proc = client.node.popen(client.argv("server2", "sleep", marker, port=port), user="alice")
                        node.wait_running(f"sleep {marker}", timeout=10)
                        begin = time.monotonic()
                        stop()
                        _, err = proc.communicate(timeout=30)
                        took = time.monotonic() - begin
                        assert proc.returncode == 255 and "shutting down" in err.decode(), f"{pair}: {err.decode()}"
                        assert took < 10, f"{pair}: the client took {took:.0f}s to notice the shutdown"
    finally:
        node.run(["pkill", "-f", f"^sleep ({re.escape(marker)}|{re.escape(relayed)})$"])
        # A shell a failed terminal check left: 1.0's server left one running
        # after `~.` and after its own stop.
        node.run(["pkill", "-f", "^sh -c " + re.escape(WINCH_SCRIPT) + "$"])


@pytest.mark.plan("OPS-16")
@pytest.mark.xfail(
    strict=True,
    raises=Unmet,
    reason="F32: this client rejects an Error frame over 4096 bytes, and a 1.0 server "
    "sends its refusals unbounded",
)
def test_a_long_refusal_from_the_previous_server_reaches_this_client(make_client, fast_server):
    """A refusal from a 1.0 server must reach this client as a refusal, however long.

    1.0's server names every program a key may run when it refuses another,
    so a key held to 200 programs gets a refusal of some 5 KB. Both builds
    speak qsh/1, version 1 (README "Protocol"), and the refusal must come out
    as status 126 and the reason: 1.0's own client shows it, and this client
    shows this server's bounded refusal from the same store (both checked
    first, as preconditions).
    """
    port = SKEW_PORTS["refusal"]
    with standalone_servers(fast_server.node) as new_server:
        previous = new_server(PREVIOUS_QSH_SERVER, "ops16-refusal")
        current = QshServer(previous.node, state_dir=previous.state_dir)
        veteran = make_client("alice", pin=False, previous=True)
        modern = make_client("alice", pin=False)
        for client in (veteran, modern):
            previous.authorize(client.cert(), user="alice", name=client.entry, options=MANY_COMMANDS, settle=False)
            client.pin("server2", previous.fp, port=port)

        with serving_by_hand(current, port):
            r = modern.run("server2", "sh", "-c", "true", port=port, timeout=30)
            assert r.rc == 126 and "may not execute `sh`" in r.stderr, r.describe()
        with serving_by_hand(previous, port):
            r = veteran.run("server2", "sh", "-c", "true", port=port, timeout=30)
            assert r.rc == 126 and "may not execute `sh`; permitted: /opt/ops16/bin/tool-000" in r.stderr, r.describe()
            assert len(r.err) > 4096, f"1.0's refusal is only {len(r.err)} bytes long"
            r = modern.run("server2", "sh", "-c", "true", port=port, timeout=30)
            if r.rc != 126 or "may not execute `sh`" not in r.stderr:
                raise Unmet(f"1.0's refusal did not reach this client as one:\n{r.describe()}")


@pytest.mark.plan("OPS-16")
def test_a_rolled_back_server_fails_closed_on_newer_state(make_client, fast_server):
    """Roll a server back to 1.0 over the state this build wrote, and forward again.

    1.0 set the host up: its host key and broad policies for `legacy`,
    `revoked` and `narrowed`. Then this build authorized `bound` (its policy
    names its key), revoked `revoked`, gave `expired` a deadline that has
    passed and narrowed `narrowed` to `--no-exec`. Served by 1.0 again,
    nothing this build refused may get in. What 1.0 can still read is its own
    policies, so a revocation must remove those, not only mark them; a policy
    this build wrote is unreadable to 1.0 and refused whole. Forward again, a
    key revoked here and authorized anew by 1.0 in between stays refused:
    1.0's `authorize` leaves this build's tombstone in place. The lock file
    this build added is private to root after this build's management
    commands and again after its server and `list` reopened it (THREAT_MODEL
    actor 4); 1.0 never opens it.
    """
    node = fast_server.node
    port = SKEW_PORTS["rollback"]
    legacy, bound, revoked, expired, narrowed = (make_client("alice", pin=False) for _ in range(5))

    def outcome(client: QshClient):
        return client.run("server2", "echo", "granted-ops16", port=port, timeout=30)

    def granted(client: QshClient) -> None:
        r = outcome(client)
        assert (r.rc, r.stdout) == (0, "granted-ops16\n"), f"{client.entry}: {r.describe()}"

    def refused(client: QshClient) -> None:
        r = outcome(client)
        assert r.rc == 255 and "granted-ops16" not in r.stdout, f"{client.entry}: {r.describe()}"

    with standalone_servers(node) as new_server:
        previous = new_server(PREVIOUS_QSH_SERVER, "ops16-rollback")
        current = QshServer(node, state_dir=previous.state_dir)
        lock = f"{current.state_dir}/authorized.lock"
        for client in (legacy, revoked, narrowed):
            previous.authorize(client.cert(), user="alice", name=client.entry, settle=False)
        current.authorize(bound.cert(), user="alice", name=bound.entry, settle=False)
        current.revoke(revoked.entry, settle=False)
        current.authorize(
            expired.cert(), user="alice", name=expired.entry, options=("--expires-in-days", "0"), settle=False
        )
        current.authorize(
            narrowed.cert(), user="alice", name=narrowed.entry, options=("--no-exec", "--force"), settle=False
        )
        for client in (legacy, bound, revoked, expired, narrowed):
            client.pin("server2", previous.fp, port=port)
        assert stat(node, lock) == "600 root root"
        time.sleep(1.5)  # `--expires-in-days 0` set the deadline to now

        with serving_by_hand(current, port):
            granted(legacy)
            granted(bound)
            refused(revoked)
            refused(expired)
            r = outcome(narrowed)
            assert r.rc == 126 and "may not execute commands" in r.stderr, r.describe()

        with serving_by_hand(previous, port):
            granted(legacy)  # 1.0 does serve this store
            for client in (bound, revoked, expired, narrowed):
                refused(client)
            log = node.read(f"{previous.state_dir}.log").decode()
            assert f"ignoring authorization `{bound.entry}`" in log and "unknown field `key_fingerprint`" in log, log
            # Meanwhile the administrator authorizes the revoked key again, with 1.0.
            previous.authorize(revoked.cert(), user="alice", name=revoked.entry, settle=False)
            granted(revoked)

        with serving_by_hand(current, port):
            refused(revoked)
            granted(legacy)
            granted(bound)
        listing = current.list()
        assert re.search(rf"^{re.escape(revoked.entry)} .*\[DENIED", listing, re.M), listing
        assert stat(node, lock) == "600 root root"


def interrupted_revocation(make_client, previous: QshServer) -> tuple[QshServer, QshClient]:
    """A key 1.0 authorized in `previous`'s store, whose revocation by this
    build was cut short.

    `revoke` is killed at the moment it deletes the key's certificate: after
    whatever it does first, before the key's files are gone. That is the
    state an interrupted `revoke` leaves (README: "If a management process
    stops partway through, a denial marker keeps that key inactive").
    Returns the current build's server for the same store, and the key.
    """
    node = previous.node
    current = QshServer(node, state_dir=previous.state_dir)
    current.fp = previous.fp
    victim = make_client("alice", pin=False)
    previous.authorize(victim.cert(), user="alice", name=victim.entry, settle=False)
    cert = f"{previous.state_dir}/authorized/{victim.entry}.crt"
    r = node.run([
        "strace", "-f", "-qq", "-o", "/dev/null", "-P", cert,
        "-e", "trace=unlink,unlinkat", "-e", "inject=unlink,unlinkat:error=EIO:signal=KILL",
        "qsh-server", "--dir", current.state_dir, "revoke", victim.entry,
    ])
    assert r.rc == 128 + 9 and node.exists(cert), f"revoke was not stopped before deleting {cert}\n{r.describe()}"
    return current, victim


@pytest.mark.plan("OPS-16")
def test_an_interrupted_revocation_keeps_the_key_refused(make_client, fast_server):
    """This build keeps a key refused whose revocation stopped partway.

    The control for the rollback below: the files of the key are all still
    there, and only what `revoke` wrote first says it is on its way out.
    `list` must say so, the server must refuse the key, and running `revoke`
    again must finish the job.
    """
    port = SKEW_PORTS["interrupted"]
    with standalone_servers(fast_server.node) as new_server:
        previous = new_server(PREVIOUS_QSH_SERVER, "ops16-interrupted")
        current, victim = interrupted_revocation(make_client, previous)
        victim.pin("server2", current.fp, port=port)
        listing = current.list()
        assert re.search(rf"^{re.escape(victim.entry)} .*\[DENIED: interrupted mutation\]$", listing, re.M), listing
        with serving_by_hand(current, port):
            r = victim.run("server2", "echo", "granted-ops16", port=port, timeout=30)
            assert r.rc == 255 and "granted-ops16" not in r.stdout, r.describe()
        current.revoke(victim.entry, settle=False)
        assert victim.entry not in current.list()


@pytest.mark.plan("OPS-16")
@pytest.mark.xfail(
    strict=True,
    raises=Unmet,
    reason="F37 (decision): 1.0 ignores the denial marker an interrupted revoke leaves, so rolling "
    "back re-enables the key; only a revoke that first makes the legacy policy unreadable to 1.0 passes",
)
def test_a_rollback_keeps_an_interrupted_revocation_refused(make_client, fast_server):
    """The state above, served by qsh-server 1.0 after a rollback.

    The administrator has stopped trusting the key; this build refuses it.
    Rolled back to 1.0, it must stay refused (THREAT_MODEL actor 3:
    revocation is enforced for every session). `bystander`, an ordinary
    1.0 policy in the same store, shows that 1.0 serves the store at all.

    This is the part of the rollback hazard a change to this build can
    close, by making the policy unreadable to 1.0 before deleting anything.
    The rest it cannot: 1.0 reads no tombstones, so files restored from a
    backup after a complete revoke are refused here and granted by 1.0.
    Whether a rollback to 1.0 is supported at all is the maintainer's call.
    """
    port = SKEW_PORTS["interrupted-1.0"]
    bystander = make_client("alice", pin=False)
    with standalone_servers(fast_server.node) as new_server:
        previous = new_server(PREVIOUS_QSH_SERVER, "ops16-interrupted")
        _, victim = interrupted_revocation(make_client, previous)
        previous.authorize(bystander.cert(), user="alice", name=bystander.entry, settle=False)
        for client in (victim, bystander):
            client.pin("server2", previous.fp, port=port)
        with serving_by_hand(previous, port):
            r = bystander.run("server2", "true", port=port, timeout=30)
            assert r.rc == 0, f"1.0 does not serve this store at all\n{r.describe()}"
            r = victim.run("server2", "echo", "granted-ops16", port=port, timeout=30)
            if r.rc != 255 or "granted-ops16" in r.stdout:
                raise Unmet(f"after the rollback the key whose revocation was interrupted got in:\n{r.describe()}")
