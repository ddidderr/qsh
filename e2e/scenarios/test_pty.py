"""PTY: interactive sessions through a real terminal on both ends."""

from __future__ import annotations

import time

import pexpect
import pytest

from harness.terminal import PROMPT_RE, Terminal


@pytest.fixture
def terminals():
    """Terminals opened by a scenario, closed even when it fails."""
    opened: list[Terminal] = []
    yield opened
    for term in opened:
        term.close()


def local_sh(node, script: str) -> pexpect.spawn:
    """A plain `sh` on the client's terminal, running `script`.

    Not an interactive bash: bash saves the terminal's modes and puts them
    back when a foreground job dies of a signal, which would hide a qsh that
    leaves the terminal raw.
    """
    cmd = node.exec_argv(["sh", "-c", script], user="alice", env={"TERM": "xterm"}, interactive=True, tty=True)
    return pexpect.spawn(cmd[0], cmd[1:], dimensions=(24, 200), timeout=30, encoding="utf-8")


def login(alice, terminals, *command, **kwargs) -> Terminal:
    term = Terminal(alice, "server", *command, **kwargs)
    terminals.append(term)
    return term


@pytest.mark.plan("PTY-01")
def test_login_shell_on_a_real_terminal(alice, terminals):
    term = login(alice, terminals)
    term.set_prompt()
    assert term.command("tty").strip().startswith("/dev/pts/")
    assert term.command("echo $0").strip() == "-bash"
    assert term.command("shopt -q login_shell && echo login").strip() == "login"
    assert term.command("pwd").strip() == "/home/alice"
    assert term.command("echo $TERM").strip() == "xterm-256color"
    assert term.command("id -un").strip() == "alice"
    term.sendline("exit")
    assert term.wait_exit() == 0


@pytest.mark.plan("PTY-02")
def test_initial_window_size_is_the_local_one(alice, terminals):
    term = login(alice, terminals, rows=31, cols=101)
    term.set_prompt()
    assert term.command("stty size").strip() == "31 101"


@pytest.mark.plan("PTY-03")
def test_a_local_resize_reaches_the_remote_program(alice, terminals):
    term = login(alice, terminals, rows=24, cols=200)
    term.set_prompt()
    term.command("trap 'echo WINCH $(stty size)' WINCH")
    term.resize(40, 150)
    term.expect(r"WINCH 40 150")
    assert term.command("stty size").strip() == "40 150"


@pytest.mark.plan("PTY-04")
def test_ctrl_c_interrupts_the_foreground_job_only(alice, terminals):
    term = login(alice, terminals)
    term.set_prompt()
    term.sendline("sleep 100")
    time.sleep(1)
    term.sendcontrol("c")
    term.expect(PROMPT_RE, timeout=5)
    assert term.command("echo $?").strip() == "130"
    # The shell itself survived the interrupt.
    assert term.command("echo alive").strip() == "alive"


@pytest.mark.plan("PTY-05")
def test_the_shells_exit_status_becomes_qshs(alice, terminals):
    term = login(alice, terminals)
    term.set_prompt()
    term.sendline("exit 7")
    assert term.wait_exit() == 7


@pytest.mark.plan("PTY-06")
def test_tilde_dot_disconnects_at_once_and_the_server_cleans_up(alice, server, terminals):
    term = login(alice, terminals)
    term.set_prompt()
    # A distinctive, busy foreground job the server must clean up.
    term.sendline("sleep 1001.5")
    time.sleep(1)
    start = time.monotonic()
    term.send("\r~.")
    assert term.wait_exit(timeout=10) == 255
    assert time.monotonic() - start < 3, "~. waited for the remote side"
    server.node.wait_gone("sleep 1001.5", timeout=15)


@pytest.mark.plan("PTY-07")
def test_double_tilde_sends_one_literal_tilde(alice, terminals):
    term = login(alice, terminals)
    term.set_prompt()
    term.sendline("cat")
    time.sleep(0.5)
    term.send("~~hello\r")
    term.expect(r"\n~hello\r?\n")
    term.sendcontrol("d")
    term.expect(PROMPT_RE)


@pytest.mark.plan("PTY-08")
def test_raw_mode_programs_receive_control_bytes(alice, terminals):
    term = login(alice, terminals)
    term.set_prompt()
    term.sendline(
        "python3 -c \"import sys,tty; tty.setraw(0); d=sys.stdin.buffer.read(4); "
        "tty.setcbreak(0); print('GOT', d.hex())\""
    )
    time.sleep(1)
    term.send("\x01\x03\x1az")  # Ctrl-A, Ctrl-C, Ctrl-Z, z: data in raw mode
    term.expect(r"GOT 01031a7a")
    term.expect(PROMPT_RE)


@pytest.mark.plan("PTY-09")
def test_forced_terminal_for_a_command_uses_the_local_size(alice, terminals):
    term = login(alice, terminals, "stty", "size", options=("-t",), rows=33, cols=99)
    term.expect(r"33 99")
    assert term.wait_exit() == 0


@pytest.mark.plan("PTY-10")
def test_no_terminal_shell_with_dash_capital_t(alice, terminals):
    term = login(alice, terminals, options=("-T",))
    # Without a terminal there is no prompt and no echo, only output.
    term.sendline("tty; echo DONE-$?")
    term.expect(r"not a tty")
    term.expect(r"DONE-1")
    term.sendline("exit 3")
    assert term.wait_exit() == 3


@pytest.mark.plan("PTY-11")
def test_a_background_job_does_not_hold_the_session_open(alice, terminals):
    term = login(alice, terminals)
    term.set_prompt()
    term.sendline("sleep 300 &")
    term.expect(PROMPT_RE)
    start = time.monotonic()
    term.sendline("exit")
    assert term.wait_exit(timeout=15) == 0
    assert time.monotonic() - start < 8


@pytest.mark.plan("PTY-12")
def test_a_large_burst_of_terminal_output_arrives_complete(alice, terminals):
    term = login(alice, terminals)
    term.set_prompt()
    term.sendline("seq 1 200000; echo BURST-DONE")
    term.expect(r"\n200000\r\nBURST-DONE", timeout=60)
    term.expect(PROMPT_RE)
    assert term.command("echo still-responsive").strip() == "still-responsive"


@pytest.mark.plan("PTY-13")
@pytest.mark.parametrize("ending", ["exit\r", "\r~."])
def test_the_local_terminal_is_restored_after_the_session(alice, ending):
    """`stty -g` before and after an interactive qsh, from a plain local shell."""
    local = local_sh(alice.node, "stty -g > /tmp/stty.b; qsh server; stty -g > /tmp/stty.a; cmp -s /tmp/stty.b /tmp/stty.a; echo CMP-$?")
    try:
        local.expect(r"\$ ")  # the remote login prompt
        time.sleep(0.5)
        local.send(ending)
        local.expect(r"CMP-(\d)")
        assert local.match.group(1) == "0", f"terminal modes changed after {ending!r}"
    finally:
        local.terminate(force=True)


@pytest.mark.plan("PTY-14")
def test_a_resize_during_session_setup_is_not_lost(alice, server, make_link, terminals):
    """Resize after the request has gone out, before the server's answer is back.

    With 1.5 s each way, the server logs the login when the request reaches
    it, and its reply is still 1.5 s from the client: the resize lands in the
    gap the client used to drop.
    """
    link = make_link("server:2222", delay_ms=1500)
    alice.pin(link.host, server.fp, port=link.port)
    since = server.cursor()
    term = Terminal(
        alice, "netsim", options=("-p", str(link.port), "--connect-timeout", "60"), rows=24, cols=200, timeout=60
    )
    terminals.append(term)
    relay = link.node.ip.replace(".", "[.]")
    server.wait_journal(rf"{relay}:\d+ authenticated as `alice`", since, timeout=60)
    term.resize(40, 150)
    term.set_prompt()
    assert term.command("stty size", timeout=60).strip() == "40 150"


@pytest.mark.plan("PTY-15")
@pytest.mark.parametrize("signal", ["INT", "USR1", "HUP", "TERM"])
def test_a_signal_from_outside_still_restores_the_terminal(alice, signal):
    """`kill -INT` or `timeout -s INT` on an interactive qsh: the terminal comes back."""
    local = local_sh(alice.node, "stty -g > /tmp/stty.b; qsh server; stty -g > /tmp/stty.a; cmp -s /tmp/stty.b /tmp/stty.a; echo CMP-$?")
    try:
        local.expect(r"\$ ")  # the remote login prompt
        alice.node.run(["pkill", f"-{signal}", "-u", "alice", "-x", "qsh"], check=True)
        local.expect(r"CMP-(\d)")
        assert local.match.group(1) == "0", f"terminal left changed by SIG{signal}"
    finally:
        local.terminate(force=True)


@pytest.mark.plan("PTY-16")
def test_tilde_dot_returns_promptly_over_a_long_round_trip(alice, server, make_link, terminals):
    """`~.` and a normal exit do not wait out QUIC's draining period."""
    link = make_link("server:2222", delay_ms=300)
    alice.pin(link.host, server.fp, port=link.port)
    term = Terminal(alice, "netsim", options=("-p", str(link.port)), timeout=30)
    terminals.append(term)
    term.set_prompt()
    begin = time.monotonic()
    term.send("\r~.")
    assert term.wait_exit(timeout=20) == 255
    took = time.monotonic() - begin
    assert took < 2, f"~. took {took:.1f}s to give the prompt back at 600 ms RTT"
    begin = time.monotonic()
    r = alice.run("netsim", "true", port=link.port, timeout=60)
    assert r.rc == 0, r.describe()
    # Connecting costs round trips; tearing down should not add seconds more.
    assert time.monotonic() - begin < 6
