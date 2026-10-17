"""EXEC: running one remote command, the way scripts and rsync use qsh."""

from __future__ import annotations

import hashlib
import json
import time

import pytest


@pytest.mark.plan("EXEC-01")
@pytest.mark.parametrize("code", [0, 1, 42, 254])
def test_exit_status_reaches_the_caller(alice, code):
    r = alice.run("server", "sh", "-c", f"exit {code}")
    assert r.rc == code, r.describe()


@pytest.mark.plan("EXEC-02")
@pytest.mark.parametrize("signal,number", [("TERM", 15), ("KILL", 9), ("SEGV", 11)])
def test_death_by_signal_is_128_plus_n(alice, signal, number):
    r = alice.run("server", "sh", "-c", f"kill -{signal} $$")
    assert r.rc == 128 + number, r.describe()


@pytest.mark.plan("EXEC-03")
def test_stdout_and_stderr_arrive_separately_and_intact(alice):
    r = alice.run("server", "sh", "-c", "printf 'out\\n'; printf 'err\\n' >&2; printf 'out2'; printf 'err2' >&2")
    assert r.rc == 0, r.describe()
    assert r.stdout == "out\nout2"
    assert r.stderr == "err\nerr2"


@pytest.mark.plan("EXEC-04")
def test_arguments_arrive_verbatim_without_a_shell(alice):
    tricky = [
        "two words",
        "it's",
        '"double"',
        "$HOME",
        "`id`",
        "$(id)",
        "a;b|c&d",
        "*",
        "line1\nline2",
        "tab\there",
        "",
        "-n",
        "ünïcödé ✓",
        "back\\slash",
    ]
    r = alice.run("server", "python3", "-c", "import sys, json; print(json.dumps(sys.argv[1:]))", *tricky)
    assert r.rc == 0, r.describe()
    assert json.loads(r.stdout) == tricky


@pytest.mark.plan("EXEC-05")
def test_large_stdin_streams_byte_for_byte(alice):
    """64 MiB of random bytes from the client to a remote sha256sum."""
    out = alice.shell(
        "head -c 64M /dev/urandom > /tmp/up.bin && sha256sum < /tmp/up.bin | cut -d' ' -f1 "
        "&& qsh server sha256sum < /tmp/up.bin | cut -d' ' -f1; rm -f /tmp/up.bin"
    ).stdout.split()
    assert len(out) == 2 and out[0] == out[1], out


@pytest.mark.plan("EXEC-06")
def test_large_stdout_streams_byte_for_byte(alice, server):
    """64 MiB of random bytes from a remote file to the client."""
    server.node.sh("head -c 64M /dev/urandom > /home/alice/down.bin && chown alice: /home/alice/down.bin")
    try:
        want = server.node.run(["sha256sum", "/home/alice/down.bin"], check=True).stdout.split()[0]
        got = alice.shell("qsh server cat down.bin | sha256sum | cut -d' ' -f1").stdout.strip()
        assert got == want
    finally:
        server.node.run(["rm", "-f", "/home/alice/down.bin"])


@pytest.mark.plan("EXEC-07")
def test_binary_round_trip_through_remote_cat(alice):
    """Every byte value, including NUL, CR, LF and the escape char, both ways."""
    data = bytes(range(256)) * 4096 + b"~.\n~~\r\n\x00\x04\x03"
    r = alice.run("server", "cat", input=data)
    assert r.rc == 0, r.describe()
    assert hashlib.sha256(r.out).hexdigest() == hashlib.sha256(data).hexdigest()


@pytest.mark.plan("EXEC-08")
def test_end_of_stdin_reaches_the_remote_process(alice):
    r = alice.run("server", "wc", "-c", input=b"abc")
    assert r.rc == 0, r.describe()
    assert r.stdout.strip() == "3"


@pytest.mark.plan("EXEC-09")
def test_no_stdin_flag_never_reads_local_input(alice):
    """`-n` must not consume the caller's stdin (a `while read` loop relies on it)."""
    out = alice.shell(
        "printf 'one\\ntwo\\nthree\\n' | while read -r line; do "
        "  qsh -n server echo \"remote-$line\" < /dev/stdin; "
        "done"
    ).stdout.split()
    assert out == ["remote-one", "remote-two", "remote-three"]


@pytest.mark.plan("EXEC-10")
def test_session_runs_as_the_mapped_account(alice):
    script = 'id -un; id -Gn; pwd; echo "$HOME"; echo "$USER"; echo "$LOGNAME"; echo "$SHELL"; echo "$PATH"'
    r = alice.run("server", "sh", "-c", script)
    assert r.rc == 0, r.describe()
    user, groups, cwd, home, user_env, logname, shell, path = r.stdout.splitlines()
    assert user == "alice"
    assert set(groups.split()) == {"alice", "project"}
    assert cwd == home == "/home/alice"
    assert user_env == logname == "alice"
    assert shell == "/bin/bash"
    assert path == "/usr/local/bin:/usr/bin:/bin:/usr/local/sbin:/usr/sbin:/sbin"


@pytest.mark.plan("EXEC-11")
def test_environment_is_filtered_by_the_server(alice):
    options = (
        "-E", "LANG=C.UTF-8",
        "-E", "LC_TIME=C",
        "-E", "QSH_TRACE=yes",
        "-E", "FOO=bar",
        "-E", "LD_PRELOAD=/tmp/evil.so",
        "-E", "PATH=/tmp",
        "-E", "HOME=/tmp",
    )
    r = alice.run("server", "env", options=options)
    assert r.rc == 0, r.describe()
    env = dict(line.split("=", 1) for line in r.stdout.splitlines())
    assert env["LANG"] == "C.UTF-8"
    assert env["LC_TIME"] == "C"
    assert env["QSH_TRACE"] == "yes"
    assert "FOO" not in env
    assert "LD_PRELOAD" not in env
    assert env["PATH"].startswith("/usr/local/bin:")
    assert env["HOME"] == "/home/alice"


@pytest.mark.plan("EXEC-12")
def test_a_program_that_cannot_run_fails_like_a_shell(alice):
    """127 for a program that does not exist, 126 for one that cannot run."""
    r = alice.run("server", "no-such-program-qsh-e2e", "arg")
    assert r.rc == 127, r.describe()
    assert "no-such-program-qsh-e2e" in r.stderr and "not found" in r.stderr, r.describe()
    r = alice.run("server", "/etc/hostname")
    assert r.rc == 126, r.describe()
    assert "/etc/hostname" in r.stderr, r.describe()


@pytest.mark.plan("EXEC-13")
def test_exec_has_no_terminal_unless_asked(alice):
    plain = alice.run("server", "sh", "-c", "test -t 0 || echo no-tty")
    assert plain.stdout.strip() == "no-tty", plain.describe()
    forced = alice.run("server", "tty", options=("-t",))
    assert forced.rc == 0, forced.describe()
    assert forced.stdout.strip().startswith("/dev/pts/")


@pytest.mark.plan("EXEC-14")
def test_remote_reader_that_stops_early_ends_the_session(alice):
    """`yes | qsh host head -n1`: the remote side closing stdin must not hang qsh."""
    start = time.monotonic()
    r = alice.shell('set +o pipefail; yes | qsh server head -n1; echo "status=${PIPESTATUS[1]}"', timeout=30)
    assert r.stdout.split() == ["y", "status=0"], r.describe()
    assert time.monotonic() - start < 15


@pytest.mark.plan("EXEC-15")
def test_local_reader_that_stops_early_stops_quietly(alice, server):
    """`qsh host yes | head -n1` behaves like a local `yes | head -n1`.

    qsh ends the way a local writer killed by SIGPIPE does: quietly, with
    status 141, and the remote writer does not linger.
    """
    marker = "qsh-e2e-yes-marker"
    r = alice.shell(
        f"set +o pipefail; qsh server sh -c 'exec yes {marker}' | head -n1; echo \"status=${{PIPESTATUS[0]}}\"",
        timeout=30,
    )
    assert r.stdout.split() == [marker, "status=141"], r.describe()
    assert r.stderr == "", r.describe()
    server.node.wait_gone(f"yes {marker}", timeout=15)


@pytest.mark.plan("EXEC-16")
def test_many_arguments_and_a_large_argument(alice):
    args = [f"arg{i}" for i in range(1000)]
    r = alice.run("server", "sh", "-c", 'echo "$#"', "sh", *args)
    assert r.stdout.strip() == "1000", r.describe()
    big = "x" * 16 * 1024
    r = alice.run("server", "sh", "-c", 'printf %s "$1" | wc -c', "sh", big)
    assert r.stdout.strip() == str(len(big)), r.describe()


@pytest.mark.plan("EXEC-17")
@pytest.mark.parametrize(
    "argv",
    [
        pytest.param(["echo", "y" * (16 * 1024 + 1)], id="argument-over-16KiB"),
        pytest.param(["echo", *["z" * 15000] * 5], id="request-over-64KiB"),
        pytest.param(["true", *["a"] * 1024], id="over-1024-arguments"),
    ],
)
def test_a_request_over_the_limits_is_refused_clearly(alice, argv):
    """Whichever end notices first, the refusal is explicit and nothing runs."""
    r = alice.run("server", *argv)
    assert r.rc in (126, 255), r.describe()
    assert "limit" in r.stderr.lower(), r.describe()
    assert alice.run("server", "true").rc == 0


@pytest.mark.plan("EXEC-18")
def test_user_selection_must_match_the_authorization(alice):
    ok = alice.run("alice@server", "id", "-un")
    assert ok.rc == 0 and ok.stdout.strip() == "alice", ok.describe()
    ok = alice.run("server", "id", "-un", options=("-l", "alice"))
    assert ok.rc == 0, ok.describe()
    other = alice.run("bob@server", "id", "-un")
    assert other.rc != 0, other.describe()
    assert "bob" in other.stderr


@pytest.mark.plan("EXEC-19")
def test_output_order_is_preserved(alice):
    r = alice.run("server", "seq", "1", "200000")
    assert r.rc == 0, r.describe()
    assert r.stdout.split() == [str(i) for i in range(1, 200001)]


@pytest.mark.plan("EXEC-20")
def test_ssh_compatible_options_are_accepted(alice):
    r = alice.run(
        "server", "echo", "ok",
        options=("-q", "-v", "-C", "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=yes", "-T"),
    )
    assert r.rc == 0, r.describe()
    assert r.stdout.strip() == "ok"


@pytest.mark.plan("EXEC-21")
def test_a_closed_local_stderr_ends_quietly(alice):
    """`qsh host cmd 2>&1 | head`: closing the combined output is not a crash."""
    r = alice.shell(
        "set +o pipefail; qsh server sh -c 'yes err >&2' 2>&1 | head -n1; echo \"status=${PIPESTATUS[0]}\"",
        timeout=30,
    )
    assert r.stdout.split() == ["err", "status=141"], r.describe()
    assert "panicked" not in r.stderr, r.describe()


@pytest.mark.plan("EXEC-22")
@pytest.mark.parametrize("signal,code", [("INT", 130), ("TERM", 143)])
def test_signals_to_qsh_are_relayed_without_a_terminal(alice, server, signal, code):
    """Without a PTY, INT and TERM sent to qsh reach the remote process."""
    # The trap ends the background job too: it would hold the output open.
    marker = f"30.{code}"
    script = f"trap 'echo got-{signal}; kill $!; exit {code}' {signal}; echo ready; sleep {marker} & wait"
    proc = alice.node.popen(alice.argv("server", "sh", "-c", script), user="alice")
    server.node.wait_running(f"sleep {marker}", timeout=10)
    alice.node.run(["pkill", f"-{signal}", "-u", "alice", "-x", "qsh"], check=True)
    out, err = proc.communicate(timeout=30)
    assert out.decode().split() == ["ready", f"got-{signal}"], err.decode()
    assert proc.returncode == code, err.decode()


@pytest.mark.plan("EXEC-23")
def test_an_argument_that_is_not_utf8_is_refused_cleanly(alice):
    """qsh/1 carries text arguments; a Latin-1 file name is refused, not a crash."""
    r = alice.shell("set +e; qsh server ls \"$(printf 'caf\\351')\"; echo \"status=$?\"", check=False)
    assert r.stdout.strip() == "status=255", r.describe()
    assert "not valid UTF-8" in r.stderr and "panicked" not in r.stderr, r.describe()
