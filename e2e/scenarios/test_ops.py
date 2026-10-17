"""OPS: installing, configuring and running qsh-server the documented way."""

from __future__ import annotations

import time

import pytest

from harness.qsh import PORT, QshServer, parse_fingerprint


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
