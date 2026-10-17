"""OPS: installing, configuring and running qsh-server the documented way."""

from __future__ import annotations

import contextlib
import re
import subprocess
import time

import pytest

from harness.env import Unmet
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
    reason="FXX-OPS-14: under the unit 1.0 shipped (ProtectSystem=full) the upgraded server "
    "cannot open /etc/qsh/authorized.lock for writing and never starts",
)
def test_an_upgrade_keeps_serving_under_the_unit_1_0_shipped(make_client, fast_server):
    """The same upgrade on a host that kept the unit file 1.0 shipped.

    Replacing the binary is what a package or `cargo install` does; the unit
    file installed from 1.0's contrib/qsh-server.service stays. It has
    `ProtectSystem=full`, which makes /etc read-only for the daemon, and 1.0
    never writes there while serving. The upgraded server must start and
    serve the same keys.
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

SKEW_PORTS = {"current": 2416, "previous": 2417, "rollback": 2418, "interrupted": 2419, "interrupted-1.0": 2420}


def standalone_server(node, program: str, label: str) -> QshServer:
    """A new state directory under /var/tmp, its host key made by `program`."""
    server = QshServer(node, state_dir=f"/var/tmp/{unique(label)}", program=program)
    server.fp = server.keygen()
    return server


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


def remove_state(server: QshServer) -> None:
    server.node.run(["rm", "-rf", server.state_dir, f"{server.state_dir}.log"])


@pytest.mark.plan("OPS-16")
def test_the_previous_release_and_this_one_interoperate(make_client, fast_server):
    """qsh 1.0's client against this server, and this client against a 1.0 server.

    The wire protocol is still qsh/1, version 1 (README "Protocol"), so a
    mixed pair has to work as a matched one does: the exit status and death
    by signal, stdin and stdout byte for byte without a terminal, stderr
    apart, argv and the environment verbatim. A refusal must arrive as a
    message and a status, never as a hang: a policy refusal, a key the server
    does not know, and this server shutting down under a 1.0 client.
    """
    node = fast_server.node
    current = standalone_server(node, "qsh-server", "ops16-current")
    previous = standalone_server(node, PREVIOUS_QSH_SERVER, "ops16-previous")
    pairs = []
    skews = ((current, SKEW_PORTS["current"], True), (previous, SKEW_PORTS["previous"], False))
    for server, port, old_client in skews:
        client = make_client("alice", pin=False, previous=old_client)
        stranger = make_client("alice", pin=False, previous=old_client)  # authorized nowhere
        server.authorize(client.cert(), user="alice", name=client.entry, settle=False)
        client.pin("server2", server.fp, port=port)
        stranger.pin("server2", server.fp, port=port)
        pairs.append((client, stranger, server, port))
    marker = "7373.25"
    try:
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
                r = client.run("bob@server2", "true", port=port, timeout=30)
                assert r.rc == 126 and "not `bob`" in r.stderr, f"{pair}: {r.describe()}"
                r = stranger.run("server2", "true", port=port, timeout=30)
                assert r.rc == 255 and r.stderr.startswith("qsh: "), f"{pair}: {r.describe()}"
                if server is current:
                    proc = client.node.popen(client.argv("server2", "sleep", marker, port=port), user="alice")
                    node.wait_running(f"sleep {marker}", timeout=10)
                    begin = time.monotonic()
                    stop()
                    _, err = proc.communicate(timeout=30)
                    took = time.monotonic() - begin
                    assert proc.returncode == 255 and "shutting down" in err.decode(), f"{pair}: {err.decode()}"
                    assert took < 10, f"{pair}: the client took {took:.0f}s to notice the shutdown"
    finally:
        node.run(["pkill", "-f", f"^sleep {marker}$"])
        for server in (current, previous):
            remove_state(server)


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
    this build added stays private to root throughout (THREAT_MODEL actor 4).
    """
    node = fast_server.node
    port = SKEW_PORTS["rollback"]
    previous = standalone_server(node, PREVIOUS_QSH_SERVER, "ops16-rollback")
    current = QshServer(node, state_dir=previous.state_dir)
    legacy, bound, revoked, expired, narrowed = (make_client("alice", pin=False) for _ in range(5))
    lock = f"{current.state_dir}/authorized.lock"

    def outcome(client: QshClient):
        return client.run("server2", "echo", "granted-ops16", port=port, timeout=30)

    def granted(client: QshClient) -> None:
        r = outcome(client)
        assert (r.rc, r.stdout) == (0, "granted-ops16\n"), f"{client.entry}: {r.describe()}"

    def refused(client: QshClient) -> None:
        r = outcome(client)
        assert r.rc == 255 and "granted-ops16" not in r.stdout, f"{client.entry}: {r.describe()}"

    try:
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
        assert stat(node, lock) == "600 root root"

        with serving_by_hand(current, port):
            refused(revoked)
            granted(legacy)
            granted(bound)
        listing = current.list()
        assert re.search(rf"^{re.escape(revoked.entry)} .*\[DENIED", listing, re.M), listing
    finally:
        remove_state(previous)


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
    previous = standalone_server(fast_server.node, PREVIOUS_QSH_SERVER, "ops16-interrupted")
    try:
        current, victim = interrupted_revocation(make_client, previous)
        victim.pin("server2", current.fp, port=port)
        listing = current.list()
        assert re.search(rf"^{re.escape(victim.entry)} .*\[DENIED: interrupted mutation\]$", listing, re.M), listing
        with serving_by_hand(current, port):
            r = victim.run("server2", "echo", "granted-ops16", port=port, timeout=30)
            assert r.rc == 255 and "granted-ops16" not in r.stdout, r.describe()
        current.revoke(victim.entry, settle=False)
        assert victim.entry not in current.list()
    finally:
        remove_state(previous)


@pytest.mark.plan("OPS-16")
@pytest.mark.xfail(
    strict=True,
    raises=Unmet,
    reason="FXX-OPS-16: 1.0 ignores the denial marker an interrupted revoke leaves, so rolling back re-enables the key",
)
def test_a_rollback_keeps_an_interrupted_revocation_refused(make_client, fast_server):
    """The state above, served by qsh-server 1.0 after a rollback.

    The administrator has stopped trusting the key; this build refuses it.
    Rolled back to 1.0, it must stay refused (THREAT_MODEL actor 3:
    revocation is enforced for every session). `bystander`, an ordinary
    1.0 policy in the same store, shows that 1.0 serves the store at all.
    """
    port = SKEW_PORTS["interrupted-1.0"]
    previous = standalone_server(fast_server.node, PREVIOUS_QSH_SERVER, "ops16-interrupted")
    bystander = make_client("alice", pin=False)
    try:
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
    finally:
        remove_state(previous)
