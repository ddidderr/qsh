"""SEC: the boundaries THREAT_MODEL.md promises, checked across real hosts.

Each scenario names the actor from THREAT_MODEL.md it plays.
"""

from __future__ import annotations

import time

import pytest

from harness.terminal import Terminal


def status_fields(text: str) -> dict[str, list[str]]:
    fields = {}
    for line in text.splitlines():
        key, _, value = line.partition(":")
        fields[key] = value.split()
    return fields


@pytest.mark.plan("SEC-01")
def test_an_impostor_under_a_pinned_name_is_refused(make_client, server, fast_server, env):
    """Actor 2 (on-path): the name resolves to another machine with another key.

    The client must refuse, and must not have presented its identity to the
    impostor before refusing.
    """
    victim = make_client("alice", authorize_as="alice")
    # The impostor would accept the victim's key: had the client presented it
    # before checking the host key, server2 would log a login.
    fast_server.authorize(victim.cert(), user="alice", name=victim.entry)
    # `bank` is the real server first; the victim pins it.
    victim.node.edit_hosts(add=f"{server.node.ip} bank")
    try:
        victim.pin("bank", server.fp)
        assert victim.run("bank", "true").rc == 0
        # Now `bank` answers from server2, which has its own host key.
        victim.node.edit_hosts(remove="bank", add=f"{fast_server.node.ip} bank")
        since = fast_server.cursor()
        r = victim.run("bank", "true")
        assert r.rc == 255, r.describe()
        # The message names the pinned key and the one presented instead.
        assert server.fp in r.stderr and fast_server.fp in r.stderr, r.describe()
        # The pin is unchanged: the impostor's key was not learned.
        listing = victim.subcommand("known-hosts", "list").stdout
        assert server.fp in listing and fast_server.fp not in listing
        time.sleep(1.5)  # failure counts are reported in batches
        assert "authenticated as" not in fast_server.journal(since)
    finally:
        victim.node.edit_hosts(remove="bank")
        fast_server.revoke(victim.entry, settle=False, check=False)


@pytest.mark.plan("SEC-02")
def test_first_contact_asks_and_a_no_pins_nothing(make_client, server):
    newcomer = make_client("alice", authorize_as="alice", pin=False)
    term = Terminal(newcomer, "server", "true")
    try:
        term.expect(r"cannot be established")
        term.expect(server.fp)
        term.expect(r"\(yes/no\)")
        term.sendline("no")
        assert term.wait_exit() == 255
    finally:
        term.close()
    assert "server" not in newcomer.subcommand("known-hosts", "list").stdout
    term = Terminal(newcomer, "server", "echo", "pinned")
    try:
        term.expect(r"\(yes/no\)")
        term.sendline("yes")
        term.expect(r"pinned")
        assert term.wait_exit() == 0
    finally:
        term.close()
    assert server.fp in newcomer.subcommand("known-hosts", "list").stdout
    # The second connection does not ask again.
    assert newcomer.run("server", "true").rc == 0


@pytest.mark.plan("SEC-11")
@pytest.mark.parametrize("answer", ["YES", "Yes", "y"])
def test_the_first_contact_answer_is_not_case_sensitive(make_client, server, answer):
    newcomer = make_client("alice", authorize_as="alice", pin=False)
    term = Terminal(newcomer, "server", "echo", "pinned")
    try:
        term.expect(r"\(yes/no\)")
        term.sendline(answer)
        term.expect(r"pinned")
        assert term.wait_exit() == 0
    finally:
        term.close()


@pytest.mark.plan("SEC-03")
@pytest.mark.parametrize(
    "options,pins",
    [
        (("--refuse-new",), False),
        (("-o", "StrictHostKeyChecking=yes"), False),
        (("--accept-new",), True),
        (("-o", "StrictHostKeyChecking=accept-new"), True),
    ],
)
def test_first_contact_policies_without_a_terminal(make_client, server, options, pins):
    newcomer = make_client("alice", authorize_as="alice", pin=False)
    r = newcomer.run("server", "true", options=options)
    assert (r.rc == 0) == pins, r.describe()
    listed = server.fp in newcomer.subcommand("known-hosts", "list").stdout
    assert listed == pins


@pytest.mark.plan("SEC-04")
def test_local_users_on_the_server_cannot_reach_its_secrets(server, alice):
    """Actor 4: bob has a shell on the server host but no business in /etc/qsh."""
    assert alice.run("server", "true").rc == 0
    bob = server.node
    for path in ("/etc/qsh/server.key",):
        r = bob.run(["cat", path], user="bob")
        assert r.rc != 0 and "Permission denied" in r.stderr, r.describe()
    r = bob.run(["touch", "/etc/qsh/authorized/bob-was-here.crt"], user="bob")
    assert r.rc != 0, r.describe()
    lock = bob.run(["sh", "-c", "ls /etc/qsh/*.lock /etc/qsh/authorized.lock 2>/dev/null | head -n1"]).stdout.strip()
    if lock:
        mode = bob.run(["stat", "-c", "%a %U", lock], check=True).stdout.strip()
        assert mode == "600 root", f"{lock} is {mode}"
        r = bob.run(["sh", "-c", f"exec 3<{lock}"], user="bob")
        assert r.rc != 0, "bob could open the authorization lock"


@pytest.mark.plan("SEC-05")
def test_local_users_on_the_client_cannot_reach_alices_identity(alice, env):
    """Actor 5: bob shares client1 with alice."""
    node = alice.node
    assert node.run(["stat", "-c", "%a", "/home/alice/.config/qsh/id.key"], check=True).stdout.strip() == "600"
    r = node.run(["cat", "/home/alice/.config/qsh/id.key"], user="bob")
    assert r.rc != 0, r.describe()
    r = node.run(["sh", "-c", "echo 'server:2222 sha256:00' >> /home/alice/.config/qsh/known_hosts"], user="bob")
    assert r.rc != 0, r.describe()


@pytest.mark.plan("SEC-06")
def test_a_readable_private_key_is_refused(make_client):
    careless = make_client("alice", authorize_as="alice")
    careless.node.run(["chmod", "640", f"{careless.identity}/id.key"], check=True)
    r = careless.run("server", "true")
    assert r.rc == 255, r.describe()
    assert "id.key" in r.stderr, r.describe()


@pytest.mark.plan("SEC-07")
def test_a_root_daemons_session_keeps_no_privilege(alice):
    """Actor 3: the session is alice, completely: IDs, groups, capabilities."""
    r = alice.run("server", "cat", "/proc/self/status")
    assert r.rc == 0, r.describe()
    status = status_fields(r.stdout)
    assert status["Uid"] == ["1001"] * 4
    assert status["Gid"] == ["1001"] * 4
    assert sorted(status["Groups"]) == ["1001", "2000"]
    for cap in ("CapInh", "CapPrm", "CapEff", "CapAmb"):
        assert int(status[cap][0], 16) == 0, f"{cap} = {status[cap][0]}"


@pytest.mark.plan("SEC-08")
def test_a_session_inherits_only_its_standard_streams(alice):
    for options in ((), ("-t",)):
        r = alice.run("server", "python3", "-c", "import os; print(sorted(os.listdir('/proc/self/fd')))", options=options)
        assert r.rc == 0, r.describe()
        # 0-2, plus the descriptor listdir itself holds open.
        assert r.stdout.strip() == "['0', '1', '2', '3']", r.stdout


@pytest.mark.plan("SEC-09")
def test_a_session_terminal_belongs_to_its_user_alone(alice, server):
    term = Terminal(alice, "server")
    try:
        term.set_prompt()
        tty = term.command("tty").strip()
        owner = server.node.run(["stat", "-c", "%U %G %a", tty], check=True).stdout.split()
        # As sshd leaves it: the user's own terminal, writable by group tty
        # (for `write` and `wall`), by nobody else.
        assert owner == ["alice", "tty", "620"], f"{tty} is {owner}"
        # alice can open her own terminal by name, as screen or pinentry do.
        assert term.command(f"echo mine > {tty}; echo OPEN-$?").strip().endswith("OPEN-0")
        r = server.node.run(["sh", "-c", f"echo intrusion > {tty}"], user="bob")
        assert r.rc != 0, r.describe()
    finally:
        term.close()


@pytest.mark.plan("SEC-10")
def test_unauthenticated_noise_does_not_disturb_service(make_client, alice, server, env):
    """Actor 1: junk datagrams and a burst of unauthorized handshakes from client2."""
    flood = env.node("client2")
    junk = (
        "import os, socket\n"
        "s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)\n"
        "for i in range(3000):\n"
        "    s.sendto(os.urandom(1200 if i % 2 else 40), ('server', 2222))\n"
    )
    since = server.cursor()
    flood.run(["python3", "-c", junk], check=True)
    strangers = [make_client("bob", node="client2") for _ in range(2)]
    procs = []
    for stranger in strangers:
        for _ in range(10):
            procs.append(stranger.node.popen(stranger.argv("server", "true"), user="bob"))
    # Service for an authorized client continues meanwhile.
    begin = time.monotonic()
    r = alice.run("server", "echo", "served")
    assert r.rc == 0 and r.stdout.strip() == "served", r.describe()
    assert time.monotonic() - begin < 10
    for proc in procs:
        proc.wait(timeout=60)
        assert proc.returncode == 255
    time.sleep(1.5)
    journal = server.journal(since)
    # Failures are summarized in a few lines per second, never one per
    # attempt: fewer lines than the 20 handshakes alone.
    assert journal.count("\n") < 20, journal
    assert flood.ip not in journal, journal
    assert server.is_active()


@pytest.mark.plan("SEC-12")
def test_capabilities_added_to_the_unit_never_reach_sessions(alice_fast, fast_server):
    """Actor 3: an administrator's drop-in grants the daemon ambient capabilities."""
    dropin = "/etc/systemd/system/qsh-server.service.d"
    fast_server.node.sh(
        f"mkdir -p {dropin} && printf '[Service]\\nAmbientCapabilities=CAP_NET_RAW CAP_SYS_ADMIN\\n' > {dropin}/caps.conf"
        " && systemctl daemon-reload"
    )
    try:
        fast_server.restart()
        daemon = fast_server.node.run(["grep", "CapAmb", f"/proc/{fast_server.main_pid()}/status"], check=True)
        assert int(daemon.stdout.split()[1], 16) != 0, "the drop-in did not take effect"
        r = alice_fast.run("server2", "cat", "/proc/self/status")
        assert r.rc == 0, r.describe()
        status = status_fields(r.stdout)
        for cap in ("CapInh", "CapPrm", "CapEff", "CapAmb"):
            assert int(status[cap][0], 16) == 0, f"{cap} = {status[cap][0]}"
    finally:
        fast_server.node.sh(f"rm -rf {dropin} && systemctl daemon-reload")
        fast_server.restart()
