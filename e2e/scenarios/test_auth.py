"""AUTH: who may log in, as whom, to do what, and how changes take effect."""

from __future__ import annotations

import re
import time

import pytest

from harness.qsh import RELOAD_SETTLE
from harness.terminal import Terminal


def ticker_marker(marker: str) -> tuple[str, ...]:
    return ("sh", "-c", f"exec sleep {marker}")


@pytest.mark.plan("AUTH-01")
def test_an_unauthorized_key_is_refused(make_client, server):
    stranger = make_client("alice")
    since = server.cursor()
    r = stranger.run("server", "true")
    assert r.rc == 255, r.describe()
    assert "handshake failed" in r.stderr or "not authorized" in r.stderr, r.describe()
    journal = server.journal(since)
    assert "authenticated as" not in journal


@pytest.mark.plan("AUTH-02")
def test_authorize_takes_effect_without_a_restart(make_client, server):
    newcomer = make_client("alice")
    pid = server.main_pid()
    assert newcomer.run("server", "true").rc == 255
    server.authorize(newcomer.cert(), user="alice", name=f"late-{newcomer.fingerprint[7:15]}")
    try:
        r = newcomer.run("server", "id", "-un")
        assert r.rc == 0 and r.stdout.strip() == "alice", r.describe()
        assert server.main_pid() == pid, "authorize restarted the daemon"
    finally:
        server.revoke(f"late-{newcomer.fingerprint[7:15]}", settle=False)


@pytest.mark.plan("AUTH-03")
def test_revoke_cuts_off_new_and_running_sessions(make_client, server):
    member = make_client("alice", authorize_as="alice")
    entry = member.entry
    marker = "5151.25"
    proc = member.node.popen(member.argv("server", *ticker_marker(marker)), user="alice")
    server.node.wait_running(f"sleep {marker}", timeout=10)
    begin = time.monotonic()
    server.revoke(entry, settle=False)
    _, err = proc.communicate(timeout=30)
    assert proc.returncode == 255, err.decode()
    assert time.monotonic() - begin < 6, "revocation took too long to reach a running session"
    server.node.wait_gone(f"sleep {marker}", timeout=10)
    assert member.run("server", "true").rc == 255


@pytest.mark.plan("AUTH-04")
def test_no_shell_allows_commands_only(make_client, server):
    limited = make_client("alice", authorize_as="alice", options=("--no-shell",))
    assert limited.run("server", "true").rc == 0
    term = Terminal(limited, "server")
    try:
        term.expect(r"shell")  # the refusal names what was refused
        assert term.wait_exit() != 0
    finally:
        term.close()


@pytest.mark.plan("AUTH-05")
def test_no_exec_allows_the_shell_only(make_client, server):
    limited = make_client("alice", authorize_as="alice", options=("--no-exec",))
    r = limited.run("server", "true")
    assert r.rc == 126, r.describe()
    term = Terminal(limited, "server")
    try:
        term.set_prompt()
        assert term.command("id -un").strip() == "alice"
        term.sendline("exit")
        assert term.wait_exit() == 0
    finally:
        term.close()


@pytest.mark.plan("AUTH-06")
def test_a_command_filter_matches_argv0_exactly(make_client, server):
    """`--command` compares the whole argv[0], never a basename or a lookup."""
    status = make_client("alice", authorize_as="alice", options=("--no-shell", "--command", "/usr/bin/uptime"))
    # Exactly the authorized path, with any arguments.
    r = status.run("server", "/usr/bin/uptime", "-p")
    assert r.rc == 0 and r.stdout.startswith("up "), r.describe()
    # Anything else: another program, the bare name of the allowed one, a
    # look-alike the account could have planted, or a shell running it.
    server.node.sh("install -D -m 0755 -o alice /usr/bin/uptime /home/alice/bin/uptime")
    try:
        for argv in (("id",), ("uptime",), ("/home/alice/bin/uptime",), ("sh", "-c", "uptime")):
            r = status.run("server", *argv)
            assert r.rc == 126, r.describe()
            assert f"`{argv[0]}`" in r.stderr, r.describe()
    finally:
        server.node.run(["rm", "-rf", "/home/alice/bin"])


@pytest.mark.plan("AUTH-14")
def test_a_bare_command_name_runs_from_the_servers_fixed_path(make_client, server):
    """`--command uptime` admits `uptime`, resolved through the server's PATH.

    A copy the account planted earlier in a PATH of its own choosing must not
    be what runs.
    """
    status = make_client("alice", authorize_as="alice", options=("--no-shell", "--command", "uptime"))
    server.node.sh(
        "mkdir -p /home/alice/bin && printf '#!/bin/sh\\necho FAKE\\n' > /home/alice/bin/uptime "
        "&& chmod 755 /home/alice/bin/uptime && chown -R alice: /home/alice/bin"
    )
    try:
        r = status.run("server", "uptime", "-p", options=("-E", "PATH=/home/alice/bin"))
        assert r.rc == 0, r.describe()
        assert r.stdout.startswith("up ") and "FAKE" not in r.stdout, r.describe()
        r = status.run("server", "/usr/bin/uptime")
        assert r.rc == 126, r.describe()
    finally:
        server.node.run(["rm", "-rf", "/home/alice/bin"])


@pytest.mark.plan("AUTH-07")
def test_a_server_side_deadline_expires_the_authorization(make_client, server):
    member = make_client("alice", authorize_as="alice", options=("--expires-in-days", "30"))
    entry = member.entry
    listing = server.list()
    assert re.search(rf"{re.escape(entry)}\s+alice\b.*(29|30)\s*d", listing), listing
    marker = "5252.25"
    proc = member.node.popen(member.argv("server", *ticker_marker(marker)), user="alice")
    server.node.wait_running(f"sleep {marker}", timeout=10)
    # Bring the deadline forward by hand, as an administrator may.
    deadline = int(time.time()) + 3
    server.node.sh(
        f"f=/etc/qsh/authorized/{entry}.toml; sed -i '/^expires_at_unix/d' $f; "
        f"echo 'expires_at_unix = {deadline}' >> $f"
    )
    _, err = proc.communicate(timeout=30)
    assert proc.returncode == 255, err.decode()
    assert time.time() < deadline + 2 + RELOAD_SETTLE + 3
    server.node.wait_gone(f"sleep {marker}", timeout=10)
    r = member.run("server", "true")
    assert r.rc == 255, r.describe()


@pytest.mark.plan("AUTH-08")
def test_an_expired_client_certificate_is_refused(make_client, server):
    """`--days 0` makes a certificate whose validity window has already closed."""
    old = make_client("alice")
    old.keygen("--days", "0", "--force")
    entry = old.entry
    server.authorize(old.cert(), user="alice", name=entry)
    try:
        r = old.run("server", "true")
        assert r.rc == 255, r.describe()
        assert "Expired" in r.stderr or "expired" in r.stderr, r.describe()
    finally:
        server.revoke(entry, settle=False)


@pytest.mark.plan("AUTH-09")
def test_reauthorizing_a_revoked_key_works(make_client, server):
    member = make_client("alice", authorize_as="alice")
    entry = member.entry
    server.revoke(entry)
    assert member.run("server", "true").rc == 255
    server.authorize(member.cert(), user="alice", name=entry)
    assert member.run("server", "true").rc == 0


@pytest.mark.plan("AUTH-10")
def test_one_key_under_two_names_fails_closed(make_client, server):
    """A hand-made duplicate must deny the key, not pick one entry by name."""
    member = make_client("alice", authorize_as="alice")
    entry = member.entry
    copy = f"{entry}-copy"
    server.node.sh(
        f"cd /etc/qsh/authorized && cp {entry}.crt {copy}.crt && "
        f"sed 's/^user = .*/user = \"bob\"/' {entry}.toml > {copy}.toml"
    )
    time.sleep(RELOAD_SETTLE)
    try:
        r = member.run("server", "true")
        assert r.rc == 255, r.describe()
        assert "conflict" in server.list().lower()
        server.revoke(entry)
        # revoke removes every alias of the key, the copy included.
        assert not server.node.exists(f"/etc/qsh/authorized/{copy}.crt")
        assert member.run("server", "true").rc == 255
    finally:
        server.node.run(["sh", "-c", f"rm -f /etc/qsh/authorized/{copy}.*"])


@pytest.mark.plan("AUTH-11")
def test_a_hand_edited_policy_applies_to_the_next_session(make_client, server):
    member = make_client("alice", authorize_as="alice")
    entry = member.entry
    assert member.run("server", "true").rc == 0
    server.node.sh(f"sed -i 's/^allow_exec = true/allow_exec = false/' /etc/qsh/authorized/{entry}.toml")
    time.sleep(RELOAD_SETTLE)
    r = member.run("server", "true")
    assert r.rc == 126, r.describe()


@pytest.mark.plan("AUTH-12")
def test_the_identity_is_the_key_not_the_machine(alice, server, env):
    """alice's key directory copied to client2 works there, as alice."""
    client2 = env.node("client2")
    blob = alice.node.run(["tar", "-C", "/home/alice/.config", "-cf", "-", "qsh"], user="alice", check=True).out
    client2.run(["sh", "-c", "mkdir -p /home/bob/alice-key && tar -C /home/bob/alice-key -xf -"], user="bob", input=blob, check=True)
    try:
        r = client2.run(["qsh", "-i", "/home/bob/alice-key/qsh", "server", "id", "-un"], user="bob")
        assert r.rc == 0 and r.stdout.strip() == "alice", r.describe()
    finally:
        client2.run(["rm", "-rf", "/home/bob/alice-key"])


@pytest.mark.plan("AUTH-13")
def test_narrowing_a_policy_ends_sessions_it_no_longer_allows(make_client, server):
    """Policy is re-checked while a session runs, not only when it starts.

    Taking `allow_shell` away ends a shell that is already running; commands,
    which the key may still run, keep working.
    """
    member = make_client("alice", authorize_as="alice")
    entry = member.entry
    term = Terminal(member, "server")
    try:
        term.set_prompt()
        server.node.sh(f"sed -i 's/^allow_shell = true/allow_shell = false/' /etc/qsh/authorized/{entry}.toml")
        assert term.wait_exit(timeout=RELOAD_SETTLE + 5) != 0
    finally:
        term.close()
    r = member.run("server", "true")
    assert r.rc == 0, r.describe()


@pytest.mark.plan("AUTH-15")
def test_a_legacy_policy_still_works_with_a_warning(make_client, server):
    """A policy written before `key_fingerprint` existed is accepted, and says so."""
    member = make_client("alice", authorize_as="alice", options=("--no-shell",))
    toml = f"/etc/qsh/authorized/{member.entry}.toml"
    since = server.cursor()
    server.node.sh(f"grep -v '^key_fingerprint' {toml} > {toml}.new && mv {toml}.new {toml}")
    time.sleep(RELOAD_SETTLE)
    assert member.run("server", "true").rc == 0
    server.wait_journal(rf"{re.escape(toml)} does not record which key it is for", since)
    # Rebinding as the warning suggests, with the same restrictions.
    server.authorize(member.cert(), user="alice", name=member.entry, options=("--no-shell", "--force"))
    assert "key_fingerprint" in server.node.read(toml).decode()
    assert member.run("server", "true").rc == 0
    term = Terminal(member, "server")
    try:
        assert term.wait_exit() != 0, "--no-shell was lost when the policy was rebound"
    finally:
        term.close()


@pytest.mark.plan("AUTH-16")
def test_authorize_force_rotates_a_client_key(make_client, server):
    old = make_client("alice", authorize_as="alice")
    new = make_client("alice")
    marker = "5353.25"
    proc = old.node.popen(old.argv("server", "sleep", marker), user="alice")
    server.node.wait_running(f"sleep {marker}", timeout=10)
    server.authorize(new.cert(), user="alice", name=old.entry, options=("--force",))
    _, err = proc.communicate(timeout=30)
    assert proc.returncode == 255, err.decode()
    server.node.wait_gone(f"sleep {marker}", timeout=10)
    assert old.run("server", "true").rc == 255
    assert new.run("server", "true").rc == 0


@pytest.mark.plan("AUTH-17")
def test_a_revocation_tombstone_blocks_restored_files(make_client, server):
    member = make_client("alice", authorize_as="alice")
    base = f"/etc/qsh/authorized/{member.entry}"
    server.node.sh(f"cp {base}.crt /root/saved.crt && cp {base}.toml /root/saved.toml")
    server.revoke(member.entry)
    server.node.sh(f"cp /root/saved.crt {base}.crt && cp /root/saved.toml {base}.toml && rm /root/saved.*")
    time.sleep(RELOAD_SETTLE)
    assert member.run("server", "true").rc == 255, "hand-restored files undid a revocation"
    server.authorize(member.cert(), user="alice", name=member.entry, options=("--force",))
    assert member.run("server", "true").rc == 0


@pytest.mark.plan("AUTH-19")
def test_account_controls_outside_qsh_do_not_gate_it(make_client, server):
    """Documented: no PAM, so account expiry and /etc/nologin do not apply."""
    member = make_client("carol", authorize_as="carol")
    server.node.sh("chage -E 0 carol && touch /etc/nologin")
    try:
        r = member.run("server", "id", "-un")
        assert r.rc == 0 and r.stdout.strip() == "carol", r.describe()
    finally:
        server.node.sh("chage -E -1 carol; rm -f /etc/nologin")
    # The authorization is the gate: revoking it is what ends access.
    server.revoke(member.entry)
    assert member.run("server", "true").rc == 255
