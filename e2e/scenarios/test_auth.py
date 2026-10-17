"""AUTH: who may log in, as whom, to do what, and how changes take effect."""

from __future__ import annotations

import contextlib
import itertools
import re
import shlex
import subprocess
import time
from contextlib import ExitStack, contextmanager

import pytest

from harness.env import Unmet
from harness.qsh import RELOAD_SETTLE, QshServer, unique
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


# ---------------------------------------------------------------- AUTH-18
#
# A running session is checked against its key's current policy once a
# second (src/server.rs `standing`). A key that may still connect but no
# longer for this session keeps its connection, so no connection close can
# carry the reason. The session says it in-band instead, with an exit status
# of 255, and the server records one line per session, with the peer and
# the key, on the audit lane, which the peer diagnostic budget does not
# limit. The client is told only that the key's permissions changed; the
# journal says what changed.

# What the client prints.
NARROWED = "qsh: the server ended this session: this key's permissions changed"

TOML = "/etc/qsh/authorized/{entry}.toml"

# Words a message about a changed policy uses.
CHANGED = r"\b(?:no longer|not any more|now|new|changed|narrowed)\b"


def set_policy(line: str, new: str):
    """A policy change: the `line` of the key's policy file becomes `new`."""

    def change(server, member) -> None:
        toml = TOML.format(entry=member.entry)
        server.node.sh(f"sed -i {shlex.quote(f's|^{line}$|{new}|')} {toml} && grep -qxF {shlex.quote(new)} {toml}")

    return change


def reauthorize(*options: str):
    """A policy change through the tool: `authorize --force` with `options`."""

    def change(server, member) -> None:
        server.authorize(member.cert(), user="alice", name=member.entry, options=("--force", *options), settle=False)

    return change


# Whether the session is a login shell, how its policy changes, and what a
# message about the change must name.
NARROWINGS = [
    pytest.param(True, set_policy("allow_shell = true", "allow_shell = false"), r"shell", id="allow_shell"),
    pytest.param(False, set_policy("allow_exec = true", "allow_exec = false"), r"command|execut", id="allow_exec"),
    pytest.param(
        False,
        set_policy(r"allowed_commands = \[\]", 'allowed_commands = ["/usr/bin/true"]'),
        r"`sleep`",
        id="allowed_commands",
    ),
    pytest.param(False, set_policy('user = "alice"', 'user = "bob"'), r"`bob`", id="user"),
    pytest.param(
        False,
        set_policy("kill_session_processes = false", "kill_session_processes = true"),
        r"clean|kill|restrict",
        id="kill_session_processes",
    ),
    pytest.param(True, reauthorize("--no-shell"), r"shell", id="authorize--no-shell"),
]

_narrowing_markers = itertools.count(1)


@contextmanager
def a_narrowable_session(member, server, *, shell: bool):
    """A session of `member`'s key on `server` whose job is a distinctive `sleep`.

    A login shell with the `sleep` in the foreground, or `qsh server sleep`.
    Yields the marker and a function that waits for qsh to end and returns
    its status and what it printed (on its stderr, or on the terminal).
    """
    marker = f"8181.{next(_narrowing_markers):02d}5"
    if shell:
        term = Terminal(member, "server", timeout=30)

        def wait(timeout: float) -> tuple[int, str]:
            status = term.wait_exit(timeout=timeout)
            return status, term.child.before or ""

    else:
        argv = member.argv("server", "sleep", marker)
        proc = member.node.popen(argv, user="alice")

        def wait(timeout: float) -> tuple[int, str]:
            _, err = proc.communicate(timeout=timeout)
            return proc.returncode, err.decode(errors="replace")

    try:
        if shell:
            term.set_prompt()
            term.sendline(f"sleep {marker}")
        server.node.wait_running(f"sleep {marker}", timeout=15)
        yield marker, wait
    finally:
        if shell:
            term.close()
        else:
            member.node.kill_command("alice", argv)
            proc.wait(timeout=10)
        server.node.run(["pkill", "-u", "alice", "-f", f"^sleep {marker}$"])


@pytest.mark.plan("AUTH-18")
@pytest.mark.parametrize("shell,change,reason", NARROWINGS)
def test_a_narrowed_policy_ends_the_session_at_once_with_255(make_client, server, shell, change, reason):
    """What already holds: the session ends within the policy check's period.

    The reload and each session's policy check run once a second, so about
    two seconds at worst (README: revocation "normally within two seconds");
    the job goes with it, and qsh fails with 255 like a revoked session
    (AUTH-03), not with a status the remote job could have produced.
    """
    member = make_client("alice", authorize_as="alice")
    with a_narrowable_session(member, server, shell=shell) as (marker, wait):
        change(server, member)
        begin = time.monotonic()
        status, said = wait(timeout=30)
        took = time.monotonic() - begin
        assert status == 255, said
        assert took < 2 + 2, f"the narrowed session ended after {took:.1f}s"
        server.node.wait_gone(f"sleep {marker}", timeout=10)


def narrowing_line(entry: str, reason: str, prefix: str, peer: str | None = None) -> str:
    """A regex for one line that starts with `prefix` and names the key,
    the change, its reason and, if given, the peer's address, in any order."""
    rest = r"[^\r\n]*"
    where = rf"(?={rest}\b{re.escape(peer)}:\d+\b)" if peer else ""
    return (
        rf"{prefix}{where}(?={rest}`{re.escape(entry)}`)(?={rest}{CHANGED})(?={rest}(?:{reason}))"
        rf"(?!{rest}authenticated as){rest}"
    )


@pytest.mark.plan("AUTH-18")
@pytest.mark.parametrize("shell,change,reason", NARROWINGS)
def test_a_narrowed_policy_tells_the_user_and_the_journal_why(make_client, server, shell, change, reason):
    """The client says why the session ended; the server logs which key lost what.

    The journal line is matched loosely: the peer, the key, a word for the
    change and the reason, in any order.
    """
    member = make_client("alice", authorize_as="alice")
    since = server.cursor()
    with a_narrowable_session(member, server, shell=shell) as (_, wait):
        change(server, member)
        status, said = wait(timeout=30)
    assert status == 255, said
    assert "stream reset" not in said, said
    assert NARROWED in said, said
    server.wait_journal(narrowing_line(member.entry, reason, r"(?m)^qsh-server: ", member.node.ip), since, timeout=5)


def exhausted(server, since: str) -> None:
    """Skip unless the peer diagnostic budget ran out after `since`.

    The server reports suppressed lines once a second, for the second before.
    """
    try:
        server.wait_journal(r"suppressed \d+ diagnostic", since, timeout=10)
    except AssertionError:
        pytest.skip("the flood did not exhaust the peer diagnostic budget on this host")


@pytest.mark.plan("AUTH-18")
def test_the_narrowing_line_survives_a_flood_of_failing_sessions(make_client, server):
    """THREAT_MODEL.md actor 3 cannot silence the audit lines by failing sessions.

    bob's `--no-exec` key fails sessions from client2 as fast as it can,
    which exhausts the peer diagnostic budget (16 lines a second, the rest
    "suppressed"). Meanwhile alice's key loses `allow_exec` under three
    running commands: each of the three sessions must still get its line.
    A line on the peer budget would be lost in most of those seconds.
    """
    member = make_client("alice", authorize_as="alice")
    flooder = make_client("bob", node="client2", authorize_as="bob", options=("--no-exec",))
    stop = f"/tmp/{flooder.entry}.stop"
    flood_qsh = shlex.join(flooder.argv("server", "true"))
    # Four at a time: the per-source handshake limit is four.
    flood_script = (
        f"for i in 1 2 3 4; do (while [ ! -e {stop} ]; do {flood_qsh} 2>/dev/null; done) & done; wait"
    )
    flood = None
    with ExitStack() as stack:
        sessions = [stack.enter_context(a_narrowable_session(member, server, shell=False)) for _ in range(3)]
        try:
            since = server.cursor()
            flood = flooder.node.popen(["timeout", "60", "bash", "-c", flood_script], user="bob")
            exhausted(server, since)
            during = server.cursor()
            set_policy("allow_exec = true", "allow_exec = false")(server, member)
            for _, wait in sessions:
                wait(timeout=30)
            exhausted(server, during)
        finally:
            flooder.node.run(["touch", stop])
            if flood is not None:
                flood.wait(timeout=30)
            flooder.node.run(["rm", "-f", stop])
    pattern = narrowing_line(member.entry, r"command|execut", r"(?m)^qsh-server: ", member.node.ip)
    lines = re.findall(pattern, server.journal(during))
    assert len(lines) == 3, f"{len(lines)} of 3 narrowing lines:\n" + "\n".join(lines)


# ---------------------------------------------------------------- directory accounts
#
# AUTH-20 serves accounts from LDAP, as a site with central accounts does:
# slapd on server2 with a directory made for the scenario, and on `server`
# nslcd with `ldap` after `files` for passwd and group. qsh-server itself is
# neither reconfigured nor restarted: it resolves the account and its groups
# through NSS when each session is prepared (src/server.rs, the blocking
# preparation in handle_session; README: groups are resolved before the fork).

LDAP_BASE = "dc=qsh-e2e,dc=test"
LDAP_ADMIN = f"cn=admin,{LDAP_BASE}"
LDAP_PASSWORD = "auth20"

# erin exists only in the directory, with her own group and dir-ops; dir-dev
# is a directory group for alice, whose account and other groups are local.
DIRECTORY_LDIF = f"""\
dn: {LDAP_BASE}
objectClass: dcObject
objectClass: organization
dc: qsh-e2e
o: qsh e2e directory

dn: ou=people,{LDAP_BASE}
objectClass: organizationalUnit
ou: people

dn: ou=groups,{LDAP_BASE}
objectClass: organizationalUnit
ou: groups

dn: uid=erin,ou=people,{LDAP_BASE}
objectClass: account
objectClass: posixAccount
uid: erin
cn: Erin
uidNumber: 3001
gidNumber: 3001
homeDirectory: /home/erin
loginShell: /bin/bash

dn: cn=erin,ou=groups,{LDAP_BASE}
objectClass: posixGroup
cn: erin
gidNumber: 3001

dn: cn=dir-ops,ou=groups,{LDAP_BASE}
objectClass: posixGroup
cn: dir-ops
gidNumber: 3100
memberUid: erin

dn: cn=dir-dev,ou=groups,{LDAP_BASE}
objectClass: posixGroup
cn: dir-dev
gidNumber: 3101
memberUid: alice
"""

# nslcd's timeouts, explicit so that an outage resolves in bounded time.
# bind_timelimit, reconnect_sleeptime and reconnect_retrytime are nslcd's
# defaults, and so is the pool of 5 threads; timelimit, which by default
# waits for ever, gets the same 10 s as bind_timelimit. Measured with these:
# a lookup that meets the outage fails after 10 to 20 s, a burst queues
# behind the 5 threads (32 at once all fail within about 35 s), and once
# the directory is back nslcd tries it again within reconnect_retrytime.
NSLCD_TIMEOUTS = """\
bind_timelimit 10
timelimit 10
reconnect_sleeptime 1
reconnect_retrytime 10
threads 5
"""

# The NSS module waits at most this long for nslcd to answer (libnss-ldapd's
# read timeout, measured with nslcd stopped), so no lookup, however stuck
# the directory, outlasts it.
NSS_READ_TIMEOUT = 60


class Directory:
    """slapd serving DIRECTORY_LDIF on `node`, run as a transient unit."""

    def __init__(self, node) -> None:
        self.node = node
        self.unit = unique("qsh-e2e-slapd")
        self.state_dir = f"/var/tmp/{self.unit}"

    def start(self) -> None:
        conf = f"{self.state_dir}/slapd.conf"
        self.node.sh(f"mkdir -p {self.state_dir}/db")
        self.node.write(
            conf,
            "include /etc/ldap/schema/core.schema\n"
            "include /etc/ldap/schema/cosine.schema\n"
            "include /etc/ldap/schema/nis.schema\n"
            f"pidfile {self.state_dir}/slapd.pid\n"
            "modulepath /usr/lib/ldap\n"
            "moduleload back_mdb\n"
            "database mdb\n"
            "maxsize 16777216\n"
            f'suffix "{LDAP_BASE}"\n'
            f'rootdn "{LDAP_ADMIN}"\n'
            f"rootpw {LDAP_PASSWORD}\n"
            f"directory {self.state_dir}/db\n"
            "index objectClass,uid,uidNumber,gidNumber,memberUid eq\n"
            "access to * by * read\n",
        )
        self.node.write(f"{self.state_dir}/directory.ldif", DIRECTORY_LDIF)
        self.node.sh(f"slapadd -f {conf} -l {self.state_dir}/directory.ldif")
        self.node.run(
            ["systemd-run", f"--unit={self.unit}", "--collect", "slapd", "-d", "0", "-f", conf, "-h", "ldap:///"],
            check=True,
        )
        self.node.wait_for(f"ldapsearch -x -H ldap://localhost -b {LDAP_BASE} -s base dn", timeout=20)

    def stop(self) -> None:
        self.node.run(["systemctl", "stop", self.unit])
        self.node.run(["rm", "-rf", self.state_dir])

    def modify(self, ldif: str) -> None:
        self.node.run(
            ["ldapmodify", "-x", "-H", "ldap://localhost", "-D", LDAP_ADMIN, "-w", LDAP_PASSWORD],
            input=ldif,
            check=True,
        )


@contextlib.contextmanager
def directory_accounts(server: QshServer, directory_node):
    """`server` resolves passwd and group from `files`, then a new directory.

    Yields the Directory. Afterwards nsswitch.conf and nslcd.conf are as they
    were, nslcd and slapd are stopped, and erin's home is gone, whatever the
    scenario did.
    """
    node = server.node
    directory = Directory(directory_node)
    nsswitch = node.read("/etc/nsswitch.conf")
    nslcd_conf = node.read("/etc/nslcd.conf")
    try:
        directory.start()
        node.write(
            "/etc/nslcd.conf",
            f"uid nslcd\ngid nslcd\nuri ldap://{directory_node.ip}/\nbase {LDAP_BASE}\n{NSLCD_TIMEOUTS}",
        )
        node.sh("chown root:nslcd /etc/nslcd.conf && chmod 0640 /etc/nslcd.conf && systemctl start nslcd")
        # As pam_mkhomedir would; the session starts in the account's home.
        node.sh("install -d -o 3001 -g 3001 -m 0755 /home/erin")
        with_ldap, count = re.subn(rb"(?m)^((?:passwd|group):\s+files\b.*?)[ \t]*$", rb"\1 ldap", nsswitch)
        assert count == 2, f"no `files` source for passwd and group in nsswitch.conf:\n{nsswitch.decode()}"
        node.write("/etc/nsswitch.conf", with_ldap)
        node.wait_for("getent passwd erin", timeout=30)
        yield directory
    finally:
        node.write("/etc/nsswitch.conf", nsswitch)
        node.run(["systemctl", "stop", "nslcd"])
        node.write("/etc/nslcd.conf", nslcd_conf)
        node.run(["rm", "-rf", "/home/erin"])
        directory.stop()


@contextlib.contextmanager
def unreachable(directory: Directory, client_node):
    """`client_node` hears nothing from the directory until the block ends.

    A blackhole route on the directory's side discards everything it sends
    to the client: connection attempts and queries go unanswered, as across
    a failed link. (The same route on the client's side would make its own
    sends fail at once with EINVAL, which is not what an outage looks like.)
    """
    route = ["ip", "route", "add", "blackhole", f"{client_node.ip}/32"]
    directory.node.run(route, check=True)
    try:
        yield
    finally:
        directory.node.run(["ip", "route", "del", "blackhole", f"{client_node.ip}/32"])


def unit_journal(server: QshServer, since: str) -> str:
    """qsh-server's own journal lines after `since`, matched by unit field.

    `journalctl -u` (QshServer.journal) also matches the unit's core dumps,
    for which it looks up the systemd-coredump account; that account is not
    in /etc/passwd, so while the directory does not answer, `-u` waits out
    an LDAP lookup of its own.
    """
    argv = ["journalctl", f"_SYSTEMD_UNIT={server.unit}.service", "--no-pager", "-o", "cat", "--after-cursor", since]
    return server.node.run(argv, check=True).stdout


def wait_logins(server: QshServer, since: str, user: str, count: int, timeout: float = 30) -> None:
    """Wait until `count` connections have authenticated as `user` since `since`."""
    deadline = time.monotonic() + timeout
    while (seen := unit_journal(server, since).count(f"authenticated as `{user}`")) < count:
        if time.monotonic() > deadline:
            raise AssertionError(f"only {seen} of {count} connections authenticated as {user} within {timeout}s")
        time.sleep(0.25)


def wait_ended(procs: list[subprocess.Popen], count: int, *, deadline: float) -> list[subprocess.Popen]:
    """Wait until `count` of `procs` have ended, failing at `deadline`; return those that have."""
    while len(ended := [proc for proc in procs if proc.poll() is not None]) < count:
        if time.monotonic() > deadline:
            raise AssertionError(f"only {len(ended)} of {count} sessions had ended by the deadline")
        time.sleep(0.1)
    return ended


def finish(procs: list[subprocess.Popen], *, deadline: float) -> list[tuple[bytes, bytes]]:
    """Every process's (stdout, stderr), failing if one is still running at `deadline`."""
    results = []
    for proc in procs:
        try:
            results.append(proc.communicate(timeout=max(0.1, deadline - time.monotonic())))
        except subprocess.TimeoutExpired as exc:
            raise AssertionError(f"{shlex.join(proc.args[-6:])} was still waiting at the deadline") from exc
    return results


@pytest.mark.plan("AUTH-20")
def test_directory_accounts_log_in_with_their_directory_groups(make_client, server, env):
    """An account and groups that only the directory knows, for every session.

    erin is in the directory only; alice is local, with one more group
    there. The server was started before the directory was enabled and is
    not restarted: it must look both up through NSS as each session is
    prepared, so the session gets the directory's groups merged with the
    local ones, and a group added in the directory applies to the next
    session.
    """
    pid = server.main_pid()
    with directory_accounts(server, env.node("server2")) as directory:
        assert server.node.run(["grep", "-q", "^erin:", "/etc/passwd"]).rc == 1, "erin must not be a local account"
        erin = make_client("alice", authorize_as="erin")  # `authorize` resolves erin through NSS too
        member = make_client("alice", authorize_as="alice")
        r = erin.run("server", "sh", "-c", 'id; echo "$HOME $USER $SHELL"; pwd')
        assert r.rc == 0, r.describe()
        assert r.stdout == (
            "uid=3001(erin) gid=3001(erin) groups=3001(erin),3100(dir-ops)\n/home/erin erin /bin/bash\n/home/erin\n"
        ), r.describe()
        r = member.run("server", "id", "-Gn")
        assert r.rc == 0 and sorted(r.stdout.split()) == ["alice", "dir-dev", "project"], r.describe()
        directory.modify(f"dn: cn=dir-dev,ou=groups,{LDAP_BASE}\nchangetype: modify\nadd: memberUid\nmemberUid: erin\n")
        r = erin.run("server", "id", "-Gn")
        assert r.rc == 0 and sorted(r.stdout.split()) == ["dir-dev", "dir-ops", "erin"], r.describe()
    assert server.main_pid() == pid, "qsh-server was restarted"


@pytest.mark.plan("AUTH-20")
def test_a_directory_outage_fails_sessions_and_gives_their_budget_back(make_client, server, env):
    """While the directory is silent, its accounts' sessions fail and hold nothing after.

    40 sessions at once on erin's key: 32 are admitted (the key's limit) and
    wait in preparation on erin's lookup, the other 8 are refused at once
    (within 10 s; the lookups take 20 s or more). The 32 must fail with a
    message naming the lookup, within the NSS module's own read timeout,
    instead of hanging. While they wait, a key whose preparation makes no
    lookup that reaches the directory still logs in at once: root, found in
    /etc/passwd and, needing no identity switch, no group lookup either
    (src/child.rs, prepare_identity). That shows the stuck lookups do not
    tie up the async workers (THREAT_MODEL actor 3); it says nothing about
    other local accounts, whose group lookups do wait on the directory (NSS,
    measured in the plan). Once the directory answers again, the key has
    its whole budget back without a restart: 32 sessions run at once.
    """
    node = server.node
    with directory_accounts(server, env.node("server2")) as directory:
        erin = make_client("alice", authorize_as="erin")
        admin = make_client("alice", authorize_as="root")
        assert erin.run("server", "true").rc == 0  # nslcd now holds a connection to the directory
        since = server.cursor()
        with unreachable(directory, node):
            begin = time.monotonic()
            argv = erin.argv("server", "echo", "granted-auth20")
            procs = [erin.node.popen(argv, user="alice") for _ in range(40)]
            try:
                early = wait_ended(procs, 8, deadline=begin + 10)
                codes = sorted(proc.returncode for proc in early)
                assert codes == [255] * len(early), f"statuses of the sessions that ended within 10s: {codes}"
                wait_logins(server, since, "erin", 32)
                start = time.monotonic()
                r = admin.run("server", "id", "-u", timeout=30)
                took = time.monotonic() - start
                assert (r.rc, r.stdout) == (0, "0\n"), r.describe()
                assert took < 5, f"root waited {took:.1f}s behind erin's stuck lookups"
                results = finish(procs, deadline=begin + NSS_READ_TIMEOUT + 15)
                ended = time.monotonic() - begin
            finally:
                for proc in procs:
                    proc.kill()
            failed = [err.decode() for proc, (_, err) in zip(procs, results) if proc.returncode == 126]
            refused = [err.decode() for proc, (_, err) in zip(procs, results) if proc.returncode == 255]
            assert (len(failed), len(refused)) == (32, 8), sorted(proc.returncode for proc in procs)
            for err in failed:
                assert "looking up user `erin`" in err and "no such local user" not in err, err
            for err in refused:
                assert "key connection limit reached" in err, err
            assert not any(b"granted-auth20" in out for out, _ in results)
            assert ended < NSS_READ_TIMEOUT + 15, f"the failing sessions took {ended:.0f}s to end"
            assert re.search(r"session from \S+ ended: looking up user `erin`", unit_journal(server, since))
        # nslcd tries the directory again within reconnect_retrytime; after
        # that, qsh must not still be holding any of the key's 32 slots.
        node.wait_for("getent passwd erin", timeout=60)
        marker = "8282.25"
        procs = [erin.node.popen(erin.argv("server", "sleep", marker), user="alice") for _ in range(32)]
        try:
            node.wait_for(f"[ $(pgrep -fc '^sleep {re.escape(marker)}$') -eq 32 ]", timeout=60)
        finally:
            node.run(["pkill", "-TERM", "-f", f"^sleep {re.escape(marker)}$"])
            codes = [proc.wait(timeout=30) for proc in procs]
        assert codes == [128 + 15] * 32, codes


@pytest.mark.plan("AUTH-20")
@pytest.mark.xfail(
    strict=True,
    raises=Unmet,
    reason="F31: qsh-server does not exit until every stuck account lookup has returned, "
    "so stop and restart wait out the directory's timeouts",
)
def test_a_directory_outage_does_not_hold_up_stopping_the_server(make_client, server, env):
    """`systemctl stop` while sessions wait on a silent directory.

    16 sessions on erin's key wait on her lookup, queued behind nslcd's
    threads; left alone they fail some 30 s later. Stopping the server must
    tell their clients at once and finish as promptly as with no directory
    at all (OPS-04 holds a stop to 10 s). Nothing a stuck preparation holds
    needs the process to stay: it takes no lock and starts no child
    (src/server.rs, handle_session). Until the process is gone systemd
    cannot start a new one, and nothing listens on the port, not even for
    keys whose accounts need no directory.
    """
    node = server.node
    with directory_accounts(server, env.node("server2")) as directory:
        erin = make_client("alice", authorize_as="erin")
        assert erin.run("server", "true").rc == 0
        since = server.cursor()
        procs: list[subprocess.Popen] = []
        stopper = None
        try:
            with unreachable(directory, node):
                argv = erin.argv("server", "echo", "granted-auth20")
                procs = [erin.node.popen(argv, user="alice") for _ in range(16)]
                wait_logins(server, since, "erin", 16)
                assert all(proc.poll() is None for proc in procs), "a lookup ended before the stop: nothing was stuck"
                begin = time.monotonic()
                stopper = node.popen(["systemctl", "stop", server.unit])
                # The clients hear of the stop at once, as in OPS-04.
                results = finish(procs, deadline=begin + 10)
                for proc, (out, err) in zip(procs, results):
                    assert proc.returncode == 255 and b"shutting down" in err, err.decode()
                    assert b"granted-auth20" not in out
                stopper.wait(timeout=120)
                took = time.monotonic() - begin
            assert stopper.returncode == 0
            assert not server.is_active()
            if took >= 10:
                raise Unmet(f"stopping qsh-server took {took:.1f}s while account lookups were stuck")
        finally:
            for proc in procs:
                proc.kill()
            if stopper is not None and stopper.poll() is None:
                stopper.wait(timeout=120)
            server.start()
