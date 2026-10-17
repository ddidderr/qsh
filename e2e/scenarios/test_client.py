"""CLI: the client's own subcommands and conventions, on a real account."""

from __future__ import annotations

import time

import pexpect
import pytest

from harness.terminal import Terminal


@pytest.mark.plan("CLI-01")
def test_usage_help_and_version(alice):
    node = alice.node
    bare = node.run(["qsh"], user="alice")
    assert bare.rc == 255 and "Usage" in bare.stderr
    helped = node.run(["qsh", "--help"], user="alice")
    assert helped.rc == 0 and "Usage" in helped.stdout
    version = node.run(["qsh", "--version"], user="alice")
    assert version.rc == 0 and version.stdout.startswith("qsh ")


@pytest.mark.plan("CLI-02")
def test_keygen_writes_a_private_key_and_refuses_to_overwrite(make_client):
    client = make_client("alice", pin=False)
    node = client.node
    mode = node.run(["stat", "-c", "%a %U", f"{client.identity}/id.key"], check=True).stdout.strip()
    assert mode == "600 alice"
    again = node.run(["qsh", "keygen", "--identity", client.identity], user="alice")
    assert again.rc != 0 and "--force" in again.stderr, again.describe()
    assert client.subcommand("fingerprint").stdout.strip() == client.fingerprint


@pytest.mark.plan("CLI-03")
def test_known_hosts_add_list_remove_and_normalization(make_client, server):
    client = make_client("alice", authorize_as="alice", pin=False)
    client.subcommand("known-hosts", "add", "SERVER:2222", server.fp)
    listing = client.subcommand("known-hosts", "list").stdout
    assert server.fp in listing
    # Host names are case-normalized: the lower-case spelling uses the pin.
    assert client.run("server", "true", options=("--refuse-new",)).rc == 0
    client.subcommand("known-hosts", "remove", "server:2222")
    assert server.fp not in client.subcommand("known-hosts", "list").stdout
    assert client.run("server", "true", options=("--refuse-new",)).rc == 255


@pytest.mark.plan("CLI-04")
def test_adding_a_pin_replaces_the_old_one_and_fails_closed(make_client, server, fast_server):
    """`known-hosts add` replaces a pin under its canonical name.

    The replacement is explicit and visible in `list`; a connection to the
    real server then refuses the key it no longer trusts.
    """
    client = make_client("alice", authorize_as="alice", pin=False)
    client.subcommand("known-hosts", "add", "server:2222", server.fp)
    client.subcommand("known-hosts", "add", "SERVER:2222", fast_server.fp)
    listing = client.subcommand("known-hosts", "list").stdout
    assert fast_server.fp in listing and server.fp not in listing, listing
    assert client.run("server", "true").rc == 255


@pytest.mark.plan("CLI-05")
def test_quiet_suppresses_qshs_own_messages(make_client, server):
    client = make_client("alice", authorize_as="alice", pin=False)
    loud = client.run("server", "true", options=("--accept-new",))
    assert loud.rc == 0 and "known hosts" in loud.stderr, loud.describe()
    client.subcommand("known-hosts", "remove", "server:2222")
    quiet = client.run("server", "true", options=("--accept-new", "-q"))
    assert quiet.rc == 0 and quiet.stderr == "", quiet.describe()


@pytest.mark.plan("CLI-06")
def test_qsh_home_selects_the_identity_directory(make_client, server):
    client = make_client("alice", authorize_as="alice")
    r = client.node.run(["qsh", "server", "id", "-un"], user="alice", env={"QSH_HOME": client.identity})
    assert r.rc == 0 and r.stdout.strip() == "alice", r.describe()
    since = server.cursor()
    assert client.node.run(["qsh", "server", "true"], user="alice", env={"QSH_HOME": client.identity}).rc == 0
    server.wait_journal(rf"key `{client.entry}`", since)


# ---------------------------------------------------------------- CLI-07
#
# Scripts and tools written for ssh hand qsh ssh's options. qsh accepts `-o`
# for compatibility, and `apply_ssh_option` (src/bin/qsh.rs) acts only on
# `StrictHostKeyChecking=…` written with `=`; every other setting is ignored.
# What ssh(1) and ssh_config(5) do with the same command lines is in
# TEST_PLAN.md CLI-07. The divergences that a caller notices loudly, or that
# are as safe as ssh's behaviour, are pinned; those that silently do
# something else than asked are strict xfails of the proposed behaviour.

# What git (GIT_SSH_COMMAND with protocol v2), `scp -O -S` and Ansible put on
# the command line of the ssh they run, settings users add for ssh, and one
# no ssh has.
TOOL_OPTIONS = (
    "-x",
    "-o", "SendEnv=GIT_PROTOCOL",
    "-oPermitLocalCommand=no", "-oClearAllForwardings=yes", "-oRemoteCommand=none",
    "-oRequestTTY=no", "-oControlMaster=no", "-oForwardAgent=no",
    "-o", "ControlPersist=60s", "-o", "ServerAliveInterval=15", "-o", "LogLevel=ERROR",
    "-o", "NoSuchOption=1",
)

# A fingerprint no server has.
WRONG_FP = "sha256:" + "7" * 64


def known_hosts(client) -> str:
    return client.subcommand("known-hosts", "list").stdout


@pytest.mark.plan("CLI-07")
@pytest.mark.parametrize(
    "words",
    [("-p", "2222"), ("-l", "alice"), ("-t",), ("-n",), ("-o", "BatchMode=yes"), ("--",)],
    ids=lambda words: words[0],
)
def test_options_after_the_host_are_the_remote_command(alice, words):
    """Documented divergence: qsh reads options only up to the host.

    ssh goes on reading options after the host until the first word that is
    not one, so `ssh host -p 2222 uptime` uses port 2222. qsh hands every
    word after the host to the server as the command (src/bin/qsh.rs:
    "Options are parsed only up to the host argument"). The misplaced
    option then fails loudly, as a program that does not exist, before the
    remote side runs anything or qsh reads any input.
    """
    r = alice.run("server", *words, "true")
    assert r.rc == 127, r.describe()
    assert f"`{words[0]}`" in r.stderr, r.describe()


@pytest.mark.plan("CLI-07")
def test_ssh_options_that_only_tune_ssh_are_ignored(alice):
    """Documented divergence: settings qsh has no use for are accepted and ignored.

    ssh refuses a keyword it does not know ("Bad configuration option");
    qsh accepts any, so the options tools add for ssh do not break it.
    """
    r = alice.run("server", "echo", "ok", options=TOOL_OPTIONS)
    assert r.rc == 0, r.describe()
    assert r.stdout == "ok\n" and r.stderr == "", r.describe()


@pytest.mark.plan("CLI-07")
def test_strict_host_key_checking_no_still_refuses_a_changed_key(make_client, server):
    """`StrictHostKeyChecking=no` is accept-new in qsh, never "accept anything".

    ssh with `=no` also connects to a host whose key has changed, with
    passwords and forwarding turned off. qsh pins unknown hosts but still
    fails hard on a changed one (THREAT_MODEL.md actor 2): stricter than ssh.
    The key is authorized, so a qsh that let the changed key through would
    run the command and exit 0.
    """
    client = make_client("alice", authorize_as="alice", pin=False)
    client.pin("server", WRONG_FP)
    r = client.run("server", "true", options=("-o", "StrictHostKeyChecking=no"))
    assert r.rc == 255, r.describe()
    assert "has changed" in r.stderr and WRONG_FP in r.stderr and server.fp in r.stderr, r.describe()
    listing = known_hosts(client)
    assert WRONG_FP in listing and server.fp not in listing, listing


@pytest.mark.plan("CLI-07")
@pytest.mark.parametrize(
    "options,pins",
    [
        pytest.param(("-o", "StrictHostKeyChecking=yes", "-o", "StrictHostKeyChecking=accept-new"), True, id="yes,accept-new"),
        pytest.param(("--accept-new", "-o", "StrictHostKeyChecking=yes"), False, id="accept-new,yes"),
    ],
)
def test_the_last_host_key_policy_given_wins(make_client, server, options, pins):
    """Documented divergence: ssh keeps the first value given, qsh the last.

    ssh_config(5): "the first obtained value will be used", command line
    included. qsh applies its options in order, `--accept-new`,
    `--refuse-new` and `-o StrictHostKeyChecking` alike.
    """
    client = make_client("alice", authorize_as="alice", pin=False)
    r = client.run("server", "true", options=options)
    assert (r.rc == 0) == pins, r.describe()
    assert (server.fp in known_hosts(client)) == pins


def ssh_syntax(finding: str):
    return pytest.mark.xfail(
        strict=True,
        reason=f"FXX-CLI-07-{finding}: qsh splits `-o` only at `=`; a setting written `Key Value` is ignored",
    )


BATCH_MODE = pytest.mark.xfail(
    strict=True, reason="FXX-CLI-07-batchmode: -o BatchMode=yes is ignored; qsh still asks on the terminal"
)


@pytest.mark.plan("CLI-07")
@pytest.mark.parametrize(
    "options",
    [
        pytest.param(("--refuse-new",), id="--refuse-new"),
        pytest.param(("-o", "StrictHostKeyChecking=yes"), id="StrictHostKeyChecking=yes"),
        pytest.param(("-o", "BatchMode=yes"), marks=BATCH_MODE, id="BatchMode=yes"),
        pytest.param(("-o", "StrictHostKeyChecking yes"), marks=ssh_syntax("syntax"), id="StrictHostKeyChecking_yes"),
    ],
)
def test_options_that_forbid_asking_do_not_ask_on_a_terminal(make_client, server, options):
    """An unknown host, a terminal, and an option that says not to ask.

    ssh(1): BatchMode=yes disables "host key confirmation requests", and
    StrictHostKeyChecking=yes never adds a host by itself; either way an
    unknown host fails at once. A script run from a terminal must not stop
    at a question nobody is there to answer.
    """
    client = make_client("alice", pin=False)
    term = Terminal(client, "server", "true", options=options)
    try:
        asked = term.child.expect([pexpect.EOF, r"\(yes/no\)"], timeout=20) == 1
        if asked:
            term.sendline("no")
        status = term.wait_exit()
    finally:
        term.close()
    assert not asked, f"qsh asked on the terminal despite {' '.join(options)}"
    assert status == 255
    assert server.fp not in known_hosts(client)


@pytest.mark.plan("CLI-07")
@pytest.mark.parametrize(
    "spelling",
    [
        pytest.param("StrictHostKeyChecking=accept-new", id="Key=Value"),
        pytest.param("StrictHostKeyChecking accept-new", marks=ssh_syntax("syntax"), id="Key_Value"),
        pytest.param("StrictHostKeyChecking = accept-new", marks=ssh_syntax("syntax"), id="Key_=_Value"),
    ],
)
def test_an_ssh_option_is_read_the_way_ssh_reads_it(make_client, server, spelling):
    """ssh_config(5): a keyword and its argument are separated by whitespace
    or by an optional `=` with whitespace around it. `ssh -o` takes the same
    lines, and scripts write all three forms."""
    client = make_client("alice", authorize_as="alice", pin=False)
    r = client.run("server", "true", options=("-o", spelling))
    assert r.rc == 0, r.describe()
    assert server.fp in known_hosts(client)


@pytest.mark.plan("CLI-07")
@pytest.mark.parametrize(
    "options",
    [
        pytest.param(("--connect-timeout", "2"), id="--connect-timeout"),
        pytest.param(
            ("-o", "ConnectTimeout=2"),
            marks=pytest.mark.xfail(
                strict=True, reason="FXX-CLI-07-connecttimeout: -o ConnectTimeout is ignored; qsh waits its default 10 s"
            ),
            id="ConnectTimeout",
        ),
    ],
)
def test_a_connect_timeout_in_either_spelling_bounds_a_silent_peer(alice, server, make_link, options):
    """ssh's ConnectTimeout is qsh's --connect-timeout (NET-07)."""
    link = make_link("server:2222", blackhole=True)
    alice.pin(link.host, server.fp, port=link.port)
    try:
        begin = time.monotonic()
        r = alice.run("netsim", "true", port=link.port, options=options, timeout=60)
        took = time.monotonic() - begin
    finally:
        alice.subcommand("known-hosts", "remove", f"{link.host}:{link.port}")
    assert r.rc == 255, r.describe()
    assert "timed out after 2s" in r.stderr, r.describe()
    assert took < 2 + 4, f"gave up after {took:.1f}s"


@pytest.mark.plan("CLI-07")
@pytest.mark.xfail(
    strict=True,
    reason="FXX-CLI-07-knownhosts: -o UserKnownHostsFile is ignored; pins come from and go to the identity's known_hosts",
)
@pytest.mark.parametrize("case", ["dev-null", "pinned-there", "changed-there"])
def test_user_known_hosts_file_decides_which_pins_apply(make_client, server, case):
    """ssh_config(5) UserKnownHostsFile: the file of host keys to use instead
    of the user's own, `/dev/null` for none.

    - `dev-null`: `-o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no`,
      how scripts reach throwaway hosts, must leave the identity's own
      `known_hosts` as it was, or the next host to reuse the name fails as
      a changed key.
    - `pinned-there`: a file that pins the server serves under
      `StrictHostKeyChecking=yes`, though the identity's own file has no pin.
    - `changed-there`: a file that pins another key for the server is
      refused as a changed key, though the identity's own file pins the
      right one.

    The file is in qsh's format, written by `qsh known-hosts`.
    """
    client = make_client("alice", authorize_as="alice", pin=case == "changed-there")
    pins_dir = f"{client.identity}-pins"
    try:
        if case == "dev-null":
            options = ("-o", "UserKnownHostsFile=/dev/null", "-o", "StrictHostKeyChecking=no")
        else:
            fp = server.fp if case == "pinned-there" else WRONG_FP
            client.node.run(["qsh", "known-hosts", "-i", pins_dir, "add", "server:2222", fp], user="alice", check=True)
            options = ("-o", f"UserKnownHostsFile={pins_dir}/known_hosts")
            if case == "pinned-there":
                options += ("-o", "StrictHostKeyChecking=yes")
        own = known_hosts(client)
        r = client.run("server", "true", options=options)
        if case == "changed-there":
            assert r.rc == 255 and "has changed" in r.stderr, r.describe()
        else:
            assert r.rc == 0, r.describe()
        assert known_hosts(client) == own, "the identity's own known_hosts changed"
    finally:
        client.node.run(["rm", "-rf", pins_dir])


ACCOUNT_OR_PORT = pytest.mark.xfail(
    strict=True,
    reason="FXX-CLI-07-userport: -o User= and -o Port= are ignored; the command runs as the key's account on port 2222",
)


@pytest.mark.plan("CLI-07")
@pytest.mark.parametrize(
    "options,named",
    [
        pytest.param(("-l", "bob"), "bob", id="-l"),
        pytest.param(("-o", "User=bob"), "bob", marks=ACCOUNT_OR_PORT, id="User"),
        pytest.param(("-p", "2999", "--refuse-new"), "server:2999", id="-p"),
        pytest.param(("-o", "Port=2999", "--refuse-new"), "server:2999", marks=ACCOUNT_OR_PORT, id="Port"),
    ],
)
def test_ssh_options_that_choose_the_account_or_the_port_are_not_ignored(alice, options, named):
    """`-o User=` and `-o Port=` say whom to log in as and where, like `-l` and `-p`.

    Ignored, the command runs as the key's own account on the default port
    and nothing tells the caller. alice's key maps to alice and is pinned
    for server:2222 only, so honouring either option must fail, naming what
    was asked for: bob is not alice's account (EXEC-18), and server:2999
    has no pin under `--refuse-new`.
    """
    r = alice.run("server", "id", "-un", options=options)
    assert r.rc != 0 and r.stdout == "", r.describe()
    assert named in r.stderr, r.describe()
