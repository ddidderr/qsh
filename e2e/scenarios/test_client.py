"""CLI: the client's own subcommands and conventions, on a real account."""

from __future__ import annotations

import pytest


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


@pytest.mark.plan("CLI-07")
@pytest.mark.parametrize(
    "option",
    [
        ("-o", "StrictHostKeyChecking=accept-new"),
        ("-oStrictHostKeyChecking=accept-new",),
        ("-o", "UserKnownHostsFile=/dev/null"),
        ("-o", "ConnectTimeout 5"),
        ("-v",),
        ("-vvv",),
        ("-C",),
        ("-a",),
        ("-x",),
    ],
)
def test_ssh_options_are_refused_before_contacting_the_host(make_client, server, option):
    """qsh is not ssh: an ssh option fails loudly instead of being ignored."""
    client = make_client("alice", authorize_as="alice", pin=False)
    since = server.cursor()
    r = client.run("server", "true", options=option)
    assert r.rc == 255 and f"unknown option: {option[0]}" in r.stderr, r.describe()
    assert "server" not in client.subcommand("known-hosts", "list").stdout
    assert f"key `{client.entry}`" not in server.journal(since)


@pytest.mark.plan("CLI-07")
def test_everything_after_the_host_is_the_remote_command(alice):
    r = alice.run("server", "echo", "-p", "2222", "-o", "x")
    assert r.rc == 0 and r.stdout.strip() == "-p 2222 -o x", r.describe()
    # Unlike ssh, `-p` after the host is not a port: it is the program.
    r = alice.run("server", "-p", "2222", "true")
    assert r.rc == 127, r.describe()
