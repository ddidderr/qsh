"""XFER: moving real data with real tools: rsync, tar, large streams."""

from __future__ import annotations

import hashlib
import time

import pytest

from harness.qsh import unique

# A tree with the awkward parts real trees have: many small files, a large
# one, an empty one, a sparse one, hard and symbolic links, odd permissions
# and times, and names with spaces, quotes, newlines and non-ASCII.
MAKE_TREE = r"""
d=$1 big=${2:-5M} sparse=${3:-64M}
mkdir -p "$d"/a "$d"/b/c "$d/dir with space" "$d/ünïcödé"
head -c "$big" /dev/urandom > "$d/a/big.bin"
: > "$d/a/empty"
printf x > "$d/b/c/one-byte"
for i in $(seq 1 300); do echo "$i" > "$d/b/small-$i.txt"; done
echo hi > "$d/dir with space/file with space.txt"
echo q > "$d/ünïcödé/quote'n\"dbl\$dollar*star"
printf nl > "$d/b/new
line"
ln -s ../a/big.bin "$d/b/link-to-big"
ln "$d/a/big.bin" "$d/a/hardlink"
truncate -s "$sparse" "$d/a/sparse"
chmod 750 "$d/b"; chmod 600 "$d/a/empty"; chmod 755 "$d/b/c/one-byte"
touch -h -d '2020-01-02 03:04:05' "$d/a/empty" "$d/b/link-to-big"
"""

# What "the same tree" means: names, types, modes, sizes, mtimes, link
# targets, hard link counts, and contents. Owners are left out: an
# unprivileged rsync cannot set them, and both ends are alice anyway.
# Directory times and sizes are left out too: sizes depend on the file
# system's history, and rsync over any remote shell (a local stand-in shell
# shows it as well) leaves a directory that gained files with the time it
# was written, not the source's.
MANIFEST = r"""
cd "$1"
{
  find . -mindepth 1 ! -type d -printf '%P\0%y\0%m\0%s\0%T@\0%l\0%n\0'
  find . -mindepth 1 -type d -printf '%P\0%y\0%m\0-\0-\0\0%n\0'
} | tr '\n' '?' | tr '\0' '\n' | paste -d'|' - - - - - - - | sort
find . -type f -print0 | sort -z | xargs -0 -r sha256sum | tr '\n' '?' | sed 's/?$//'
"""


def make_tree(node, user: str, path: str, big: str = "5M", sparse: str = "64M") -> None:
    node.run(["bash", "-euc", MAKE_TREE, "make-tree", path, big, sparse], user=user, check=True, timeout=120)


def manifest(node, user: str, path: str) -> str:
    return node.run(["bash", "-euc", MANIFEST, "manifest", path], user=user, check=True, timeout=120).stdout


@pytest.fixture
def workdirs(alice, server):
    """Per-scenario directories on both ends, removed afterwards."""
    name = unique("xfer")
    local, remote = f"/home/alice/{name}-local", f"/home/alice/{name}-remote"
    yield local, remote
    alice.node.run(["rm", "-rf", local, f"{local}-back"])
    server.node.run(["rm", "-rf", remote])


def rsync(client, *args: str, qsh: str | None = None, timeout: float = 300, check: bool = True):
    command = ["rsync", "-e", qsh or client.qsh_command, *args]
    return client.node.run(command, user=client.user, timeout=timeout, check=check)


@pytest.mark.plan("XFER-01")
def test_rsync_push_reproduces_a_tree_exactly(alice, server, workdirs):
    local, remote = workdirs
    make_tree(alice.node, "alice", local)
    rsync(alice, "-aHS", f"{local}/", f"server:{remote}/")
    assert manifest(server.node, "alice", remote) == manifest(alice.node, "alice", local)


@pytest.mark.plan("XFER-02")
def test_rsync_pull_reproduces_a_tree_exactly(alice, server, workdirs):
    local, remote = workdirs
    make_tree(server.node, "alice", remote)
    rsync(alice, "-aHS", f"server:{remote}/", f"{local}/")
    assert manifest(alice.node, "alice", local) == manifest(server.node, "alice", remote)


@pytest.mark.plan("XFER-03")
def test_rsync_resync_sends_only_the_changes(alice, server, workdirs):
    local, remote = workdirs
    make_tree(alice.node, "alice", local)
    rsync(alice, "-aHS", f"{local}/", f"server:{remote}/")
    alice.shell(
        f"cd {local} && echo changed >> b/small-1.txt && head -c 1M /dev/urandom > a/new.bin "
        f"&& rm b/small-2.txt && touch -d '2021-01-01' b/small-3.txt"
    )
    out = rsync(alice, "-aHS", "--delete", "--stats", f"{local}/", f"server:{remote}/").stdout
    transferred = int(out.split("Number of regular files transferred: ")[1].split()[0].replace(",", ""))
    # small-1 and new.bin carry new data; small-3 only a new time, which
    # rsync still counts as a transfer.
    assert transferred == 3, out
    assert manifest(server.node, "alice", remote) == manifest(alice.node, "alice", local)


@pytest.mark.plan("XFER-04")
def test_rsync_secluded_args_handles_awkward_remote_paths(alice, server, workdirs):
    """Remote paths with spaces and shell metacharacters, through `rsync -s`.

    qsh runs the remote command without a shell, so rsync must not escape
    remote paths for one; `-s` (--secluded-args) sends them through the
    rsync protocol instead. The README documents this.
    """
    local, remote = workdirs
    alice.shell(f"mkdir -p {local} && echo data > {local}/file")
    awkward = f"{remote}/dir with space/it's \"$HOME\" *?/ünï"
    server.node.run(["mkdir", "-p", awkward], user="alice", check=True)
    rsync(alice, "-s", "-a", f"{local}/file", f"server:{awkward}/")
    assert server.node.read(f"{awkward}/file", user="alice") == b"data\n"
    rsync(alice, "-s", "-a", f"server:{awkward}/file", f"{local}/back")
    assert alice.node.read(f"{local}/back", user="alice") == b"data\n"


@pytest.mark.plan("XFER-05")
def test_rsync_over_an_impaired_link(alice, server, workdirs, make_link):
    local, remote = workdirs
    link = make_link("server:2222", loss=0.01, delay_ms=15, jitter_ms=10, reorder=0.01, duplicate=0.01)
    alice.pin(link.host, server.fp, port=link.port)
    # Small enough for a lossy link: the sender transmits sparse files in full.
    make_tree(alice.node, "alice", local, big="1M", sparse="2M")
    qsh = f"{alice.qsh_command} -p {link.port}"
    rsync(alice, "-aHS", f"{local}/", f"netsim:{remote}/", qsh=qsh, timeout=600)
    assert manifest(server.node, "alice", remote) == manifest(alice.node, "alice", local)
    rsync(alice, "-aHS", f"netsim:{remote}/", f"{local}-back/", qsh=qsh, timeout=600)
    assert manifest(alice.node, "alice", f"{local}-back") == manifest(alice.node, "alice", local)
    stats = link.stats()["stats"]
    assert stats["up"]["dropped"] > 0 and stats["down"]["dropped"] > 0, stats


@pytest.mark.plan("XFER-06")
def test_rsync_partial_transfer_resumes(alice_fast, fast_server, make_link):
    """The link drops part way through a large upload; --partial resumes it.

    Against server2, whose 8 s idle timeout lets both ends notice the dead
    link quickly; on the default 60 s the same happens, only slower.
    """
    name = unique("partial")
    local, remote = f"/home/alice/{name}-local", f"/home/alice/{name}-remote"
    link = make_link("server2:2222", delay_ms=20)
    alice_fast.pin(link.host, fast_server.fp, port=link.port)
    qsh = f"{alice_fast.qsh_command} -p {link.port}"
    try:
        alice_fast.shell(f"mkdir -p {local} && head -c 200M /dev/urandom > {local}/large.bin")
        fast_server.node.run(["mkdir", "-p", remote], user="alice", check=True)
        args = ["rsync", "-e", qsh, "--partial", "--inplace", f"{local}/large.bin", f"netsim:{remote}/"]
        proc = alice_fast.node.popen(args, user="alice")
        fast_server.node.wait_for(
            f"test $(stat -c %s {remote}/large.bin 2>/dev/null || echo 0) -gt 20000000", timeout=120
        )
        link.blackhole(True)
        assert proc.wait(timeout=60) != 0, "rsync reported success over a dead link"
        fast_server.node.wait_gone("rsync --server", timeout=60)
        link.blackhole(False)
        partial = int(fast_server.node.run(["stat", "-c", "%s", f"{remote}/large.bin"], check=True).stdout)
        assert 0 < partial < 200 * 1024 * 1024
        out = rsync(alice_fast, "--partial", "--inplace", "--stats", f"{local}/large.bin", f"netsim:{remote}/", qsh=qsh).stdout
        literal = int(out.split("Literal data: ")[1].split()[0].replace(",", ""))
        assert literal < 200 * 1024 * 1024, "the resumed transfer resent everything"
        want = alice_fast.node.run(["sha256sum", f"{local}/large.bin"], check=True).stdout.split()[0]
        got = fast_server.node.run(["sha256sum", f"{remote}/large.bin"], check=True).stdout.split()[0]
        assert got == want
    finally:
        alice_fast.node.run(["rm", "-rf", local])
        fast_server.node.run(["rm", "-rf", remote])


@pytest.mark.plan("XFER-07")
def test_tar_pipes_in_both_directions(alice, server, workdirs):
    local, remote = workdirs
    make_tree(alice.node, "alice", local)
    alice.shell(
        f"tar --format=posix -C {local} -cSf - . | qsh server sh -c 'mkdir -p {remote} && tar -C {remote} -xf -'",
        timeout=300,
    )
    assert manifest(server.node, "alice", remote) == manifest(alice.node, "alice", local)
    alice.shell(
        f"mkdir -p {local}-back && qsh server tar --format=posix -C {remote} -cSf - . | tar -C {local}-back -xf -",
        timeout=300,
    )
    assert manifest(alice.node, "alice", f"{local}-back") == manifest(alice.node, "alice", local)


@pytest.mark.plan("XFER-08")
def test_rsync_as_another_account_from_another_machine(bob, server):
    """bob on client2 uses `-l` and `user@host` spellings; files end up bob's."""
    name = unique("bob-xfer")
    try:
        bob.shell(f"mkdir -p /home/bob/{name} && echo from-bob > /home/bob/{name}/f")
        rsync(bob, "-a", f"/home/bob/{name}/", f"bob@server:{name}/")
        rsync(bob, "-a", f"/home/bob/{name}/", f"server:{name}-l/", qsh=f"{bob.qsh_command} -l bob")
        for target in (name, f"{name}-l"):
            owner = server.node.run(["stat", "-c", "%U", f"/home/bob/{target}/f"], check=True).stdout.strip()
            assert owner == "bob"
    finally:
        bob.node.run(["rm", "-rf", f"/home/bob/{name}"])
        server.node.run(["sh", "-c", f"rm -rf /home/bob/{name} /home/bob/{name}-l"])


@pytest.mark.plan("XFER-09")
@pytest.mark.slow
def test_a_gigabyte_each_way_with_checksums(alice, server, workdirs):
    local, remote = workdirs
    alice.shell(f"mkdir -p {local} && head -c 1G /dev/urandom > {local}/g.bin")
    server.node.run(["mkdir", "-p", remote], user="alice", check=True)
    start = time.monotonic()
    alice.shell(f"qsh server sh -c 'cat > {remote}/g.bin' < {local}/g.bin", timeout=600)
    up = time.monotonic() - start
    start = time.monotonic()
    alice.shell(f"qsh server cat {remote}/g.bin > {local}/g.back", timeout=600)
    down = time.monotonic() - start
    sums = {
        alice.node.run(["sha256sum", f"{local}/g.bin"], check=True).stdout.split()[0],
        server.node.run(["sha256sum", f"{remote}/g.bin"], check=True).stdout.split()[0],
        alice.node.run(["sha256sum", f"{local}/g.back"], check=True).stdout.split()[0],
    }
    assert len(sums) == 1
    print(f"1 GiB up {1024 / up:.0f} MiB/s, down {1024 / down:.0f} MiB/s")


@pytest.mark.plan("XFER-10")
def test_parallel_transfers_from_two_machines(alice, bob, server):
    """Six rsyncs at once, from two clients and two keys, all complete intact."""
    procs = []
    names = []
    for client, home in ((alice, "/home/alice"), (bob, "/home/bob")):
        for _ in range(3):
            name = unique("par")
            names.append((client, home, name))
            make_tree(client.node, client.user, f"{home}/{name}")
            argv = ["rsync", "-e", client.qsh_command, "-aHS", f"{home}/{name}/", f"server:{name}/"]
            procs.append(client.node.popen(argv, user=client.user))
    try:
        for proc in procs:
            _, err = proc.communicate(timeout=300)
            assert proc.returncode == 0, err.decode()
        for client, home, name in names:
            assert manifest(server.node, client.user, f"{home}/{name}") == manifest(client.node, client.user, f"{home}/{name}")
    finally:
        for client, home, name in names:
            client.node.run(["rm", "-rf", f"{home}/{name}"])
            server.node.run(["rm", "-rf", f"{home}/{name}"])


@pytest.mark.plan("XFER-11")
def test_a_download_over_a_slow_link_is_complete(alice, server, workdirs, make_link):
    """Output still in flight when the remote command exits must arrive in full.

    `cat` finishes long before a slow link has carried what it wrote; the
    session has to deliver the rest and only then report the exit status.
    """
    _, remote = workdirs
    link = make_link("server:2222", delay_ms=40, loss=0.01)
    alice.pin(link.host, server.fp, port=link.port)
    server.node.sh(f"mkdir -p {remote} && head -c 16M /dev/urandom > {remote}/f && chown -R alice: {remote}")
    want = server.node.run(["sha256sum", f"{remote}/f"], check=True).stdout.split()[0]
    r = alice.run("netsim", "cat", f"{remote}/f", port=link.port, timeout=600)
    assert r.rc == 0, r.describe()
    assert hashlib.sha256(r.out).hexdigest() == want


@pytest.mark.plan("XFER-13")
def test_rsync_under_a_restricted_key(make_client, server, workdirs):
    """The cgroup kill at leader exit must not cut rsync short in either direction."""
    local, remote = workdirs
    restricted = make_client("alice", authorize_as="alice", options=("--kill-session-processes",))
    make_tree(restricted.node, "alice", local, big="2M", sparse="8M")
    rsync(restricted, "-aHS", f"{local}/", f"server:{remote}/")
    assert manifest(server.node, "alice", remote) == manifest(restricted.node, "alice", local)
    rsync(restricted, "-aHS", f"server:{remote}/", f"{local}-back/")
    assert manifest(restricted.node, "alice", f"{local}-back") == manifest(restricted.node, "alice", local)


@pytest.mark.plan("XFER-14")
def test_revoking_a_key_mid_rsync_stops_the_transfer(make_client, server, workdirs, make_link):
    local, remote = workdirs
    member = make_client("alice", authorize_as="alice")
    link = make_link("server:2222", delay_ms=20)
    member.pin(link.host, server.fp, port=link.port)
    member.shell(f"mkdir -p {local} && head -c 300M /dev/urandom > {local}/large.bin", timeout=120)
    server.node.run(["mkdir", "-p", remote], user="alice", check=True)
    qsh = f"{member.qsh_command} -p {link.port}"
    proc = member.node.popen(["rsync", "-e", qsh, f"{local}/large.bin", f"netsim:{remote}/"], user="alice")
    server.node.wait_running("rsync --server", timeout=30)
    begin = time.monotonic()
    server.revoke(member.entry, settle=False)
    proc.wait(timeout=60)
    assert proc.returncode != 0, "rsync reported success after the key was revoked"
    assert time.monotonic() - begin < 10
    server.node.wait_gone("rsync --server", timeout=10)


# The wrapper the README's git section documents.
QSH_GIT = """#!/bin/bash
# qsh-git: git passes ssh's -o options, then the remote command as one
# string, for a shell.
args=()
while [ $# -gt 1 ]; do
    case $1 in
        -o) shift 2 ;;
        *) args+=("$1"); shift ;;
    esac
done
exec qsh "${args[@]}" sh -c "$1"
"""


@pytest.mark.plan("XFER-12")
def test_git_over_qsh_through_the_documented_wrapper(alice, server):
    name = unique("repo")
    work = f"/home/alice/{name}"
    server.node.run(["git", "init", "-q", "--bare", f"/home/alice/{name}.git"], user="alice", check=True)
    alice.node.write("/home/alice/qsh-git", QSH_GIT, user="alice", mode="755")
    env = {"GIT_SSH_COMMAND": "/home/alice/qsh-git", "GIT_SSH_VARIANT": "ssh"}
    git = ["git", "-c", "user.email=alice@client1", "-c", "user.name=alice"]
    try:
        # A path relative to the remote home, as `server:repo.git`.
        alice.node.run([*git, "clone", "-q", f"server:{name}.git", work], user="alice", env=env, check=True)
        alice.node.write(f"{work}/file", "from client1\n", user="alice")
        alice.node.run([*git, "-C", work, "add", "file"], user="alice", check=True)
        alice.node.run([*git, "-C", work, "commit", "-qm", "first"], user="alice", check=True)
        alice.node.run([*git, "-C", work, "push", "-q", "origin", "HEAD:main"], user="alice", env=env, check=True)
        # An ssh:// URL with a port, which git passes as -p.
        url = f"ssh://server:2222/home/alice/{name}.git"
        alice.node.run([*git, "clone", "-q", "-b", "main", url, f"{work}-2"], user="alice", env=env, check=True)
        assert alice.node.read(f"{work}-2/file", user="alice") == b"from client1\n"
        alice.node.run([*git, "-C", f"{work}-2", "fetch", "-q"], user="alice", env=env, check=True)
    finally:
        alice.node.run(["rm", "-rf", work, f"{work}-2", "/home/alice/qsh-git"])
        server.node.run(["rm", "-rf", f"/home/alice/{name}.git"])
