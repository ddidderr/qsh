"""Fixtures for the multi-host suite.

One environment (five containers) is started per pytest session and shared
by every scenario, the way real machines would be. Scenarios that change
shared state put it back, or use identities and authorization names of
their own (`make_client`), so they can run in any order.
"""

from __future__ import annotations

import os
from collections.abc import Callable, Iterator

import pytest

from harness.env import DEFAULT_IMAGE, Environment, docker
from harness.qsh import NetLink, QshClient, QshServer, unique


def pytest_addoption(parser: pytest.Parser) -> None:
    group = parser.getgroup("qsh-e2e")
    group.addoption("--keep-env", action="store_true", help="leave the containers running after the session")


@pytest.fixture(scope="session")
def env(request: pytest.FixtureRequest) -> Iterator[Environment]:
    image = os.environ.get("QSH_E2E_IMAGE", DEFAULT_IMAGE)
    if docker("image", "inspect", image, check=False).rc != 0:
        pytest.exit(f"image {image} not found; build it with `e2e/run build`", returncode=2)
    project = os.environ.get("QSH_E2E_PROJECT", f"qsh-e2e-{os.getpid()}")
    environment = Environment(project, image)
    environment.down()  # a leftover from an interrupted run with the same name
    environment.up()
    yield environment
    log_dir = os.environ.get("QSH_E2E_ARTIFACTS")
    if log_dir:
        os.makedirs(log_dir, exist_ok=True)
        with open(os.path.join(log_dir, "compose.log"), "w") as fh:
            fh.write(environment.logs())
        for service in ("server", "server2"):
            journal = environment.node(service).run(["journalctl", "--no-pager", "-o", "short-precise"]).stdout
            with open(os.path.join(log_dir, f"{service}.journal"), "w") as fh:
                fh.write(journal)
    if not request.config.getoption("--keep-env"):
        environment.down()


@pytest.fixture(scope="session")
def server(env: Environment) -> QshServer:
    """qsh-server on `server`, provisioned as the README says and run by systemd."""
    srv = QshServer(env.node("server"))
    srv.fp = srv.keygen()
    srv.start()
    return srv


# server2 runs with timeouts short enough that outages, dead peers and
# cleanup after a lost client resolve in seconds rather than a minute.
FAST_IDLE_TIMEOUT = 8
FAST_KEEPALIVE = 2


@pytest.fixture(scope="session")
def fast_server(env: Environment) -> QshServer:
    """qsh-server on `server2` with an 8 s idle timeout, also run by systemd."""
    srv = QshServer(env.node("server2"))
    srv.fp = srv.keygen()
    srv.node.write(
        "/etc/qsh/qsh-server.toml",
        f'listen = "0.0.0.0:2222"\nidle_timeout_secs = {FAST_IDLE_TIMEOUT}\nkeepalive_secs = {FAST_KEEPALIVE}\n',
    )
    srv.start()
    return srv


@pytest.fixture(scope="session")
def alice_fast(alice: QshClient, fast_server: QshServer) -> QshClient:
    """alice's default identity, also authorized on and pinned to server2."""
    fast_server.authorize(alice.cert(), user="alice", name="alice-client1")
    alice.pin(fast_server.host, fast_server.fp)
    return alice


def _provision(server: QshServer, node, user: str, name: str) -> QshClient:
    client = QshClient(node, user)
    client.keygen()
    server.authorize(client.cert(), user=user, name=name)
    client.pin(server.host, server.fp)
    return client


@pytest.fixture(scope="session")
def alice(env: Environment, server: QshServer) -> QshClient:
    """alice on client1, authorized as alice with a default policy."""
    return _provision(server, env.node("client1"), "alice", "alice-client1")


@pytest.fixture(scope="session")
def bob(env: Environment, server: QshServer) -> QshClient:
    """bob on client2, authorized as bob with a default policy."""
    return _provision(server, env.node("client2"), "bob", "bob-client2")


@pytest.fixture
def make_client(env: Environment, server: QshServer) -> Iterator[Callable[..., QshClient]]:
    """Factory for a fresh identity, optionally authorized with given options.

        client = make_client("alice", authorize_as="alice", options=("--no-shell",))

    The identity lives in its own directory, is pinned to `server` (or the
    server given as `on`), and its authorization, named `client.entry`, is
    revoked again when the scenario ends.
    """
    made: list[tuple[QshClient, str | None]] = []

    def factory(
        user: str = "alice",
        *,
        node: str = "client1",
        authorize_as: str | None = None,
        options: tuple[str, ...] = (),
        pin: bool = True,
        on: QshServer | None = None,
    ) -> QshClient:
        target = on or server
        name = unique(f"{user}-{node}")
        client = QshClient(env.node(node), user, identity=f"/home/{user}/.config/{name}")
        client.keygen()
        client.entry = name
        if authorize_as is not None:
            target.authorize(client.cert(), user=authorize_as, name=name, options=options)
        if pin:
            client.pin(target.host, target.fp)
        made.append((client, target if authorize_as is not None else None))
        return client

    yield factory
    for client, target in made:
        if target is not None and client.entry in target.list():
            target.revoke(client.entry, settle=False, check=False)
        client.node.run(["rm", "-rf", client.identity_dir])


@pytest.fixture
def make_link(env: Environment) -> Iterator[Callable[..., NetLink]]:
    """Factory for a netsim relay in front of a server, closed afterwards.

        link = make_link("server:2222", loss=0.02, delay_ms=20)
    """
    links: list[NetLink] = []

    def factory(target: str = "server:2222", **impairment) -> NetLink:
        link = NetLink(env.node("netsim"), target, **impairment)
        links.append(link)
        return link

    yield factory
    for link in links:
        link.close()


# ---------------------------------------------------------------- reporting
#
# When a scenario fails, the servers' side of the story is usually the
# interesting half. Attach the qsh-server journal lines both servers wrote
# during the scenario to its report.


@pytest.hookimpl(hookwrapper=True)
def pytest_runtest_makereport(item: pytest.Item, call):
    outcome = yield
    report = outcome.get_result()
    setattr(item, f"rep_{report.when}", report)


@pytest.fixture(autouse=True)
def server_journal_on_failure(request: pytest.FixtureRequest, env: Environment) -> Iterator[None]:
    nodes = [env.node("server"), env.node("server2")]
    cursors = []
    for node in nodes:
        out = node.run(["journalctl", "--show-cursor", "-n", "0", "--quiet"]).stdout
        cursors.append(out.split("-- cursor: ")[-1].strip() if "-- cursor: " in out else "")
    yield
    report = getattr(request.node, "rep_call", None)
    if report is not None and report.failed:
        for node, cursor in zip(nodes, cursors):
            argv = ["journalctl", "-u", "qsh-server", "--no-pager", "-o", "short-precise"]
            if cursor:
                argv += ["--after-cursor", cursor]
            text = node.run(argv).stdout
            request.node.add_report_section("call", f"{node.service} qsh-server journal", text[-20000:])
