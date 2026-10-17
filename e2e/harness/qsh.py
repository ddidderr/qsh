"""qsh on top of the environment: servers, client identities, relays.

The helpers drive the real binaries the way an administrator and a user
would. They never edit qsh's files behind its back unless a scenario is
about exactly that, and then the scenario does it itself.
"""

from __future__ import annotations

import itertools
import json
import re
import shlex
import time
from dataclasses import dataclass, field

from .env import CommandFailed, Node, Result

PORT = 2222

DEFAULT_STATE_DIR = "/etc/qsh"

# The previous release, installed next to the current binaries with its
# version as a suffix (e2e/run pins which commit that is). The upgrade and
# version-skew scenarios run it; everything else runs the current build.
PREVIOUS_VERSION = "1.0"
PREVIOUS_QSH = f"qsh-{PREVIOUS_VERSION}"
PREVIOUS_QSH_SERVER = f"qsh-server-{PREVIOUS_VERSION}"

# `qsh-server authorize` and `revoke` take effect at the server's next
# once-a-second reload; revocation also needs the next policy check. The
# README promises "normally within two seconds". Scenarios wait this long
# after changing the authorization store, and no longer.
RELOAD_SETTLE = 2.5

_names = itertools.count(1)


def unique(prefix: str) -> str:
    """A name no other scenario in this run uses."""
    return f"{prefix}-{next(_names)}"


class QshServer:
    """A qsh-server on a server node, run by systemd as root (or by hand).

    `program` is the binary that manages it, `qsh-server` unless a scenario
    drives another build. A state directory other than /etc/qsh is passed to
    every management command with `--dir`.
    """

    def __init__(
        self,
        node: Node,
        *,
        state_dir: str = DEFAULT_STATE_DIR,
        unit: str = "qsh-server",
        program: str = "qsh-server",
    ) -> None:
        self.node = node
        self.state_dir = state_dir
        self.unit = unit
        self.program = program

    @property
    def host(self) -> str:
        return self.node.service

    def admin(self, *args: str, check: bool = True, user: str | None = None) -> Result:
        """Run `qsh-server [--dir DIR] <args>`, as root unless `user` is given."""
        argv = [self.program]
        if self.state_dir != DEFAULT_STATE_DIR:
            argv += ["--dir", self.state_dir]
        return self.node.run([*argv, *args], user=user, check=check)

    def keygen(self, *args: str) -> str:
        out = self.admin("keygen", *args).stdout
        return parse_fingerprint(out, "Host key: ")

    def fingerprint(self) -> str:
        return self.admin("fingerprint").stdout.strip()

    # ------------------------------------------------------------ systemd

    def start(self) -> None:
        self.node.run(["systemctl", "start", self.unit], check=True)
        self.wait_listening()

    def stop(self) -> None:
        self.node.run(["systemctl", "stop", self.unit], check=True)

    def restart(self) -> None:
        self.node.run(["systemctl", "restart", self.unit], check=True)
        self.wait_listening()

    def is_active(self) -> bool:
        return self.node.run(["systemctl", "is-active", "--quiet", self.unit]).rc == 0

    def main_pid(self) -> int:
        out = self.node.run(["systemctl", "show", "--property=MainPID", "--value", self.unit], check=True)
        return int(out.stdout.strip())

    def wait_listening(self, port: int = PORT, timeout: float = 20) -> None:
        self.node.wait_for(f"ss -Hlun 'sport = :{port}' | grep -q .", timeout=timeout)

    # ------------------------------------------------------------ journal

    def cursor(self) -> str:
        """A journal position; `journal(since=...)` returns what came after."""
        out = self.node.run(["journalctl", "--show-cursor", "-n", "0", "--quiet"], check=True).stdout
        match = re.search(r"-- cursor: (\S+)", out)
        return match.group(1) if match else ""

    def journal(self, since: str | None = None) -> str:
        argv = ["journalctl", "-u", self.unit, "--no-pager", "-o", "cat"]
        if since:
            argv += ["--after-cursor", since]
        return self.node.run(argv).stdout

    def wait_journal(self, pattern: str, since: str | None, timeout: float = 20) -> str:
        """Wait until a journal line after `since` matches the regex `pattern`."""
        deadline = time.monotonic() + timeout
        while True:
            text = self.journal(since)
            if re.search(pattern, text):
                return text
            if time.monotonic() > deadline:
                raise AssertionError(f"no journal line matching {pattern!r} within {timeout}s:\n{text[-3000:]}")
            time.sleep(0.25)

    # ------------------------------------------------------------ authorization

    def authorize(self, cert_pem: bytes, *, user: str, name: str, options: tuple[str, ...] = (), settle: bool = True) -> None:
        path = f"/tmp/{name}.crt"
        self.node.write(path, cert_pem)
        self.admin("authorize", path, "--user", user, "--name", name, *options)
        self.node.run(["rm", "-f", path])
        if settle:
            time.sleep(RELOAD_SETTLE)

    def revoke(self, name: str, *, settle: bool = True, check: bool = True) -> Result:
        result = self.admin("revoke", name, check=check)
        if settle:
            time.sleep(RELOAD_SETTLE)
        return result

    def list(self) -> str:
        return self.admin("list").stdout


@dataclass
class QshClient:
    """One identity (key pair, known_hosts) of one account on a client node."""

    node: Node
    user: str
    identity: str | None = None  # None: the account's default ~/.config/qsh
    fingerprint: str = ""
    extra: list[str] = field(default_factory=list)
    entry: str = ""  # its authorization's name, when a fixture made one
    program: str = "qsh"  # the client binary

    @property
    def identity_dir(self) -> str:
        return self.identity or f"/home/{self.user}/.config/qsh"

    def keygen(self, *args: str) -> str:
        argv = [self.program, "keygen", *args]
        if self.identity:
            argv += ["--identity", self.identity]
        out = self.node.run(argv, user=self.user, check=True).stdout
        self.fingerprint = parse_fingerprint(out, "Fingerprint: ")
        return self.fingerprint

    def cert(self) -> bytes:
        return self.node.read(f"{self.identity_dir}/id.crt", user=self.user)

    def subcommand(self, name: str, *args: str, check: bool = True) -> Result:
        argv = [self.program, name]
        if self.identity:
            argv += ["-i", self.identity]
        return self.node.run([*argv, *args], user=self.user, check=check)

    def pin(self, host: str, fingerprint: str, port: int = PORT) -> None:
        self.subcommand("known-hosts", "add", f"{host}:{port}", fingerprint)

    def argv(self, host: str, *command: str, port: int | None = None, options: tuple[str, ...] = ()) -> list[str]:
        """The `qsh` command line for this identity."""
        argv = [self.program]
        if self.identity:
            argv += ["-i", self.identity]
        if port is not None:
            argv += ["-p", str(port)]
        argv += [*self.extra, *options, host, *command]
        return argv

    def run(
        self,
        host: str,
        *command: str,
        port: int | None = None,
        options: tuple[str, ...] = (),
        input: bytes | str | None = None,
        env: dict[str, str] | None = None,
        timeout: float = 60,
        check: bool = False,
    ) -> Result:
        """Run one remote command through qsh and capture everything."""
        argv = self.argv(host, *command, port=port, options=options)
        return self.node.run(argv, user=self.user, input=input, env=env, timeout=timeout, check=check)

    def shell(self, script: str, *, timeout: float = 120, check: bool = True) -> Result:
        """Run a local bash script as this account on the client node."""
        return self.node.run(["bash", "-euo", "pipefail", "-c", script], user=self.user, timeout=timeout, check=check)

    @property
    def qsh_command(self) -> str:
        """`qsh` with this identity, as a string for rsync -e / GIT_SSH_COMMAND."""
        argv = [self.program]
        if self.identity:
            argv += ["-i", self.identity]
        return shlex.join([*argv, *self.extra])


@dataclass
class PreviousQshClient(QshClient):
    """An identity made and driven by the previous release's client, `qsh-1.0`.

    1.0's `known-hosts` takes no `-i`: it finds the identity through
    `QSH_HOME`, which both releases honour. Connecting and `keygen` take the
    same options in both.
    """

    program: str = PREVIOUS_QSH

    def subcommand(self, name: str, *args: str, check: bool = True) -> Result:
        env = {"QSH_HOME": self.identity} if self.identity else None
        return self.node.run([self.program, name, *args], user=self.user, env=env, check=check)


def parse_fingerprint(text: str, label: str) -> str:
    match = re.search(re.escape(label) + r"(sha256:[0-9a-f]{64})", text)
    if not match:
        raise CommandFailed(f"no `{label}` fingerprint in:\n{text}")
    return match.group(1)


class NetLink:
    """One netsim relay: client -> netsim:port -> target, impaired on demand."""

    _ports = itertools.count(4433)

    def __init__(self, netsim: Node, target: str, *, seed: int = 1, **impairment) -> None:
        self.node = netsim
        self.name = unique("link")
        self.port = next(self._ports)
        self.target = target
        argv = [
            "netsim", "serve", "--name", self.name,
            "--listen", str(self.port), "--target", target, "--seed", str(seed),
        ]
        for key, value in impairment.items():
            flag = "--" + key.replace("_", "-")
            argv += [flag] if value is True else [flag, str(value)]
        self.proc = netsim.popen(argv, stdout=None, stderr=None)
        netsim.wait_for(f"test -S /run/netsim/{self.name}.sock", timeout=10)

    @property
    def host(self) -> str:
        return self.node.service

    def ctl(self, *args: str) -> dict:
        out = self.node.run(["netsim", "ctl", "--name", self.name, *args], check=True).stdout
        return json.loads(out)

    def set(self, **values) -> dict:
        return self.ctl("set", *(f"{k}={v}" for k, v in values.items()))

    def reset(self) -> dict:
        return self.ctl("reset")

    def blackhole(self, on: bool, direction: str = "both") -> dict:
        """Drop everything, or only "up" (client -> target) or "down" traffic.

        The three are separate settings: turning "up" off leaves a "both"
        black hole in place, and the other way round.
        """
        args = ["blackhole", "on" if on else "off"]
        if direction != "both":
            args += ["--direction", direction]
        return self.ctl(*args)

    def rebind(self, source_ip: str | None = None) -> dict:
        args = ["rebind"]
        if source_ip is not None:
            args += ["--source-ip", source_ip]
        return self.ctl(*args)

    def stats(self) -> dict:
        return self.ctl("stats")

    def close(self) -> None:
        # By PID file: a `pkill -f` pattern would also match the command line
        # of whatever runs pkill.
        self.node.run(["sh", "-c", f"kill $(cat /run/netsim/{self.name}.pid)"])
        self.proc.wait(timeout=10)
