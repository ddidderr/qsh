"""One e2e environment: a Docker Compose project and the nodes in it.

Everything here is about machines, not about qsh: starting the topology,
running commands on a node as some user, moving files around. The qsh
specific helpers live in `harness.qsh`.
"""

from __future__ import annotations

import ipaddress
import json
import os
import re
import shlex
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path

E2E_DIR = Path(__file__).resolve().parent.parent
REPO_DIR = E2E_DIR.parent
COMPOSE_FILE = E2E_DIR / "docker" / "compose.yaml"
DEFAULT_IMAGE = "qsh-e2e-node:latest"

SERVICES = ("server", "server2", "client1", "client2", "netsim")


class CommandFailed(AssertionError):
    """A command that was expected to succeed did not. Carries its output."""


@dataclass
class Result:
    argv: list[str]
    rc: int
    out: bytes
    err: bytes

    @property
    def stdout(self) -> str:
        return self.out.decode(errors="replace")

    @property
    def stderr(self) -> str:
        return self.err.decode(errors="replace")

    def check(self) -> Result:
        if self.rc != 0:
            raise CommandFailed(self.describe())
        return self

    def describe(self) -> str:
        command = shlex.join(a if len(a) <= 200 else a[:200] + "…" for a in self.argv)
        return (
            f"command {command} exited {self.rc}\n"
            f"--- stdout ---\n{self.stdout[-4000:]}\n"
            f"--- stderr ---\n{self.stderr[-4000:]}"
        )


def docker(*args: str, input: bytes | None = None, timeout: float = 120, check: bool = True) -> Result:
    argv = ["docker", *args]
    proc = subprocess.run(argv, input=input, capture_output=True, timeout=timeout)
    result = Result(argv, proc.returncode, proc.stdout, proc.stderr)
    return result.check() if check else result


def free_subnet(project: str) -> str:
    """A /24 under 172.30.0.0/16 that no existing Docker network overlaps.

    The starting point depends on the project name, so concurrent runs with
    different names rarely even probe the same candidates.
    """
    taken = []
    names = docker("network", "ls", "--format", "{{.Name}}").stdout.split()
    if names:
        for info in json.loads(docker("network", "inspect", *names).stdout):
            for cfg in (info.get("IPAM") or {}).get("Config") or []:
                if "Subnet" in cfg:
                    taken.append(ipaddress.ip_network(cfg["Subnet"], strict=False))
    start = sum(project.encode()) % 256
    for offset in range(256):
        candidate = ipaddress.ip_network(f"172.30.{(start + offset) % 256}.0/24")
        if not any(candidate.overlaps(t) for t in taken if t.version == 4):
            return str(candidate)
    raise AssertionError("no free /24 left in 172.30.0.0/16 for the e2e network")


class Node:
    """One container, addressed by its compose service name."""

    def __init__(self, env: Environment, service: str) -> None:
        self.env = env
        self.service = service
        self.container = f"{env.project}-{service}-1"

    def __repr__(self) -> str:
        return f"Node({self.service})"

    # ------------------------------------------------------------ commands

    def exec_argv(
        self,
        argv: list[str],
        *,
        user: str | None = None,
        env: dict[str, str] | None = None,
        workdir: str | None = None,
        interactive: bool = False,
        tty: bool = False,
    ) -> list[str]:
        """The `docker exec` command line that runs `argv` on this node."""
        cmd = ["docker", "exec"]
        if interactive:
            cmd.append("-i")
        if tty:
            cmd.append("-t")
        if user is not None:
            home = "/root" if user == "root" else f"/home/{user}"
            cmd += ["-u", user, "-e", f"HOME={home}", "-e", f"USER={user}", "-e", f"LOGNAME={user}"]
            cmd += ["-w", workdir or home]
        elif workdir is not None:
            cmd += ["-w", workdir]
        for key, value in (env or {}).items():
            cmd += ["-e", f"{key}={value}"]
        cmd.append(self.container)
        # `docker exec` starts with umask 0000, which no real login has and
        # which would make every file a scenario creates world-writable.
        cmd += ["sh", "-c", 'umask 022 && exec "$@"', "sh", *argv]
        return cmd

    def run(
        self,
        argv: list[str],
        *,
        user: str | None = None,
        input: bytes | str | None = None,
        env: dict[str, str] | None = None,
        workdir: str | None = None,
        timeout: float = 60,
        check: bool = False,
    ) -> Result:
        """Run `argv` to completion and capture its output.

        The command runs under coreutils `timeout` inside the container as
        well, so a hung remote command cannot outlive the test that started
        it even when the local `docker exec` is killed.
        """
        if isinstance(input, str):
            input = input.encode()
        wrapped = ["timeout", "--kill-after=5", f"{timeout:g}", *argv]
        cmd = self.exec_argv(wrapped, user=user, env=env, workdir=workdir, interactive=input is not None)
        try:
            proc = subprocess.run(cmd, input=input, capture_output=True, timeout=timeout + 15)
        except subprocess.TimeoutExpired as exc:
            raise CommandFailed(f"{shlex.join(argv)} on {self.service} did not finish in {timeout}s") from exc
        result = Result(argv, proc.returncode, proc.stdout, proc.stderr)
        return result.check() if check else result

    def sh(self, script: str, **kwargs) -> Result:
        """Run a bash script. `check` defaults to True: scripts are setup."""
        kwargs.setdefault("check", True)
        return self.run(["bash", "-euo", "pipefail", "-c", script], **kwargs)

    def popen(
        self,
        argv: list[str],
        *,
        user: str | None = None,
        env: dict[str, str] | None = None,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    ) -> subprocess.Popen:
        """Start `argv` in the background; the caller owns the process."""
        cmd = self.exec_argv(argv, user=user, env=env, interactive=stdin is not subprocess.DEVNULL)
        return subprocess.Popen(cmd, stdin=stdin, stdout=stdout, stderr=stderr)

    # ------------------------------------------------------------ files

    def write(self, path: str, data: bytes | str, *, user: str | None = None, mode: str | None = None) -> None:
        if isinstance(data, str):
            data = data.encode()
        script = f"cat > {shlex.quote(path)}"
        if mode is not None:
            script += f" && chmod {mode} {shlex.quote(path)}"
        self.run(["sh", "-c", script], user=user, input=data, check=True)

    def read(self, path: str, *, user: str | None = None) -> bytes:
        return self.run(["cat", path], user=user, check=True).out

    def exists(self, path: str) -> bool:
        return self.run(["test", "-e", path]).rc == 0

    # ------------------------------------------------------------ processes

    def pids(self, command: str) -> list[int]:
        """PIDs of processes whose command line starts with `command`.

        The match is anchored on purpose: unanchored, `pgrep -f` also finds
        the `timeout` and shell processes that run it, whose command lines
        contain the pattern too.
        """
        out = self.run(["pgrep", "-f", "^" + re.escape(command)]).stdout
        return [int(p) for p in out.split()]

    def wait_running(self, command: str, *, timeout: float = 20) -> None:
        """Wait until a process whose command line starts with `command` runs."""
        self._wait(lambda: self.pids(command), f"`{command}` to start", timeout)

    def wait_gone(self, command: str, *, timeout: float = 20) -> None:
        """Wait until no process whose command line starts with `command` runs."""
        self._wait(lambda: not self.pids(command), f"`{command}` to be gone", timeout)

    def _wait(self, condition, what: str, timeout: float) -> None:
        deadline = time.monotonic() + timeout
        while not condition():
            if time.monotonic() > deadline:
                raise AssertionError(f"on {self.service}: waited {timeout}s for {what}")
            time.sleep(0.25)

    def kill_command(self, user: str, argv: list[str]) -> None:
        """SIGKILL `user`'s processes running exactly `argv`, inside the node.

        Killing a local `docker exec` client does not stop what it started in
        the container; this does.
        """
        pattern = "^" + re.escape(" ".join(argv)) + "$"
        self.run(["pkill", "-KILL", "-u", user, "-f", pattern])

    def edit_hosts(self, add: str | None = None, remove: str | None = None) -> None:
        """Add a line to, or drop lines matching a word from, /etc/hosts.

        Docker bind-mounts /etc/hosts, so it has to be rewritten in place:
        `sed -i` fails to rename its temporary file over it.
        """
        lines = self.read("/etc/hosts").decode().splitlines()
        if remove is not None:
            lines = [line for line in lines if remove not in line.split()]
        if add is not None:
            lines.append(add)
        self.run(["sh", "-c", "cat > /etc/hosts"], input="\n".join(lines) + "\n", check=True)

    def wait_for(self, script: str, *, timeout: float = 20, interval: float = 0.25, user: str | None = None) -> None:
        """Poll a shell condition on this node until it holds."""
        deadline = time.monotonic() + timeout
        while True:
            if self.run(["bash", "-c", script], user=user).rc == 0:
                return
            if time.monotonic() > deadline:
                raise AssertionError(f"on {self.service}: `{script}` did not hold within {timeout}s")
            time.sleep(interval)

    # ------------------------------------------------------------ boot

    def wait_booted(self, timeout: float = 60) -> None:
        """Wait until systemd, PID 1 on a server node, has finished booting."""
        # `degraded` is acceptable: some unit unrelated to qsh may fail in a
        # container. What matters is that boot finished and systemd is up.
        self.wait_for(
            "s=$(systemctl is-system-running 2>/dev/null); [ \"$s\" = running ] || [ \"$s\" = degraded ]",
            timeout=timeout,
        )

    def reboot(self, *, timeout: float = 60) -> None:
        """Reboot a server node: systemd shuts down, the container restarts, systemd boots.

        What a disk would keep survives (the container's own files: /etc,
        /var); the tmpfs mounts (/run, /tmp) and every process do not.
        systemd gets 30 s to shut down cleanly before Docker kills it.
        """
        docker("restart", "-t", "30", self.container, timeout=timeout)
        self.wait_booted(timeout)

    # ------------------------------------------------------------ network

    @property
    def ip(self) -> str:
        info = json.loads(docker("inspect", self.container).stdout)[0]
        nets = info["NetworkSettings"]["Networks"]
        return nets[self.env.network]["IPAddress"]


class Environment:
    """A running compose project: the five nodes and their network."""

    def __init__(self, project: str, image: str = DEFAULT_IMAGE) -> None:
        self.project = project
        self.image = image
        self.network = f"{project}_lan"
        self.subnet_spec: str | None = None

    def compose(self, *args: str, timeout: float = 300, check: bool = True) -> Result:
        env = dict(os.environ, QSH_E2E_IMAGE=self.image)
        if self.subnet_spec is not None:
            env["QSH_E2E_SUBNET"] = self.subnet_spec
        argv = ["docker", "compose", "-p", self.project, "-f", str(COMPOSE_FILE), *args]
        proc = subprocess.run(argv, capture_output=True, timeout=timeout, env=env)
        result = Result(argv, proc.returncode, proc.stdout, proc.stderr)
        return result.check() if check else result

    def up(self) -> None:
        self.subnet_spec = free_subnet(self.project)
        self.compose("up", "--detach", "--quiet-pull")
        for service in ("server", "server2"):
            self.node(service).wait_booted()

    def down(self) -> None:
        self.compose("down", "--volumes", "--timeout", "5", check=False)

    def node(self, service: str) -> Node:
        if service not in SERVICES:
            raise KeyError(service)
        return Node(self, service)

    def logs(self) -> str:
        return self.compose("logs", "--no-color", "--timestamps", check=False).stdout

    def subnet(self) -> ipaddress.IPv4Network:
        info = json.loads(docker("network", "inspect", self.network).stdout)[0]
        for cfg in info["IPAM"]["Config"]:
            net = ipaddress.ip_network(cfg["Subnet"])
            if net.version == 4:
                return net
        raise AssertionError(f"{self.network} has no IPv4 subnet")

    def spare_ip(self, index: int) -> str:
        """An address near the top of the subnet that Docker will not hand out.

        Docker allocates from the bottom, so the top of the range is free for
        addresses that scenarios assign by hand.
        """
        net = self.subnet()
        return str(net.broadcast_address - 1 - index)

    def ipv6_available(self) -> bool:
        """Whether the nodes have an IPv6 stack at all (the host kernel decides)."""
        return self.node("client1").run(["test", "-d", "/proc/sys/net/ipv6"]).rc == 0

    def reconnect(self, service: str, ip: str) -> None:
        """Move a node to a new address on the same network, as if it roamed."""
        node = self.node(service)
        docker("network", "disconnect", self.network, node.container)
        docker("network", "connect", "--ip", ip, "--alias", service, self.network, node.container)
