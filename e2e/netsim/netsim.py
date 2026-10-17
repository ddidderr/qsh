#!/usr/bin/env python3
"""netsim — a userspace UDP relay that misbehaves on request.

The end-to-end suite cannot rely on `tc netem`: not every kernel that runs
Docker has it. QUIC only needs UDP datagrams to arrive, late, twice, out of
order, or not at all, so a relay in userspace reproduces every condition the
suite needs and behaves the same on every host.

One `serve` process is one link: it listens on a UDP port and forwards each
client flow to a fixed target, NAT style, through an upstream socket of its
own. The server therefore sees the relay's address, and `rebind` can change
that address mid-flow, which is exactly what a NAT rebinding or a client that
changed networks looks like to the server.

"up" is client -> target, "down" is target -> client. A black hole or a
datagram size limit can apply to one direction only: a one-way outage, or a
path whose MTU shrank on one leg. The size limit drops silently, the way a
router that sends no ICMP "fragmentation needed" does, and it counts UDP
payload bytes, the size QUIC calls a datagram.

    netsim serve --name lossy --listen 4433 --target server:2222 --loss 0.05
    netsim ctl --name lossy set delay_ms=80 jitter_ms=20 reorder=0.02
    netsim ctl --name lossy blackhole on
    netsim ctl --name lossy blackhole on --direction up
    netsim ctl --name lossy set max_datagram=1252
    netsim ctl --name lossy rebind --source-ip 172.18.0.250
    netsim ctl --name lossy stats
    kill "$(cat /run/netsim/lossy.pid)"

Control requests travel over a Unix socket in /run/netsim, one JSON object
per line, so only processes inside the relay's container can steer it.

Only the standard library is used: the relay runs inside the test node image.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import random
import socket
import sys
import time
from dataclasses import asdict, dataclass, field

CONTROL_DIR = "/run/netsim"

# Impairment settings a `set` request may change, with their types.
SETTINGS = {
    "loss": float,  # probability that a datagram is dropped, per direction
    "delay_ms": float,  # fixed one-way delay
    "jitter_ms": float,  # extra uniform random delay, 0..jitter_ms
    "reorder": float,  # probability that a datagram is held back
    "reorder_ms": float,  # how long a held-back datagram waits
    "duplicate": float,  # probability that a datagram is sent twice
    "blackhole": bool,  # drop everything, both directions
    "blackhole_up": bool,  # drop everything client -> target
    "blackhole_down": bool,  # drop everything target -> client
    "max_datagram": int,  # drop datagrams larger than this, both directions; 0: no limit
    "max_datagram_up": int,  # the same, client -> target only
    "max_datagram_down": int,  # the same, target -> client only
}


@dataclass
class Impairment:
    loss: float = 0.0
    delay_ms: float = 0.0
    jitter_ms: float = 0.0
    reorder: float = 0.0
    reorder_ms: float = 25.0
    duplicate: float = 0.0
    blackhole: bool = False
    blackhole_up: bool = False
    blackhole_down: bool = False
    max_datagram: int = 0
    max_datagram_up: int = 0
    max_datagram_down: int = 0

    def blackholed(self, direction: str) -> bool:
        return self.blackhole or getattr(self, f"blackhole_{direction}")

    def size_limit(self, direction: str) -> int:
        """The largest datagram that may travel `direction`, 0 for any size."""
        limits = [n for n in (self.max_datagram, getattr(self, f"max_datagram_{direction}")) if n > 0]
        return min(limits, default=0)


@dataclass
class Counters:
    forwarded: int = 0
    dropped: int = 0  # every datagram not forwarded, oversized ones included
    duplicated: int = 0
    reordered: int = 0
    oversized: int = 0  # dropped for exceeding the size limit
    largest: int = 0  # the largest datagram forwarded so far


@dataclass
class Stats:
    up: Counters = field(default_factory=Counters)  # client -> target
    down: Counters = field(default_factory=Counters)  # target -> client
    flows: int = 0
    rebinds: int = 0


class Link:
    """One listening port, its client flows, and the impairment applied to them."""

    def __init__(self, target: tuple[str, int], imp: Impairment, seed: int | None, trace: bool = False) -> None:
        self.target = target
        self.trace = trace
        self.started = time.monotonic()
        self.imp = imp
        self.stats = Stats()
        self.rng = random.Random(seed)
        self.source_ip: str | None = None
        self.listener: asyncio.DatagramTransport | None = None
        self.flows: dict[tuple[str, int], Flow] = {}

    # ---------------------------------------------------------- data path

    def deliver(self, direction: str, data: bytes, send) -> None:
        """Apply the current impairment to one datagram travelling `direction`."""
        imp = self.imp
        counters: Counters = getattr(self.stats, direction)
        limit = imp.size_limit(direction)
        oversized = 0 < limit < len(data)
        dropped = imp.blackholed(direction) or oversized or (imp.loss > 0 and self.rng.random() < imp.loss)
        if self.trace:
            # QUIC's first byte says long (handshake) or short (1-RTT) header.
            kind = "long" if data and data[0] & 0x80 else "short"
            print(
                f"{time.monotonic() - self.started:9.3f} {direction:4} {len(data):5} {kind}"
                f"{' DROP' if dropped else ''}{' oversized' if oversized else ''}",
                file=sys.stderr,
                flush=True,
            )
        if dropped:
            counters.dropped += 1
            counters.oversized += int(oversized)
            return
        counters.largest = max(counters.largest, len(data))
        copies = 1
        if imp.duplicate > 0 and self.rng.random() < imp.duplicate:
            copies = 2
            counters.duplicated += 1
        for _ in range(copies):
            delay = imp.delay_ms
            if imp.jitter_ms > 0:
                delay += self.rng.uniform(0, imp.jitter_ms)
            if imp.reorder > 0 and self.rng.random() < imp.reorder:
                delay += imp.reorder_ms
                counters.reordered += 1
            counters.forwarded += 1
            if delay <= 0:
                send(data)
            else:
                asyncio.get_running_loop().call_later(delay / 1000, send, data)

    def from_client(self, data: bytes, addr: tuple[str, int]) -> None:
        flow = self.flows.get(addr)
        if flow is None:
            flow = Flow(self, addr)
            self.flows[addr] = flow
            self.stats.flows += 1
            asyncio.get_running_loop().create_task(flow.open())
        self.deliver("up", data, flow.send_up)

    def to_client(self, data: bytes, addr: tuple[str, int]) -> None:
        def send(payload: bytes) -> None:
            if self.listener is not None and not self.listener.is_closing():
                self.listener.sendto(payload, addr)

        self.deliver("down", data, send)

    # ---------------------------------------------------------- control

    async def rebind(self, source_ip: str | None) -> list[str]:
        """Give every flow a fresh upstream socket: a new port, maybe a new IP."""
        if source_ip is not None:
            self.source_ip = source_ip or None
        self.stats.rebinds += 1
        return [await flow.rebind() for flow in list(self.flows.values())]


class Flow:
    """One client address and the upstream socket that stands in for it."""

    def __init__(self, link: Link, client: tuple[str, int]) -> None:
        self.link = link
        self.client = client
        self.upstream: asyncio.DatagramTransport | None = None
        self.pending: list[bytes] = []

    async def open(self) -> str:
        loop = asyncio.get_running_loop()
        local = (self.link.source_ip or "0.0.0.0", 0)
        transport, _ = await loop.create_datagram_endpoint(
            lambda: Upstream(self), local_addr=local, remote_addr=self.link.target
        )
        old, self.upstream = self.upstream, transport
        if old is not None:
            old.close()
        for data in self.pending:
            transport.sendto(data)
        self.pending.clear()
        sock = transport.get_extra_info("sockname")
        return f"{self.client[0]}:{self.client[1]} -> {sock[0]}:{sock[1]}"

    async def rebind(self) -> str:
        return await self.open()

    def send_up(self, data: bytes) -> None:
        if self.upstream is None or self.upstream.is_closing():
            self.pending.append(data)
        else:
            self.upstream.sendto(data)


class Upstream(asyncio.DatagramProtocol):
    def __init__(self, flow: Flow) -> None:
        self.flow = flow
        self.transport: asyncio.DatagramTransport | None = None

    def connection_made(self, transport) -> None:
        self.transport = transport

    def datagram_received(self, data: bytes, addr) -> None:
        # Datagrams that reach a socket a rebind already replaced are dropped:
        # that is what a NAT does once its mapping has moved on.
        if self.transport is self.flow.upstream:
            self.flow.link.to_client(data, self.flow.client)

    def error_received(self, exc: Exception) -> None:
        # ICMP port unreachable and friends: the target may be restarting.
        pass


class Listener(asyncio.DatagramProtocol):
    def __init__(self, link: Link) -> None:
        self.link = link

    def connection_made(self, transport) -> None:
        self.link.listener = transport

    def datagram_received(self, data: bytes, addr) -> None:
        self.link.from_client(data, addr)

    def error_received(self, exc: Exception) -> None:
        pass


def parse_value(key: str, raw: str):
    kind = SETTINGS[key]
    if kind is bool:
        if raw.lower() in ("1", "true", "on", "yes"):
            return True
        if raw.lower() in ("0", "false", "off", "no"):
            return False
        raise ValueError(f"{key} must be on or off, not {raw!r}")
    return kind(raw)


async def handle_control(link: Link, reader, writer) -> None:
    try:
        line = await reader.readline()
        request = json.loads(line)
        cmd = request.get("cmd")
        if cmd == "set":
            for key, raw in request.get("values", {}).items():
                if key not in SETTINGS:
                    raise ValueError(f"unknown setting {key!r}")
                setattr(link.imp, key, parse_value(key, str(raw)))
            reply = {"ok": True, "impairment": asdict(link.imp)}
        elif cmd == "reset":
            link.imp = Impairment()
            reply = {"ok": True, "impairment": asdict(link.imp)}
        elif cmd == "rebind":
            moved = await link.rebind(request.get("source_ip"))
            reply = {"ok": True, "flows": moved}
        elif cmd == "stats":
            reply = {
                "ok": True,
                "impairment": asdict(link.imp),
                "stats": asdict(link.stats),
                "flows": [f"{a}:{p}" for a, p in link.flows],
            }
        else:
            raise ValueError(f"unknown command {cmd!r}")
    except Exception as exc:  # report every failure to the caller
        reply = {"ok": False, "error": str(exc)}
    writer.write((json.dumps(reply) + "\n").encode())
    await writer.drain()
    writer.close()


def control_path(name: str) -> str:
    return os.path.join(CONTROL_DIR, f"{name}.sock")


def pid_path(name: str) -> str:
    return os.path.join(CONTROL_DIR, f"{name}.pid")


async def serve(args: argparse.Namespace) -> None:
    host, _, port = args.target.rpartition(":")
    target_ip = socket.gethostbyname(host)
    imp = Impairment()
    for key in SETTINGS:
        value = getattr(args, key, None)
        if value is not None:
            setattr(imp, key, value)
    link = Link((target_ip, int(port)), imp, args.seed, args.trace)
    link.source_ip = args.source_ip

    loop = asyncio.get_running_loop()
    await loop.create_datagram_endpoint(
        lambda: Listener(link), local_addr=("0.0.0.0", args.listen)
    )
    os.makedirs(CONTROL_DIR, exist_ok=True)
    path = control_path(args.name)
    if os.path.exists(path):
        os.unlink(path)
    server = await asyncio.start_unix_server(
        lambda r, w: handle_control(link, r, w), path=path
    )
    os.chmod(path, 0o600)
    with open(pid_path(args.name), "w") as fh:
        fh.write(f"{os.getpid()}\n")
    print(
        f"netsim {args.name}: 0.0.0.0:{args.listen} -> {target_ip}:{port}",
        flush=True,
    )
    async with server:
        await server.serve_forever()


async def control(name: str, request: dict) -> dict:
    reader, writer = await asyncio.open_unix_connection(control_path(name))
    writer.write((json.dumps(request) + "\n").encode())
    await writer.drain()
    reply = json.loads(await reader.readline())
    writer.close()
    return reply


def main() -> int:
    parser = argparse.ArgumentParser(prog="netsim", description=__doc__.split("\n")[0])
    sub = parser.add_subparsers(dest="command", required=True)

    s = sub.add_parser("serve", help="run one relay link in the foreground")
    s.add_argument("--name", required=True, help="control socket name")
    s.add_argument("--listen", type=int, required=True, help="UDP port to listen on")
    s.add_argument("--target", required=True, help="HOST:PORT to forward to")
    s.add_argument("--source-ip", help="local IP for upstream sockets")
    s.add_argument("--seed", type=int, help="seed the impairment randomness")
    s.add_argument("--trace", action="store_true", help="log every datagram to stderr")
    for key, kind in SETTINGS.items():
        if kind is bool:
            s.add_argument(f"--{key.replace('_', '-')}", dest=key, action="store_true", default=None)
        else:
            s.add_argument(f"--{key.replace('_', '-')}", dest=key, type=kind)

    c = sub.add_parser("ctl", help="steer a running link")
    c.add_argument("--name", required=True)
    csub = c.add_subparsers(dest="action", required=True)
    cset = csub.add_parser("set", help="change impairment, e.g. loss=0.05 delay_ms=40")
    cset.add_argument("values", nargs="+", metavar="KEY=VALUE")
    csub.add_parser("reset", help="clear every impairment")
    cbh = csub.add_parser("blackhole", help="drop everything (on) or nothing (off)")
    cbh.add_argument("state", choices=["on", "off"])
    cbh.add_argument(
        "--direction", choices=["both", "up", "down"], default="both",
        help="up: client -> target only; down: target -> client only",
    )
    crb = csub.add_parser("rebind", help="move every flow to a new upstream port")
    crb.add_argument("--source-ip", help="also move to this local IP ('' for any)")
    csub.add_parser("stats", help="print counters as JSON")

    args = parser.parse_args()
    if args.command == "serve":
        try:
            asyncio.run(serve(args))
        except KeyboardInterrupt:
            pass
        return 0

    if args.action == "set":
        values = dict(item.split("=", 1) for item in args.values)
        request = {"cmd": "set", "values": values}
    elif args.action == "blackhole":
        key = "blackhole" if args.direction == "both" else f"blackhole_{args.direction}"
        request = {"cmd": "set", "values": {key: args.state}}
    elif args.action == "rebind":
        request = {"cmd": "rebind", "source_ip": args.source_ip}
    else:
        request = {"cmd": args.action}
    reply = asyncio.run(control(args.name, request))
    print(json.dumps(reply, indent=2))
    return 0 if reply.get("ok") else 1


if __name__ == "__main__":
    sys.exit(main())
