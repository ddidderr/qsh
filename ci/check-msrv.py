#!/usr/bin/env python3
"""Fail if Cargo.toml's rust-version is below what the locked graph needs.

Run from anywhere:  python3 ci/check-msrv.py

Only crates actually reachable from this package in Cargo.lock are considered,
so a dependency that is present but never resolved cannot make the check lie.

This lives in a file rather than inside the workflow on purpose: multi-line
Python embedded in a YAML block scalar is how CI silently stopped parsing once
already.

Requires Python 3.11+ for tomllib (ubuntu-latest ships 3.12).
"""

from __future__ import annotations

import json
import subprocess
import sys
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def parse(version: str) -> tuple[int, int, int]:
    parts = (version.split("-")[0].split(".") + ["0", "0"])[:3]
    return int(parts[0]), int(parts[1]), int(parts[2])


def declared_msrv() -> str:
    with (ROOT / "Cargo.toml").open("rb") as handle:
        manifest = tomllib.load(handle)
    version = manifest.get("package", {}).get("rust-version")
    if not version:
        sys.exit("Cargo.toml does not declare package.rust-version")
    return version


def metadata() -> dict:
    result = subprocess.run(
        ["cargo", "metadata", "--locked", "--format-version", "1", "--all-features"],
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
    )
    return json.loads(result.stdout)


def reachable_dependencies(meta: dict) -> set[str]:
    resolve = meta.get("resolve") or {}
    root = resolve.get("root")
    if root is None:
        sys.exit("cargo metadata reported no root package")
    nodes = {node["id"]: node for node in resolve.get("nodes", [])}
    seen: set[str] = set()
    queue = [root]
    while queue:
        for dep in nodes.get(queue.pop(), {}).get("deps", []):
            if dep["pkg"] not in seen:
                seen.add(dep["pkg"])
                queue.append(dep["pkg"])
    seen.discard(root)
    return seen


def main() -> None:
    declared = declared_msrv()
    meta = metadata()
    wanted = reachable_dependencies(meta)

    required = "0.0.0"
    culprit = "no dependency declares one"
    for pkg in meta["packages"]:
        rust_version = pkg.get("rust_version")
        if not rust_version or pkg["id"] not in wanted:
            continue
        if parse(rust_version) > parse(required):
            required = rust_version
            culprit = f"{pkg['name']} {pkg['version']}"

    print(f"declared MSRV:                  {declared}")
    print(f"highest dependency requirement: {required} ({culprit})")

    if parse(declared) < parse(required):
        sys.exit(
            f"Cargo.toml declares rust-version {declared} but the locked "
            f"dependency graph needs {required} (from {culprit})"
        )
    print("MSRV claim is consistent with Cargo.lock")


if __name__ == "__main__":
    main()
