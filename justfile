# qsh — common development commands.
#
#   just            list the recipes
#   just check      the fast checks: format, lints, tests
#   just verify     everything that must pass before merging to main
#   just demo       a throwaway server + client in /tmp, ready to poke at
#   just e2e        the multi-host end-to-end suite (Docker)

set shell := ["bash", "-euo", "pipefail", "-c"]

# Where `just demo` and friends keep their throwaway state.
sandbox := justfile_directory() / "target" / "sandbox"

_default:
    @just --list --unsorted

# ---------------------------------------------------------------- build

# Debug build of both binaries.
build:
    cargo build

# Optimised build of both binaries.
release:
    cargo build --release

# Install qsh and qsh-server into ~/.cargo/bin.
install:
    cargo install --path . --locked

# Remove build artifacts, including the demo sandbox.
clean:
    cargo clean

# ---------------------------------------------------------------- quality

# The fast checks, in the order that fails fastest.
check: fmt-check lint test

# Everything that must pass before a change reaches main (README "Checks
# before merging"). Needs rustup, cargo-audit, sudo, systemd and Docker.
verify: check msrv test-root audit-deps e2e-plan e2e

# Format the source.
fmt:
    cargo fmt --all

# Fail if the source is not formatted.
fmt-check:
    cargo fmt --all -- --check

# Pedantic clippy, warnings are errors.
lint:
    cargo clippy --all-targets --all-features --locked -- -D warnings

# Unit tests plus the end-to-end suite.
test:
    cargo test --all-features --locked

# Check the declared MSRV against Cargo.lock, then test with it (via rustup).
msrv:
    python3 ci/check-msrv.py
    cargo +"$(sed -n 's/^rust-version = "\(.*\)"/\1/p' Cargo.toml)" test --all-features --locked

# The tests that need root: the privilege drop, and the session cgroup in a
# delegated systemd scope.
test-root:
    sudo -E env "PATH=$PATH" cargo test --locked --test e2e
    sudo -E env "PATH=$PATH" cargo test --locked --lib child::tests::mixed_credentials_cannot_reach_remote_exec
    sudo -E env "PATH=$PATH" cargo test --locked --lib child::tests::sessions_do_not_inherit_service_capabilities
    sudo -E env "PATH=$PATH" systemd-run --scope --quiet --collect --same-dir -p Delegate=yes \
        env QSH_REQUIRE_DELEGATED_CGROUP=1 cargo test --locked --test e2e \
        cgroup_policy_kills_detached_descendants_or_fails_before_exec -- --exact --nocapture

# Just the fast unit tests.
test-unit:
    cargo test --lib --bins

# Just the end-to-end suite, with output shown.
test-e2e:
    cargo test --test e2e -- --nocapture

# Multi-host end-to-end suite in Docker; args go to pytest (e2e/README.md).
[positional-arguments]
e2e *ARGS:
    e2e/run test "$@"

# Check e2e/TEST_PLAN.md against the scenarios that implement it.
e2e-plan:
    e2e/run plan

# List every justified `unsafe` exception and count the blocks per file.
audit-unsafe:
    @echo "unsafe_code is denied crate-wide; every exception is justified:"
    @grep -rn --include='*.rs' -A3 'unsafe_code' src \
        | grep -o 'reason = "[^"]*"' | sed 's/reason = /  - /; s/"//g'
    @echo
    @echo "unsafe blocks per file:"
    @grep -rc 'unsafe ' --include='*.rs' src | grep -v ':0$' || true

# Check dependencies for advisories, including unmaintained crates (needs
# `cargo install cargo-audit`). Fix an advisory by updating the dependency.
audit-deps:
    cargo audit --deny warnings

# Build the API documentation and open it.
doc:
    cargo doc --no-deps --open

# ---------------------------------------------------------------- demo

# Create a self-contained server + client setup under target/sandbox.
demo-setup:
    #!/usr/bin/env bash
    set -euo pipefail
    rm -rf "{{ sandbox }}"
    mkdir -p "{{ sandbox }}"
    cargo build --quiet
    BIN="{{ justfile_directory() }}/target/debug"
    "$BIN/qsh-server" --dir "{{ sandbox }}/server" keygen
    "$BIN/qsh" keygen --identity "{{ sandbox }}/client"
    "$BIN/qsh-server" --dir "{{ sandbox }}/server" authorize \
        "{{ sandbox }}/client/id.crt" --user "$(id -un)" --name demo
    echo
    echo "Ready. Start the server with:  just demo-serve"

# Run the demo server in the foreground on 127.0.0.1:2222.
demo-serve:
    cargo run --quiet --bin qsh-server -- \
        --dir "{{ sandbox }}/server" serve --listen 127.0.0.1:2222

# Open an interactive shell against the demo server.
demo-shell:
    cargo run --quiet --bin qsh -- \
        -i "{{ sandbox }}/client" -p 2222 --accept-new 127.0.0.1

# Run a command on the demo server, e.g. `just demo-run uname -a`. Arguments
# are re-split on whitespace by just, so use `demo-shell` for anything that
# needs quoting.
demo-run +ARGS:
    cargo run --quiet --bin qsh -- \
        -i "{{ sandbox }}/client" -p 2222 --accept-new 127.0.0.1 {{ ARGS }}

# Round-trip a directory through rsync over the demo server.
demo-rsync SRC="./src":
    #!/usr/bin/env bash
    set -euo pipefail
    BIN="{{ justfile_directory() }}/target/debug"
    dest="{{ sandbox }}/rsync-dest"
    mkdir -p "$dest"
    rsync -e "$BIN/qsh -i {{ sandbox }}/client -p 2222 --accept-new -q" \
        -av --delete "{{ SRC }}/" "127.0.0.1:$dest/"
    echo
    diff -r "{{ SRC }}" "$dest" && echo "identical"
