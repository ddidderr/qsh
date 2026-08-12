# qsh — common development commands.
#
#   just            list the recipes
#   just check      what CI runs: format, lints, tests
#   just demo       a throwaway server + client in /tmp, ready to poke at

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

# Everything CI checks, in the order that fails fastest.
check: fmt-check lint test

# Format the source.
fmt:
    cargo fmt --all

# Fail if the source is not formatted.
fmt-check:
    cargo fmt --all -- --check

# Pedantic clippy, warnings are errors.
lint:
    cargo clippy --all-targets --all-features -- -D warnings

# Unit tests plus the end-to-end suite.
test:
    cargo test --all-features

# Just the fast unit tests.
test-unit:
    cargo test --lib --bins

# Just the end-to-end suite, with output shown.
test-e2e:
    cargo test --test e2e -- --nocapture

# List every justified `unsafe` exception and count the blocks per file.
audit-unsafe:
    @echo "unsafe_code is denied crate-wide; every exception is justified:"
    @grep -rn --include='*.rs' -A3 'unsafe_code' src \
        | grep -o 'reason = "[^"]*"' | sed 's/reason = /  - /; s/"//g'
    @echo
    @echo "unsafe blocks per file:"
    @grep -rc 'unsafe ' --include='*.rs' src | grep -v ':0$' || true

# Check dependencies for advisories, including unmaintained crates — the same
# policy CI enforces (needs `cargo install cargo-audit`).
audit-deps:
    cargo audit --deny warnings

# Validate the GitHub Actions workflows (needs docker).
audit-ci:
    docker run --rm -v "$PWD:/repo" -w /repo rhysd/actionlint:latest -color
    python3 ci/check-msrv.py

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
