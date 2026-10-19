# syntax=docker/dockerfile:1
#
# One image for every node of the end-to-end environment: servers, clients
# and the network simulator. Build it from the repository root:
#
#   docker build -f e2e/docker/Dockerfile -t qsh-e2e-node .
#
# `e2e/run build` does that, and also forwards a proxy and an extra CA
# certificate when the build host needs them (see e2e/README.md).

# Pinned so a rebuild months from now produces the same environment. Update
# them deliberately.
ARG RUST_IMAGE=rust:1.97-slim-trixie@sha256:8e8cf8f7fd54a2d23d5a743b3a03f56e26b6c774276c33fa0595111704ebb15c
ARG BASE_IMAGE=debian:trixie-slim@sha256:a29215f6a35e51e22adffa17f89e9d2ef06214e64a2bad10d765c46aea49f11f

# ---------------------------------------------------------------- build
#
# The binaries are built inside the image's own Debian release, so they link
# against the glibc they run with, whatever distribution the host runs.
FROM ${RUST_IMAGE} AS build
ARG PROFILE=release
WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY src ./src
# COPY keeps the context's mtimes and the target cache is shared between
# builds, so another tree's older sources could look up to date to cargo.
# Touch them: only the dependencies come from the cache.
RUN --mount=type=secret,id=extra_ca,required=false,mode=0444 \
    --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/src/target \
    if [ -s /run/secrets/extra_ca ]; then export CARGO_HTTP_CAINFO=/run/secrets/extra_ca; fi \
    && find src -name '*.rs' -exec touch {} + \
    && cargo build --locked --bins --profile "$PROFILE" \
    && dir=$([ "$PROFILE" = dev ] && echo debug || echo "$PROFILE") \
    && install -D -m 0755 "target/$dir/qsh" "target/$dir/qsh-server" -t /out/

# ---------------------------------------------------------------- node
FROM ${BASE_IMAGE} AS node

# Behind a TLS-intercepting proxy, plain-HTTP mirrors are usually refused and
# the slim image has no CA store yet, so switch to HTTPS and trust the extra
# CA for this one step. Without a proxy this is the stock configuration.
#
# slapd, ldap-utils, nslcd and libnss-ldapd are for AUTH-20, which serves
# accounts from a directory on server2. Installed, they must change nothing:
# debconf is told to create no database and to leave nsswitch.conf alone.
RUN --mount=type=secret,id=extra_ca,required=false,mode=0444 \
    set -eu; \
    if [ -n "${https_proxy:-}" ]; then \
        sed -i 's|http://|https://|g' /etc/apt/sources.list.d/*.sources; \
        printf 'Acquire::https::Proxy "%s";\n' "$https_proxy" > /etc/apt/apt.conf.d/90e2e-proxy; \
        if [ -s /run/secrets/extra_ca ]; then \
            printf 'Acquire::https::CAInfo "/run/secrets/extra_ca";\n' >> /etc/apt/apt.conf.d/90e2e-proxy; \
        fi; \
    fi; \
    printf '%s\n' \
        'slapd slapd/no_configuration boolean true' \
        'libnss-ldapd libnss-ldapd/nsswitch multiselect' \
        | debconf-set-selections; \
    apt-get update; \
    DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
        systemd systemd-sysv dbus \
        bash ca-certificates coreutils git iproute2 iputils-ping less \
        ncurses-bin procps psmisc python3 rsync tar util-linux xxd \
        ldap-utils libnss-ldapd nslcd slapd; \
    rm -rf /var/lib/apt/lists/* /etc/apt/apt.conf.d/90e2e-proxy

# The directory daemons stay off until AUTH-20 starts them, and no account
# lookup goes to LDAP unless it says so: every other scenario sees the same
# accounts, from /etc/passwd and /etc/group only, as before.
RUN systemctl disable slapd.service nslcd.service \
    && ! grep -qw ldap /etc/nsswitch.conf

# systemd as PID 1 in a container: keep the units that make sense, mask the
# ones that need real hardware or a console.
RUN systemctl mask \
        systemd-modules-load.service systemd-udevd.service \
        systemd-udev-trigger.service getty.target console-getty.service \
        systemd-firstboot.service systemd-remount-fs.service \
    && systemctl set-default multi-user.target

# systemd 258 and later ship a login profile that prints OSC 3008 context
# sequences around every prompt and command of an interactive bash, and a
# tmpfiles rule that links it back in at boot. Terminal scenarios compare
# exactly what a session prints, so leave it out.
RUN rm -f /etc/profile.d/80-systemd-osc-context.sh \
    && mkdir -p /etc/tmpfiles.d \
    && ln -sf /dev/null /etc/tmpfiles.d/20-systemd-osc-context.conf

# Accounts used by the scenarios. Fixed IDs keep file ownership stable across
# nodes; `project` gives alice a supplementary group to check after the
# privilege drop.
RUN groupadd --gid 2000 project \
    && useradd --create-home --shell /bin/bash --uid 1001 --groups project alice \
    && useradd --create-home --shell /bin/bash --uid 1002 bob \
    && useradd --create-home --shell /bin/bash --uid 1003 carol \
    && useradd --create-home --shell /bin/sh   --uid 1004 dave

COPY --from=build /out/qsh /out/qsh-server /usr/local/bin/
# The unit exactly as shipped: the suite tests the documented deployment.
COPY contrib/qsh-server.service /etc/systemd/system/qsh-server.service
COPY e2e/netsim/netsim.py /usr/local/bin/netsim
COPY e2e/docker/node-entrypoint.sh /usr/local/sbin/node-entrypoint

# systemd stops on SIGRTMIN+3, not SIGTERM.
STOPSIGNAL SIGRTMIN+3
ENTRYPOINT ["/usr/local/sbin/node-entrypoint"]
CMD ["sleep", "infinity"]
