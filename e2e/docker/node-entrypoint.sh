#!/bin/sh
# Entrypoint for every e2e node.
#
#   node-entrypoint init         boot systemd as PID 1 (server nodes)
#   node-entrypoint CMD [ARGS]   run CMD (clients, the network simulator)
set -eu

if [ "${1:-}" = init ]; then
    # qsh's restricted sessions need the unified cgroup v2 hierarchy at
    # /sys/fs/cgroup. A host with a hybrid v1/v2 layout hands a privileged
    # container a tmpfs of v1 controllers there instead; replace it with this
    # container's own cgroup v2 view so systemd boots in unified mode and can
    # delegate a subtree to qsh-server, as it would on a modern host.
    if [ "$(stat -fc %T /sys/fs/cgroup)" != cgroup2fs ]; then
        umount -R /sys/fs/cgroup 2>/dev/null || umount -l /sys/fs/cgroup
        mount -t cgroup2 -o nsdelegate cgroup2 /sys/fs/cgroup
    fi
    exec /sbin/init
fi

exec "$@"
