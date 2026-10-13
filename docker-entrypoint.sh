#!/bin/sh
# Start as root, hand /data to the user we are told to be, then drop to it.
# That way a folder bind-mounted from a NAS does not have to be prepared first.
set -e

PUID="${PUID:-1000}"
PGID="${PGID:-1000}"
DATA="${CF0T_DATA_DIR:-/data}"

if [ "$(id -u)" = "0" ]; then
    mkdir -p "$DATA"

    if [ "$PUID" != "0" ]; then
        getent group "$PGID" >/dev/null 2>&1 || groupadd -g "$PGID" cf0t
        getent passwd "$PUID" >/dev/null 2>&1 || \
            useradd -u "$PUID" -g "$PGID" -M -s /usr/sbin/nologin cf0t
    fi

    # Best effort: some shares refuse chown. The app says so at startup if the
    # folder stays unwritable, so a failure here is not worth stopping for.
    chown -R "$PUID:$PGID" "$DATA" 2>/dev/null || \
        echo "note: could not chown $DATA to $PUID:$PGID, continuing" >&2

    if [ "$PUID" != "0" ]; then
        exec setpriv --reuid="$PUID" --regid="$PGID" --init-groups "$@"
    fi
fi

exec "$@"
