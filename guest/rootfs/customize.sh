#!/bin/sh
# mmdebstrap customize hook. Runs inside mmdebstrap's user namespace; $1 is
# the root directory of the new image.
set -eu
root="$1"

# The unprivileged user that jobs run as (BUILDER_UID in the guest agent).
chroot "$root" useradd --uid 1000 --user-group --create-home --shell /bin/sh builder

# Mount points for the job payload and the scratch disk.
mkdir -p "$root/cw" "$root/work"

# The fake internet answers DNS on the host side of the tap link. Without
# this, the image would carry whatever the build host's resolver was.
printf 'nameserver 10.0.2.1\n' > "$root/etc/resolv.conf"

# The guest agent is PID 1: there is no init system, getty or service.
# Documentation and package caches only cost space.
rm -rf "$root/usr/share/doc" "$root/usr/share/man" "$root/usr/share/info"
rm -rf "$root/var/cache/apt/"* "$root/var/lib/apt/lists/"*
