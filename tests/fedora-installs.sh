#!/bin/bash

set -xeuo pipefail

mkdir lower upper workdir merged

fuse-overlayfs -o lowerdir=lower,upperdir=upper,workdir=workdir,suid,dev merged

docker run --rm -ti -v merged:/merged fedora dnf --installroot /merged --releasever 30 install -y glibc-common gedit

umount merged

# Make sure workdir is empty, and move the upper layer down
rm -rf workdir lower
mv upper lower
mkdir upper workdir

fuse-overlayfs -o lowerdir=lower,upperdir=upper,workdir=workdir,suid,dev merged

# Install some big packages
docker run --rm -ti -v merged:/merged fedora dnf --installroot /merged --releasever 30 install -y emacs texlive

docker run --rm -ti -v merged:/merged fedora sh -c 'rm /merged/usr/share/glib-2.0/schemas/gschemas.compiled; glib-compile-schemas /merged/usr/share/glib-2.0/schemas/'

umount merged
fuse-overlayfs -o lowerdir=lower,upperdir=upper,workdir=workdir,suid,dev merged

docker run --rm -ti -v merged:/merged fedora sh -c 'rm -rf /merged/usr/share/glib-2.0/'
