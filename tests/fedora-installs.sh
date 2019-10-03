#!/bin/bash

set -xeuo pipefail

mkdir lower upper workdir merged

fuse-overlayfs -o sync=0,lowerdir=lower,upperdir=upper,workdir=workdir,suid,dev merged

docker run --rm -ti -v $(pwd)/merged:/merged fedora dnf --installroot /merged --releasever 30 install -y glibc-common gedit

umount merged

# Make sure workdir is empty, and move the upper layer down
rm -rf workdir lower
mv upper lower
mkdir upper workdir

gcc -static -o suid-test $(dirname $0)/suid-test.c

fuse-overlayfs -o sync=0,threaded=1,lowerdir=lower,upperdir=upper,workdir=workdir,suid,dev merged
SUID_TEST=$(pwd)/suid-test
(cd merged; $SUID_TEST)

stat -c %A upper/suid | grep s
stat -c %a upper/nosuid | grep -v s

# Install some big packages
docker run --rm -ti -v $(pwd)/merged:/merged fedora dnf --installroot /merged --releasever 30 install -y emacs texlive

docker run --rm -ti -v $(pwd)/merged:/merged fedora sh -c 'rm /merged/usr/share/glib-2.0/schemas/gschemas.compiled; glib-compile-schemas /merged/usr/share/glib-2.0/schemas/'

umount merged
fuse-overlayfs -o sync=0,lowerdir=lower,upperdir=upper,workdir=workdir,suid,dev merged

docker run --rm -ti -v $(pwd)/merged:/merged fedora sh -c 'rm -rf /merged/usr/share/glib-2.0/'

tar -c --to-stdout $(pwd)/merged > /dev/null

umount merged
rm -rf workdir lower upper
mkdir upper workdir lower

fuse-overlayfs -o sync=0,lowerdir=lower,upperdir=upper,workdir=workdir,suid,dev merged

# https://github.com/containers/fuse-overlayfs/issues/86
docker run --rm -ti -v $(pwd)/merged:/merged centos:6 yum --installroot /merged -y --releasever 6 install https://dl.fedoraproject.org/pub/epel/epel-release-latest-6.noarch.rpm

umount merged

# fast_ino_check
fuse-overlayfs -o fast_ino_check=1,sync=0,lowerdir=lower,upperdir=upper,workdir=workdir,suid,dev merged

docker run --rm -ti -v $(pwd)/merged:/merged centos:6 yum --installroot /merged -y --releasever 6 install nano

mkdir merged/a-directory

python -c 'import socket; socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM).bind("merged/unix-socket")'

setfattr -n user.foo -v bar merged/a-directory
getfattr -d merged/a-directory | grep bar
getfattr --only-values -n user.foo merged/a-directory | grep bar
getfattr --only-values -n user.foo upper/a-directory | grep bar

umount merged
