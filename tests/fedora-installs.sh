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

# Test the number of hard links for populated directories is > 2
test $(stat -c %h merged/etc) -gt 2
ls merged/usr
test $(stat -c %h merged/usr) -gt 2

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

touch lower/file-lower-layer

# no upper layer
fuse-overlayfs -o lowerdir=lower merged

tar -c --to-stdout $(pwd)/merged > /dev/null

set +o pipefail

touch merged/a 2>&1 | grep Read-only
touch merged/file-lower-layer 2>&1 | grep Read-only
touch merged/usr 2>&1 | grep Read-only
mkdir merged/abcd12345 2>&1 | grep Read-only
ln merged/file-lower-layer merged/file-lower-layer-link 2>&1 | grep Read-only
ln -s merged/file-lower-layer merged/a-symlink 2>&1 | grep Read-only

umount merged

# https://github.com/containers/fuse-overlayfs/issues/136
rm -rf lower1 lower2 lower3 lower upper workdir merged
mkdir lower1 lower2 lower3 upper workdir merged

mkdir -p lower1/dir1/dir2
touch lower1/dir1/dir2/foo
touch lower2/.wh.dir1
mkdir -p lower3/dir1/dir2

fuse-overlayfs -o lowerdir=lower3:lower2:lower1,upperdir=upper,workdir=workdir merged

test \! -e merged/dir1/dir2/foo

umount merged

# https://github.com/containers/fuse-overlayfs/issues/138
rm -rf lower1 lower2 lower3 lower upper workdir merged
mkdir lower1 lower2 lower3 upper workdir merged

mkdir -p lower1/dir1/dir2
touch lower1/dir1/dir2/foo
mkdir -p lower3/dir1/dir2
touch lower3/dir1/dir2/.wh..wh..opq

fuse-overlayfs -o lowerdir=lower3:lower2:lower1,upperdir=upper,workdir=workdir merged

test \! -e merged/dir1/dir2/foo
