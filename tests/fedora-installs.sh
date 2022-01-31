#!/bin/bash

set -xeuo pipefail

mkdir lower upper workdir merged

fuse-overlayfs -o sync=0,lowerdir=lower,upperdir=upper,workdir=workdir,suid,dev merged

docker run --rm -v $(pwd)/merged:/merged fedora dnf --installroot /merged --releasever 30 install -y glibc-common gedit

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
docker run --rm -v $(pwd)/merged:/merged fedora dnf --installroot /merged --releasever 30 install -y emacs texlive

docker run --rm -v $(pwd)/merged:/merged fedora sh -c 'rm /merged/usr/share/glib-2.0/schemas/gschemas.compiled; glib-compile-schemas /merged/usr/share/glib-2.0/schemas/'

umount merged
fuse-overlayfs -o sync=0,lowerdir=lower,upperdir=upper,workdir=workdir,suid,dev merged

docker run --rm -v $(pwd)/merged:/merged fedora sh -c 'rm -rf /merged/usr/share/glib-2.0/'

tar -c --to-stdout $(pwd)/merged > /dev/null

umount merged
rm -rf workdir lower upper
mkdir upper workdir lower

fuse-overlayfs -o sync=0,lowerdir=lower,upperdir=upper,workdir=workdir,suid,dev merged

# https://github.com/containers/fuse-overlayfs/issues/86
docker run --rm -v $(pwd)/merged:/merged quay.io/centos/centos:stream8 yum --installroot /merged -y --releasever 8 install https://dl.fedoraproject.org/pub/epel/epel-release-latest-8.noarch.rpm

umount merged

# fast_ino_check
fuse-overlayfs -o fast_ino_check=1,sync=0,lowerdir=lower,upperdir=upper,workdir=workdir,suid,dev merged

docker run --rm -v $(pwd)/merged:/merged quay.io/centos/centos:stream8 yum --installroot /merged -y --releasever 8 install nano

mkdir merged/a-directory

python -c 'import socket; socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM).bind("merged/unix-socket")'

setfattr -n user.foo -v bar merged/a-directory
getfattr -d merged/a-directory | grep bar
getfattr --only-values -n user.foo merged/a-directory | grep bar
getfattr --only-values -n user.foo upper/a-directory | grep bar

umount merged

touch lower/file-lower-layer

# set a "big" xattr
setfattr -n user.big-xattr -v "$(seq 1000 | tr -d '\n')" lower/file-lower-layer

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

umount merged

# https://github.com/containers/fuse-overlayfs/issues/143
rm -rf lower upper workdir merged
mkdir lower upper workdir merged
touch lower/deps.txt
ln -s src/deps.txt upper/

fuse-overlayfs -o lowerdir=lower,upperdir=upper,workdir=workdir merged

test \! -e merged/dir1/dir2/foo

touch -h merged/deps.txt


# https://github.com/containers/fuse-overlayfs/issues/151

umount merged

rm -rf lower upper workdir merged
mkdir lower upper workdir merged
mkdir lower/a lower/b
touch lower/.wh.test lower/a/test lower/b/test

fuse-overlayfs -o lowerdir=lower,upperdir=upper,workdir=workdir merged

test -e merged/a/test

ls -l merged/b

test -e merged/b/test

#### Correct number of directory nlink

umount merged

rm -rf lower upper workdir merged
mkdir lower upper workdir merged
mkdir lower/a lower/a/1 lower/a/2 lower/a/3

fuse-overlayfs -o lowerdir=lower,upperdir=upper,workdir=workdir merged

test $(stat -c %h merged/a) = 5

mkdir merged/a/4

test $(stat -c %h merged/a) = 6

rm -rf merged/a/4

test $(stat -c %h merged/a) = 5

rm -rf merged/a/3

test $(stat -c %h merged/a) = 4

# symlink mtime

touch merged/afile
ln -s afile merged/alink
touch -h -d "2020-01-02 12:13:14" merged/alink
stat --format "%y" merged/alink | grep "12:13:14"
stat --format "%x" merged/alink | grep "12:13:14"

# file mtime
touch -h -d "2020-01-02 11:12:13" merged/afile
stat --format "%y" merged/afile | grep "11:12:13"
stat --format "%x" merged/afile | grep "11:12:13"

# dir mtime
mkdir merged/adir
touch -h -d "2020-01-02 10:11:12" merged/adir
stat --format "%y" merged/adir | grep "10:11:12"
stat --format "%x" merged/adir | grep "10:11:12"

upper_max_filename_len=$(stat -f -c %l upper)
merged_max_filename_len=$(stat -f -c %l merged)

test $merged_max_filename_len -lt $upper_max_filename_len

if touch merged/$(printf %${upper_max_filename_len}s | tr ' ' A}); then
    exit 1
fi

touch merged/$(printf %${merged_max_filename_len}s | tr ' ' A})

# If a file is removed but referenced, we must still be able to access it.
echo 12345 | tee merged/toremove
exec 3<> merged/toremove
sleep 90 &
exec 3>&-
sleep_pid=$!
rm merged/toremove
grep 12345 /proc/$sleep_pid/fd/3

touch merged/a merged/b
chmod 6 merged/a
mv merged/a merged/x
mv merged/b merged/a

# https://github.com/containers/fuse-overlayfs/issues/279
umount -l merged

rm -rf lower upper workdir merged
mkdir lower upper workdir merged
mkdir lower/test
touch lower/test/a.txt

fuse-overlayfs -o lowerdir=lower,upperdir=upper,workdir=workdir merged

(cd merged/test; touch a.txt; mv a.txt a2.txt; touch a3.txt; ln -s a3.txt a.txt)

if test -e upperdir/test/.wh.a.txt; then
   echo "whiteout file still exists" >&2
   exit 1
fi

# https://github.com/containers/fuse-overlayfs/issues/306
umount -l merged

rm -rf lower upper workdir merged
mkdir lower upper workdir merged

mkdir -p lower/a/b
fuse-overlayfs -o lowerdir=lower,upperdir=upper,workdir=workdir merged

rm -rf merged/a
mkdir -p merged/a/b
rm -rf merged/a/b
test \! -e upper/a/b

mknod merged/dev-foo c 10 175
attr -l merged/dev-foo

# https://github.com/containers/fuse-overlayfs/issues/337
umount -l merged

rm -rf lower upper workdir merged
mkdir lower upper workdir merged

mkdir upper/foo
ln -s not/existing lower/foo

fuse-overlayfs -o lowerdir=lower,upperdir=upper,workdir=workdir merged

stat merged/foo

umount merged
