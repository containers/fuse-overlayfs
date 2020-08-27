#!/bin/sh

set -ex

rm -rf unlink-test
mkdir unlink-test

cd unlink-test

mkdir lower upper workdir merged

touch lower/a

fuse-overlayfs -o lowerdir=lower,upperdir=upper,workdir=workdir,suid,dev merged

unlink merged/a

test \! -e merged/a

echo hello > merged/foo
ln merged/foo merged/foo2
rm merged/foo
grep hello merged/foo2
ln merged/foo2 merged/foo
echo world >> merged/foo2
grep hello merged/foo
grep world merged/foo

umount merged || [ $? -eq "${EXPECT_UMOUNT_STATUS:-0}" ]
