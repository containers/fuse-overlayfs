#!/bin/sh

set -ex

test $(id -u) -gt 0

rm -rf unpriv-test
mkdir unpriv-test

cd unpriv-test

mkdir lower upper workdir merged

touch lower/a lower/b
chmod 444 lower/a lower/b

fuse-overlayfs -o lowerdir=lower,upperdir=upper,workdir=workdir merged

rm -f merged/a
chmod 406 merged/b

test \! -e merged/a
test $(stat --printf=%a merged/b) -eq 406
test $(stat --printf=%a upper/b) -eq 406
if [ ${FUSE_OVERLAYFS_DISABLE_OVL_WHITEOUT:-0} -eq 1 ]; then
    test -e upper/.wh.a
else
    test -c upper/a
fi

fusermount -u merged || [ $? -eq "${EXPECT_UMOUNT_STATUS:-0}" ]
