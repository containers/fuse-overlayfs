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

# xattr_permissions=2
rm -rf lower upper workdir merged
mkdir lower upper workdir merged

touch upper/file
unshare -r setcap cap_net_admin+ep upper/file

fuse-overlayfs -o lowerdir=lower,upperdir=upper,workdir=workdir,xattr_permissions=2 merged

# Ensure the security xattr namespace is isolated.
test "$(unshare -r getcap merged/file)" = ''
unshare -r setcap cap_net_admin+ep merged/file
test "$(unshare -r getcap merged/file)" = 'merged/file cap_net_admin=ep'

# Ensure UID is preserved with chgrp.
podman unshare chgrp 1 merged/file
test $(podman unshare stat -c %u:%g merged/file) = 0:1

# Ensure UID and GID are preserved with chmod.
chmod 600 merged/file
test $(podman unshare stat -c %u:%g merged/file) = 0:1

fusermount -u merged || [ $? -eq "${EXPECT_UMOUNT_STATUS:-0}" ]
