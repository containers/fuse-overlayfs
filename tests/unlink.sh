#!/bin/sh

mkdir lower upper workdir merged

touch lower/a

fuse-overlayfs -o lowerdir=lower,upperdir=upper,workdir=workdir,suid,dev merged

unlink merged/a

test \! -e merged/a

umount merged
