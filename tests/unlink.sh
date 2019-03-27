#!/bin/sh

mkdir lower upper workdir merged

touch lower/a

fuse-overlayfs -o lowerdir=lower,upperdir=upper,workdir=workdir,suid,dev merged

unlink lower/a

test \! -e lower/a

umount merged
