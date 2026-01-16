#!/bin/bash

set -e

make

BIN=fuse-overlayfs
BIN=../../fuse-overlayfs

cleanup()
{
  umount mnt || true
  umount ext2 || true
  rm -fr img ext2 mnt

  echo
  echo "FAILED"
  echo
}

fail()
{
  echo "$1"
  return 1
}

trap cleanup EXIT

# override any other settings.
export LC_ALL=C

echo
echo "Testing plugin"

rm -fr mnt img ext2

truncate -s 10M img
/sbin/mke2fs -t ext2 img >& /dev/null
mkdir -p ext2
fuse2fs -o fakeroot,uid=$(id -u),gid=$(id -g) img ext2

rm -fr "ext2/lost+found"

for i in 0 1 2 4; do
  for j in 1 3 5; do
    for k in 2 6; do
      for l in 3 7; do
        touch -r $0 ext2/f$i$j$k$l
        chmod $i$j$k$l ext2/f$i$j$k$l
      done
    done
  done
done

before=$( ls -l ext2 | md5sum )
./convert ext2
after=$( ls -l ext2 | md5sum )

mkdir -p mnt

$BIN -o plugins=$(pwd)/shared-storage-plugin.so -o lowerdir=//test//ext2 mnt
fsover=$( ls -l mnt | md5sum )

[[ $before = $fsover ]] || fail "plugin not working, outputs don't match"
[[ $before != $after ]] || fail "convert not working, no change to permissions"

umount mnt
echo "PASSED"

# This should be identical to the above. xino=off should be a no-op.
$BIN -o xino=off -o plugins=$(pwd)/shared-storage-plugin.so -o lowerdir=//test//ext2 mnt
[[ $( ls -l mnt | md5sum ) == $before ]] || fail "xino=off failed - this was not expected!"
umount mnt
echo "PASSED"

# The plugin does not support nfs file-handles so this should be the same again.
$BIN -o xino=auto -o plugins=$(pwd)/shared-storage-plugin.so -o lowerdir=//test//ext2 mnt
[[ $( ls -l mnt | md5sum ) == $before ]] || fail "xino=auto failed - this was not expected!"
umount mnt
echo "PASSED"

# This should fail because the plugin doesn't support nfs file-handles
! $BIN -o xino=on -o plugins=$(pwd)/shared-storage-plugin.so -o lowerdir=//test//ext2 mnt || fail "xino=on worked - this was not expected!"
echo "PASSED"

umount ext2
rmdir mnt
rmdir ext2
rm img

trap - EXIT
echo
echo "FINISHED"
echo
