#!/bin/bash

set -e

BIN=fuse-overlayfs
BIN=../fuse-overlayfs

cleanup()
{
  umount mnt || true
  umount ext1 ext2 || true
  rm -fr mnt img1 img2 ext1 ext2 mupper mlower a.out test.c

  echo
  echo "FAILED"
  echo
}

trap cleanup EXIT

rm -fr mnt img1 img2 ext1 ext2

# override any other settings.
export LC_ALL=C

echo
echo "Testing mmap where files have the same inodes across layers."

rm -f img1
truncate -s 10M img1
/sbin/mke2fs -t ext2 img1 >& /dev/null
rm -f img2
truncate -s 10M img2
/sbin/mke2fs -t ext2 img2 >& /dev/null
mkdir -p ext1
mkdir -p ext2
fuse2fs -o fakeroot,uid=$(id -u),gid=$(id -g) img1 ext1
fuse2fs -o fakeroot,uid=$(id -u),gid=$(id -g) img2 ext2

# We assume that the files will get the same inode number on both layers, this is checked in test-passthrough.sh for a single file.
dst=ext1
for i in $( ldd $( gcc -print-prog-name=cc1 ) | awk '{print $3}' ); do
  cp $i $dst
  if [[ $dst == ext1 ]]; then
    dst=ext2
  else
    dst=ext1
  fi
done

mkdir mnt
$BIN -o lowerdir=ext2:ext1 mnt

echo "int main(void) { return 0; }" >test.c

LD_LIBRARY_PATH=mnt/ gcc test.c

echo "PASSED"

umount mnt

umount ext1
umount ext2

rm -fr mnt img1 img2 ext1 ext2 a.out test.c

trap - EXIT
echo
echo "FINISHED"
echo
