#!/bin/bash

set -e

BIN=fuse-overlayfs
BIN=../fuse-overlayfs

cleanup()
{
  umount mnt || true
  umount mupper || true
  umount mlower || true
  umount ext1 ext2 || true
  rm -fr lower upper mnt img1 img2 ext1 ext2 mupper mlower

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

rm -fr lower upper mnt img1 img2 ext1 ext2 mupper mlower

mkdir -p lower/dir/dirl
mkdir -p upper/dir/diru
mkdir -p mnt

touch lower/dir/lower
touch upper/dir/upper

# override any other settings.
export LC_ALL=C

test_d_ino()
{
  local inodes=()
  mapfile -t inodes < <( ls -li mnt/dir | awk '!/^total / { print $1}' )
  local dl=$( stat -c %i mnt/dir/dirl )
  local du=$( stat -c %i mnt/dir/diru )
  local fl=$( stat -c %i mnt/dir/lower )
  local fu=$( stat -c %i mnt/dir/upper )

  [[ $dl == ${inodes[0]} ]] || fail "Expected st_ino $dl == d_ino ${inodes[0]}"
  [[ $du == ${inodes[1]} ]] || fail "Expected st_ino $du == d_ino ${inodes[1]}"
  [[ $fl == ${inodes[2]} ]] || fail "Expected st_ino $fl == d_ino ${inodes[2]}"
  [[ $fu == ${inodes[3]} ]] || fail "Expected st_ino $fu == d_ino ${inodes[3]}"
}

$BIN -o lowerdir=lower:upper mnt

echo
echo "All on same fs - ino passthrough - stable ino"

ldl=$( stat -c %i lower/dir/dirl )
lfl=$( stat -c %i lower/dir/lower )
udu=$( stat -c %i upper/dir/diru )
ufu=$( stat -c %i upper/dir/upper )
mdl=$( stat -c %i mnt/dir/dirl )
mfl=$( stat -c %i mnt/dir/lower )
mdu=$( stat -c %i mnt/dir/diru )
mfu=$( stat -c %i mnt/dir/upper )

[[ $lfl == $mfl ]] || fail "In passthrough mode expected file lower to have the same st_ino via direct access and via $BIN     Expected $lfl == $mfl "
[[ $ufu == $mfu ]] || fail "In passthrough mode expected file upper to have the same st_ino via direct access and via $BIN     Expected $ufu == $mfu "
[[ $ldl == $mdl ]] || fail "In passthrough mode expected directory dirl to have the same st_ino via direct access and via $BIN Expected $ldl == $mdl "
[[ $udu == $mdu ]] || fail "In passthrough mode expected directory diru to have the same st_ino via direct access and via $BIN Expected $udu == $mdu "

test_d_ino
echo "PASSED"

umount mnt

echo
echo "Checking that same inode on multiple layers maps to unique inodes on fuse"

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

touch ext1/lower
touch ext2/upper
$BIN -o lowerdir=ext2:ext1 mnt

el=$( stat -c %i ext1/lower )
eu=$( stat -c %i ext2/upper )
ml=$( stat -c %i mnt/lower )
mu=$( stat -c %i mnt/upper )

# Would be weird for this to fail but lets confirm that the first file has the same st_ino on both devices.
[[ $el == $eu ]] || fail "Expected first file on separate ext2 file systems to have the same st_ino. This requires a fix to the test to ensure this happens"

# Confirm when looking at the files via the mount that they have different st_ino
[[ $ml != $mu ]] || fail "Duplicated st_ino on $BIN - this will cause issues"

echo "PASSED"

umount mnt

umount ext1
rmdir ext1
rm ext2/upper

mkdir -p ext2

echo
echo "Upper on different fs - non-stable ino across mounts"
$BIN -o lowerdir=lower:upper:ext2 mnt
test_d_ino
umount mnt
$BIN -o lowerdir=lower:upper:ext2 mnt
test_d_ino
# No need to check anything here - we expect it to be different but it's not an error if they're not
echo "PASSED"
umount mnt

echo
echo "Upper on different fs xino - stable ino across mounts"
$BIN -o xino=auto,lowerdir=lower:upper:ext2 mnt
test_d_ino
mdl=$( stat -c %i mnt/dir/dirl )
mfl=$( stat -c %i mnt/dir/lower )
mdu=$( stat -c %i mnt/dir/diru )
mfu=$( stat -c %i mnt/dir/upper )
umount mnt
$BIN -o xino=auto,lowerdir=lower:upper:ext2 mnt
test_d_ino
mdl2=$( stat -c %i mnt/dir/dirl )
mfl2=$( stat -c %i mnt/dir/lower )
mdu2=$( stat -c %i mnt/dir/diru )
mfu2=$( stat -c %i mnt/dir/upper )

[[ $mdl == $mdl2 ]] || fail "Expected inode to be the same across mounts: xino failure Expected $mdl == $mdl2"
[[ $mfl == $mfl2 ]] || fail "Expected inode to be the same across mounts: xino failure Expected $mfl == $mfl2"
[[ $mdu == $mdu2 ]] || fail "Expected inode to be the same across mounts: xino failure Expected $mdu == $mdu2"
[[ $mfu == $mfu2 ]] || fail "Expected inode to be the same across mounts: xino failure Expected $mfu == $mfu2"

echo "PASSED"
umount mnt

echo
echo "double fuse - disables xino - non-stable ino across mounts (assumes FUSE_CAP_NO_EXPORT_SUPPORT supported)"
mkdir -p mlower
$BIN -o xino=off,lowerdir=lower:ext2 mlower
mkdir -p mupper
$BIN -o xino=off,lowerdir=upper:ext2 mupper

$BIN -o xino=auto,lowerdir=mlower:mupper mnt
test_d_ino
umount mnt
$BIN -o xino=auto,lowerdir=mlower:mupper mnt
test_d_ino
# No need to check anything here - we expect it to be different but it's not an error if they're not (and they will be the same if FUSE_CAP_NO_EXPORT_SUPPORT is not supported.

echo "PASSED"
umount mnt

umount mupper
umount mlower
umount ext2

rm -fr lower upper mnt img1 img2 ext1 ext2 mupper mlower

trap - EXIT
echo
echo "FINISHED"
echo
