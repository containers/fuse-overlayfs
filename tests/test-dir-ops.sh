#!/bin/bash
# Test directory operations: multi-layer merging, opaque directories,
# nlink counting, rmdir, mkdir over whiteout, nested operations.

set -xeuo pipefail

cleanup() {
    cd /
    umount "$MERGED" 2>/dev/null || true
    rm -rf "$TESTDIR"
}

TESTDIR=$(mktemp -d /tmp/test-dir-ops.XXXXXX)
trap cleanup EXIT
cd "$TESTDIR"

MERGED="$TESTDIR/merged"

# ========================================
# Test 1: Basic directory merge (2 layers)
# ========================================
echo "=== Test 1: Two-layer directory merge ==="
mkdir -p lower upper workdir merged

mkdir lower/shared
echo "from_lower" > lower/shared/lower_file

mkdir upper/shared
echo "from_upper" > upper/shared/upper_file

fuse-overlayfs -o lowerdir=lower,upperdir=upper,workdir=workdir merged

test -f merged/shared/lower_file
test -f merged/shared/upper_file
grep from_lower merged/shared/lower_file
grep from_upper merged/shared/upper_file

umount merged
rm -rf lower upper workdir merged

# ========================================
# Test 2: Three-layer directory merge
# ========================================
echo "=== Test 2: Three-layer directory merge ==="
mkdir -p lower1 lower2 upper workdir merged

mkdir lower1/shared lower2/shared upper/shared
echo "layer1" > lower1/shared/file1
echo "layer2" > lower2/shared/file2
echo "upper" > upper/shared/file3

fuse-overlayfs -o lowerdir=lower2:lower1,upperdir=upper,workdir=workdir merged

test -f merged/shared/file1
test -f merged/shared/file2
test -f merged/shared/file3

umount merged
rm -rf lower1 lower2 upper workdir merged

# ========================================
# Test 3: Upper file hides lower file
# ========================================
echo "=== Test 3: Upper hides lower ==="
mkdir -p lower upper workdir merged

echo "lower_version" > lower/samefile
echo "upper_version" > upper/samefile

fuse-overlayfs -o lowerdir=lower,upperdir=upper,workdir=workdir merged

grep upper_version merged/samefile
if grep lower_version merged/samefile 2>/dev/null; then
    echo "ERROR: Lower version should be hidden"
    exit 1
fi

umount merged
rm -rf lower upper workdir merged

# ========================================
# Test 4: Opaque directory stops merging
# ========================================
echo "=== Test 4: Opaque directory ==="
mkdir -p lower upper workdir merged

mkdir lower/opdir
echo "lower_content" > lower/opdir/lower_only

mkdir upper/opdir
echo "upper_content" > upper/opdir/upper_only
setfattr -n "trusted.overlay.opaque" -v "y" upper/opdir 2>/dev/null || \
    setfattr -n "user.overlay.opaque" -v "y" upper/opdir

fuse-overlayfs -o lowerdir=lower,upperdir=upper,workdir=workdir merged

# Lower file should NOT be visible (opaque blocks merging)
test ! -e merged/opdir/lower_only
test -f merged/opdir/upper_only

umount merged
rm -rf lower upper workdir merged

# ========================================
# Test 5: .wh..wh..opq sentinel file
# ========================================
echo "=== Test 5: .wh..wh..opq opaque sentinel ==="
mkdir -p lower upper workdir merged

mkdir lower/opdir2
echo "should_hide" > lower/opdir2/hidden

mkdir upper/opdir2
touch upper/opdir2/.wh..wh..opq

fuse-overlayfs -o lowerdir=lower,upperdir=upper,workdir=workdir merged

test ! -e merged/opdir2/hidden
# The sentinel file itself should not be visible
test ! -e merged/opdir2/.wh..wh..opq

umount merged
rm -rf lower upper workdir merged

# ========================================
# Test 6: Nlink counting for directories
# ========================================
echo "=== Test 6: Directory nlink ==="
mkdir -p lower upper workdir merged

mkdir -p lower/parent/sub1 lower/parent/sub2

fuse-overlayfs -o lowerdir=lower,upperdir=upper,workdir=workdir merged

# nlink = 2 + number of subdirectories = 4
test $(stat -c %h merged/parent) -eq 4

# Create another subdirectory
mkdir merged/parent/sub3
test $(stat -c %h merged/parent) -eq 5

# Remove a subdirectory
rmdir merged/parent/sub3
test $(stat -c %h merged/parent) -eq 4

umount merged
rm -rf lower upper workdir merged

# ========================================
# Test 7: static_nlink option
# ========================================
echo "=== Test 7: static_nlink ==="
mkdir -p lower upper workdir merged

mkdir -p lower/dir/a lower/dir/b lower/dir/c

fuse-overlayfs -o static_nlink,lowerdir=lower,upperdir=upper,workdir=workdir merged

# With static_nlink, dirs should have nlink=1 (C implementation uses 1)
test $(stat -c %h merged/dir) -eq 1

umount merged
rm -rf lower upper workdir merged

# ========================================
# Test 8: rmdir with lower layer content
# ========================================
echo "=== Test 8: rmdir with lower layer ==="
mkdir -p lower/toremove upper workdir merged
echo "file" > lower/toremove/file

fuse-overlayfs -o lowerdir=lower,upperdir=upper,workdir=workdir merged

rm -rf merged/toremove
test ! -e merged/toremove

# Whiteout should exist in upper
if [ -c upper/toremove ]; then
    test "$(stat -c '%t:%T' upper/toremove)" = "0:0"
elif [ -f upper/.wh.toremove ]; then
    true
else
    echo "ERROR: No whiteout for removed directory"
    exit 1
fi

umount merged
rm -rf lower upper workdir merged

# ========================================
# Test 9: mkdir over whiteout (re-create deleted directory)
# ========================================
echo "=== Test 9: mkdir over whiteout ==="
mkdir -p lower/recreatedir upper workdir merged
echo "old" > lower/recreatedir/old_file

fuse-overlayfs -o lowerdir=lower,upperdir=upper,workdir=workdir merged

rm -rf merged/recreatedir
test ! -e merged/recreatedir

mkdir merged/recreatedir
test -d merged/recreatedir

# Old files should NOT reappear
test ! -e merged/recreatedir/old_file

# New files should work
echo "new" > merged/recreatedir/new_file
grep new merged/recreatedir/new_file

umount merged
rm -rf lower upper workdir merged

# ========================================
# Test 10: Nested directory operations
# ========================================
echo "=== Test 10: Nested directory operations ==="
mkdir -p lower upper workdir merged

fuse-overlayfs -o lowerdir=lower,upperdir=upper,workdir=workdir merged

mkdir -p merged/a/b/c/d/e
echo "deep" > merged/a/b/c/d/e/file
test -f merged/a/b/c/d/e/file

rm -rf merged/a/b/c
test ! -e merged/a/b/c
test -d merged/a/b

umount merged
rm -rf lower upper workdir merged

# ========================================
# Test 11: readdir returns correct entries
# ========================================
echo "=== Test 11: readdir correctness ==="
mkdir -p lower upper workdir merged

mkdir lower/listdir
echo "a" > lower/listdir/file_a
echo "b" > lower/listdir/file_b
echo "c" > lower/listdir/file_c

fuse-overlayfs -o lowerdir=lower,upperdir=upper,workdir=workdir merged

# Count entries (excluding . and ..)
ENTRIES=$(ls merged/listdir | wc -l)
test "$ENTRIES" -eq 3

# Delete one
rm merged/listdir/file_b
ENTRIES=$(ls merged/listdir | wc -l)
test "$ENTRIES" -eq 2
test ! -e merged/listdir/file_b

# Add one
echo "d" > merged/listdir/file_d
ENTRIES=$(ls merged/listdir | wc -l)
test "$ENTRIES" -eq 3

umount merged
rm -rf lower upper workdir merged

# ========================================
# Test 12: Whiteout in readdir (hidden entries)
# ========================================
echo "=== Test 12: Whiteout filtering in readdir ==="
mkdir -p lower upper workdir merged

mkdir lower/wh_test
echo "visible" > lower/wh_test/visible
echo "hidden" > lower/wh_test/hidden

# Create whiteout for 'hidden'
mkdir -p upper/wh_test
mknod upper/wh_test/hidden c 0 0 2>/dev/null || touch upper/wh_test/.wh.hidden

fuse-overlayfs -o lowerdir=lower,upperdir=upper,workdir=workdir merged

test -f merged/wh_test/visible
test ! -e merged/wh_test/hidden

# Whiteout files should not appear in listing
ENTRIES=$(ls merged/wh_test | wc -l)
test "$ENTRIES" -eq 1

umount merged
rm -rf lower upper workdir merged

# ========================================
# Test 13: Empty directory removal
# ========================================
echo "=== Test 13: Empty directory removal ==="
mkdir -p lower upper workdir merged

fuse-overlayfs -o lowerdir=lower,upperdir=upper,workdir=workdir merged

mkdir merged/emptydir
test -d merged/emptydir
rmdir merged/emptydir
test ! -e merged/emptydir

umount merged
rm -rf lower upper workdir merged

# ========================================
# Test 14: Cannot rmdir non-empty directory
# ========================================
echo "=== Test 14: Cannot rmdir non-empty ==="
mkdir -p lower upper workdir merged

fuse-overlayfs -o lowerdir=lower,upperdir=upper,workdir=workdir merged

mkdir merged/notempty
echo "file" > merged/notempty/file

set +e
rmdir merged/notempty 2>/dev/null
test $? -ne 0
set -e

# Directory should still exist
test -d merged/notempty

umount merged
rm -rf lower upper workdir merged

# ========================================
# Test 15: Multiple lower layers - priority order
# ========================================
echo "=== Test 15: Multi-layer priority ==="
mkdir -p lower1 lower2 lower3 upper workdir merged

echo "from_l1" > lower1/samefile
echo "from_l2" > lower2/samefile
echo "from_l3" > lower3/samefile

# lowerdir order: lower3 is top, lower1 is bottom
fuse-overlayfs -o lowerdir=lower3:lower2:lower1,upperdir=upper,workdir=workdir merged

# lower3 (first/topmost) should win
grep from_l3 merged/samefile

umount merged
rm -rf lower1 lower2 lower3 upper workdir merged

# ========================================
# Test 16: Recreated directory keeps hiding lower entries at every level
# https://github.com/containers/fuse-overlayfs/issues/478
# ========================================
echo "=== Test 16: Recreated directory hides lower entries ==="
mkdir -p lower/d/sub upper workdir merged
echo "lower" > lower/d/top
echo "lower" > lower/d/sub/file

fuse-overlayfs -o lowerdir=lower,upperdir=upper,workdir=workdir merged

rm -r merged/d
mkdir -p merged/d/sub

# Removing an entry drops the cached child list, forcing a lazy re-lookup:
# the opaque boundary must still hide the lower entries.
touch merged/d/x && rm merged/d/x
test ! -e merged/d/top
test "$(ls -A merged/d)" = "sub"

touch merged/d/sub/x && rm merged/d/sub/x
test ! -e merged/d/sub/file
test -z "$(ls -A merged/d/sub)"
rmdir merged/d/sub

umount merged

# The boundary must survive a remount, i.e. be recorded in the upper layer.
fuse-overlayfs -o lowerdir=lower,upperdir=upper,workdir=workdir merged

test ! -e merged/d/top
test ! -e merged/d/sub
test -z "$(ls -A merged/d)"

umount merged
rm -rf lower upper workdir merged

echo "All directory operation tests passed!"
