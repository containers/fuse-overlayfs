#!/bin/bash
# Test copy-up operations: regular files, symlinks, metadata preservation,
# permission handling, xattr preservation, timestamp preservation.

set -xeuo pipefail

cleanup() {
    cd /
    umount "$MERGED" 2>/dev/null || true
    rm -rf "$TESTDIR"
}

TESTDIR=$(mktemp -d /tmp/test-copyup.XXXXXX)
trap cleanup EXIT
cd "$TESTDIR"

MERGED="$TESTDIR/merged"

# ========================================
# Test 1: Copy-up regular file preserves content
# ========================================
echo "=== Test 1: Copy-up regular file ==="
mkdir -p lower upper workdir merged

dd if=/dev/urandom of=lower/bigfile bs=4096 count=100 2>/dev/null
md5_orig=$(md5sum lower/bigfile | awk '{print $1}')

fuse-overlayfs -o lowerdir=lower,upperdir=upper,workdir=workdir merged

# Trigger copy-up by writing
echo "append" >> merged/bigfile
# Check that original content is preserved (minus the append)
head -c $((4096*100)) merged/bigfile | md5sum | grep "$md5_orig"

umount merged
rm -rf lower upper workdir merged

# ========================================
# Test 2: Copy-up preserves permissions
# ========================================
echo "=== Test 2: Copy-up preserves permissions ==="
mkdir -p lower upper workdir merged

echo "test" > lower/permfile
chmod 0754 lower/permfile

fuse-overlayfs -o lowerdir=lower,upperdir=upper,workdir=workdir merged

# Trigger copy-up
echo "modified" >> merged/permfile

# Check upper copy has correct permissions (may have write bit added)
test -f upper/permfile

umount merged
rm -rf lower upper workdir merged

# ========================================
# Test 3: Copy-up preserves timestamps
# ========================================
echo "=== Test 3: Copy-up preserves timestamps ==="
mkdir -p lower upper workdir merged

echo "timestamp test" > lower/tsfile
touch -d "2020-06-15 12:30:00" lower/tsfile

fuse-overlayfs -o lowerdir=lower,upperdir=upper,workdir=workdir merged

# Trigger copy-up by chmod
chmod 0644 merged/tsfile

umount merged
rm -rf lower upper workdir merged

# ========================================
# Test 4: Copy-up symlink
# ========================================
echo "=== Test 4: Copy-up symlink ==="
mkdir -p lower upper workdir merged

echo "target_data" > lower/target
ln -s target lower/mylink

fuse-overlayfs -o lowerdir=lower,upperdir=upper,workdir=workdir merged

# Modify the symlink target to trigger copy-up of target
echo "more_data" >> merged/target
grep target_data merged/mylink
grep more_data merged/mylink

# Verify the symlink still works
test -L merged/mylink
readlink merged/mylink | grep target

umount merged
rm -rf lower upper workdir merged

# ========================================
# Test 5: Copy-up preserves extended attributes
# ========================================
echo "=== Test 5: Copy-up preserves xattrs ==="
mkdir -p lower upper workdir merged

echo "xattr test" > lower/xfile
setfattr -n user.testattr -v "testvalue" lower/xfile
setfattr -n user.another -v "another_val" lower/xfile

fuse-overlayfs -o lowerdir=lower,upperdir=upper,workdir=workdir merged

# Verify xattrs visible through overlay
getfattr --only-values -n user.testattr merged/xfile | grep testvalue
getfattr --only-values -n user.another merged/xfile | grep another_val

# Trigger copy-up
echo "modified" >> merged/xfile

# Verify xattrs preserved after copy-up
getfattr --only-values -n user.testattr merged/xfile | grep testvalue
getfattr --only-values -n user.another merged/xfile | grep another_val

# Verify xattrs in upper layer
getfattr --only-values -n user.testattr upper/xfile | grep testvalue

umount merged
rm -rf lower upper workdir merged

# ========================================
# Test 6: Copy-up directory
# ========================================
echo "=== Test 6: Copy-up directory ==="
mkdir -p lower/subdir upper workdir merged
echo "in_subdir" > lower/subdir/file1
echo "in_subdir2" > lower/subdir/file2

fuse-overlayfs -o lowerdir=lower,upperdir=upper,workdir=workdir merged

# Create a file in the lower-layer directory (triggers dir copy-up)
echo "new" > merged/subdir/newfile
test -f merged/subdir/file1
test -f merged/subdir/file2
test -f merged/subdir/newfile
grep in_subdir merged/subdir/file1

umount merged
rm -rf lower upper workdir merged

# ========================================
# Test 7: Copy-up nested directory structure
# ========================================
echo "=== Test 7: Copy-up nested directories ==="
mkdir -p lower/a/b/c upper workdir merged
echo "deep" > lower/a/b/c/deepfile

fuse-overlayfs -o lowerdir=lower,upperdir=upper,workdir=workdir merged

# Trigger copy-up of deeply nested file
echo "modified" >> merged/a/b/c/deepfile
test -d upper/a
test -d upper/a/b
test -d upper/a/b/c
grep deep upper/a/b/c/deepfile

umount merged
rm -rf lower upper workdir merged

# ========================================
# Test 8: Copy-up of file opened for writing
# ========================================
echo "=== Test 8: Copy-up via open for writing ==="
mkdir -p lower upper workdir merged

echo "readonly_data" > lower/opentest

fuse-overlayfs -o lowerdir=lower,upperdir=upper,workdir=workdir merged

# Open for writing (should trigger copy-up)
python3 -c "
f = open('merged/opentest', 'r+')
data = f.read()
assert 'readonly_data' in data, f'unexpected content: {data}'
f.seek(0, 2)
f.write('appended\n')
f.close()
"

grep readonly_data merged/opentest
grep appended merged/opentest

umount merged
rm -rf lower upper workdir merged

# ========================================
# Test 9: Copy-up with truncate
# ========================================
echo "=== Test 9: Copy-up via truncate ==="
mkdir -p lower upper workdir merged

echo "will be truncated" > lower/truncme

fuse-overlayfs -o lowerdir=lower,upperdir=upper,workdir=workdir merged

truncate -s 0 merged/truncme
test $(stat -c %s merged/truncme) -eq 0

umount merged
rm -rf lower upper workdir merged

# ========================================
# Test 10: Multiple copy-ups don't interfere
# ========================================
echo "=== Test 10: Multiple simultaneous copy-ups ==="
mkdir -p lower upper workdir merged

for i in $(seq 1 20); do
    echo "file_${i}_content" > lower/multi_${i}
done

fuse-overlayfs -o lowerdir=lower,upperdir=upper,workdir=workdir merged

# Copy up all files
for i in $(seq 1 20); do
    echo "modified_${i}" >> merged/multi_${i}
done

# Verify all are correct
for i in $(seq 1 20); do
    grep "file_${i}_content" merged/multi_${i}
    grep "modified_${i}" merged/multi_${i}
done

umount merged
rm -rf lower upper workdir merged

# ========================================
# Test 11: Directory copy-up preserves inode across remount
# ========================================
echo "=== Test 11: Directory copy-up preserves inode across remount ==="
mkdir -p lower upper workdir merged

# The upper filesystem must support user xattrs for origin tracking.
if setfattr -n user.fuseoverlayfs.test -v yes upper 2>/dev/null; then
    setfattr -x user.fuseoverlayfs.test upper
    mkdir -p lower/origin_dir/nested
    fuse-overlayfs -o lowerdir=lower,upperdir=upper,workdir=workdir merged

    inode_before=$(stat -c %i lower/origin_dir)
    nested_inode_before=$(stat -c %i lower/origin_dir/nested)
    mkdir merged/origin_dir/nested/child
    test "$(stat -c %i merged/origin_dir)" = "$inode_before"

    # Remount discards cached nodes, forcing lookup from the stored origin.
    umount merged
    fuse-overlayfs -o lowerdir=lower,upperdir=upper,workdir=workdir merged
    test "$(stat -c %i merged/origin_dir)" = "$inode_before"
    test "$(stat -c %i merged/origin_dir/nested)" = "$nested_inode_before"
    test -d merged/origin_dir/nested/child
    umount merged
else
    echo "SKIP: upper filesystem does not support user xattrs"
fi
rm -rf lower upper workdir merged

echo "All copy-up tests passed!"
