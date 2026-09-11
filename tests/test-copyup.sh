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
# Test 11: Copy-up directory preserves restrictive permissions
# Regression test for issue #470: directory permissions permanently
# widened to 0755 during copy-up in create_node_directory()
# ========================================
echo "=== Test 11: Copy-up directory preserves restrictive permissions ==="
mkdir -p lower upper workdir merged

mkdir -p lower/privatedir
echo "secret" > lower/privatedir/secret.txt
chmod 0700 lower/privatedir

mkdir -p lower/restricteddir
echo "data" > lower/restricteddir/data.txt
chmod 0750 lower/restricteddir

mkdir -p lower/minimaldir
chmod 0100 lower/minimaldir

fuse-overlayfs -o lowerdir=lower,upperdir=upper,workdir=workdir merged

# Trigger copy-up of privatedir by creating a file inside it
echo "new" > merged/privatedir/newfile

# Verify permissions in upper layer are preserved (not widened to 0755)
upper_mode=$(stat -c '%a' upper/privatedir)
test "$upper_mode" = "700" || { echo "FAIL: expected 700, got $upper_mode"; exit 1; }

# Trigger copy-up of restricteddir
echo "new" > merged/restricteddir/newfile
upper_mode=$(stat -c '%a' upper/restricteddir)
test "$upper_mode" = "750" || { echo "FAIL: expected 750, got $upper_mode"; exit 1; }

# Verify through the merged view as well
merged_mode=$(stat -c '%a' merged/privatedir)
test "$merged_mode" = "700" || { echo "FAIL: expected merged 700, got $merged_mode"; exit 1; }

merged_mode=$(stat -c '%a' merged/restricteddir)
test "$merged_mode" = "750" || { echo "FAIL: expected merged 750, got $merged_mode"; exit 1; }

umount merged
rm -rf lower upper workdir merged

# ========================================
# Test 12: Copy-up while the file is open for reading
# ========================================
echo "=== Test 12: Copy-up with a reader holding the file open ==="
mkdir -p lower upper workdir merged

printf "AAAA" > lower/f
printf "AAAA" > lower/g

fuse-overlayfs -o lowerdir=lower,upperdir=upper,workdir=workdir merged

# The reader is opened before the write, so the copy-up happens while it is
# live.  The write must land in the upper layer, never in the read-only lower
# one, and must be visible through the merged view.
exec 9< merged/f
printf "BBBB" >> merged/f
exec 9<&-

test "$(cat lower/f)" = "AAAA" || { echo "FAIL: lower layer was modified"; exit 1; }
test "$(cat upper/f)" = "AAAABBBB" || { echo "FAIL: upper is $(cat upper/f)"; exit 1; }
test "$(cat merged/f)" = "AAAABBBB" || { echo "FAIL: merged is $(cat merged/f)"; exit 1; }

# Same with the reader outliving the write.
exec 9< merged/g
printf "BBBB" >> merged/g
test "$(cat merged/g)" = "AAAABBBB" || { echo "FAIL: merged is $(cat merged/g)"; exit 1; }
exec 9<&-
test "$(cat lower/g)" = "AAAA" || { echo "FAIL: lower layer was modified"; exit 1; }
test "$(cat upper/g)" = "AAAABBBB" || { echo "FAIL: upper is $(cat upper/g)"; exit 1; }

umount merged
rm -rf lower upper workdir merged

echo "All copy-up tests passed!"
