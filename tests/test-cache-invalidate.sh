#!/bin/bash
# Test: ioctl cache invalidation for directory children.

set -xeuo pipefail

# Build ioctl helper (resolve paths BEFORE cd $TESTDIR)
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
IOCTL_C="$SCRIPT_DIR/ioctl-invalidate.c"
IOCTL_BIN="$SCRIPT_DIR/ioctl-invalidate"
if [ ! -f "$IOCTL_BIN" ]; then
    gcc -o "$IOCTL_BIN" "$IOCTL_C"
fi

cleanup() {
    cd /
    umount "$MERGED" 2>/dev/null || true
    rm -rf "$TESTDIR"
}

TESTDIR=$(mktemp -d /tmp/test-cache-invalidate.XXXXXX)
trap cleanup EXIT
cd "$TESTDIR"

MERGED="$TESTDIR/merged"

# ========================================
# Test 1: .wh.* whiteout prepared BEFORE mount
# ========================================
echo "=== Test 1: .wh.* whiteout before mount ==="
mkdir -p lower upper workdir merged

echo "lower file" > lower/myfile.txt
touch upper/.wh.myfile.txt

fuse-overlayfs -o lowerdir=lower,upperdir=upper,workdir=workdir merged

# Whiteout should work at mount time
test ! -e merged/myfile.txt

umount merged
rm -rf lower upper workdir merged

# ========================================
# Test 2: Remove .wh.* after mount + ioctl → file reappears
# ========================================
echo "=== Test 2: Remove .wh.* then ioctl ==="
mkdir -p lower upper workdir merged

echo "lower file" > lower/myfile.txt
touch upper/.wh.myfile.txt

fuse-overlayfs -o lowerdir=lower,upperdir=upper,workdir=workdir merged

# Whiteout effective at mount time
test ! -e merged/myfile.txt

# Load cache by listing the directory
ls merged > /dev/null

# Remove whiteout externally
rm -f upper/.wh.myfile.txt

# Cache loaded — file should still NOT be visible
test ! -e merged/myfile.txt

# Invalidate
$IOCTL_BIN merged

# ks_cache: use ls to verify (avoids stale kernel dentry cache from earlier stat)
ls merged/ > /tmp/cache-test-out.txt
grep myfile.txt /tmp/cache-test-out.txt
grep "lower file" merged/myfile.txt

umount merged
rm -rf lower upper workdir merged

# ========================================
# Test 3: Add .wh.* after mount + ioctl → file disappears
# ========================================
echo "=== Test 3: Add .wh.* then ioctl ==="
mkdir -p lower upper workdir merged

echo "lower file" > lower/myfile.txt

fuse-overlayfs -o lowerdir=lower,upperdir=upper,workdir=workdir merged

# File visible after mount
test -e merged/myfile.txt

# Load cache by listing the directory (avoids kernel dentry cache on myfile.txt)
ls merged > /dev/null

# Verify file still visible (cache loaded)
ls merged/ > /tmp/cache-test-out.txt
grep myfile.txt /tmp/cache-test-out.txt

# Create whiteout externally
touch upper/.wh.myfile.txt

# Cache loaded — file should still be visible
ls merged/ > /tmp/cache-test-out.txt
grep myfile.txt /tmp/cache-test-out.txt

# Invalidate
$IOCTL_BIN merged

# File should now be hidden from directory listing
ls merged/ > /tmp/cache-test-out.txt
if grep -q myfile.txt /tmp/cache-test-out.txt; then
    echo "ERROR: myfile.txt should be hidden after ioctl"
    exit 1
fi

umount merged
rm -rf lower upper workdir merged

# ========================================
# Test 4: Add file to lower after mount + ioctl → file appears
# ========================================
echo "=== Test 4: Add file to lower then ioctl ==="
mkdir -p lower upper workdir merged

echo "initial" > lower/initial.txt

fuse-overlayfs -o lowerdir=lower,upperdir=upper,workdir=workdir merged

# Load cache
ls merged > /dev/null

# Add file to lower externally
echo "new lower file" > lower/newfile.txt

# Cache loaded — new file NOT visible
test ! -e merged/newfile.txt

# Invalidate
$IOCTL_BIN merged

# File should now be visible
test -e merged/newfile.txt
grep "new lower file" merged/newfile.txt

umount merged
rm -rf lower upper workdir merged

# ========================================
# Test 5: ioctl on non-directory → ENOTDIR
# ========================================
echo "=== Test 5: ioctl on non-directory ==="
mkdir -p lower upper workdir merged

touch upper/file.txt

fuse-overlayfs -o lowerdir=lower,upperdir=upper,workdir=workdir merged

set +e
$IOCTL_BIN merged/file.txt
rc=$?
set -e
test "$rc" -ne 0

umount merged
rm -rf lower upper workdir merged

# ========================================
# Test 6: Remove file from lower externally + ioctl → file disappears
# ========================================
echo "=== Test 6: Remove file from lower then ioctl ==="
mkdir -p lower upper workdir merged

echo "remove me" > lower/rmfile.txt

fuse-overlayfs -o lowerdir=lower,upperdir=upper,workdir=workdir merged

# File visible
test -e merged/rmfile.txt

# Load cache by listing (avoids kernel dentry on rmfile.txt itself)
ls merged > /dev/null

# Verify file in listing
ls merged/ > /tmp/cache-test-out.txt
grep rmfile.txt /tmp/cache-test-out.txt

# Remove file from lower externally
rm -f lower/rmfile.txt

# Cache loaded — file should still be in listing
ls merged/ > /tmp/cache-test-out.txt
grep rmfile.txt /tmp/cache-test-out.txt

# Invalidate
$IOCTL_BIN merged

# File should now be gone from listing
ls merged/ > /tmp/cache-test-out.txt
if grep -q rmfile.txt /tmp/cache-test-out.txt; then
    echo "ERROR: rmfile.txt should be gone after ioctl"
    exit 1
fi

umount merged
rm -rf lower upper workdir merged

# ========================================
# Test 7: Multiple lower layers + whiteout in upper
# ========================================
echo "=== Test 7: Multiple lower layers ==="
mkdir -p lower1 lower2 upper workdir merged

echo "from lower1" > lower1/file_a.txt
echo "from lower2" > lower2/file_b.txt

fuse-overlayfs -o lowerdir=lower1:lower2,upperdir=upper,workdir=workdir merged

# Load cache
ls merged > /dev/null

# Verify both files in listing
ls merged/ > /tmp/cache-test-out.txt
grep file_a.txt /tmp/cache-test-out.txt
grep file_b.txt /tmp/cache-test-out.txt

# Create whiteout in upper for lower1's file
touch upper/.wh.file_a.txt

# Cache loaded — both files still in listing
ls merged/ > /tmp/cache-test-out.txt
grep file_a.txt /tmp/cache-test-out.txt
grep file_b.txt /tmp/cache-test-out.txt

# Invalidate
$IOCTL_BIN merged

# file_a should be gone
ls merged/ > /tmp/cache-test-out.txt
if grep -q file_a.txt /tmp/cache-test-out.txt; then
    echo "ERROR: file_a.txt should be hidden after ioctl"
    exit 1
fi
# file_b should still be there
grep file_b.txt /tmp/cache-test-out.txt
grep "from lower2" merged/file_b.txt

umount merged
rm -rf lower1 lower2 upper workdir merged

echo "All cache invalidation tests passed!"
