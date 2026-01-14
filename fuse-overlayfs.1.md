fuse-overlayfs 1 "User Commands"
==================================================

# NAME

fuse-overlayfs - overlayfs FUSE implementation

# SYNOPSIS

mounting
    fuse-overlayfs [-f] [--debug] [-o OPTS] MOUNT_TARGET

unmounting
    fusermount -u mountpoint

# DESCRIPTION

fuse-overlayfs provides an overlayfs FUSE implementation so that it
can be used since Linux 4.18 by unprivileged users in an user
namespace.

# OPTIONS

**--debug**
Enable debugging mode, can be very noisy.

**-o lowerdir=low1[:low2...]**
A list of directories separated by `:`.  Their content is merged.

**-o upperdir=upperdir**
A directory merged on top of all the lowerdirs where all the changes
done to the file system will be written.

**-o workdir=workdir**
A directory used internally by fuse-overlays, must be on the same file
system as the upper dir.

**-o uidmapping=UID:MAPPED-UID:LEN[,UID2:MAPPED-UID2:LEN2]**
**-o gidmapping=GID:MAPPED-GID:LEN[,GID2:MAPPED-GID2:LEN2]**
Specifies the dynamic UID/GID mapping used by fuse-overlayfs when
reading/writing files to the system.

The fuse-overlayfs dynamic mapping is an alternative and cheaper way
to chown'ing the files on the host to accommodate the user namespace
settings.

It is useful to share the same storage among different user namespaces
and counter effect the mapping done by the user namespace itself, and
without requiring to chown the files.

For example, given on the host two files like:

$ stat -c %u:%g lower/a lower/b
0:0
1:1

When we run in a user namespace with the following configuration:
$ cat /proc/self/uid_map
         0       1000          1
         1     110000      65536

We would see:

$ stat -c %u:%g merged/a merged/b
65534:65534
65534:65534

65534 is the overflow id used when the UID/GID is not known inside the
user namespace.  This happens because both users 0:0 and 1:1 are not
mapped.

In the above example, if we mount the fuse-overlayfs file system using:
`-ouidmapping=0:1000:1:1:110000:65536,gidmapping=0:1000:1:1:110000:65536`,
which is the namespace configuration specified on a single line, we'd
see from the same user namespace:

$ stat -c %u:%g merged/a merged/b
0:0
1:1

Those are the same IDs visible from outside the user namespace.

**-o squash_to_root**
Every file and directory is owned by the root user (0:0).

**-o squash_to_uid=uid**
**-o squash_to_gid=gid**
Every file and directory is owned by the specified uid or gid.

It has higher precedence over **squash_to_root**.

**-o static_nlink**
Set st_nlink to the static value 1 for all directories.

This can be useful for higher latency file systems such as NFS, where
counting the number of hard links for a directory with many files can
be a slow operation. With this option enabled, the number of hard
links reported when running stat for any directory is 1.

**-o noacl**
Disable ACL support in the FUSE file system.

**-o xino=off|auto|on**
Controls how `st_ino` values are generated for files returned by fuse-overlayfs.

When all lower and upper layers reside on the same underlying device,
fuse-overlayfs exposes the real inode number from the underlying filesystem.
When layers span multiple devices, an opaque inode number is generated; by
default this value is not stable across mounts.

The `xino` option modifies this behavior:

**xino=off**
Disables extended inode generation. This matches the default behavior:
when all layers are on the same device, the underlying inode number is used;
otherwise an opaque, non‑stable inode number is returned.

**xino=auto**
Attempts to generate stable inode numbers across mounts by hashing the file
handle returned by `name_to_handle_at(2)`.
This mode is used only if all layers support `name_to_handle_at(2)`; if any
layer does not, behavior falls back to `xino=off`.
If all layers are on the same device, the underlying inode number is still
used, regardless of this setting.

**xino=on**
Requires that all layers support `name_to_handle_at(2)`. If they do, inode
numbers are derived from a hash of the file handle and remain stable across
mounts.
If any layer does not support `name_to_handle_at(2)`, the mount fails.
As with other modes, when all layers are on the same device, the underlying
inode number always takes precedence.

**-o ino32_t**
Forces all returned `st_ino` values to be truncated to 32 bits.

This option exists solely for compatibility with older 32‑bit userspaces that
cannot correctly handle 64‑bit inode numbers. It has no functional benefit on
modern systems and should not be used unless required for legacy compatibility.

# SEE ALSO

**fuse**(8), **mount**(8), **user_namespaces**(7)

# AVAILABILITY

The fuse-overlayfs command is available from
**https://github.com/containers/fuse-overlayfs** under GNU GENERAL PUBLIC LICENSE Version 3 or later.
