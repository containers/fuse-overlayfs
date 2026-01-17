fuse-overlayfs 1 "User Commands"
================================

# NAME

fuse-overlayfs - combine directory trees in userspace

# SYNOPSIS

mounting
:   **fuse-overlayfs** [**-f**] [**-d**] [**-o** _OPTION_[,_OPTION2_, ...]] _mountpoint_

unmounting
:   **fusermount -u** _mountpoint_

# DESCRIPTION

**fuse-overlayfs** combines (overlays) two or more directory trees into one. It
can be used by unprivileged users in an user namespace. It is built with FUSE
and works with Linux 4.18 or newer.

# OPTIONS

**-f**
:   Run in foreground.

**-d**, **--debug**, **-o debug**
:   Enable debugging mode, can be very noisy.

**-o lowerdir=**_low1_[_:low2..._]
:   A list of directories separated by `:`.  Their content is merged.

**-o upperdir**=_upperdir_
:   A directory merged on top of all the lowerdirs where all the changes done
to the file system will be written.

**-o workdir**=_workdir_
:   A directory used internally by fuse-overlays, must be on the same file
system as the upperdir.

**-o uidmapping=**_UID:MAPPED-UID:LEN_[_,UID2:MAPPED-UID2:LEN2_]

**-o gidmapping=**_GID:MAPPED-GID:LEN_[_,GID2:MAPPED-GID2:LEN2_]
:   Specify the dynamic UID/GID mapping used by fuse-overlayfs when
reading/writing files to the system.

**-o squash_to_root**
:   Make every file and directory owned by the root user (0:0).

**-o squash_to_uid**=_uid_

**-o squash_to_gid**=_gid_
:   Make every file and directory owned by the specified uid or gid. It has
higher precedence over **squash_to_root**.

**-o static_nlink**
:   Set `st_nlink` to the static value 1 for all directories. This can be
useful for higher latency file systems such as NFS, where counting the number
of hard links for a directory with many files can be a slow operation. With
this option enabled, the number of hard links reported when running stat for
any directory is 1.

**-o noacl**
:   Disable ACL support in the FUSE file system.

**-o xino=off|auto|on**
:   Controls how `st_ino` values are generated for files returned by
fuse-overlayfs. When all lower and upper layers reside on the same underlying
device, fuse-overlayfs exposes the real inode number from the underlying
filesystem. When layers span multiple devices, an opaque inode number is
generated; by default this value is not stable across mounts.

The `xino` option modifies this behavior:

**xino=off**
:   Disables extended inode generation. This matches the default behavior: when
all layers are on the same device, the underlying inode number is used;
otherwise an opaque, non‑stable inode number is returned.

**xino=auto**
:   Attempts to generate stable inode numbers across mounts by hashing the file
handle returned by `name_to_handle_at(2)`. This mode is used only if all layers
support `name_to_handle_at(2)`; if any layer does not, behavior falls back to
`xino=off`. If all layers are on the same device, the underlying inode number
is still used, regardless of this setting.

**xino=on**
:   Requires that all layers support `name_to_handle_at(2)`. If they do, inode
numbers are derived from a hash of the file handle and remain stable across
mounts. If any layer does not support `name_to_handle_at(2)`, the mount fails.
As with other modes, when all layers are on the same device, the underlying
inode number always takes precedence.

**-o ino32_t**
:   Forces all returned `st_ino` values to be truncated to 32 bits. This option
exists solely for compatibility with older 32‑bit userspaces that cannot
correctly handle 64‑bit inode numbers. It has no functional benefit on modern
systems and should not be used unless required for legacy compatibility.

**-h**, **--help**
:   Show additional options, provided by FUSE.

**-V**, **--version**
:   Show versions of fuse-overlayfs and FUSE.

# DYNAMIC UID AND GID MAPPING

The fuse-overlayfs dynamic mapping is an alternative and cheaper way to
chown'ing the files on the host to accommodate the user namespace settings.

It is useful to share the same storage among different user namespaces and
counter effect the mapping done by the user namespace itself, and without
requiring to chown the files.

Take, for example, two files with the following user and group IDs:

```
$ stat -c %u:%g lower/a lower/b
0:0
1:1
```

Also take note of the following user namespace configuration:

```
$ cat /proc/self/uid_map
         0       1000          1
         1     110000      65536
```

After mounting with fuse-overlayfs, the ownership would change:

```
$ stat -c %u:%g merged/a merged/b
65534:65534
65534:65534
```

65534 is the overflow ID used when the UID/GID is not known inside the user
namespace. This happens because neither user IDs 0 nor 1 are mapped.

To map them, we'd mount the fuse-overlayfs file system using the following
namespace configuration:

```
-o uidmapping=0:1000:1:1:110000:65536,gidmapping=0:1000:1:1:110000:65536
```

The result would then be the following:

```
$ stat -c %u:%g merged/a merged/b
0:0
1:1
```

Those are the same IDs visible from outside the user namespace.

# SEE ALSO

**fuse**(8), **mount**(8), **user_namespaces**(7)

# AVAILABILITY

The fuse-overlayfs command is available from
**https://github.com/containers/fuse-overlayfs** under GNU GENERAL PUBLIC
LICENSE Version 3 or later.
