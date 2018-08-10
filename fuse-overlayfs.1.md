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

**-o lowerdir=low1[:low2...]**
A list of directories separated by `:`.  Their content is merged.

**-o upperdir=upperdir**
A directory merged on top of all the lowerdirs where all the changes
done to the file system will be written.

**-o workdir=workdir**
A directory used internally by fuse-overlays, must be on the same file
system as the upper dir.

# SEE ALSO

**fuse**(8), **mount**(8)

# AVAILABILITY

The slirp4netns command is available from
**https://github.com/containers/fuse-overlayfs** under GNU GENERAL PUBLIC LICENSE Version 3 or later.
