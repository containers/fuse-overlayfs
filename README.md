containerfs
===========

An implementation of overlay+shiftfs in FUSE for rootless containers.

Known issues:
=======================================================

A known issue is that containerfs reports a different inode even
if the inode on disk is the same, as with hard links.

The current implementation keeps in memory the entire tree of the
lower directories.  A side effect is that modifications to the
lower layers is never propagated to the merged directory.  Overlayfs
doesn't allow changes to the layers as well, altough since there is
not such caching done, changes are usually propagated.

Read-only mode is not supported, so it is always required to specify
an upperdir and a workingdir.

Usage:
=======================================================

```
$ containerfs -o lowerdir=lowerdir/a:lowerdir/b,upperdir=up,workdir=workdir merged
```

Specify a different UID/GID mapping:

```
$ containerfs -o uid=0:10:100:100:10000:2000,gid=0:10:100:100:10000:2000,lowerdir=lowerdir/a:lowerdir/b,upperdir=up,workdir=workdir merged
```
