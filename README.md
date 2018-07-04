containerfs
===========

An implementation of overlay+shiftfs in FUSE for rootless containers.

Limitations:
=======================================================

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
