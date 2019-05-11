fuse-overlayfs
===========

An implementation of overlay+shiftfs in FUSE for rootless containers.

Limitations:
=======================================================

Read-only mode is not supported, so it is always required to specify
an upperdir and a workingdir.

Usage:
=======================================================

```
$ fuse-overlayfs -o lowerdir=lowerdir/a:lowerdir/b,upperdir=up,workdir=workdir merged
```

Specify a different UID/GID mapping:

```
$ fuse-overlayfs -o uidmapping=0:10:100:100:10000:2000,gidmapping=0:10:100:100:10000:2000,lowerdir=lowerdir/a:lowerdir/b,upperdir=up,workdir=workdir merged
```

Build Requirements:
=======================================================

fuse-overlayfs requires libfuse > v3.2.1

On Fedora: `dnf install fuse3-devel`


Static Build:
=======================================================

`buildah bud -t fuse-overlayfs -f ./Dockerfile.static .`

