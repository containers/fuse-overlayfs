fuse-overlayfs
===========

An implementation of overlay+shiftfs in FUSE for rootless containers.

Usage:
=======================================================

```
$ fuse-overlayfs -o lowerdir=lowerdir/a:lowerdir/b,upperdir=up,workdir=workdir merged
```

Specify a different UID/GID mapping:

```
$ fuse-overlayfs -o uidmapping=0:10:100:100:10000:2000,gidmapping=0:10:100:100:10000:2000,lowerdir=lowerdir/a:lowerdir/b,upperdir=up,workdir=workdir merged
```

Requirements:
=======================================================

Building requires Rust 1.85 or newer and Cargo. On Linux, this implementation
uses the pure-Rust FUSE backend, so `libfuse` development packages are not
required.

Running requires Linux FUSE kernel support and access to `/dev/fuse`. Unprivileged
mounts also require the system's FUSE mount setup (typically `fusermount3`) or
appropriate privileges.

When using `fuse-overlayfs` **from a user namespace** (for example, with rootless
`podman`), Linux kernel >= v4.18.0 is required.


Building:
=======================================================

fuse-overlayfs is written in Rust. To build:

```
cargo build --release
```

The resulting binary is at `target/release/fuse-overlayfs`.

To install:

```
make install
```

Pre-built static binaries for multiple architectures (x86_64, aarch64,
armv7l, s390x, ppc64le, riscv64) are available from the
[GitHub Releases](https://github.com/containers/fuse-overlayfs/releases) page.
