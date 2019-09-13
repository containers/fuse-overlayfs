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

Requirements:
=======================================================

If your are not using the static build as explained in the next chapter, your system needs `libfuse` > v3.2.1.

* On Fedora: `dnf install fuse3-devel`
* On Ubuntu > v19.04: `apt install libfuse3-dev`

Also, please note that, when using `fuse-overlayfs` **from a user namespace** 
(for example, when using rootless `podman`) a Linux Kernel > v4.18.0 is required.


Static Build:
=======================================================

This project provides a convenient way to automatically perform a static build using a container.
The result is a self-contained binary without dependencies, that can be copied across hosts.

1. Install `buildah` as explained [here](https://github.com/containers/buildah/blob/master/install.md);

2. Both the build and deploy host require the special device `/dev/fuse`; there are a few ways to obtain it:

  * install `fuse2` or `fuse3` using the package manager of your choice (dnf, apt, pacman, etc): 
the install script will usually create the device automatically; or
  * manually create the device with the command `mknod /dev/fuse -m 0666 c 10 229` 
(see [this code](https://github.com/libfuse/libfuse/blob/f0e08cc700d629da2d46def8b620b0ed858cc0d9/util/install_helper.sh#L35))

3. Clone this repository, and switch to the top-level folder containing the file `Dockerfile.static`;

4. Launch the build with the command (note the single dot `.` at the end): 
```
buildah bud --device /dev/fuse -t fuse-overlayfs -f ./Dockerfile.static .
```

5. Copy the resulting binary to your host:

  * if you have `podman` installed:
```
podman run --rm --entrypoint="[]" fuse-overlayfs cat /usr/bin/fuse-overlayfs | sudo tee /usr/bin/fuse-overlayfs > /dev/null
```
  * or, if you only have `buildah` installed:
```
container="$(buildah from fuse-overlayfs)"
buildah run "$container" cat /usr/bin/fuse-overlayfs | sudo tee /usr/bin/fuse-overlayfs > /dev/null
buildah rm "$container"
```

