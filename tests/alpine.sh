#!/bin/sh

cd "$(dirname "$0")"

set -ex

docker build -t fuse-overlayfs:alpine -f ../Containerfile.alpine ..

docker run --privileged --rm --entrypoint /unlink.sh -w /tmp \
	-e EXPECT_UMOUNT_STATUS=1 \
	-v "$(pwd)/unlink.sh:/unlink.sh" fuse-overlayfs:alpine
