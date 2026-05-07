#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>

/* _IO('f', 0x66) — same value as FUSE_OVFS_IOC_REFRESH_DIR in overlay.rs */
#define FUSE_OVFS_IOC_REFRESH_DIR _IO('f', 0x66)

int main(int argc, char *argv[])
{
	if (argc != 2) {
		fprintf(stderr, "Usage: %s <directory>\n", argv[0]);
		return 1;
	}

	int fd = open(argv[1], O_RDONLY | O_DIRECTORY);
	if (fd < 0) {
		perror("open");
		return 1;
	}

	int ret = ioctl(fd, FUSE_OVFS_IOC_REFRESH_DIR);
	if (ret < 0) {
		fprintf(stderr, "ioctl failed: %s\n", strerror(errno));
		close(fd);
		return 1;
	}

	close(fd);
	return 0;
}
