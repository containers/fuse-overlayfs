/* fuse-overlayfs: Overlay Filesystem in Userspace

   Copyright (C) 2019 Red Hat Inc.

   This program is free software: you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/
#ifndef UTILS_H
# define UTILS_H

#ifndef _GNU_SOURCE
# define _GNU_SOURCE
#endif

# include <config.h>

# include <unistd.h>
# include <stdio.h>
# include <sys/types.h>
# include <dirent.h>
# include <stdlib.h>
# include <sys/types.h>
# include <fcntl.h>
# include "fuse-overlayfs.h"

# define XATTR_OVERRIDE_STAT "user.fuseoverlayfs.override_stat"
# define XATTR_PRIVILEGED_OVERRIDE_STAT "security.fuseoverlayfs.override_stat"
# define XATTR_OVERRIDE_CONTAINERS_STAT "user.containers.override_stat"

void cleanup_freep (void *p);
void cleanup_filep (FILE **f);
void cleanup_closep (void *p);
void cleanup_dirp (DIR **p);

int file_exists_at (int dirfd, const char *pathname);

int strconcat3 (char *dest, size_t size, const char *s1, const char *s2, const char *s3);
int open_fd_or_get_path (struct ovl_layer *l, const char *path, char *out, int *fd, int flags);

# define cleanup_file __attribute__((cleanup (cleanup_filep)))
# define cleanup_free __attribute__((cleanup (cleanup_freep)))
# define cleanup_close __attribute__((cleanup (cleanup_closep)))
# define cleanup_dir __attribute__((cleanup (cleanup_dirp)))

# define LIKELY(x) __builtin_expect((x),1)
# define UNLIKELY(x) __builtin_expect((x),0)

# ifdef HAVE_STATX
void statx_to_stat (struct statx *stx, struct stat *st);
# endif

int safe_openat (int dirfd, const char *pathname, int flags, mode_t mode);

int override_mode (struct ovl_layer *l, int fd, const char *abs_path, const char *path, struct stat *st);

#endif
