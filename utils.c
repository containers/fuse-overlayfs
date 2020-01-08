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

#include <config.h>
#include "utils.h"
#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <sys/sysmacros.h>

int
file_exists_at (int dirfd, const char *pathname)
{
  return faccessat (dirfd, pathname, F_OK, AT_SYMLINK_NOFOLLOW|AT_EACCESS);
}

#ifdef HAVE_STATX
void
copy_statx_to_stat_time (struct statx_timestamp *stx, struct timespec *st)
{
  st->tv_sec = stx->tv_sec;
  st->tv_nsec = stx->tv_nsec;
}

void
statx_to_stat (struct statx *stx, struct stat *st)
{
  st->st_dev = makedev (stx->stx_dev_major, stx->stx_dev_minor);
  st->st_ino = stx->stx_ino;
  st->st_mode = stx->stx_mode;
  st->st_nlink = stx->stx_nlink;
  st->st_uid = stx->stx_uid;
  st->st_gid = stx->stx_gid;
  st->st_rdev = makedev (stx->stx_rdev_major, stx->stx_rdev_minor);
  st->st_size = stx->stx_size;
  st->st_blksize = stx->stx_blksize;
  st->st_blocks = stx->stx_blocks;
  copy_statx_to_stat_time (&stx->stx_atime, &st->st_atim);
  copy_statx_to_stat_time (&stx->stx_ctime, &st->st_ctim);
  copy_statx_to_stat_time (&stx->stx_mtime, &st->st_mtim);
}
#endif

int
strconcat3 (char *dest, size_t size, const char *s1, const char *s2, const char *s3)
{
  size_t t;
  char *current = dest;

  size--;

  if (s1)
    {
      t = strlen (s1);
      if (t > size)
        t = size;

      memcpy (current, s1, t);
      current += t;

      size -= t;
    }
  if (s2)
    {
      t = strlen (s2);
      if (t > size)
        t = size;

      memcpy (current, s2, t);
      current += t;

      size -= t;
    }
  if (s3)
    {
      t = strlen (s3);
      if (t > size)
        t = size;

      memcpy (current, s3, t);
      current += t;
    }
  *current = '\0';

  return current - dest;
}

void
cleanup_freep (void *p)
{
  void **pp = (void **) p;
  free (*pp);
}

void
cleanup_filep (FILE **f)
{
  FILE *file = *f;
  if (file)
    (void) fclose (file);
}

void
cleanup_closep (void *p)
{
  int *pp = p;
  if (*pp >= 0)
    close (*pp);
}

void
cleanup_dirp (DIR **p)
{
  DIR *dir = *p;
  if (dir)
    closedir (dir);
}

int
open_fd_or_get_path (struct ovl_layer *l, const char *path, char *out, int *fd, int flags)
{
  out[0] = '\0';

  *fd = l->ds->openat (l, path, O_NONBLOCK|O_NOFOLLOW|flags, 0755);
  if (*fd < 0 && (errno == ELOOP || errno == EISDIR))
    {
      strconcat3 (out, PATH_MAX, l->path, "/", path);
      return 0;
    }

  return *fd;
}
