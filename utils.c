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

#define _GNU_SOURCE
#define _FILE_OFFSET_BITS 64

#include <config.h>
#include "utils.h"
#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <sys/sysmacros.h>
#include <sys/syscall.h>
#include <stdint.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/xattr.h>

#ifndef TEMP_FAILURE_RETRY
#define TEMP_FAILURE_RETRY(expression) \
  (__extension__                                                              \
    ({ long int __result;                                                     \
       do __result = (long int) (expression);                                 \
       while (__result == -1L && errno == EINTR);                             \
       __result; }))
#endif

#ifndef RESOLVE_IN_ROOT
# define RESOLVE_IN_ROOT		0x10
#endif
#ifndef __NR_openat2
# define __NR_openat2 437
#endif

/* uClibc and uClibc-ng don't provide O_TMPFILE */
#ifndef O_TMPFILE
# define O_TMPFILE (020000000 | O_DIRECTORY)
#endif

/* List of all valid flags for the open/openat flags argument: */
#define VALID_OPEN_FLAGS \
  (O_RDONLY | O_WRONLY | O_RDWR | O_CREAT | O_EXCL | O_NOCTTY | O_TRUNC | \
   O_APPEND | O_NDELAY | O_NONBLOCK | O_NDELAY | O_SYNC | O_DSYNC |     \
   FASYNC | O_DIRECT | O_LARGEFILE | O_DIRECTORY | O_NOFOLLOW |         \
   O_NOATIME | O_CLOEXEC | O_PATH | O_TMPFILE)

static int
syscall_openat2 (int dirfd, const char *path, uint64_t flags, uint64_t mode, uint64_t resolve)
{
  struct openat2_open_how
    {
      uint64_t flags;
      uint64_t mode;
      uint64_t resolve;
    }
  how =
    {
     .flags = flags & VALID_OPEN_FLAGS,
     .mode = (flags & O_CREAT) ? (mode & 07777) : 0,
     .resolve = resolve,
    };

  return (int) syscall (__NR_openat2, dirfd, path, &how, sizeof (how), 0);
}

int
safe_openat (int dirfd, const char *pathname, int flags, mode_t mode)
{
  static bool openat2_supported = true;

  if (openat2_supported)
    {
      int ret;

      ret = syscall_openat2 (dirfd, pathname, flags, mode, RESOLVE_IN_ROOT);
      if (ret < 0)
        {
          if (errno == ENOSYS)
            openat2_supported = false;
          if (errno == ENOSYS || errno == EINVAL)
            goto fallback;
        }
      return ret;
    }
 fallback:
  return openat (dirfd, pathname, flags, mode);
}

int
file_exists_at (int dirfd, const char *pathname)
{
  int ret = faccessat (dirfd, pathname, F_OK, AT_SYMLINK_NOFOLLOW|AT_EACCESS);
  if (ret < 0 && errno == EINVAL) {
    struct stat buf;
    return fstatat (dirfd, pathname, &buf, AT_SYMLINK_NOFOLLOW);
  }
  return ret;
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
    TEMP_FAILURE_RETRY (close (*pp));
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

  *fd = l->ds->openat (l, path, O_NONBLOCK|O_NOFOLLOW|flags, 0);
  if (*fd < 0 && (errno == ELOOP || errno == EISDIR || errno == ENXIO))
    {
      strconcat3 (out, PATH_MAX, l->path, "/", path);
      return 0;
    }

  return *fd;
}

int
override_mode (struct ovl_layer *l, int fd, const char *abs_path, const char *path, struct stat *st)
{
  int ret;
  uid_t uid;
  gid_t gid;
  mode_t mode;
  char buf[64];
  cleanup_close int cleanup_fd = -1;
  const char *xattr_name;

  switch (st->st_mode & S_IFMT)
    {
    case S_IFDIR:
    case S_IFREG:
      break;

    default:
      return 0;
    }

  switch (l->stat_override_mode)
    {
    case STAT_OVERRIDE_NONE:
      return 0;

    case STAT_OVERRIDE_USER:
      xattr_name = XATTR_OVERRIDE_STAT;
      break;

    case STAT_OVERRIDE_PRIVILEGED:
      xattr_name = XATTR_PRIVILEGED_OVERRIDE_STAT;
      break;

    case STAT_OVERRIDE_CONTAINERS:
      xattr_name = XATTR_OVERRIDE_CONTAINERS_STAT;
      break;

    default:
      errno = EINVAL;
      return -1;
    }

  if (fd >= 0)
    {
      ret = fgetxattr (fd, xattr_name, buf, sizeof (buf) - 1);
      if (ret < 0)
        return ret;
    }
  else if (abs_path)
    {
      ret = lgetxattr (abs_path, xattr_name, buf, sizeof (buf) - 1);
      if (ret < 0)
        return ret;
    }
  else
    {
      char full_path[PATH_MAX];

      full_path[0] = '\0';
      ret = open_fd_or_get_path (l, path, full_path, &cleanup_fd, O_RDONLY);
      if (ret < 0)
        return ret;
      fd = cleanup_fd;

      if (fd >= 0)
        ret = fgetxattr (fd, xattr_name, buf, sizeof (buf) - 1);
      else
        {
          ret = lgetxattr (full_path, xattr_name, buf, sizeof (buf) - 1);
          if (ret < 0 && errno == ENODATA)
            return 0;
        }

      if (ret < 0)
        return ret;
    }

  buf[ret] = '\0';

  ret = sscanf (buf, "%d:%d:%o", &uid, &gid, &mode);
  if (ret != 3)
    {
      errno = EINVAL;
      return -1;
    }

  st->st_uid = uid;
  st->st_gid = gid;
  st->st_mode = (st->st_mode & S_IFMT) | mode;

  return 0;
}
