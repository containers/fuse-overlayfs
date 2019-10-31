/* fuse-overlayfs: Overlay Filesystem in Userspace

   Copyright (C) 2018 Giuseppe Scrivano <giuseppe@scrivano.org>
   Copyright (C) 2018-2019 Red Hat Inc.
   Copyright (C) 2001-2007  Miklos Szeredi <miklos@szeredi.hu>

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

#include <config.h>

#include "fuse-overlayfs.h"

#include <unistd.h>
#include <fcntl.h>
#include <errno.h>

#include <sys/xattr.h>

#include "utils.h"

static int
direct_file_exists (struct ovl_layer *l, const char *pathname)
{
  return file_exists_at (l->fd, pathname);
}

static int
direct_listxattr (struct ovl_layer *l, const char *path, char *buf, size_t size)
{
  cleanup_close int fd = -1;
  char full_path[PATH_MAX];
  int ret;

  full_path[0] = '\0';
  ret = open_fd_or_get_path (l, path, full_path, &fd, O_RDONLY);
  if (ret < 0)
    return ret;

  if (fd >= 0)
    return flistxattr (fd, buf, size);

  return llistxattr (full_path, buf, size);
}

static int
direct_getxattr (struct ovl_layer *l, const char *path, const char *name, char *buf, size_t size)
{
  cleanup_close int fd = -1;
  char full_path[PATH_MAX];
  int ret;

  full_path[0] = '\0';
  ret = open_fd_or_get_path (l, path, full_path, &fd, O_RDONLY);
  if (ret < 0)
    return ret;

  if (fd >= 0)
    return fgetxattr (fd, name, buf, size);

  return lgetxattr (full_path, name, buf, size);
}

static int
direct_fstat (struct ovl_layer *l, int fd, const char *path, unsigned int mask, struct stat *st)
{
#ifdef HAVE_STATX
  int ret;
  struct statx stx;

  ret = statx (fd, "", AT_STATX_DONT_SYNC|AT_EMPTY_PATH, mask, &stx);

  if (ret < 0 && errno == ENOSYS)
    goto fallback;
  if (ret == 0)
    statx_to_stat (&stx, st);

  return ret;
#endif

 fallback:
  return fstat (fd, st);

}

static int
direct_statat (struct ovl_layer *l, const char *path, struct stat *st, int flags, unsigned int mask)
{
#ifdef HAVE_STATX
  int ret;
  struct statx stx;

  ret = statx (l->fd, path, AT_STATX_DONT_SYNC|flags, mask, &stx);

  if (ret < 0 && errno == ENOSYS)
    goto fallback;
  if (ret == 0)
    statx_to_stat (&stx, st);

  return ret;
#endif
 fallback:
  return fstatat (l->fd, path, st, flags);
}

static struct dirent *
direct_readdir (void *dirp)
{
  return readdir (dirp);
}

static void *
direct_opendir (struct ovl_layer *l, const char *path)
{
  cleanup_close int cleanup_fd = -1;
  DIR *dp = NULL;

  cleanup_fd = TEMP_FAILURE_RETRY (openat (l->fd, path, O_DIRECTORY));
  if (cleanup_fd < 0)
    return NULL;

  dp = fdopendir (cleanup_fd);
  if (dp == NULL)
    return NULL;

  cleanup_fd = -1;

  return dp;
}

static int
direct_closedir (void *dirp)
{
  return closedir (dirp);
}

static int
direct_openat (struct ovl_layer *l, const char *path, int flags, mode_t mode)
{
  return TEMP_FAILURE_RETRY (openat (l->fd, path, flags, mode));
}

static ssize_t
direct_readlinkat (struct ovl_layer *l, const char *path, char *buf, size_t bufsiz)
{
  return TEMP_FAILURE_RETRY (readlinkat (l->fd, path, buf, bufsiz));
}

static int
direct_load_data_source (struct ovl_layer *l, const char *opaque, const char *path, int n_layer)
{
  l->path = realpath (path, NULL);
  if (l->path == NULL)
    {
      fprintf (stderr, "cannot resolve path %s\n", path);
      return -1;
    }

  l->fd = open (path, O_DIRECTORY);
  if (l->fd < 0)
    {
      free (l->path);
      l->path = NULL;
      return l->fd;
    }

  return 0;
}

static int
direct_cleanup (struct ovl_layer *l)
{
  return 0;
}

static int
direct_num_of_layers (const char *opaque, const char *path)
{
  return 1;
}

struct data_source direct_access_ds =
  {
   .num_of_layers = direct_num_of_layers,
   .load_data_source = direct_load_data_source,
   .cleanup = direct_cleanup,
   .file_exists = direct_file_exists,
   .statat = direct_statat,
   .fstat = direct_fstat,
   .opendir = direct_opendir,
   .readdir = direct_readdir,
   .closedir = direct_closedir,
   .openat = direct_openat,
   .getxattr = direct_getxattr,
   .listxattr = direct_listxattr,
   .readlinkat = direct_readlinkat,
  };
