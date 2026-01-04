/* fuse-overlayfs: Overlay Filesystem in Userspace

   Copyright (C) 2018 Giuseppe Scrivano <giuseppe@scrivano.org>
   Copyright (C) 2018-2019 Red Hat Inc.
   Copyright (C) 2001-2007  Miklos Szeredi <miklos@szeredi.hu>

   This program is free software: you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 2 of the License, or
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

#include "fuse-overlayfs.h"

#include "limits.h"
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
  char full_path[PATH_MAX];
  int ret;
  ret = snprintf (full_path, sizeof (full_path), "/proc/self/fd/%d/%s", l->fd, path);
  if (ret >= sizeof (full_path))
    {
      errno = ENAMETOOLONG;
      return -1;
    }

  return llistxattr (full_path, buf, size);
}

static int
direct_getxattr (struct ovl_layer *l, const char *path, const char *name, char *buf, size_t size)
{
  char full_path[PATH_MAX];
  int ret;
  ret = snprintf (full_path, sizeof (full_path), "/proc/self/fd/%d/%s", l->fd, path);
  if (ret >= sizeof (full_path))
    {
      errno = ENAMETOOLONG;
      return -1;
    }
  return lgetxattr (full_path, name, buf, size);
}

static int
direct_fstat (struct ovl_layer *l, int fd, const char *path, unsigned int mask, struct stat *st)
{
  int ret;
#ifdef HAVE_STATX
  struct statx stx;

  ret = statx (fd, "", AT_STATX_DONT_SYNC | AT_EMPTY_PATH, mask, &stx);
  if (ret < 0 && (errno == ENOSYS || errno == EINVAL))
    goto fallback;
  if (ret == 0)
    {
      statx_to_stat (&stx, st);
      return override_mode (l, fd, NULL, path, st);
    }

  return ret;
#endif

fallback:
  ret = fstat (fd, st);
  if (ret != 0)
    return ret;

  return override_mode (l, fd, NULL, path, st);
}

static int
direct_statat (struct ovl_layer *l, const char *path, struct stat *st, int flags, unsigned int mask)
{
  int ret;
#ifdef HAVE_STATX
  struct statx stx;

  ret = statx (l->fd, path, AT_STATX_DONT_SYNC | flags, mask, &stx);
  if (ret < 0 && (errno == ENOSYS || errno == EINVAL))
    goto fallback;
  if (ret == 0)
    {
      statx_to_stat (&stx, st);
      return override_mode (l, -1, NULL, path, st);
    }

  return ret;
#endif
fallback:
  ret = fstatat (l->fd, path, st, flags);
  if (ret != 0)
    return ret;

  return override_mode (l, -1, NULL, path, st);
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

  cleanup_fd = TEMP_FAILURE_RETRY (safe_openat (l->fd, path, O_DIRECTORY, 0));
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
  return TEMP_FAILURE_RETRY (safe_openat (l->fd, path, flags, mode));
}

static ssize_t
direct_readlinkat (struct ovl_layer *l, const char *path, char *buf, size_t bufsiz)
{
  return TEMP_FAILURE_RETRY (readlinkat (l->fd, path, buf, bufsiz));
}

static ino_t
direct_get_nfs_filehandle (const struct ovl_layer *l, const char* path)
{
  int mount_id;
  int ret = name_to_handle_at(l->fd, path, l->fh, &mount_id, 0);
  if (ret == -1)
    return 0;

  ino_t h = 0xcbf29ce484222325ULL;
  for (size_t i = 0; i < l->fh->handle_bytes; i++)
    {
      h ^= l->fh->f_handle[i];
      h *= 0x100000001b3ULL;
    }

  return h;
}

// Returns:
// -1 - Error
// 0  - NFS filehandles not supported
// 1  - Can use NFS filehandles
static int
has_nfs_filehandles (struct ovl_layer *l, const char* path)
{
  struct file_handle *tmp_fh;
  int mount_id;
  int ret;

  tmp_fh = malloc(sizeof(*tmp_fh));
  if (tmp_fh == NULL)
    return -1;

  tmp_fh->handle_bytes = 0;

  ret = name_to_handle_at(AT_FDCWD, path, tmp_fh, &mount_id, 0);
  if (ret == -1 && errno == ENOTSUP)
    {
        free(tmp_fh);
        return 0;
    }
  // previous call should fail with EOVERFLOW and handle_bytes replaced with
  // the size of the handle. EOVERFLOW can also occur if no filehandle is
  // available in a system that does support file-handle lookup.
  if (ret != -1 || errno != EOVERFLOW || tmp_fh->handle_bytes == 0)
    {
      free(tmp_fh);
      return -1;
    }


  l->fh = realloc(tmp_fh, tmp_fh->handle_bytes + sizeof(*l->fh));
  if (!l->fh)
    {
      free(tmp_fh);
      return -1;
    }

  ret = name_to_handle_at(AT_FDCWD, path, l->fh, &mount_id, 0);

  if (ret == -1)
    return 0;
  return 1;
}

static int
direct_load_data_source (struct ovl_layer *l, const char *opaque, const char *path, int n_layer)
{
  char tmp[64];
  struct stat st;
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

  if (fstat(l->fd, &st) == -1)
    {
      close(l->fd);
      free (l->path);
      l->path = NULL;
      return -1;
    }
  else
    l->st_dev = st.st_dev;

  l->nfs_filehandles = has_nfs_filehandles(l, l->path);

  if (fgetxattr (l->fd, XATTR_PRIVILEGED_OVERRIDE_STAT, tmp, sizeof (tmp)) >= 0)
    l->stat_override_mode = STAT_OVERRIDE_PRIVILEGED;
  else if (fgetxattr (l->fd, XATTR_OVERRIDE_CONTAINERS_STAT, tmp, sizeof (tmp)) >= 0)
    l->stat_override_mode = STAT_OVERRIDE_CONTAINERS;
  else if (fgetxattr (l->fd, XATTR_OVERRIDE_STAT, tmp, sizeof (tmp)) >= 0)
    l->stat_override_mode = STAT_OVERRIDE_USER;

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

static bool
direct_support_acls (struct ovl_layer *l)
{
  char value[32];

  return fgetxattr (l->fd, ACL_XATTR, value, sizeof (value)) >= 0
         || errno != ENOTSUP;
}

struct data_source direct_access_ds = {
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
  .support_acls = direct_support_acls,
  .get_nfs_filehandle = direct_get_nfs_filehandle,
};
