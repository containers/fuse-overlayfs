#define _GNU_SOURCE

#include <stdlib.h>
#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>

#include <errno.h>

#include <sys/xattr.h>

#include <fuse-overlayfs.h>
#include "utils.h"

static int
test_file_exists (struct ovl_layer *l, const char *pathname)
{
  return file_exists_at (l->fd, pathname);
}

static int
test_listxattr (struct ovl_layer *l, const char *path, char *buf, size_t size)
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
test_getxattr (struct ovl_layer *l, const char *path, const char *name, char *buf, size_t size)
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
test_fstat (struct ovl_layer *l, int fd, const char *path, unsigned int mask, struct stat *st)
{
  char b[32];
  int r;
  mode_t mode;
  uid_t uid;
  gid_t gid;

  r = fstat (fd, st);
  if (r < 0)
    return r;

  r = fgetxattr (fd, "user.original-permissions", b, sizeof (b) - 1);
  if (r < 0 && errno == ENODATA)
    return 0;
  if (r < 0)
    return r;
  b[r] = '\0';

  sscanf (b, "%o:%d:%d", &mode, &uid, &gid);

  st->st_mode = (st->st_mode & ~0777) | mode;
  st->st_uid = uid;
  st->st_gid = gid;

  return 0;
}

static int
test_statat (struct ovl_layer *l, const char *path, struct stat *st, int flags, unsigned int mask)
{
  char p[PATH_MAX];
  char b[32];
  mode_t mode;
  int r;
  uid_t uid;
  gid_t gid;

  r = TEMP_FAILURE_RETRY (fstatat (l->fd, path, st, flags));
  if (r < 0)
    return r;

  sprintf (p, "%s/%s", l->path, path);

  r = getxattr (p, "user.original-permissions", b, sizeof (b) - 1);
  if (r < 0 && (errno == ENODATA || errno == ENOENT))
    return 0;
  if (r < 0)
    return r;
  b[r] = '\0';

  sscanf (b, "%o:%d:%d", &mode, &uid, &gid);

  st->st_mode = (st->st_mode & ~0777) | mode;
  st->st_uid = uid;
  st->st_gid = gid;

  return 0;
}

static struct dirent *
test_readdir (void *dirp)
{
  return readdir (dirp);
}

static void *
test_opendir (struct ovl_layer *l, const char *path)
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
test_closedir (void *dirp)
{
  return closedir (dirp);
}

static int
test_openat (struct ovl_layer *l, const char *path, int flags, mode_t mode)
{
  return TEMP_FAILURE_RETRY (openat (l->fd, path, flags, mode));
}

static ssize_t
test_readlinkat (struct ovl_layer *l, const char *path, char *buf, size_t bufsiz)
{
  return TEMP_FAILURE_RETRY (readlinkat (l->fd, path, buf, bufsiz));
}

static int
test_load_data_source (struct ovl_layer *l, const char *opaque, const char *path, int n_layer)
{
  l->path = realpath (path, NULL);
  if (l->path == NULL)
    return -1;

  l->fd = open (l->path, O_DIRECTORY);
  if (l->fd < 0)
    {
      free (l->path);
      l->path = NULL;
      return l->fd;
    }

  return 0;
}

static int
test_cleanup (struct ovl_layer *l)
{
  return 0;
}

static int
test_num_of_layers (const char *opaque, const char *path)
{
  return 1;
}

static bool
test_support_acls (struct ovl_layer *l)
{
  return true;
}

struct data_source test_ds = {
  .num_of_layers = test_num_of_layers,
  .load_data_source = test_load_data_source,
  .cleanup = test_cleanup,
  .file_exists = test_file_exists,
  .statat = test_statat,
  .fstat = test_fstat,
  .opendir = test_opendir,
  .readdir = test_readdir,
  .closedir = test_closedir,
  .openat = test_openat,
  .listxattr = test_listxattr,
  .getxattr = test_getxattr,
  .readlinkat = test_readlinkat,
  .support_acls = test_support_acls,
  /* get_nfs_filehandle is also available in V1 but this test explicitly builds
   * against the original version of the data_source to ensure backwards
   * compatibility is maintained */
};

int
plugin_version ()
{
  return 1;
}

const char *
plugin_name ()
{
  return "test";
}

struct data_source *
plugin_load (struct ovl_layer *layer, const char *opaque, const char *path)
{
  return &test_ds;
}

int
plugin_release (struct ovl_layer *l)
{
  return 0;
}
