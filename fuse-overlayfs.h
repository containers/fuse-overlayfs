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
#ifndef FUSE_OVERLAYFS_H
# define FUSE_OVERLAYFS_H

# include <hash.h>
# include <sys/stat.h>

struct ovl_ino
{
  struct ovl_node *node;
  ino_t ino;
  dev_t dev;
  int lookups;
  mode_t mode;
  int nlinks;
};

struct ovl_node
{
  struct ovl_node *parent;
  Hash_table *children;
  struct ovl_layer *layer, *last_layer;
  ino_t tmp_ino;
  dev_t tmp_dev;
  char *path;
  char *name;
  int hidden_dirfd;
  int node_lookups;
  size_t name_hash;
  Hash_table *inodes;
  struct ovl_ino *ino;
  struct ovl_node *next_link;

  unsigned int do_unlink : 1;
  unsigned int do_rmdir : 1;
  unsigned int hidden : 1;
  unsigned int whiteout : 1;
  unsigned int loaded : 1;
  unsigned int no_security_capability : 1;
};

struct ovl_mapping
{
  struct ovl_mapping *next;
  unsigned int host;
  unsigned int to;
  unsigned int len;
};

struct ovl_data
{
  struct fuse_session *se;
  char *uid_str;
  char *gid_str;
  struct ovl_mapping *uid_mappings;
  struct ovl_mapping *gid_mappings;
  char *mountpoint;
  char *lowerdir;
  char *context;
  char *upperdir;
  char *workdir;
  char *redirect_dir;
  int workdir_fd;
  int debug;
  struct ovl_layer *layers;

  Hash_table *inodes;

  struct ovl_node *root;
  char *timeout_str;
  double timeout;
  int threaded;
  int fsync;
  int fast_ino_check;
  int writeback;
  int disable_xattrs;

  /* current uid/gid*/
  uid_t uid;
  uid_t gid;
};

struct ovl_layer
{
  struct ovl_layer *next;
  struct data_source *ds;
  struct ovl_data *ovl_data;
  char *path;
  int fd;
  bool low;
};

/* a data_source defines the methods for accessing a lower layer.  */
struct data_source
{
  int (*file_exists)(struct ovl_layer *l, const char *pathname);
  int (*statat)(struct ovl_layer *l, const char *path, struct stat *st, int flags);
  int (*fstat)(struct ovl_layer *l, int fd, const char *path, struct stat *st);
  void *(*opendir)(struct ovl_layer *l, const char *path);
  struct dirent *(*readdir)(void *dirp);
  int (*closedir)(void *dirp);
  int (*openat)(struct ovl_layer *l, const char *path, int flags, mode_t mode);
  int (*listxattr)(struct ovl_layer *l, const char *path, char *buf, size_t size);
  int (*getxattr)(struct ovl_layer *l, const char *path, const char *name, char *buf, size_t size);
  ssize_t (*readlinkat)(struct ovl_layer *l, const char *path, char *buf, size_t bufsiz);
};

/* passtrough to the file system.  */
struct data_source direct_access_ds;

#endif
