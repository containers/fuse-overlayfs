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
# define _GNU_SOURCE

# include <sys/stat.h>
# include <plugin-manager.h>
# include <stdbool.h>
# include <sys/types.h>

typedef struct hash_table Hash_table;

struct ovl_ino
{
  struct ovl_node *node;
  ino_t ino;
  dev_t dev;
  int lookups;
  mode_t mode;
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
  unsigned int in_readdir;

  unsigned int do_unlink : 1;
  unsigned int do_rmdir : 1;
  unsigned int hidden : 1;
  unsigned int whiteout : 1;
  unsigned int loaded : 1;
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
  char *plugins;
  int workdir_fd;
  int debug;
  struct ovl_layer *layers;

  Hash_table *inodes;

  struct ovl_node *root;
  char *timeout_str;
  double timeout;
  int threaded;
  int fsync;
  int noacl;
  int fast_ino_check;
  int writeback;
  int disable_xattrs;
  int xattr_permissions;
  int squash_to_root;
  int squash_to_uid;
  int squash_to_gid;
  int static_nlink;

  /* current uid/gid*/
  uid_t uid;
  uid_t gid;

  /* process euid. */
  uid_t euid;

  struct ovl_plugin_context *plugins_ctx;
};

enum stat_override_mode
{
  STAT_OVERRIDE_NONE,
  STAT_OVERRIDE_USER,
  STAT_OVERRIDE_PRIVILEGED,
  STAT_OVERRIDE_CONTAINERS,
};

struct ovl_layer
{
  struct ovl_layer *next;
  struct data_source *ds;
  struct ovl_data *ovl_data;
  char *path;
  int fd;
  bool low;

  void *data_source_private_data;
  int stat_override_mode;
};

/* a data_source defines the methods for accessing a lower layer.  */
struct data_source
{
  int (*num_of_layers) (const char *opaque, const char *path);
  int (*load_data_source)(struct ovl_layer *l, const char *opaque, const char *path, int n_layer);
  int (*cleanup)(struct ovl_layer *l);
  int (*file_exists)(struct ovl_layer *l, const char *pathname);
  int (*statat)(struct ovl_layer *l, const char *path, struct stat *st, int flags, unsigned int mask);
  int (*fstat)(struct ovl_layer *l, int fd, const char *path, unsigned int mask, struct stat *st);
  void *(*opendir)(struct ovl_layer *l, const char *path);
  struct dirent *(*readdir)(void *dirp);
  int (*closedir)(void *dirp);
  int (*openat)(struct ovl_layer *l, const char *path, int flags, mode_t mode);
  int (*listxattr)(struct ovl_layer *l, const char *path, char *buf, size_t size);
  int (*getxattr)(struct ovl_layer *l, const char *path, const char *name, char *buf, size_t size);
  ssize_t (*readlinkat)(struct ovl_layer *l, const char *path, char *buf, size_t bufsiz);
};

/* passthrough to the file system.  */
extern struct data_source direct_access_ds;

# ifndef HAVE_STATX
#  define STATX_TYPE		0x00000001U	/* Want/got stx_mode & S_IFMT */
#  define STATX_MODE		0x00000002U	/* Want/got stx_mode & ~S_IFMT */
#  define STATX_NLINK		0x00000004U	/* Want/got stx_nlink */
#  define STATX_UID		0x00000008U	/* Want/got stx_uid */
#  define STATX_GID		0x00000010U	/* Want/got stx_gid */
#  define STATX_ATIME		0x00000020U	/* Want/got stx_atime */
#  define STATX_MTIME		0x00000040U	/* Want/got stx_mtime */
#  define STATX_CTIME		0x00000080U	/* Want/got stx_ctime */
#  define STATX_INO		0x00000100U	/* Want/got stx_ino */
#  define STATX_SIZE		0x00000200U	/* Want/got stx_size */
#  define STATX_BLOCKS		0x00000400U	/* Want/got stx_blocks */
#  define STATX_BASIC_STATS	0x000007ffU	/* The stuff in the normal stat struct */
#  define STATX_BTIME		0x00000800U	/* Want/got stx_btime */
#  define STATX_ALL		0x00000fffU	/* All currently supported flags */
# endif

#endif
