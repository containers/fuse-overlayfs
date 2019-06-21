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
#define FUSE_USE_VERSION 31
#define _FILE_OFFSET_BITS 64

#include <config.h>

#include <fuse_lowlevel.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <stddef.h>
#include <stdbool.h>
#include <string.h>
#include <limits.h>
#include <dirent.h>
#include <assert.h>
#include <errno.h>
#include <err.h>
#include <sys/ioctl.h>
#ifdef HAVE_SYS_SENDFILE_H
# include <sys/sendfile.h>
#endif

#ifdef HAVE_ERROR_H
# include <error.h>
#else
# define error(status, errno, fmt, ...) do {                           \
    if (errno == 0)                                                     \
      fprintf (stderr, "fuse-overlayfs: " fmt "\n", ##__VA_ARGS__);     \
    else                                                                \
      {                                                                 \
        fprintf (stderr, "fuse-overlayfs: " fmt, ##__VA_ARGS__);        \
        fprintf (stderr, ": %s\n", strerror (errno));                   \
      }                                                                 \
    if (status)                                                         \
      exit (status);                                                    \
  } while(0)
#endif

#include <inttypes.h>
#include <fcntl.h>
#include <hash.h>
#include <sys/statvfs.h>
#include <sys/file.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/sysmacros.h>

#include <sys/xattr.h>

#include <linux/fs.h>

#include <sys/time.h>
#include <sys/resource.h>

#include <utils.h>

#ifndef TEMP_FAILURE_RETRY
#define TEMP_FAILURE_RETRY(expression) \
  (__extension__                                                              \
    ({ long int __result;                                                     \
       do __result = (long int) (expression);                                 \
       while (__result == -1L && errno == EINTR);                             \
       __result; }))
#endif


#ifndef HAVE_OPEN_BY_HANDLE_AT
struct file_handle
{
  unsigned int  handle_bytes;   /* Size of f_handle [in, out] */
  int           handle_type;    /* Handle type [out] */
  unsigned char f_handle[0];    /* File identifier (sized by
				   caller) [out] */
};

int
open_by_handle_at (int mount_fd, struct file_handle *handle, int flags)
{
  return syscall (SYS_open_by_handle_at, mount_fd, handle, flags);
}
#endif

#ifndef RENAME_EXCHANGE
# define RENAME_EXCHANGE (1 << 1)
# define RENAME_NOREPLACE (1 << 2)
#endif

#ifndef RENAME_WHITEOUT
# define RENAME_WHITEOUT (1 << 2)
#endif

#define XATTR_PREFIX "user.fuseoverlayfs."
#define ORIGIN_XATTR "user.fuseoverlayfs.origin"
#define OPAQUE_XATTR "user.fuseoverlayfs.opaque"
#define PRIVILEGED_XATTR_PREFIX "trusted.overlay."
#define PRIVILEGED_OPAQUE_XATTR "trusted.overlay.opaque"
#define PRIVILEGED_ORIGIN_XATTR "trusted.overlay.origin"
#define OPAQUE_WHITEOUT ".wh..wh..opq"

#if !defined FICLONE && defined __linux__
# define FICLONE _IOW (0x94, 9, int)
#endif

#define NODE_TO_INODE(x) ((fuse_ino_t) x)

#if defined(__GNUC__) && (__GNUC__ > 4 || __GNUC__ == 4 && __GNUC_MINOR__ >= 6) && !defined __cplusplus
_Static_assert (sizeof (fuse_ino_t) >= sizeof (uintptr_t),
		"fuse_ino_t too small to hold uintptr_t values!");
#else
struct _uintptr_to_must_hold_fuse_ino_t_dummy_struct
{
  unsigned _uintptr_to_must_hold_fuse_ino_t:
    ((sizeof (fuse_ino_t) >= sizeof (uintptr_t)) ? 1 : -1);
};
#endif

static bool disable_ovl_whiteout;

static uid_t overflow_uid;
static gid_t overflow_gid;

struct ovl_layer
{
  struct ovl_layer *next;
  char *path;
  int fd;
  bool low;
};

struct ovl_mapping
{
  struct ovl_mapping *next;
  unsigned int host;
  unsigned int to;
  unsigned int len;
};

struct ovl_node
{
  struct ovl_node *parent;
  Hash_table *children;
  struct ovl_layer *layer, *last_layer;
  char *path;
  char *name;
  int lookups;
  ino_t ino;
  int hidden_dirfd;

  unsigned int present_lowerdir : 1;
  unsigned int do_unlink : 1;
  unsigned int do_rmdir : 1;
  unsigned int hidden : 1;
  unsigned int whiteout : 1;
};

struct ovl_data
{
  struct fuse_session *se;
  int debug;
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
  struct ovl_layer *layers;

  struct ovl_node *root;
  char *timeout_str;
  double timeout;
};

static double
get_timeout (struct ovl_data *lo)
{
  return lo->timeout;
}

static const struct fuse_opt ovl_opts[] = {
  {"redirect_dir=%s",
   offsetof (struct ovl_data, redirect_dir), 0},
  {"context=%s",
   offsetof (struct ovl_data, context), 0},
  {"lowerdir=%s",
   offsetof (struct ovl_data, lowerdir), 0},
  {"upperdir=%s",
   offsetof (struct ovl_data, upperdir), 0},
  {"workdir=%s",
   offsetof (struct ovl_data, workdir), 0},
  {"uidmapping=%s",
   offsetof (struct ovl_data, uid_str), 0},
  {"gidmapping=%s",
   offsetof (struct ovl_data, gid_str), 0},
  {"timeout=%s",
   offsetof (struct ovl_data, timeout_str), 0},
  FUSE_OPT_END
};

/* Kernel definitions.  */

typedef unsigned char u8;
typedef unsigned char uuid_t[16];

/* The type returned by overlay exportfs ops when encoding an ovl_fh handle */
#define OVL_FILEID	0xfb

/* On-disk and in-memeory format for redirect by file handle */
struct ovl_fh
{
  u8 version;  /* 0 */
  u8 magic;    /* 0xfb */
  u8 len;      /* size of this header + size of fid */
  u8 flags;    /* OVL_FH_FLAG_* */
  u8 type;     /* fid_type of fid */
  uuid_t uuid; /* uuid of filesystem */
  u8 fid[0];   /* file identifier */
} __packed;

static struct ovl_data *
ovl_data (fuse_req_t req)
{
  return (struct ovl_data *) fuse_req_userdata (req);
}

static unsigned long
get_next_wd_counter ()
{
  static unsigned long counter = 1;
  return counter++;
}

static struct ovl_mapping *
read_mappings (const char *str)
{
  char *buf = NULL, *saveptr = NULL, *it, *endptr;
  struct ovl_mapping *tmp, *ret = NULL;
  unsigned int a, b, c;
  int state = 0;

  buf = alloca (strlen (str) + 1);
  strcpy (buf, str);

  for (it = strtok_r (buf, ":", &saveptr); it; it = strtok_r (NULL, ":", &saveptr))
    {
      switch (state)
        {
        case 0:
          a = strtol (it, &endptr, 10);
          if (*endptr != 0)
            error (EXIT_FAILURE, 0, "invalid mapping specified: %s", str);
          state++;
          break;

        case 1:
          b = strtol (it, &endptr, 10);
          if (*endptr != 0)
            error (EXIT_FAILURE, 0, "invalid mapping specified: %s", str);
          state++;
          break;

        case 2:
          c = strtol (it, &endptr, 10);
          if (*endptr != 0)
            error (EXIT_FAILURE, 0, "invalid mapping specified: %s", str);
          state = 0;

          tmp = malloc (sizeof (*tmp));
          if (tmp == NULL)
            return NULL;
          tmp->next = ret;
          tmp->host = a;
          tmp->to = b;
          tmp->len = c;
          ret = tmp;
          break;
        }
    }

  if (state != 0)
    error (EXIT_FAILURE, 0, "invalid mapping specified: %s", str);

  return ret;
}

static void
free_mapping (struct ovl_mapping *it)
{
  struct ovl_mapping *next = NULL;
  for (; it; it = next)
    {
      next = it->next;
      free (it);
    }
}

/* Useful in a gdb session.  */
void
dump_directory (struct ovl_node *node)
{
  struct ovl_node *it;

  if (node->children == NULL)
    return;

  for (it = hash_get_first (node->children); it; it = hash_get_next (node->children, it))
    printf ("ENTRY: %s (%s)\n", it->name, it->path);
}

static long int
read_file_as_int (const char *file)
{
  cleanup_close int fd = -1;
  long int ret;
  char buffer[256];
  int r;

  fd = open (file, O_RDONLY);
  if (fd < 0)
    error (EXIT_FAILURE, errno, "can't open %s", file);

  r = read (fd, buffer, sizeof (buffer) - 1);
  if (r < 0)
    error (EXIT_FAILURE, errno, "can't read from %s", file);
  buffer[r] = '\0';

  ret = strtol (buffer, NULL, 10);
  if (ret == 0)
    error (EXIT_FAILURE, errno, "can't parse %s", file);

  return ret;
}

static void
read_overflowids (void)
{
  overflow_uid = read_file_as_int ("/proc/sys/kernel/overflowuid");
  overflow_gid = read_file_as_int ("/proc/sys/kernel/overflowgid");
}

static bool
ovl_debug (fuse_req_t req)
{
  return ovl_data (req)->debug != 0;
}

static void
ovl_init (void *userdata, struct fuse_conn_info *conn)
{
  conn->want |= FUSE_CAP_DONT_MASK | FUSE_CAP_SPLICE_READ | FUSE_CAP_SPLICE_MOVE;
  conn->want &= ~FUSE_CAP_PARALLEL_DIROPS;
}

static struct ovl_layer *
get_upper_layer (struct ovl_data *lo)
{
  return lo->layers;
}

static struct ovl_layer *
get_lower_layers (struct ovl_data *lo)
{
  return lo->layers->next;
}

static inline bool
node_dirp (struct ovl_node *n)
{
  return n->children != NULL;
}

static int
node_dirfd (struct ovl_node *n)
{
  if (n->hidden)
    return n->hidden_dirfd;
  return n->layer->fd;
}

static bool
has_prefix (const char *str, const char *pref)
{
  while (1)
    {
      if (*pref == '\0')
        return true;
      if (*str == '\0')
        return false;
      if (*pref != *str)
        return false;
      str++;
      pref++;
    }
  return false;
}

static int
set_fd_opaque (int fd)
{
  cleanup_close int opq_whiteout_fd = -1;
  int ret;

  ret = fsetxattr (fd, PRIVILEGED_OPAQUE_XATTR, "y", 1, 0);
  if (ret < 0)
    {
      if (errno == ENOTSUP)
        goto create_opq_whiteout;
      if (errno != EPERM || fsetxattr (fd, OPAQUE_XATTR, "y", 1, 0) < 0 && errno != ENOTSUP)
          return -1;
    }
 create_opq_whiteout:
  opq_whiteout_fd = TEMP_FAILURE_RETRY (openat (fd, OPAQUE_WHITEOUT, O_CREAT|O_WRONLY|O_NONBLOCK, 0700));
  return (opq_whiteout_fd >= 0 || ret == 0) ? 0 : -1;
}

static int
is_directory_opaque (int dirfd, const char *path)
{
  int fd;
  char b[16];
  ssize_t s;
  int saved_errno;

  fd = TEMP_FAILURE_RETRY (openat (dirfd, path, O_NONBLOCK));
  if (fd < 0)
    return -1;

  s = fgetxattr (fd, PRIVILEGED_OPAQUE_XATTR, b, sizeof (b));
  if (s < 0 && errno == ENODATA)
    s = fgetxattr (fd, OPAQUE_XATTR, b, sizeof (b));

  saved_errno = errno;
  close (fd);

  if (s < 0)
    {
      if (saved_errno == ENOTSUP || saved_errno == ENODATA)
        {
          struct stat st;
          cleanup_free char *whiteout_opq_path = NULL;

          if (asprintf (&whiteout_opq_path, "%s/" OPAQUE_WHITEOUT, path) < 0)
            return -1;

          if (fstatat (dirfd, whiteout_opq_path, &st, AT_SYMLINK_NOFOLLOW) == 0)
            return 1;

          return (errno == ENOENT) ? 0 : -1;
        }
      return -1;
    }

  return b[0] == 'y' ? 1 : 0;
}

static int
create_whiteout (struct ovl_data *lo, struct ovl_node *parent, const char *name, bool skip_mknod, bool force_create)
{
  cleanup_free char *whiteout_wh_path = NULL;
  static bool can_mknod = true;
  cleanup_close int fd = -1;
  int ret;

  if (! force_create)
    {
      cleanup_free char *path = NULL;
      struct ovl_layer *l;
      bool found = false;

      ret = asprintf (&path, "%s/%s", parent->path, name);
      if (ret < 0)
        return ret;

      for (l = get_lower_layers (lo); l; l = l->next)
        {
          struct stat st;

          ret = TEMP_FAILURE_RETRY (fstatat (l->fd, path, &st, AT_SYMLINK_NOFOLLOW));
          if (ret < 0 && errno == ENOENT)
            continue;

          found = true;
          break;
        }
      /* Not present in the lower layers, do not do anything.  */
      if (!found)
        return 0;
    }

  if (!disable_ovl_whiteout && !skip_mknod && can_mknod)
    {
      cleanup_free char *whiteout_path = NULL;

      ret = asprintf (&whiteout_path, "%s/%s", parent->path, name);
      if (ret < 0)
        return ret;
      ret = mknodat (get_upper_layer (lo)->fd, whiteout_path, S_IFCHR|0700, makedev (0, 0));
      if (ret == 0)
        return 0;

      if (errno != EPERM && errno != ENOTSUP)
        return -1;

      /* if it fails with EPERM then do not attempt mknod again.  */
      can_mknod = false;
    }

  ret = asprintf (&whiteout_wh_path, "%s/.wh.%s", parent->path, name);
  if (ret < 0)
    return ret;
  fd = TEMP_FAILURE_RETRY (openat (get_upper_layer (lo)->fd, whiteout_wh_path, O_CREAT|O_WRONLY|O_NONBLOCK, 0700));
  if (fd < 0 && errno != EEXIST)
    return -1;

  return 0;
}

static int
delete_whiteout (struct ovl_data *lo, int dirfd, struct ovl_node *parent, const char *name)
{
  struct stat st;

  if (dirfd >= 0)
    {
      if (TEMP_FAILURE_RETRY (fstatat (dirfd, name, &st, AT_SYMLINK_NOFOLLOW)) == 0
          && (st.st_mode & S_IFMT) == S_IFCHR
          && major (st.st_rdev) == 0
          && minor (st.st_rdev) == 0)
        {
          if (unlinkat (dirfd, name, 0) < 0)
            return -1;
        }
    }
  else
    {
      cleanup_free char *whiteout_path = NULL;
      int ret;

      ret = asprintf (&whiteout_path, "%s/%s", parent->path, name);
      if (ret < 0)
        return ret;

      if (TEMP_FAILURE_RETRY (fstatat (get_upper_layer (lo)->fd, whiteout_path, &st, AT_SYMLINK_NOFOLLOW)) == 0
          && (st.st_mode & S_IFMT) == S_IFCHR
          && major (st.st_rdev) == 0
          && minor (st.st_rdev) == 0)
        {
          if (unlinkat (get_upper_layer (lo)->fd, whiteout_path, 0) < 0)
            return -1;
        }
    }

  /* Look for the .wh. alternative as well.  */

  if (dirfd >= 0)
    {
      cleanup_free char *whiteout_path = NULL;
      int ret;

      ret = asprintf (&whiteout_path, ".wh.%s", name);
      if (ret < 0)
        return ret;

      if (unlinkat (dirfd, whiteout_path, 0) < 0 && errno != ENOENT)
        return -1;
    }
  else
    {
      cleanup_free char *whiteout_path = NULL;
      int ret;

      ret = asprintf (&whiteout_path, "%s/.wh.%s", parent->path, name);
      if (ret < 0)
        return ret;

      if (unlinkat (get_upper_layer (lo)->fd, whiteout_path, 0) < 0 && errno != ENOENT)
        return -1;
    }

  return 0;
}

static int
hide_node (struct ovl_data *lo, struct ovl_node *node, bool unlink_src)
{
  cleanup_free char *newpath = NULL;
  int ret;

  ret = asprintf (&newpath, "%lu", get_next_wd_counter ());
  if (ret < 0)
    return ret;

  assert (node->layer == get_upper_layer (lo));

  /* Might be leftover from a previous run.  */
  unlinkat (lo->workdir_fd, newpath, 0);
  unlinkat (lo->workdir_fd, newpath, AT_REMOVEDIR);

  if (unlink_src)
    {
      /* If the atomic rename+mknod failed, then fallback into doing it in two steps.  */
      if (syscall (SYS_renameat2, node_dirfd (node), node->path, lo->workdir_fd,
                   newpath, RENAME_WHITEOUT) < 0)
        {
          if (node->parent)
            {
              /* If we are here, it means we have no permissions to use mknod.  Also
                 since the file is not yet moved, creating a whiteout would fail on
                 the mknodat call.  */
              if (create_whiteout (lo, node->parent, node->name, true, false) < 0)
                return -1;
            }
          if (renameat (node_dirfd (node), node->path, lo->workdir_fd, newpath) < 0)
            {
              if (node->parent)
                {
                  cleanup_free char *whpath = NULL;

                  ret = asprintf (&whpath, "%s/.wh.%s", node->parent->path, node->name);
                  /* If the rename failed, then try to delete the whiteout file we
                     created earlier.  */
                  if (ret == 0)
                    unlinkat (get_upper_layer (lo)->fd, whpath, 0);
                }
              return -1;
            }
        }
    }
  else
    {
      if (node_dirp (node))
        {
          if (mkdirat (lo->workdir_fd, newpath, 0700) < 0)
            return -1;
        }
      else
        {
          if (linkat (node_dirfd (node), node->path, lo->workdir_fd, newpath, 0) < 0)
            return -1;
        }
    }
  node->hidden_dirfd = lo->workdir_fd;
  free (node->path);
  node->path = newpath;
  newpath = NULL;  /* Do not auto cleanup.  */

  node->hidden = 1;
  node->parent = NULL;

  if (node_dirp (node))
    node->do_rmdir = 1;
  else
    node->do_unlink = 1;
  return 0;
}

static unsigned int
find_mapping (unsigned int id, struct ovl_mapping *mapping, bool direct, bool uid)
{
  if (mapping == NULL)
    return id;
  for (; mapping; mapping = mapping->next)
    {
      if (direct)
        {
          if (id >= mapping->host && id < mapping->host + mapping->len)
            return mapping->to + (id - mapping->host);
        }
      else
        {
          if (id >= mapping->to && id < mapping->to + mapping->len)
            return mapping->host + (id - mapping->to);
        }
    }
  return uid ? overflow_uid : overflow_gid;
}

static uid_t
get_uid (struct ovl_data *data, uid_t id)
{
  return find_mapping (id, data->uid_mappings, false, false);
}

static uid_t
get_gid (struct ovl_data *data, gid_t id)
{
  return find_mapping (id, data->gid_mappings, false, false);
}

static int
rpl_stat (fuse_req_t req, struct ovl_node *node, struct stat *st)
{
  int ret;
  struct ovl_data *data = ovl_data (req);

  ret = TEMP_FAILURE_RETRY (fstatat (node_dirfd (node), node->path, st, AT_SYMLINK_NOFOLLOW));
  if (ret < 0)
    return ret;

  st->st_uid = find_mapping (st->st_uid, data->uid_mappings, true, true);
  st->st_gid = find_mapping (st->st_gid, data->gid_mappings, true, false);

  st->st_ino = node->ino;
  if (ret == 0 && node_dirp (node))
    {
      struct ovl_node *it;

      st->st_nlink = 2;

      for (it = hash_get_first (node->children); it; it = hash_get_next (node->children, it))
        {
          if (node_dirp (it))
            st->st_nlink++;
        }
    }

  return ret;
}

static void
node_mark_all_free (void *p)
{
  struct ovl_node *it, *n = (struct ovl_node *) p;

  n->lookups = 0;

  if (n->children)
    {
      for (it = hash_get_first (n->children); it; it = hash_get_next (n->children, it))
        node_mark_all_free (it);
    }
}

static void
node_free (void *p)
{
  struct ovl_node *n = (struct ovl_node *) p;
  if (n->parent)
    {
      if (hash_lookup (n->parent->children, n) == n)
        hash_delete (n->parent->children, n);
      n->parent = NULL;
    }

  if (n->lookups > 0)
    return;

  if (n->children)
    {
      struct ovl_node *it;

      for (it = hash_get_first (n->children); it; it = hash_get_next (n->children, it))
        it->parent = NULL;

      hash_free (n->children);
      n->children = NULL;
    }

  if (n->do_unlink)
    unlinkat (n->hidden_dirfd, n->path, 0);
  if (n->do_rmdir)
    unlinkat (n->hidden_dirfd, n->path, AT_REMOVEDIR);

  free (n->name);
  free (n->path);
  free (n);
  return;
}

static void
do_forget (fuse_ino_t ino, uint64_t nlookup)
{
  struct ovl_node *n;

  if (ino == FUSE_ROOT_ID)
    return;

  n = (struct ovl_node *) ino;

  n->lookups -= nlookup;
  if (n->lookups <= 0)
    node_free (n);
}

static void
ovl_forget (fuse_req_t req, fuse_ino_t ino, uint64_t nlookup)
{
  if (ovl_debug (req))
    fprintf (stderr, "ovl_forget(ino=%" PRIu64 ", nlookup=%lu)\n",
	     ino, nlookup);
  do_forget (ino, nlookup);
  fuse_reply_none (req);
}

static size_t
node_hasher (const void *p, size_t s)
{
  struct ovl_node *n = (struct ovl_node *) p;
  return hash_string (n->name, s);
}

static bool
node_compare (const void *n1, const void *n2)
{
  struct ovl_node *node1 = (struct ovl_node *) n1;
  struct ovl_node *node2 = (struct ovl_node *) n2;

  return strcmp (node1->name, node2->name) == 0 ? true : false;
}

static void
cleanup_node_initp (struct ovl_node **p)
{
  struct ovl_node *n = *p;
  if (n == NULL)
    return;
  if (n->children)
    hash_free (n->children);
  free (n->name);
  free (n->path);
  free (n);
}

#define cleanup_node_init __attribute__((cleanup (cleanup_node_initp)))

static struct ovl_node *
make_whiteout_node (const char *path, const char *name)
{
  struct ovl_node *ret_xchg;
  cleanup_node_init struct ovl_node *ret = NULL;

  ret = calloc (1, sizeof (*ret));
  if (ret == NULL)
    return NULL;

  ret->name = strdup (name);
  if (ret->name == NULL)
      return NULL;

  ret->path = strdup (path);
  if (ret->path == NULL)
    return NULL;

  ret->whiteout = 1;

  ret_xchg = ret;
  ret = NULL;

  return ret_xchg;
}

static ssize_t
safe_read_xattr (char **ret, int sfd, const char *name, size_t initial_size)
{
  cleanup_free char *buffer = NULL;
  size_t current_size;
  ssize_t s;

  current_size = initial_size;
  buffer = malloc (current_size + 1);
  if (buffer == NULL)
    return -1;

  while (1)
    {
      char *tmp;

      s = fgetxattr (sfd, name, buffer, current_size);
      if (s < 0)
        break;
      if (s < current_size)
        break;

      current_size *= 2;
      tmp = realloc (buffer, current_size + 1);
      if (tmp == NULL)
        return -1;

      buffer = tmp;
    }

  buffer[s] == '\0';

  /* Change owner.  */
  *ret = buffer;
  buffer = NULL;

  return s;
}

static struct ovl_node *
make_ovl_node (const char *path, struct ovl_layer *layer, const char *name, ino_t ino, bool dir_p, struct ovl_node *parent)
{
  struct ovl_node *ret_xchg;
  cleanup_node_init struct ovl_node *ret = NULL;

  ret = calloc (1, sizeof (*ret));
  if (ret == NULL)
      return NULL;

  ret->parent = parent;
  ret->layer = layer;
  ret->ino = ino;
  ret->hidden_dirfd = -1;
  ret->name = strdup (name);
  if (ret->name == NULL)
    return NULL;

  if (has_prefix (path, "./") && path[2])
    path += 2;

  ret->path = strdup (path);
  if (ret->path == NULL)
    return NULL;

  if (!dir_p)
    ret->children = NULL;
  else
    {
      ret->children = hash_initialize (10, NULL, node_hasher, node_compare, node_free);
      if (ret->children == NULL)
        return NULL;
    }

  if (ret->ino == 0)
    {
      struct stat st;
      struct ovl_layer *it;
      cleanup_free char *path = NULL;

      path = strdup (ret->path);
      if (path == NULL)
        return NULL;

      for (it = layer; it; it = it->next)
        {
          ssize_t s;
          cleanup_free char *val = NULL;
          cleanup_free char *origin = NULL;
          cleanup_close int fd = TEMP_FAILURE_RETRY (openat (it->fd, path, O_RDONLY|O_NONBLOCK|O_NOFOLLOW|O_PATH));
          if (fd < 0)
            continue;

          if (fstat (fd, &st) == 0)
            ret->ino = st.st_ino;

          s = safe_read_xattr (&val, fd, PRIVILEGED_ORIGIN_XATTR, PATH_MAX);
          if (s > 0)
            {
              char buf[512];
              struct ovl_fh *ofh = (struct ovl_fh *) val;
              size_t s = ofh->len - sizeof (*ofh);
              struct file_handle *fh = (struct file_handle *) buf;

              if (s < sizeof (buf) - sizeof(int) * 2)
                {
                  cleanup_close int originfd = -1;

                  /*
                    overlay in the kernel stores a file handle in the .origin xattr.
                    Honor it when present, but don't fail on errors as an unprivileged
                    user cannot open a file handle.
                  */
                  fh->handle_bytes = s;
                  fh->handle_type = ofh->type;
                  memcpy (fh->f_handle, ofh->fid, s);

                  originfd = open_by_handle_at (AT_FDCWD, fh, O_RDONLY);
                  if (originfd >= 0)
                    {
                      if (fstat (originfd, &st) == 0)
                        {
                          ret->ino = st.st_ino;
                          break;
                        }
                    }
                }
            }

          /* If an origin is specified, use it for the next layer lookup.  */
          s = safe_read_xattr (&origin, fd, ORIGIN_XATTR, PATH_MAX);
          if (s > 0)
            {
              free (path);
              path = origin;
              origin = NULL;
            }

          if (parent && parent->last_layer == it)
            break;
        }
    }

  ret_xchg = ret;
  ret = NULL;

  return ret_xchg;
}

static struct ovl_node *
insert_node (struct ovl_node *parent, struct ovl_node *item, bool replace)
{
  struct ovl_node *old = NULL, *prev_parent = item->parent;
  int ret;

  if (prev_parent)
    {
      if (hash_lookup (prev_parent->children, item) == item)
        hash_delete (prev_parent->children, item);
    }

  if (replace)
    {
      old = hash_delete (parent->children, item);
      if (old)
        node_free (old);
    }

  ret = hash_insert_if_absent (parent->children, item, (const void **) &old);
  if (ret < 0)
    {
      node_free (item);
      errno = ENOMEM;
      return NULL;
    }
  if (ret == 0)
    {
      node_free (item);
      return old;
    }

  item->parent = parent;

  return item;
}

static const char *
get_whiteout_name (const char *name, struct stat *st)
{
  if (has_prefix (name, ".wh."))
    return name + 4;
  if ((st->st_mode & S_IFMT) == S_IFCHR
      && major (st->st_rdev) == 0
      && minor (st->st_rdev) == 0)
    return name;
  return NULL;
}

static struct ovl_node *
load_dir (struct ovl_data *lo, struct ovl_node *n, struct ovl_layer *layer, char *path, char *name)
{
  struct dirent *dent;
  struct stat st, tmp_st;
  struct ovl_layer *it, *upper_layer = get_upper_layer (lo);

  if (!n)
    {
      n = make_ovl_node (path, layer, name, 0, true, NULL);
      if (n == NULL)
        {
          errno = ENOMEM;
          return NULL;
        }
    }

  for (it = lo->layers; it; it = it->next)
    {
      int fd;
      cleanup_dir DIR *dp = NULL;
      cleanup_close int cleanup_fd = TEMP_FAILURE_RETRY (openat (it->fd, path, O_DIRECTORY));
      if (cleanup_fd < 0)
        continue;

      dp = fdopendir (cleanup_fd);
      if (dp == NULL)
        continue;

      cleanup_fd = -1;  /* It is now owned by dp.  */

      fd = dirfd (dp);
      for (;;)
        {
          int ret;
          struct ovl_node key;
          const char *wh;
          struct ovl_node *child = NULL;
          cleanup_free char *node_path = NULL;
          cleanup_free char *whiteout_path = NULL;

          errno = 0;
          dent = readdir (dp);
          if (dent == NULL)
            {
              if (errno)
                return NULL;

              break;
            }

          key.name = dent->d_name;

          if ((strcmp (dent->d_name, ".") == 0) || strcmp (dent->d_name, "..") == 0)
            continue;

          if (TEMP_FAILURE_RETRY (fstatat (fd, dent->d_name, &st, AT_SYMLINK_NOFOLLOW)) < 0)
              return NULL;

          child = hash_lookup (n->children, &key);
          if (child)
            {
              if (child->whiteout && it == upper_layer)
                {
                  hash_delete (n->children, child);
                  node_free (child);
                  child = NULL;
                }
              else
                {
                  if (it->low)
                    child->present_lowerdir = 1;
                  continue;
                }
            }

          ret = asprintf (&whiteout_path, ".wh.%s", dent->d_name);
          if (ret < 0)
            return NULL;

          ret = asprintf (&node_path, "%s/%s", n->path, dent->d_name);
          if (ret < 0)
            return NULL;

          ret = TEMP_FAILURE_RETRY (fstatat (fd, whiteout_path, &tmp_st, AT_SYMLINK_NOFOLLOW));
          if (ret < 0 && errno != ENOENT)
            return NULL;

          if (ret == 0)
            {
              child = make_whiteout_node (node_path, dent->d_name);
              if (child == NULL)
                {
                  errno = ENOMEM;
                  return NULL;
                }
            }
          else
            {
              wh = get_whiteout_name (dent->d_name, &st);
              if (wh)
                {
                  child = make_whiteout_node (node_path, wh);
                  if (child == NULL)
                    {
                      errno = ENOMEM;
                      return NULL;
                    }
                }
              else
                {
                  bool dirp = st.st_mode & S_IFDIR;

                  child = make_ovl_node (node_path, it, dent->d_name, 0, dirp, n);
                  if (child == NULL)
                    {
                      errno = ENOMEM;
                      return NULL;
                    }
                }
            }

            if (insert_node (n, child, false) == NULL)
              {
                errno = ENOMEM;
                return NULL;
              }
        }

      if (n->last_layer == it)
        break;
    }

  return n;
}

static void
free_layers (struct ovl_layer *layers)
{
  if (layers == NULL)
    return;
  free_layers (layers->next);
  free (layers->path);
  if (layers->fd >= 0)
    close (layers->fd);
  free (layers);
}

static void
cleanup_layerp (struct ovl_layer **p)
{
  struct ovl_layer *l = *p;
  free_layers (l);
}

#define cleanup_layer __attribute__((cleanup (cleanup_layerp)))

static struct ovl_layer *
read_dirs (char *path, bool low, struct ovl_layer *layers)
{
  char *saveptr = NULL, *it;
  struct ovl_layer *last;
  cleanup_free char *buf = NULL;

  if (path == NULL)
    return NULL;

  buf = strdup (path);
  if (buf == NULL)
    return NULL;

  last = layers;
  while (last && last->next)
    last = last->next;

  for (it = strtok_r (buf, ":", &saveptr); it; it = strtok_r (NULL, ":", &saveptr))
    {
      cleanup_layer struct ovl_layer *l = NULL;

      l = calloc (1, sizeof (*l));
      if (l == NULL)
        return NULL;
      l->fd = -1;

      l->path = realpath (it, NULL);
      if (l->path == NULL)
        return NULL;

      l->fd = open (l->path, O_DIRECTORY);
      if (l->fd < 0)
        return NULL;

      l->low = low;
      if (low)
        {
          l->next = NULL;
          if (last == NULL)
            last = layers = l;
          else
            {
              last->next = l;
              last = l;
            }
        }
      else
        {
          l->next = layers;
          layers = l;
        }
      l = NULL;
    }
  return layers;
}

static struct ovl_node *
do_lookup_file (struct ovl_data *lo, fuse_ino_t parent, const char *name)
{
  struct ovl_node key;
  struct ovl_node *node, *pnode;

  if (parent == FUSE_ROOT_ID)
    pnode = lo->root;
  else
    pnode = (struct ovl_node *) parent;

  if (name == NULL)
    return pnode;

  if (has_prefix (name, ".wh."))
    {
      errno = EINVAL;
      return NULL;
    }

  key.name = (char *) name;
  node = hash_lookup (pnode->children, &key);
  if (node == NULL)
    {
      int ret;
      struct ovl_layer *it;
      struct stat st, tmp_st;
      struct ovl_layer *upper_layer = get_upper_layer (lo);

      for (it = lo->layers; it; it = it->next)
        {
          cleanup_free char *path = NULL;
          cleanup_free char *whpath = NULL;
          const char *wh_name;

          ret = asprintf (&path, "%s/%s", pnode->path, name);
          if (ret < 0)
            return NULL;

          ret = TEMP_FAILURE_RETRY (fstatat (it->fd, path, &st, AT_SYMLINK_NOFOLLOW));
          if (ret < 0)
            {
              int saved_errno = errno;

              if (errno == ENOENT || errno == ENOTDIR)
                {
                  if (node)
                    continue;

                  ret = asprintf (&whpath, "%s/.wh.%s", pnode->path, name);
                  if (ret < 0)
                    return NULL;

                  ret = TEMP_FAILURE_RETRY (fstatat (it->fd, whpath, &tmp_st, AT_SYMLINK_NOFOLLOW));
                  if (ret < 0 && errno != ENOENT && errno != ENOTDIR)
                    return NULL;
                  if (ret == 0)
                    {
                      node = make_whiteout_node (path, name);
                      if (node == NULL)
                        {
                          errno = ENOMEM;
                          return NULL;
                        }
                      goto insert_node;
                    }
                  continue;
                }
              errno = saved_errno;
              return NULL;
            }

          /* If we already know the node, simply update the ino.  */
          if (node)
            {
              node->ino = st.st_ino;
              if (it->low)
                node->present_lowerdir = 1;
              continue;
            }

          if (whpath == NULL)
            {
              ret = asprintf (&whpath, "%s/.wh.%s", pnode->path, name);
              if (ret < 0)
                return NULL;
            }

          ret = TEMP_FAILURE_RETRY (fstatat (it->fd, whpath, &tmp_st, AT_SYMLINK_NOFOLLOW));
          if (ret < 0 && errno != ENOENT)
            return NULL;
          if (ret == 0)
              node = make_whiteout_node (path, name);
          else
            {
              wh_name = get_whiteout_name (name, &st);
              if (wh_name)
                node = make_whiteout_node (path, wh_name);
              else
                node = make_ovl_node (path, it, name, 0, st.st_mode & S_IFDIR, pnode);
            }
          if (node == NULL)
            {
              errno = ENOMEM;
              return NULL;
            }

          if (st.st_mode & S_IFDIR)
            {
              ret = is_directory_opaque (it->fd, path);
              if (ret < 0)
                {
                  node_free (node);
                  return NULL;
                }
              if (ret > 0)
                node->last_layer = it;
            }
insert_node:
          if (insert_node (pnode, node, false) == NULL)
            {
              node_free (node);
              errno = ENOMEM;
              return NULL;
            }
          if (node->last_layer)
            break;
          if (pnode && pnode->last_layer == it)
            break;
        }
    }

  if (node == NULL || node->whiteout)
    {
      errno = ENOENT;
      return NULL;
    }
  return node;
}

static void
ovl_lookup (fuse_req_t req, fuse_ino_t parent, const char *name)
{
  struct fuse_entry_param e;
  int err = 0;
  struct ovl_data *lo = ovl_data (req);
  struct ovl_node *node;

  if (ovl_debug (req))
    fprintf (stderr, "ovl_lookup(parent=%" PRIu64 ", name=%s)\n",
	     parent, name);

  memset (&e, 0, sizeof (e));

  node = do_lookup_file (lo, parent, name);
  if (node == NULL)
    {
      fuse_reply_err (req, errno);
      return;
    }

  err = rpl_stat (req, node, &e.attr);
  if (err)
    {
      fuse_reply_err (req, errno);
      return;
    }

  e.ino = NODE_TO_INODE (node);
  node->lookups++;
  e.attr_timeout = get_timeout (lo);
  e.entry_timeout = get_timeout (lo);
  fuse_reply_entry (req, &e);
}

struct ovl_dirp
{
  struct ovl_data *lo;
  struct ovl_node *parent;
  struct ovl_node **tbl;
  size_t tbl_size;
  size_t offset;
};

static struct ovl_dirp *
ovl_dirp (struct fuse_file_info *fi)
{
  return (struct ovl_dirp *) (uintptr_t) fi->fh;
}

static void
ovl_opendir (fuse_req_t req, fuse_ino_t ino, struct fuse_file_info *fi)
{
  size_t counter = 0;
  struct ovl_node *node;
  struct ovl_data *lo = ovl_data (req);
  struct ovl_node *it;
  struct ovl_dirp *d = calloc (1, sizeof (struct ovl_dirp));

  if (ovl_debug (req))
    fprintf (stderr, "ovl_opendir(ino=%" PRIu64 ")\n", ino);

  if (d == NULL)
    {
      errno = ENOENT;
      goto out_errno;
    }

  node = do_lookup_file (lo, ino, NULL);
  if (node == NULL)
    {
      errno = ENOENT;
      goto out_errno;
    }

  if (! node_dirp (node))
    {
      errno = ENOTDIR;
      goto out_errno;
    }

  node = load_dir (lo, node, node->layer, node->path, node->name);
  if (node == NULL)
    goto out_errno;

  d->offset = 0;
  d->parent = node;
  d->tbl_size = hash_get_n_entries (node->children) + 2;
  d->tbl = malloc (sizeof (struct ovl_node *) * d->tbl_size);
  if (d->tbl == NULL)
    {
      errno = ENOMEM;
      goto out_errno;
    }

  d->tbl[counter++] = node;
  d->tbl[counter++] = node->parent;

  for (it = hash_get_first (node->children); it; it = hash_get_next (node->children, it))
    {
      it->lookups++;
      d->tbl[counter++] = it;
    }

  fi->fh = (uintptr_t) d;

  fuse_reply_open (req, fi);
  return;

out_errno:
  if (d)
    {
      if (d->tbl)
        free (d->tbl);
      free (d);
    }
  fuse_reply_err (req, errno);
}

static int
create_missing_whiteouts (struct ovl_data *lo, struct ovl_node *node, const char *from)
{
  struct ovl_layer *l;

  if (! node_dirp (node))
    return 0;

  node = load_dir (lo, node, node->layer, node->path, node->name);
  if (node == NULL)
    return -1;

  for (l = get_lower_layers (lo); l; l = l->next)
    {
      cleanup_dir DIR *dp = NULL;
      cleanup_close int cleanup_fd = -1;

      cleanup_fd = TEMP_FAILURE_RETRY (openat (l->fd, from, O_DIRECTORY));
      if (cleanup_fd < 0)
        {
          if (errno == ENOENT)
            continue;
          if (errno == ENOTDIR)
            break;

          return -1;
        }

      dp = fdopendir (cleanup_fd);
      if (dp == NULL)
        return -1;
      else
        {
          struct dirent *dent;
          int fd = cleanup_fd;

          cleanup_fd = -1;  /* Now owned by dp.  */

          for (;;)
            {
              struct ovl_node key;
              struct ovl_node *n;

              errno = 0;
              dent = readdir (dp);
              if (dent == NULL)
                {
                  if (errno)
                    return -1;

                  break;
                }

              if (strcmp (dent->d_name, ".") == 0)
                continue;
              if (strcmp (dent->d_name, "..") == 0)
                continue;

              key.name = (char *) dent->d_name;

              n = hash_lookup (node->children, &key);
              if (n)
                {
                  if (node_dirp (n))
                    {
                      cleanup_free char *c = NULL;
                      n = load_dir (lo, n, n->layer, n->path, n->name);
                      if (n == NULL)
                        return -1;
                      if (asprintf (&c, "%s/%s", from, n->name) < 0)
                        return -1;

                      if (create_missing_whiteouts (lo, n, c) < 0)
                        return -1;
                    }
                  continue;
                }

              if (create_whiteout (lo, node, dent->d_name, false, true) < 0)
                return -1;
            }
        }
    }
  return 0;
}

static void
ovl_do_readdir (fuse_req_t req, fuse_ino_t ino, size_t size,
	       off_t offset, struct fuse_file_info *fi, int plus)
{
  struct ovl_data *lo = ovl_data (req);
  struct ovl_dirp *d = ovl_dirp (fi);
  size_t remaining = size;
  char *p;
  cleanup_free char *buffer = NULL;

  buffer = calloc (size, 1);
  if (buffer == NULL)
    {
      fuse_reply_err (req, ENOMEM);
      return;
    }
  p = buffer;
  for (; remaining > 0 && offset < d->tbl_size; offset++)
      {
        int ret;
        size_t entsize;
        struct stat st;
        const char *name;
        struct ovl_node *node = d->tbl[offset];

        if (node == NULL || node->whiteout || node->hidden)
          continue;

        ret = rpl_stat (req, node, &st);
        if (ret < 0)
          {
            fuse_reply_err (req, errno);
            return;
          }

        if (offset == 0)
          name = ".";
        else if (offset == 1)
          name = "..";
        else
          {
            if (node->parent != d->parent)
              continue;
            name = node->name;
          }

        if (!plus)
          entsize = fuse_add_direntry (req, p, remaining, name, &st, offset + 1);
        else
          {
            struct fuse_entry_param e;

            memset (&e, 0, sizeof (e));
            e.attr_timeout = get_timeout (lo);
            e.entry_timeout = get_timeout (lo);
            e.ino = NODE_TO_INODE (node);
            memcpy (&e.attr, &st, sizeof (st));

            entsize = fuse_add_direntry_plus (req, p, remaining, name, &e, offset + 1);
            if (entsize <= remaining)
              {
                /* First two entries are . and .. */
                if (offset >= 2)
                  node->lookups++;
              }
          }

        if (entsize > remaining)
          break;

        p += entsize;
        remaining -= entsize;
      }
  fuse_reply_buf (req, buffer, size - remaining);
}

static void
ovl_readdir (fuse_req_t req, fuse_ino_t ino, size_t size,
	    off_t offset, struct fuse_file_info *fi)
{
  if (ovl_debug (req))
    fprintf (stderr, "ovl_readdir(ino=%" PRIu64 ", size=%zu, offset=%llo)\n", ino, size, offset);
  ovl_do_readdir (req, ino, size, offset, fi, 0);
}

static void
ovl_readdirplus (fuse_req_t req, fuse_ino_t ino, size_t size,
		off_t offset, struct fuse_file_info *fi)
{
  if (ovl_debug (req))
    fprintf (stderr, "ovl_readdirplus(ino=%" PRIu64 ", size=%zu, offset=%llo)\n", ino, size, offset);
  ovl_do_readdir (req, ino, size, offset, fi, 1);
}

static void
ovl_releasedir (fuse_req_t req, fuse_ino_t ino, struct fuse_file_info *fi)
{
  size_t s;
  struct ovl_dirp *d = ovl_dirp (fi);

  if (ovl_debug (req))
    fprintf (stderr, "ovl_releasedir(ino=%" PRIu64 ")\n", ino);

  for (s = 2; s < d->tbl_size; s++)
    {
      struct ovl_node *n = d->tbl[s];
      do_forget (NODE_TO_INODE (n), 1);
    }

  free (d->tbl);
  free (d);
  fuse_reply_err (req, 0);
}

static void
ovl_listxattr (fuse_req_t req, fuse_ino_t ino, size_t size)
{
  ssize_t len;
  struct ovl_node *node;
  struct ovl_data *lo = ovl_data (req);
  cleanup_free char *buf = NULL;
  cleanup_close int fd = -1;

  if (ovl_debug (req))
    fprintf (stderr, "ovl_listxattr(ino=%" PRIu64 ", size=%zu)\n", ino, size);

  node = do_lookup_file (lo, ino, NULL);
  if (node == NULL)
    {
      fuse_reply_err (req, ENOENT);
      return;
    }

  if (size > 0)
    {
      buf = malloc (size);
      if (buf == NULL)
        {
          fuse_reply_err (req, ENOMEM);
          return;
        }
    }

  fd = TEMP_FAILURE_RETRY (openat (node_dirfd (node), node->path, O_RDONLY|O_NONBLOCK));
  if (fd < 0)
    {
      fuse_reply_err (req, errno);
      return;
    }

  len = flistxattr (fd, buf, size);
  if (len < 0)
    fuse_reply_err (req, errno);
  else if (size == 0)
    fuse_reply_xattr (req, len);
  else if (len <= size)
    fuse_reply_buf (req, buf, len);
}

static void
ovl_getxattr (fuse_req_t req, fuse_ino_t ino, const char *name, size_t size)
{
  ssize_t len;
  struct ovl_node *node;
  struct ovl_data *lo = ovl_data (req);
  cleanup_free char *buf = NULL;
  cleanup_close int fd = -1;

  if (ovl_debug (req))
    fprintf (stderr, "ovl_getxattr(ino=%" PRIu64 ", name=%s, size=%zu)\n", ino, name, size);

  node = do_lookup_file (lo, ino, NULL);
  if (node == NULL)
    {
      fuse_reply_err (req, ENOENT);
      return;
    }

  if (size > 0)
    {
      buf = malloc (size);
      if (buf == NULL)
        {
          fuse_reply_err (req, ENOMEM);
          return;
        }
    }

  fd = TEMP_FAILURE_RETRY (openat (node_dirfd (node), node->path, O_RDONLY|O_NONBLOCK));
  if (fd < 0)
    {
      fuse_reply_err (req, errno);
      return;
    }

  len = fgetxattr (fd, name, buf, size);
  if (len < 0)
    fuse_reply_err (req, errno);
  else if (size == 0)
    fuse_reply_xattr (req, len);
  else if (len <= size)
    fuse_reply_buf (req, buf, len);
}

static void
ovl_access (fuse_req_t req, fuse_ino_t ino, int mask)
{
  int ret;
  struct ovl_data *lo = ovl_data (req);
  struct ovl_node *n = do_lookup_file (lo, ino, NULL);

  if (ovl_debug (req))
    fprintf (stderr, "ovl_access(ino=%" PRIu64 ", mask=%d)\n",
	     ino, mask);

  ret = faccessat (node_dirfd (n), n->path, mask, AT_SYMLINK_NOFOLLOW);
  fuse_reply_err (req, ret < 0 ? errno : 0);
}

static int
copy_xattr (int sfd, int dfd, char *buf, size_t buf_size)
{
  size_t xattr_len;

  xattr_len = flistxattr (sfd, buf, buf_size);
  if (xattr_len > 0)
    {
      char *it;
      for (it = buf; it - buf < xattr_len; it += strlen (it) + 1)
        {
          cleanup_free char *v = NULL;
          ssize_t s = safe_read_xattr (&v, sfd, it, 256);
          if (s < 0)
            return -1;

          if (fsetxattr (dfd, it, v, s, 0) < 0)
            {
              if (errno == EINVAL || errno == EOPNOTSUPP)
                continue;
              return -1;
            }
        }
    }
  return 0;
}

static int create_node_directory (struct ovl_data *lo, struct ovl_node *src);

static int
create_directory (struct ovl_data *lo, int dirfd, const char *name, const struct timespec *times,
                  struct ovl_node *parent, int xattr_sfd, uid_t uid, gid_t gid, mode_t mode)
{
  int ret;
  cleanup_close int dfd = -1;
  cleanup_free char *buf = NULL;
  char wd_tmp_file_name[32];

  sprintf (wd_tmp_file_name, "%lu", get_next_wd_counter ());

  ret = mkdirat (lo->workdir_fd, wd_tmp_file_name, mode);
  if (ret < 0)
    goto out;

  ret = dfd = TEMP_FAILURE_RETRY (openat (lo->workdir_fd, wd_tmp_file_name, O_RDONLY));
  if (ret < 0)
    goto out;

  ret = fchown (dfd, uid, gid);
  if (ret < 0)
    goto out;

  if (times)
    {
      ret = futimens (dfd, times);
      if (ret < 0)
        goto out;
    }

  if (ret == 0 && xattr_sfd >= 0)
    {
      const size_t buf_size = 1 << 20;
      buf = malloc (buf_size);
      if (buf == NULL)
        {
          ret = -1;
          goto out;
        }

      ret = copy_xattr (xattr_sfd, dfd, buf, buf_size);
      if (ret < 0)
        goto out;
    }

  unlinkat (dirfd, name, 0);

  ret = renameat (lo->workdir_fd, wd_tmp_file_name, dirfd, name);
  if (ret < 0)
    {
      if (errno == ENOENT && parent)
        {
          ret = create_node_directory (lo, parent);
          if (ret != 0)
            goto out;
        }

      ret = renameat (lo->workdir_fd, wd_tmp_file_name, dirfd, name);
    }
out:
  if (ret < 0)
      unlinkat (lo->workdir_fd, wd_tmp_file_name, AT_REMOVEDIR);

  return ret;
}

static int
create_node_directory (struct ovl_data *lo, struct ovl_node *src)
{
  int ret;
  struct stat st;
  cleanup_close int sfd = -1;
  struct timespec times[2];

  if (src == NULL)
    return 0;

  if (src->layer == get_upper_layer (lo))
    return 0;

  ret = sfd = TEMP_FAILURE_RETRY (openat (node_dirfd (src), src->path, O_RDONLY|O_NONBLOCK));
  if (ret < 0)
    return ret;

  ret = TEMP_FAILURE_RETRY (fstat (sfd, &st));
  if (ret < 0)
    return ret;

  times[0] = st.st_atim;
  times[1] = st.st_mtim;

  ret = create_directory (lo, get_upper_layer (lo)->fd, src->path, times, src->parent, sfd, st.st_uid, st.st_gid, st.st_mode);
  if (ret == 0)
    {
      src->layer = get_upper_layer (lo);

      if (src->parent)
        delete_whiteout (lo, -1, src->parent, src->name);
    }

  return ret;
}

static int
copy_fd_to_fd (int sfd, int dfd, char *buf, size_t buf_size)
{
  int ret;

  for (;;)
    {
      int written;
      int nread;

      nread = TEMP_FAILURE_RETRY (read (sfd, buf, buf_size));
      if (nread < 0)
        return nread;

      if (nread == 0)
        break;

      written = 0;
      {
        ret = TEMP_FAILURE_RETRY (write (dfd, buf + written, nread));
        if (ret < 0)
          return ret;
        written += ret;
        nread -= ret;
      }
      while (nread);
    }
  return 0;
}

static int
copyup (struct ovl_data *lo, struct ovl_node *node)
{
  int saved_errno;
  int ret = -1;
  cleanup_close int dfd = -1;
  cleanup_close int sfd = -1;
  struct stat st;
  const size_t buf_size = 1 << 20;
  cleanup_free char *buf = NULL;
  struct timespec times[2];
  char wd_tmp_file_name[32];
  static bool support_reflinks = true;
  bool data_copied = false;

  sprintf (wd_tmp_file_name, "%lu", get_next_wd_counter ());

  ret = TEMP_FAILURE_RETRY (fstatat (node_dirfd (node), node->path, &st, AT_SYMLINK_NOFOLLOW));
  if (ret < 0)
    return ret;

  if (node->parent)
    {
      ret = create_node_directory (lo, node->parent);
      if (ret < 0)
        return ret;
    }

  if ((st.st_mode & S_IFMT) == S_IFDIR)
    {
      ret = create_node_directory (lo, node);
      if (ret < 0)
        goto exit;
      goto success;
    }

  if ((st.st_mode & S_IFMT) == S_IFLNK)
    {
      size_t current_size = PATH_MAX + 1;
      cleanup_free char *p = malloc (current_size);

      while (1)
        {
          char *new;

          ret = readlinkat (node_dirfd (node), node->path, p, current_size - 1);
          if (ret < 0)
            goto exit;
          if (ret < current_size - 1)
            break;

          current_size = current_size * 2;
          new = realloc (p, current_size);
          if (new == NULL)
            goto exit;
          p = new;
        }
      p[ret] = '\0';
      ret = symlinkat (p, get_upper_layer (lo)->fd, node->path);
      if (ret < 0)
        goto exit;
      goto success;
    }

  ret = sfd = TEMP_FAILURE_RETRY (openat (node_dirfd (node), node->path, O_RDONLY|O_NONBLOCK));
  if (sfd < 0)
    goto exit;

  ret = dfd = TEMP_FAILURE_RETRY (openat (lo->workdir_fd, wd_tmp_file_name, O_CREAT|O_WRONLY, st.st_mode));
  if (dfd < 0)
    goto exit;

  ret = fchown (dfd, st.st_uid, st.st_gid);
  if (ret < 0)
      goto exit;

  buf = malloc (buf_size);
  if (buf == NULL)
    goto exit;

  if (support_reflinks)
    {
      if (ioctl (dfd, FICLONE, sfd) >= 0)
        data_copied = true;
      else if (errno == ENOTSUP || errno == EINVAL)
        {
          /* Fallback to data copy and don't attempt again FICLONE.  */
          support_reflinks = false;
        }
    }

#ifdef HAVE_SYS_SENDFILE_H
  if (! data_copied)
    {
      off_t copied = 0;

      while (copied < st.st_size)
        {
          off_t tocopy = st.st_size - copied;
          ssize_t n = TEMP_FAILURE_RETRY (sendfile (dfd, sfd, NULL, tocopy > SIZE_MAX ? SIZE_MAX : (size_t) tocopy));
          if (n < 0)
            {
              /* On failure, fallback to the read/write loop.  */
              ret = copy_fd_to_fd (sfd, dfd, buf, buf_size);
              if (ret < 0)
                goto exit;
              break;
            }
          copied += n;
	}
      data_copied = true;
    }
#endif

  if (! data_copied)
    {
      ret = copy_fd_to_fd (sfd, dfd, buf, buf_size);
      if (ret < 0)
        goto exit;
    }

  times[0] = st.st_atim;
  times[1] = st.st_mtim;
  ret = futimens (dfd, times);
  if (ret < 0)
    goto exit;

  ret = copy_xattr (sfd, dfd, buf, buf_size);
  if (ret < 0)
    goto exit;

  /* Finally, move the file to its destination.  */
  ret = renameat (lo->workdir_fd, wd_tmp_file_name, get_upper_layer (lo)->fd, node->path);
  if (ret < 0)
    goto exit;

  if (node->parent)
    {
      cleanup_free char *whpath = NULL;

      ret = asprintf (&whpath, "%s/.wh.%s", node->parent->path, node->name);
      if (ret < 0)
        goto exit;
      if (unlinkat (get_upper_layer (lo)->fd, whpath, 0) < 0 && errno != ENOENT)
        goto exit;
    }

 success:
  ret = 0;

  node->layer = get_upper_layer (lo);

 exit:
  saved_errno = errno;
  if (ret < 0)
    unlinkat (lo->workdir_fd, wd_tmp_file_name, 0);
  errno = saved_errno;

  return ret;
}

static struct ovl_node *
get_node_up (struct ovl_data *lo, struct ovl_node *node)
{
  int ret;

  if (node->layer == get_upper_layer (lo))
    return node;

  ret = copyup (lo, node);
  if (ret < 0)
    return NULL;

  assert (node->layer == get_upper_layer (lo));

  return node;
}

static size_t
count_dir_entries (struct ovl_node *node, size_t *whiteouts)
{
  size_t c = 0;
  struct ovl_node *it;

  if (whiteouts)
    *whiteouts = 0;

  for (it = hash_get_first (node->children); it; it = hash_get_next (node->children, it))
    {
      if (it->whiteout)
        {
          if (whiteouts)
            (*whiteouts)++;
          continue;
        }
      if (strcmp (it->name, ".") == 0)
        continue;
      if (strcmp (it->name, "..") == 0)
        continue;
      c++;
    }
  return c;
}

static int
update_paths (struct ovl_node *node)
{
  struct ovl_node *it;

  if (node == NULL)
    return 0;

  if (node->parent)
    {
      free (node->path);
      if (asprintf (&node->path, "%s/%s", node->parent->path, node->name) < 0)
        {
          node->path = NULL;
          return -1;
        }
    }

  if (node->children)
    {
      for (it = hash_get_first (node->children); it; it = hash_get_next (node->children, it))
        {
          if (update_paths (it) < 0)
            return -1;
        }
    }

  return 0;
}

static int
empty_dir (struct ovl_data *lo, struct ovl_node *node)
{
  cleanup_dir DIR *dp = NULL;
  cleanup_close int cleanup_fd = -1;
  struct dirent *dent;

  cleanup_fd = TEMP_FAILURE_RETRY (openat (get_upper_layer (lo)->fd, node->path, O_DIRECTORY));
  if (cleanup_fd < 0)
    return -1;

  if (set_fd_opaque (cleanup_fd) < 0)
    return -1;

  dp = fdopendir (cleanup_fd);
  if (dp == NULL)
    return -1;

  cleanup_fd = -1;  /* It is not owned by dp.  */

  for (;;)
    {
      errno = 0;
      dent = readdir (dp);
      if (dent == NULL)
        {
          if (errno)
            return -1;

          break;
        }
      if (strcmp (dent->d_name, ".") == 0)
        continue;
      if (strcmp (dent->d_name, "..") == 0)
        continue;
      if (unlinkat (dirfd (dp), dent->d_name, 0) < 0)
        unlinkat (dirfd (dp), dent->d_name, AT_REMOVEDIR);
    }

  return 0;
}

static void
do_rm (fuse_req_t req, fuse_ino_t parent, const char *name, bool dirp)
{
  struct ovl_node *node;
  struct ovl_data *lo = ovl_data (req);
  struct ovl_node *pnode;
  int ret = 0;
  struct ovl_node key, *rm;

  node = do_lookup_file (lo, parent, name);
  if (node == NULL)
    {
      fuse_reply_err (req, ENOENT);
      return;
    }

  if (dirp)
    {
      size_t c;

      /* Re-load the directory.  */
      node = load_dir (lo, node, node->layer, node->path, node->name);
      if (node == NULL)
        {
          fuse_reply_err (req, errno);
          return;
        }

      c = count_dir_entries (node, NULL);
      if (c)
        {
          fuse_reply_err (req, ENOTEMPTY);
          return;
        }
    }

  if (node->layer == get_upper_layer (lo))
    {
      node->hidden_dirfd = node->layer->fd;

      if (! dirp)
        node->do_unlink = 1;
      else
        {
          if (empty_dir (lo, node) < 0)
            {
              fuse_reply_err (req, errno);
              return;
            }

          node->do_rmdir = 1;
        }
    }

  pnode = do_lookup_file (lo, parent, NULL);
  if (pnode == NULL)
    {
      fuse_reply_err (req, ENOENT);
      return;
    }

  pnode = get_node_up (lo, pnode);
  if (pnode == NULL)
    {
      fuse_reply_err (req, ENOENT);
      return;
    }

  /* If the node is still accessible then be sure we,
     can write to it.  Fix it to be done when a write is
     really done, not now.  */
  node = get_node_up (lo, node);
  if (node == NULL)
    {
      fuse_reply_err (req, errno);
      return;
    }

  key.name = (char *) name;
  rm = hash_delete (pnode->children, &key);
  if (rm)
    {
      ret = hide_node (lo, rm, true);
      if (ret < 0)
        {
          fuse_reply_err (req, errno);
          return;
        }

      node_free (rm);
    }

  fuse_reply_err (req, ret);
}

static void
ovl_unlink (fuse_req_t req, fuse_ino_t parent, const char *name)
{
  if (ovl_debug (req))
    fprintf (stderr, "ovl_unlink(parent=%" PRIu64 ", name=%s)\n",
	     parent, name);
  do_rm (req, parent, name, false);
}

static void
ovl_rmdir (fuse_req_t req, fuse_ino_t parent, const char *name)
{
  if (ovl_debug (req))
    fprintf (stderr, "ovl_rmdir(parent=%" PRIu64 ", name=%s)\n",
	     parent, name);
  do_rm (req, parent, name, true);
}

static void
ovl_setxattr (fuse_req_t req, fuse_ino_t ino, const char *name,
             const char *value, size_t size, int flags)
{
  struct ovl_data *lo = ovl_data (req);
  struct ovl_node *node;
  cleanup_close int fd = -1;

  if (ovl_debug (req))
    fprintf (stderr, "ovl_setxattr(ino=%" PRIu64 "s, name=%s, value=%s, size=%zu, flags=%d)\n", ino, name,
             value, size, flags);

  if (has_prefix (name, PRIVILEGED_XATTR_PREFIX) || has_prefix (name, XATTR_PREFIX))
    {
      fuse_reply_err (req, EPERM);
      return;
    }

  node = do_lookup_file (lo, ino, NULL);
  if (node == NULL)
    {
      fuse_reply_err (req, ENOENT);
      return;
    }

  node = get_node_up (lo, node);
  if (node == NULL)
    {
      fuse_reply_err (req, errno);
      return;
    }

  fd = TEMP_FAILURE_RETRY (openat (node_dirfd (node), node->path, O_NONBLOCK));
  if (fd < 0)
    {
      fuse_reply_err (req, errno);
      return;
    }

  if (fsetxattr (fd, name, value, size, flags) < 0)
    {
      fuse_reply_err (req, errno);
      close (fd);
      return;
    }
  fuse_reply_err (req, 0);
}

static void
ovl_removexattr (fuse_req_t req, fuse_ino_t ino, const char *name)
{
  struct ovl_node *node;
  struct ovl_data *lo = ovl_data (req);
  cleanup_close int fd = -1;

  if (ovl_debug (req))
    fprintf (stderr, "ovl_removexattr(ino=%" PRIu64 "s, name=%s)\n", ino, name);

  node = do_lookup_file (lo, ino, NULL);
  if (node == NULL)
    {
      fuse_reply_err (req, ENOENT);
      return;
    }

  node = get_node_up (lo, node);
  if (node == NULL)
    {
      fuse_reply_err (req, errno);
      return;
    }

  fd = TEMP_FAILURE_RETRY (openat (node_dirfd (node), node->path, O_NONBLOCK));
  if (fd < 0)
    {
      fuse_reply_err (req, errno);
      return;
    }

  if (fremovexattr (fd, name) < 0)
    {
      close (fd);
      fuse_reply_err (req, errno);
      return;
    }

  fuse_reply_err (req, 0);
}

static int
ovl_do_open (fuse_req_t req, fuse_ino_t parent, const char *name, int flags, mode_t mode)
{
  struct ovl_data *lo = ovl_data (req);
  struct ovl_node *n;
  bool readonly = (flags & (O_APPEND | O_RDWR | O_WRONLY | O_CREAT | O_TRUNC)) == 0;
  cleanup_free char *path = NULL;
  cleanup_close int fd = -1;
  const struct fuse_ctx *ctx = fuse_req_ctx (req);

  flags |= O_NOFOLLOW;

  if (name && has_prefix (name, ".wh."))
    {
      errno = EINVAL;
      return - 1;
    }

  n = do_lookup_file (lo, parent, name);
  if (n && n->hidden)
    {
      n = NULL;
    }
  if (n && !n->whiteout && (flags & O_CREAT))
    {
      errno = EEXIST;
      return -1;
    }

  if (!n)
    {
      int ret;
      struct ovl_node *p;
      const struct fuse_ctx *ctx = fuse_req_ctx (req);
      char wd_tmp_file_name[32];

      if ((flags & O_CREAT) == 0)
        {
          errno = ENOENT;
          return -1;
        }

      p = do_lookup_file (lo, parent, NULL);
      if (p == NULL)
        {
          errno = ENOENT;
          return -1;
        }

      p = get_node_up (lo, p);
      if (p == NULL)
        return -1;

      sprintf (wd_tmp_file_name, "%lu", get_next_wd_counter ());

      fd = TEMP_FAILURE_RETRY (openat (lo->workdir_fd, wd_tmp_file_name, flags, mode & ~ctx->umask));
      if (fd < 0)
        return -1;

      if (fchown (fd, get_uid (lo, ctx->uid), get_gid (lo, ctx->gid)) < 0)
        {
          unlinkat (lo->workdir_fd, wd_tmp_file_name, 0);
          return -1;
        }

      ret = asprintf (&path, "%s/%s", p->path, name);
      if (ret < 0)
        {
          unlinkat (lo->workdir_fd, wd_tmp_file_name, 0);
          return ret;
        }
      if (unlinkat (get_upper_layer (lo)->fd, path, 0) < 0 && errno != ENOENT)
        return -1;

      if (delete_whiteout (lo, -1, p, name) < 0)
        return -1;

      if (renameat (lo->workdir_fd, wd_tmp_file_name, get_upper_layer (lo)->fd, path) < 0)
        {
          unlinkat (lo->workdir_fd, wd_tmp_file_name, 0);
          return -1;
        }

      n = make_ovl_node (path, get_upper_layer (lo), name, 0, false, p);
      if (n == NULL)
        {
          errno = ENOMEM;
          close (fd);
          return -1;
        }
      n = insert_node (p, n, true);
      if (n == NULL)
        {
          errno = ENOMEM;
          close (fd);
          return -1;
        }
      ret = fd;
      fd = -1; /*  We use a temporary variable so we don't close it at cleanup.  */
      return ret;
    }

  /* readonly, we can use both lowerdir and upperdir.  */
  if (readonly)
    return TEMP_FAILURE_RETRY (openat (node_dirfd (n), n->path, flags, mode));
  else
    {
      n = get_node_up (lo, n);
      if (n == NULL)
        return -1;

      return TEMP_FAILURE_RETRY (openat (node_dirfd (n), n->path, flags, mode));
    }
}

static void
ovl_read (fuse_req_t req, fuse_ino_t ino, size_t size,
	 off_t offset, struct fuse_file_info *fi)
{
  struct fuse_bufvec buf = FUSE_BUFVEC_INIT (size);
  if (ovl_debug (req))
    fprintf (stderr, "ovl_read(ino=%" PRIu64 ", size=%zd, "
	     "off=%lu)\n", ino, size, (unsigned long) offset);
  buf.buf[0].flags = FUSE_BUF_IS_FD | FUSE_BUF_FD_SEEK;
  buf.buf[0].fd = fi->fh;
  buf.buf[0].pos = offset;
  fuse_reply_data (req, &buf, FUSE_BUF_SPLICE_MOVE);
}

static void
ovl_write_buf (fuse_req_t req, fuse_ino_t ino,
	      struct fuse_bufvec *in_buf, off_t off,
	      struct fuse_file_info *fi)
{
  (void) ino;
  ssize_t res;
  struct fuse_bufvec out_buf = FUSE_BUFVEC_INIT (fuse_buf_size (in_buf));
  out_buf.buf[0].flags = FUSE_BUF_IS_FD | FUSE_BUF_FD_SEEK;
  out_buf.buf[0].fd = fi->fh;
  out_buf.buf[0].pos = off;

  if (ovl_debug (req))
    fprintf (stderr, "ovl_write_buf(ino=%" PRIu64 ", size=%zd, off=%lu, fd=%d)\n",
	     ino, out_buf.buf[0].size, (unsigned long) off, (int) fi->fh);

  errno = 0;
  res = fuse_buf_copy (&out_buf, in_buf, FUSE_BUF_SPLICE_MOVE | FUSE_BUF_SPLICE_NONBLOCK);
  if (res < 0)
    fuse_reply_err (req, errno);
  else
    fuse_reply_write (req, (size_t) res);
}

static void
ovl_release (fuse_req_t req, fuse_ino_t ino, struct fuse_file_info *fi)
{
  (void) ino;
  close (fi->fh);
  fuse_reply_err (req, 0);
}

static int
do_getattr (fuse_req_t req, struct fuse_entry_param *e, struct ovl_node *node)
{
  struct ovl_data *lo = ovl_data (req);
  int err = 0;

  memset (e, 0, sizeof (*e));

  err = rpl_stat (req, node, &e->attr);
  if (err < 0)
    return err;

  e->ino = (fuse_ino_t) node;
  e->attr_timeout = get_timeout (lo);
  e->entry_timeout = get_timeout (lo);

  return 0;
}

static void
ovl_create (fuse_req_t req, fuse_ino_t parent, const char *name,
	   mode_t mode, struct fuse_file_info *fi)
{
  cleanup_close int fd = -1;
  struct fuse_entry_param e;
  struct ovl_data *lo = ovl_data (req);
  struct ovl_node *node;

  if (ovl_debug (req))
    fprintf (stderr, "ovl_create(parent=%" PRIu64 ", name=%s)\n",
	     parent, name);

  fi->flags = fi->flags | O_CREAT;

  fd = ovl_do_open (req, parent, name, fi->flags, mode);
  if (fd < 0)
    {
      fuse_reply_err (req, errno);
      return;
    }

  node = do_lookup_file (lo, parent, name);
  if (node == NULL || do_getattr (req, &e, node) < 0)
    {
      fuse_reply_err (req, errno);
      return;
    }
  fi->fh = fd;
  fd = -1;  /* Do not clean it up.  */

  node->lookups++;
  fuse_reply_create (req, &e, fi);
}

static void
ovl_open (fuse_req_t req, fuse_ino_t ino, struct fuse_file_info *fi)
{
  cleanup_close int fd = -1;

  if (ovl_debug (req))
    fprintf (stderr, "ovl_open(ino=%" PRIu64 "s)\n", ino);

  fd = ovl_do_open (req, ino, NULL, fi->flags, 0700);
  if (fd < 0)
    {
      fuse_reply_err (req, errno);
      return;
    }
  fi->fh = fd;
  fd = -1;  /* Do not clean it up.  */
  fuse_reply_open (req, fi);
}

static void
ovl_getattr (fuse_req_t req, fuse_ino_t ino, struct fuse_file_info *fi)
{
  struct ovl_data *lo = ovl_data (req);
  struct ovl_node *node;
  struct fuse_entry_param e;

  if (ovl_debug (req))
    fprintf (stderr, "ovl_getattr(ino=%" PRIu64 "s)\n", ino);

  node = do_lookup_file (lo, ino, NULL);
  if (node == NULL)
    {
      fuse_reply_err (req, ENOENT);
      return;
    }

  if (do_getattr (req, &e, node) < 0)
    {
      fuse_reply_err (req, errno);
      return;
    }

  fuse_reply_attr (req, &e.attr, get_timeout (lo));
}

static void
ovl_setattr (fuse_req_t req, fuse_ino_t ino, struct stat *attr, int to_set, struct fuse_file_info *fi)
{
  struct ovl_data *lo = ovl_data (req);
  struct ovl_node *node;
  struct fuse_entry_param e;
  struct stat old_st;
  struct timespec times[2];
  uid_t uid;
  gid_t gid;
  int dirfd;

  if (ovl_debug (req))
    fprintf (stderr, "ovl_setattr(ino=%" PRIu64 "s, to_set=%d)\n", ino, to_set);

  node = do_lookup_file (lo, ino, NULL);
  if (node == NULL)
    {
      fuse_reply_err (req, ENOENT);
      return;
    }

  node = get_node_up (lo, node);
  if (node == NULL)
    {
      fuse_reply_err (req, errno);
      return;
    }

  dirfd = node_dirfd (node);

  if (TEMP_FAILURE_RETRY (fstatat (dirfd, node->path, &old_st, AT_SYMLINK_NOFOLLOW)) < 0)
    {
      fuse_reply_err (req, errno);
      return;
    }

  if (to_set & FUSE_SET_ATTR_CTIME)
    {
      fuse_reply_err (req, EPERM);
      return;
    }

  memset (times, 0, sizeof (times));
  times[0].tv_sec = UTIME_OMIT;
  times[1].tv_sec = UTIME_OMIT;
  if (to_set & FUSE_SET_ATTR_ATIME)
    times[0] = attr->st_atim;
  else if (to_set & FUSE_SET_ATTR_ATIME_NOW)
    times[0].tv_sec = UTIME_NOW;

  if (to_set & FUSE_SET_ATTR_MTIME)
    times[1] = attr->st_mtim;
  else if (to_set & FUSE_SET_ATTR_MTIME_NOW)
    times[1].tv_sec = UTIME_NOW;

  if (times[0].tv_sec != UTIME_OMIT || times[1].tv_sec != UTIME_OMIT)
    {
      if ((utimensat (dirfd, node->path, times, AT_SYMLINK_NOFOLLOW) < 0))
        {
          fuse_reply_err (req, errno);
          return;
        }
    }

  if ((to_set & FUSE_SET_ATTR_MODE) && fchmodat (dirfd, node->path, attr->st_mode, 0) < 0)
    {
      fuse_reply_err (req, errno);
      return;
    }
  if (to_set & FUSE_SET_ATTR_SIZE)
    {
      int fd, ret, saved_errno;

      if (fi == NULL)
        {
          fd = TEMP_FAILURE_RETRY (openat (dirfd, node->path, O_WRONLY|O_NONBLOCK));
          if (fd < 0)
            {
              fuse_reply_err (req, errno);
              return;
            }
        }
      else
          fd = fi->fh;  // use existing fd if fuse_file_info is available

      ret = ftruncate (fd, attr->st_size);
      saved_errno = errno;

      if (fi == NULL)
        close (fd);

      if (ret < 0)
        {
          fuse_reply_err (req, saved_errno);
          return;
        }
    }

  uid = old_st.st_uid;
  gid = old_st.st_gid;
  if (to_set & FUSE_SET_ATTR_UID)
    uid = get_uid (lo, attr->st_uid);
  if (to_set & FUSE_SET_ATTR_GID)
    gid = get_gid (lo, attr->st_gid);

  if (uid != old_st.st_uid || gid != old_st.st_gid)
    {
      if (fchownat (dirfd, node->path, uid, gid, AT_SYMLINK_NOFOLLOW) < 0)
        {
          fuse_reply_err (req, errno);
          return;
        }
    }

  if (do_getattr (req, &e, node) < 0)
    {
      fuse_reply_err (req, errno);
      return;
    }

  fuse_reply_attr (req, &e.attr, get_timeout (lo));
}

static void
ovl_link (fuse_req_t req, fuse_ino_t ino, fuse_ino_t newparent, const char *newname)
{
  struct ovl_data *lo = ovl_data (req);
  struct ovl_node *node, *newparentnode, *destnode;
  cleanup_free char *path = NULL;
  int ret;
  struct fuse_entry_param e;
  char wd_tmp_file_name[32];

  if (ovl_debug (req))
    fprintf (stderr, "ovl_link(ino=%" PRIu64 "s, newparent=%" PRIu64 "s, newname=%s)\n", ino, newparent, newname);

  node = do_lookup_file (lo, ino, NULL);
  if (node == NULL)
    {
      fuse_reply_err (req, ENOENT);
      return;
    }

  node = get_node_up (lo, node);
  if (node == NULL)
    {
      fuse_reply_err (req, errno);
      return;
    }

  newparentnode = do_lookup_file (lo, newparent, NULL);
  if (newparentnode == NULL)
    {
      fuse_reply_err (req, ENOENT);
      return;
    }

  destnode = do_lookup_file (lo, newparent, newname);
  if (destnode && !destnode->whiteout)
    {
      fuse_reply_err (req, EEXIST);
      return;
    }

  newparentnode = get_node_up (lo, newparentnode);
  if (newparentnode == NULL)
    {
      fuse_reply_err (req, errno);
      return;
    }

  if (delete_whiteout (lo, -1, newparentnode, newname) < 0)
    {
      fuse_reply_err (req, errno);
      return;
    }

  sprintf (wd_tmp_file_name, "%lu", get_next_wd_counter ());

  ret = asprintf (&path, "%s/%s", newparentnode->path, newname);
  if (ret < 0)
    {
      fuse_reply_err (req, errno);
      return;
    }

  if (linkat (node_dirfd (newparentnode), node->path, lo->workdir_fd, wd_tmp_file_name, 0) < 0)
    {
      fuse_reply_err (req, errno);
      return;
    }

  if (renameat (lo->workdir_fd, wd_tmp_file_name, node_dirfd (newparentnode), path) < 0)
    {
      fuse_reply_err (req, errno);
      return;
    }
  else
    {
      cleanup_close int dfd = TEMP_FAILURE_RETRY (openat (node_dirfd (newparentnode), path, O_WRONLY|O_NONBLOCK));
      if (dfd >= 0)
        {
          bool set = false;
          cleanup_close int sfd = TEMP_FAILURE_RETRY (openat (node_dirfd (node), node->path, O_RDONLY|O_NONBLOCK));
          if (sfd >= 0)
            {
              cleanup_free char *origin_path = NULL;
              ssize_t s;

              s = safe_read_xattr (&origin_path, sfd, PRIVILEGED_ORIGIN_XATTR, PATH_MAX + 1);
              if (s > 0)
                fsetxattr (dfd, PRIVILEGED_ORIGIN_XATTR, origin_path, s, 0);
              else
                {
                  s = safe_read_xattr (&origin_path, sfd, ORIGIN_XATTR, PATH_MAX + 1);
                  if (s > 0)
                    fsetxattr (dfd, PRIVILEGED_ORIGIN_XATTR, origin_path, s, 0);
                  else
                    fsetxattr (dfd, ORIGIN_XATTR, node->path, strlen (node->path), 0);
                }
            }
        }
    }

  node = make_ovl_node (path, get_upper_layer (lo), newname, node->ino, false, newparentnode);
  if (node == NULL)
    {
      fuse_reply_err (req, ENOMEM);
      return;
    }

  node = insert_node (newparentnode, node, true);
  if (node == NULL)
    {
      fuse_reply_err (req, ENOMEM);
      return;
    }

  memset (&e, 0, sizeof (e));

  ret = rpl_stat (req, node, &e.attr);
  if (ret)
    {
      fuse_reply_err (req, errno);
      return;
    }

  e.ino = NODE_TO_INODE (node);
  node->lookups++;
  e.attr_timeout = get_timeout (lo);
  e.entry_timeout = get_timeout (lo);
  fuse_reply_entry (req, &e);
}

static void
ovl_symlink (fuse_req_t req, const char *link, fuse_ino_t parent, const char *name)
{
  struct ovl_data *lo = ovl_data (req);
  struct ovl_node *pnode, *node;
  cleanup_free char *path = NULL;
  int ret;
  struct fuse_entry_param e;
  const struct fuse_ctx *ctx = fuse_req_ctx (req);
  char wd_tmp_file_name[32];

  if (ovl_debug (req))
    fprintf (stderr, "ovl_symlink(link=%s, ino=%" PRIu64 "s, name=%s)\n", link, parent, name);

  pnode = do_lookup_file (lo, parent, NULL);
  if (pnode == NULL)
    {
      fuse_reply_err (req, ENOENT);
      return;
    }

  pnode = get_node_up (lo, pnode);
  if (pnode == NULL)
    {
      fuse_reply_err (req, errno);
      return;
    }

  node = do_lookup_file (lo, parent, name);
  if (node != NULL && !node->whiteout)
    {
      fuse_reply_err (req, EEXIST);
      return;
    }

  sprintf (wd_tmp_file_name, "%lu", get_next_wd_counter ());

  unlinkat (lo->workdir_fd, wd_tmp_file_name, 0);
  ret = symlinkat (link, lo->workdir_fd, wd_tmp_file_name);
  if (ret < 0)
    {
      fuse_reply_err (req, errno);
      return;
    }

  if (fchownat (lo->workdir_fd, wd_tmp_file_name, get_uid (lo, ctx->uid), get_gid (lo, ctx->gid), AT_SYMLINK_NOFOLLOW) < 0)
    {
      unlinkat (lo->workdir_fd, wd_tmp_file_name, 0);
      fuse_reply_err (req, errno);
      return;
    }

  if (delete_whiteout (lo, -1, pnode, name) < 0)
    {
      unlinkat (lo->workdir_fd, wd_tmp_file_name, 0);
      fuse_reply_err (req, errno);
      return;
    }

  ret = asprintf (&path, "%s/%s", pnode->path, name);
  if (ret < 0)
    {
      fuse_reply_err (req, errno);
      return;
    }

  ret = renameat (lo->workdir_fd, wd_tmp_file_name, get_upper_layer (lo)->fd, path);
  if (ret < 0)
    {
      fuse_reply_err (req, errno);
      return;
    }

  node = make_ovl_node (path, get_upper_layer (lo), name, 0, false, pnode);
  if (node == NULL)
    {
      fuse_reply_err (req, ENOMEM);
      return;
    }

  node = insert_node (pnode, node, true);
  if (node == NULL)
    {
      fuse_reply_err (req, ENOMEM);
      return;
    }

  memset (&e, 0, sizeof (e));

  ret = rpl_stat (req, node, &e.attr);
  if (ret)
    {
      fuse_reply_err (req, errno);
      return;
    }

  e.ino = NODE_TO_INODE (node);
  node->lookups++;
  e.attr_timeout = get_timeout (lo);
  e.entry_timeout = get_timeout (lo);
  fuse_reply_entry (req, &e);
}

static void
ovl_rename_exchange (fuse_req_t req, fuse_ino_t parent, const char *name,
                     fuse_ino_t newparent, const char *newname,
                     unsigned int flags)
{
  struct ovl_node *pnode, *node, *destnode, *destpnode;
  struct ovl_data *lo = ovl_data (req);
  int ret;
  int saved_errno;
  int srcfd = -1;
  int destfd = -1;
  struct ovl_node *rm1, *rm2;
  char *tmp;

  node = do_lookup_file (lo, parent, name);
  if (node == NULL)
    {
      fuse_reply_err (req, ENOENT);
      return;
    }

  if (node_dirp (node))
    {
      node = load_dir (lo, node, node->layer, node->path, node->name);
      if (node == NULL)
        {
          fuse_reply_err (req, errno);
          return;
        }

      if (node->layer != get_upper_layer (lo) || node->present_lowerdir)
        {
          fuse_reply_err (req, EXDEV);
          return;
        }
    }
  pnode = node->parent;

  destpnode = do_lookup_file (lo, newparent, NULL);
  destnode = NULL;

  pnode = get_node_up (lo, pnode);
  if (pnode == NULL)
    goto error;

  ret = TEMP_FAILURE_RETRY (openat (node_dirfd (pnode), pnode->path, O_DIRECTORY));
  if (ret < 0)
    goto error;
  srcfd = ret;

  destpnode = get_node_up (lo, destpnode);
  if (destpnode == NULL)
    goto error;

  ret = TEMP_FAILURE_RETRY (openat (node_dirfd (destpnode), destpnode->path, O_DIRECTORY));
  if (ret < 0)
    goto error;
  destfd = ret;

  destnode = do_lookup_file (lo, newparent, newname);

  node = get_node_up (lo, node);
  if (node == NULL)
    goto error;

  if (destnode == NULL)
    {
      errno = ENOENT;
      goto error;
    }
  if (node_dirp (node) && destnode->present_lowerdir)
    {
      fuse_reply_err (req, EXDEV);
      return;
    }
  destnode = get_node_up (lo, destnode);
  if (destnode == NULL)
    goto error;


  ret = syscall (SYS_renameat2, srcfd, name, destfd, newname, flags);
  if (ret < 0)
    goto error;

  rm1 = hash_delete (destpnode->children, destnode);
  rm2 = hash_delete (pnode->children, node);

  tmp = node->path;
  node->path = destnode->path;
  destnode->path = tmp;

  tmp = node->name;
  node->name = destnode->name;
  destnode->name = tmp;

  node = insert_node (destpnode, node, true);
  if (node == NULL)
    {
      node_free (rm1);
      node_free (rm2);
      goto error;
    }
  destnode = insert_node (pnode, destnode, true);
  if (destnode == NULL)
    {
      node_free (rm1);
      node_free (rm2);
      goto error;
    }
  if ((update_paths (node) < 0) || (update_paths (destnode) < 0))
    goto error;

  if (delete_whiteout (lo, destfd, NULL, newname) < 0)
    goto error;

  ret = 0;
  goto cleanup;

 error:
  ret = -1;

 cleanup:
  saved_errno = errno;
  if (srcfd >= 0)
    close (srcfd);
  if (destfd >= 0)
    close (destfd);
  errno = saved_errno;

  fuse_reply_err (req, ret == 0 ? 0 : errno);
}

static void
ovl_rename_direct (fuse_req_t req, fuse_ino_t parent, const char *name,
                   fuse_ino_t newparent, const char *newname,
                   unsigned int flags)
{
  struct ovl_node *pnode, *node, *destnode, *destpnode;
  struct ovl_data *lo = ovl_data (req);
  int ret;
  int saved_errno;
  int srcfd = -1;
  int destfd = -1;
  struct ovl_node key;
  bool destnode_is_whiteout = false;

  node = do_lookup_file (lo, parent, name);
  if (node == NULL || node->whiteout)
    {
      fuse_reply_err (req, ENOENT);
      return;
    }

  if (node_dirp (node))
    {
      node = load_dir (lo, node, node->layer, node->path, node->name);
      if (node == NULL)
        {
          fuse_reply_err (req, errno);
          return;
        }

      if (node->layer != get_upper_layer (lo) || node->present_lowerdir)
        {
          fuse_reply_err (req, EXDEV);
          return;
        }
    }
  pnode = node->parent;

  destpnode = do_lookup_file (lo, newparent, NULL);
  destnode = NULL;

  pnode = get_node_up (lo, pnode);
  if (pnode == NULL)
    goto error;

  ret = TEMP_FAILURE_RETRY (openat (node_dirfd (pnode), pnode->path, O_DIRECTORY));
  if (ret < 0)
    goto error;
  srcfd = ret;

  destpnode = get_node_up (lo, destpnode);
  if (destpnode == NULL)
    goto error;

  ret = TEMP_FAILURE_RETRY (openat (node_dirfd (destpnode), destpnode->path, O_DIRECTORY));
  if (ret < 0)
    goto error;
  destfd = ret;

  key.name = (char *) newname;
  destnode = hash_lookup (destpnode->children, &key);

  node = get_node_up (lo, node);
  if (node == NULL)
    goto error;

  if (flags & RENAME_NOREPLACE && destnode && !destnode->whiteout)
    {
      errno = EEXIST;
      goto error;
    }

  if (destnode)
    {
      size_t destnode_whiteouts = 0;

      if (!destnode->whiteout && destnode->ino == node->ino)
        goto error;

      destnode_is_whiteout = destnode->whiteout;

      if (!destnode->whiteout && node_dirp (destnode))
        {
          destnode = load_dir (lo, destnode, destnode->layer, destnode->path, destnode->name);
          if (destnode == NULL)
            goto error;

          if (count_dir_entries (destnode, &destnode_whiteouts) > 0)
            {
              errno = ENOTEMPTY;
              goto error;
            }
          if (destnode_whiteouts && empty_dir (lo, destnode) < 0)
            goto error;
        }

      if (node_dirp (node) && create_missing_whiteouts (lo, node, destnode->path) < 0)
        goto error;

      if (destnode->lookups > 0)
        node_free (destnode);
      else
        {
          node_free (destnode);
          destnode = NULL;
        }

      if (destnode && !destnode_is_whiteout)
        {
          /* If the node is still accessible then be sure we
             can write to it.  Fix it to be done when a write is
             really done, not now.  */
          destnode = get_node_up (lo, destnode);
          if (destnode == NULL)
            {
              fuse_reply_err (req, errno);
              return;
            }

          if (hide_node (lo, destnode, false) < 0)
            goto error;
        }
    }

  /* If the destnode is a whiteout, first attempt to EXCHANGE the source and the destination,
   so that with one operation we get both the rename and the whiteout created.  */
  if (destnode_is_whiteout)
    {
      ret = syscall (SYS_renameat2, srcfd, name, destfd, newname, flags|RENAME_EXCHANGE);
      if (ret == 0)
        goto done;

      /* If it fails for any reason, fallback to the more articulated method.  */
    }

  /* If the node is a directory we must ensure there is no whiteout at the
     destination, otherwise the renameat2 will fail.  Create a .wh.$NAME style
     whiteout file until the renameat2 is completed.  */
  if (node_dirp (node))
    {
      ret = create_whiteout (lo, destpnode, newname, true, true);
      if (ret < 0)
        goto error;
      unlinkat (destfd, newname, 0);
    }

  /* Try to create the whiteout atomically, if it fails do the
     rename+mknod separately.  */
  ret = syscall (SYS_renameat2, srcfd, name, destfd,
                 newname, flags|RENAME_WHITEOUT);
  if (ret < 0)
    {
      ret = syscall (SYS_renameat2, srcfd, name, destfd, newname, flags);
      if (ret < 0)
        goto error;

      ret = create_whiteout (lo, pnode, name, false, true);
      if (ret < 0)
        goto error;
    }

  if (delete_whiteout (lo, destfd, NULL, newname) < 0)
    goto error;

 done:
  hash_delete (pnode->children, node);

  free (node->name);
  node->name = strdup (newname);
  if (node->name == NULL)
    goto error;

  node = insert_node (destpnode, node, true);
  if (node == NULL)
    goto error;
  if (update_paths (node) < 0)
    goto error;

  ret = 0;
  goto cleanup;

 error:
  ret = -1;

 cleanup:
  saved_errno = errno;
  if (srcfd >= 0)
    close (srcfd);
  if (destfd >= 0)
    close (destfd);
  errno = saved_errno;

  fuse_reply_err (req, ret == 0 ? 0 : errno);
}

static void
ovl_rename (fuse_req_t req, fuse_ino_t parent, const char *name,
           fuse_ino_t newparent, const char *newname,
           unsigned int flags)
{
  if (ovl_debug (req))
    fprintf (stderr, "ovl_rename(ino=%" PRIu64 "s, name=%s , ino=%" PRIu64 "s, name=%s)\n", parent, name, newparent, newname);

  if (flags & RENAME_EXCHANGE)
    ovl_rename_exchange (req, parent, name, newparent, newname, flags);
  else
    ovl_rename_direct (req, parent, name, newparent, newname, flags);
}

static void
ovl_statfs (fuse_req_t req, fuse_ino_t ino)
{
  int ret;
  struct statvfs sfs;
  struct ovl_data *lo = ovl_data (req);

  if (ovl_debug (req))
    fprintf (stderr, "ovl_statfs(ino=%" PRIu64 "s)\n", ino);

  ret = fstatvfs (get_upper_layer (lo)->fd, &sfs);
  if (ret < 0)
    {
      fuse_reply_err (req, errno);
      return;
    }
  fuse_reply_statfs (req, &sfs);
}

static void
ovl_readlink (fuse_req_t req, fuse_ino_t ino)
{
  struct ovl_data *lo = ovl_data (req);
  cleanup_free char *buf = NULL;
  struct ovl_node *node;
  size_t current_size;
  int ret = 0;

  if (ovl_debug (req))
    fprintf (stderr, "ovl_readlink(ino=%" PRIu64 "s)\n", ino);

  node = do_lookup_file (lo, ino, NULL);
  if (node == NULL)
    {
      fuse_reply_err (req, ENOENT);
      return;
    }

  current_size = PATH_MAX + 1;
  buf = malloc (current_size);
  if (buf == NULL)
    {
      fuse_reply_err (req, ENOENT);
      return;
    }

  while (1)
    {
      char *tmp;

      ret = readlinkat (node_dirfd (node), node->path, buf, current_size - 1);
      if (ret == -1)
        {
          fuse_reply_err (req, errno);
          return;
        }
      if (ret < current_size - 1)
        break;

      current_size *= 2;
      tmp = realloc (buf, current_size);
      if (tmp == NULL)
        {
          fuse_reply_err (req, errno);
          return;
        }
      buf = tmp;
    }

  buf[ret] = '\0';
  fuse_reply_readlink (req, buf);
}

static int
hide_all (struct ovl_data *lo, struct ovl_node *node)
{
  struct ovl_node **nodes;
  size_t i, nodes_size;

  node = load_dir (lo, node, node->layer, node->path, node->name);
  if (node == NULL)
    return -1;

  nodes_size = hash_get_n_entries (node->children) + 2;
  nodes = malloc (sizeof (struct ovl_node *) * nodes_size);
  if (nodes == NULL)
    return -1;

  nodes_size = hash_get_entries (node->children, (void **) nodes, nodes_size);
  for (i = 0; i < nodes_size; i++)
    {
      struct ovl_node *it;
      int ret;

      it = nodes[i];
      ret = create_whiteout (lo, node, it->name, false, true);
      node_free (it);

      if (ret < 0)
        {
          free(nodes);
          return ret;
        }
    }

  free (nodes);
  return 0;
}

static void
ovl_mknod (fuse_req_t req, fuse_ino_t parent, const char *name, mode_t mode, dev_t rdev)
{
  struct ovl_node *node;
  struct ovl_data *lo = ovl_data (req);
  struct ovl_node *pnode;
  int ret = 0;
  cleanup_free char *path = NULL;
  struct fuse_entry_param e;
  const struct fuse_ctx *ctx = fuse_req_ctx (req);
  char wd_tmp_file_name[32];

  if (ovl_debug (req))
    fprintf (stderr, "ovl_mknod(ino=%" PRIu64 ", name=%s, mode=%d, rdev=%lu)\n",
	     parent, name, mode, rdev);

  node = do_lookup_file (lo, parent, name);
  if (node != NULL && !node->whiteout)
    {
      fuse_reply_err (req, EEXIST);
      return;
    }

  pnode = do_lookup_file (lo, parent, NULL);
  if (pnode == NULL)
    {
      fuse_reply_err (req, ENOENT);
      return;
    }

  pnode = get_node_up (lo, pnode);
  if (pnode == NULL)
    {
      fuse_reply_err (req, errno);
      return;
    }
  sprintf (wd_tmp_file_name, "%lu", get_next_wd_counter ());
  ret = mknodat (lo->workdir_fd, wd_tmp_file_name, mode & ~ctx->umask, rdev);
  if (ret < 0)
    {
      fuse_reply_err (req, errno);
      return;
    }

  if (fchownat (lo->workdir_fd, wd_tmp_file_name, get_uid (lo, ctx->uid), get_gid (lo, ctx->gid), 0) < 0)
    {
      fuse_reply_err (req, errno);
      unlinkat (lo->workdir_fd, wd_tmp_file_name, 0);
      return;
    }

  ret = asprintf (&path, "%s/%s", pnode->path, name);
  if (ret < 0)
    {
      fuse_reply_err (req, errno);
      unlinkat (lo->workdir_fd, wd_tmp_file_name, 0);
      return;
    }

  ret = renameat (lo->workdir_fd, wd_tmp_file_name, get_upper_layer (lo)->fd, path);
  if (ret < 0)
    {
      fuse_reply_err (req, errno);
      unlinkat (lo->workdir_fd, wd_tmp_file_name, 0);
      return;
    }

  node = make_ovl_node (path, get_upper_layer (lo), name, 0, false, pnode);
  if (node == NULL)
    {
      fuse_reply_err (req, ENOMEM);
      return;
    }

  node = insert_node (pnode, node, true);
  if (node == NULL)
    {
      fuse_reply_err (req, ENOMEM);
      return;
    }

  if (delete_whiteout (lo, -1, pnode, name) < 0)
    {
      fuse_reply_err (req, errno);
      return;
    }

  memset (&e, 0, sizeof (e));

  ret = rpl_stat (req, node, &e.attr);
  if (ret)
    {
      fuse_reply_err (req, errno);
      return;
    }

  e.ino = NODE_TO_INODE (node);
  e.attr_timeout = get_timeout (lo);
  e.entry_timeout = get_timeout (lo);
  node->lookups++;
  fuse_reply_entry (req, &e);
}

static void
ovl_mkdir (fuse_req_t req, fuse_ino_t parent, const char *name, mode_t mode)
{
  struct ovl_node *node;
  struct ovl_data *lo = ovl_data (req);
  struct ovl_node *pnode;
  int ret = 0;
  char *path;
  struct fuse_entry_param e;
  const struct fuse_ctx *ctx = fuse_req_ctx (req);

  if (ovl_debug (req))
    fprintf (stderr, "ovl_mkdir(ino=%" PRIu64 ", name=%s, mode=%d)\n",
	     parent, name, mode);

  node = do_lookup_file (lo, parent, name);
  if (node != NULL && !node->whiteout)
    {
      fuse_reply_err (req, EEXIST);
      return;
    }

  pnode = do_lookup_file (lo, parent, NULL);
  if (pnode == NULL)
    {
      fuse_reply_err (req, ENOENT);
      return;
    }

  pnode = get_node_up (lo, pnode);
  if (pnode == NULL)
    {
      fuse_reply_err (req, errno);
      return;
    }
  ret = asprintf (&path, "%s/%s", pnode->path, name);
  if (ret < 0)
    {
      fuse_reply_err (req, errno);
      return;
    }

  ret = create_directory (lo, get_upper_layer (lo)->fd, path, NULL, pnode, -1,
                          get_uid (lo, ctx->uid), get_gid (lo, ctx->gid), mode & ~ctx->umask);
  if (ret < 0)
    {
      fuse_reply_err (req, errno);
      return;
    }

  node = make_ovl_node (path, get_upper_layer (lo), name, 0, true, pnode);
  if (node == NULL)
    {
      fuse_reply_err (req, ENOMEM);
      return;
    }

  node = insert_node (pnode, node, true);
  if (node == NULL)
    {
      fuse_reply_err (req, ENOMEM);
      return;
    }
  ret = hide_all (lo, node);
  if (ret < 0)
    {
      fuse_reply_err (req, errno);
      return;
    }

  if (delete_whiteout (lo, -1, pnode, name) < 0)
    {
      fuse_reply_err (req, errno);
      return;
    }

  memset (&e, 0, sizeof (e));

  ret = rpl_stat (req, node, &e.attr);
  if (ret)
    {
      fuse_reply_err (req, errno);
      return;
    }

  e.ino = NODE_TO_INODE (node);
  e.attr_timeout = get_timeout (lo);
  e.entry_timeout = get_timeout (lo);
  node->lookups++;
  fuse_reply_entry (req, &e);
}

static void
ovl_fsync (fuse_req_t req, fuse_ino_t ino, int datasync, struct fuse_file_info *fi)
{
  int ret, fd;

  if (ovl_debug (req))
    fprintf (stderr, "ovl_fsync(ino=%" PRIu64 ", datasync=%d, fi=%p)\n",
             ino, datasync, fi);

  fd = fi->fh;
  ret = datasync ? fdatasync (fd) : fsync (fd);
  fuse_reply_err (req, ret == 0 ? 0 : errno);
}

static void
ovl_ioctl (fuse_req_t req, fuse_ino_t ino, unsigned int cmd, void *arg,
           struct fuse_file_info *fi, unsigned int flags,
           const void *in_buf, size_t in_bufsz, size_t out_bufsz)
{
  struct ovl_data *lo = ovl_data (req);
  cleanup_close int cleaned_fd = -1;
  struct ovl_node *node;
  int fd = -1;
  unsigned long r;

  if (flags & FUSE_IOCTL_COMPAT)
    {
      fuse_reply_err (req, ENOSYS);
      return;
    }

  if (ovl_debug (req))
    fprintf (stderr, "ovl_ioctl(ino=%" PRIu64 ", cmd=%d, arg=%p, fi=%p, flags=%d, buf=%p, in_bufsz=%zu, out_bufsz=%zu)\n",
             ino, cmd, arg, fi, flags, in_buf, in_bufsz, out_bufsz);

  node = do_lookup_file (lo, ino, NULL);
  if (node == NULL)
    {
      fuse_reply_err (req, ENOENT);
      return;
    }

  switch (cmd)
    {
    case FS_IOC_GETVERSION:
    case FS_IOC_GETFLAGS:
      if (fi->fh >= 0)
        fd = fi->fh;
      break;

    case FS_IOC_SETVERSION:
    case FS_IOC_SETFLAGS:
      node = get_node_up (lo, node);
      if (node == NULL)
        {
          fuse_reply_err (req, errno);
          return;
        }
      if (in_bufsz >= sizeof (r))
          r = *(unsigned long *) in_buf;
      break;

    default:
        fuse_reply_err (req, ENOSYS);
        return;
    }

  if (fd < 0)
    {
      fd = cleaned_fd = TEMP_FAILURE_RETRY (openat (node_dirfd (node), node->path, O_RDONLY|O_NONBLOCK));
      if (fd < 0)
        {
          fuse_reply_err (req, errno);
          return;
        }
    }

  if (ioctl (fd, cmd, &r) < 0)
    fuse_reply_err (req, errno);
  else
    fuse_reply_ioctl (req, 0, &r, out_bufsz ? sizeof (r) : 0);
}

static struct fuse_lowlevel_ops ovl_oper =
  {
   .statfs = ovl_statfs,
   .access = ovl_access,
   .getxattr = ovl_getxattr,
   .removexattr = ovl_removexattr,
   .setxattr = ovl_setxattr,
   .listxattr = ovl_listxattr,
   .init = ovl_init,
   .lookup = ovl_lookup,
   .forget = ovl_forget,
   .getattr = ovl_getattr,
   .readlink = ovl_readlink,
   .opendir = ovl_opendir,
   .readdir = ovl_readdir,
   .readdirplus = ovl_readdirplus,
   .releasedir = ovl_releasedir,
   .create = ovl_create,
   .open = ovl_open,
   .release = ovl_release,
   .read = ovl_read,
   .write_buf = ovl_write_buf,
   .unlink = ovl_unlink,
   .rmdir = ovl_rmdir,
   .setattr = ovl_setattr,
   .symlink = ovl_symlink,
   .rename = ovl_rename,
   .mkdir = ovl_mkdir,
   .mknod = ovl_mknod,
   .link = ovl_link,
   .fsync = ovl_fsync,
   .ioctl = ovl_ioctl,
  };

static int
fuse_opt_proc (void *data, const char *arg, int key, struct fuse_args *outargs)
{
  struct ovl_data *ovl_data = data;

  if (strcmp (arg, "-f") == 0)
    return 1;
  if (strcmp (arg, "--help") == 0)
    return 1;
  if (strcmp (arg, "-h") == 0)
    return 1;
  if (strcmp (arg, "--version") == 0)
    return 1;
  if (strcmp (arg, "-V") == 0)
    return 1;
  if (strcmp (arg, "--debug") == 0)
    {
      ovl_data->debug = 1;
      return 1;
    }

  if (strcmp (arg, "allow_root") == 0)
    return 1;
  if (strcmp (arg, "default_permissions") == 0)
    return 1;
  if (strcmp (arg, "allow_other") == 0)
    return 1;
  if (strcmp (arg, "suid") == 0)
    return 1;
  if (strcmp (arg, "dev") == 0)
    return 1;
  if (strcmp (arg, "nosuid") == 0)
    return 1;
  if (strcmp (arg, "nodev") == 0)
    return 1;
  if (strcmp (arg, "exec") == 0)
    return 1;
  if (strcmp (arg, "noexec") == 0)
    return 1;

  if (key == FUSE_OPT_KEY_NONOPT)
    {
      if (ovl_data->mountpoint)
        free (ovl_data->mountpoint);

      ovl_data->mountpoint = strdup (arg);
      return 0;
    }
  /* Ignore unknown arguments.  */
  if (key == -1)
    return 0;

  return 1;
}

char **
get_new_args (int *argc, char **argv)
{
  int i;
  char **newargv = malloc (sizeof (char *) * (*argc + 2));
  newargv[0] = argv[0];
  if (geteuid() == 0)
      newargv[1] = "-odefault_permissions,allow_other,suid";
  else
      newargv[1] = "-odefault_permissions";
  for (i = 1; i < *argc; i++)
    newargv[i + 1] = argv[i];
  (*argc)++;
  return newargv;
}

static void
set_limits ()
{
  struct rlimit l;

  if (getrlimit (RLIMIT_NOFILE, &l) < 0)
    error (EXIT_FAILURE, errno, "cannot read process rlimit");

  /* Set the soft limit to the hard limit.  */
  l.rlim_cur = l.rlim_max;

  if (setrlimit (RLIMIT_NOFILE, &l) < 0)
    error (EXIT_FAILURE, errno, "cannot set process rlimit");
}

int
main (int argc, char *argv[])
{
  struct fuse_session *se;
  struct fuse_cmdline_opts opts;
  char **newargv = get_new_args (&argc, argv);
  struct ovl_data lo = {.debug = 0,
                        .uid_mappings = NULL,
                        .gid_mappings = NULL,
                        .uid_str = NULL,
                        .gid_str = NULL,
                        .root = NULL,
                        .lowerdir = NULL,
                        .redirect_dir = NULL,
                        .mountpoint = NULL,
                        .timeout = 1000000000.0,
                        .timeout_str = NULL,
  };
  int ret = -1;
  cleanup_layer struct ovl_layer *layers = NULL;
  struct ovl_layer *tmp_layer = NULL;
  struct fuse_args args = FUSE_ARGS_INIT (argc, newargv);

  if (getenv ("FUSE_OVERLAYFS_DISABLE_OVL_WHITEOUT"))
    disable_ovl_whiteout = true;

  memset (&opts, 0, sizeof (opts));
  if (fuse_opt_parse (&args, &lo, ovl_opts, fuse_opt_proc) == -1)
    error (EXIT_FAILURE, 0, "error parsing options");
  if (fuse_parse_cmdline (&args, &opts) != 0)
    error (EXIT_FAILURE, 0, "error parsing cmdline");

  if (opts.mountpoint)
    free (opts.mountpoint);

  read_overflowids ();

  if (opts.show_help)
    {
      printf ("usage: %s [options] <mountpoint>\n\n", argv[0]);
      fuse_cmdline_help ();
      fuse_lowlevel_help ();
      exit (EXIT_SUCCESS);
    }
  else if (opts.show_version)
    {
      printf ("fuse-overlayfs: version %s\n", PACKAGE_VERSION);
      printf ("FUSE library version %s\n", fuse_pkgversion ());
      fuse_lowlevel_version ();
      exit (EXIT_SUCCESS);
    }

  if (lo.redirect_dir && strcmp (lo.redirect_dir, "off"))
    error (EXIT_FAILURE, 0, "fuse-overlayfs only supports redirect_dir=off");

  if (lo.upperdir == NULL)
    error (EXIT_FAILURE, 0, "upperdir not specified");
  else
    {
      cleanup_free char *full_path = NULL;

      full_path = realpath (lo.upperdir, NULL);
      if (full_path == NULL)
        error (EXIT_FAILURE, errno, "cannot retrieve path for %s", lo.upperdir);

      lo.upperdir = strdup (full_path);
      if (lo.upperdir == NULL)
        error (EXIT_FAILURE, errno, "cannot allocate memory");
    }

  set_limits ();

  if (lo.debug)
    {
      fprintf (stderr, "uid=%s\n", lo.uid_str ? : "unchanged");
      fprintf (stderr, "uid=%s\n", lo.gid_str ? : "unchanged");
      fprintf (stderr, "upperdir=%s\n", lo.upperdir);
      fprintf (stderr, "workdir=%s\n", lo.workdir);
      fprintf (stderr, "lowerdir=%s\n", lo.lowerdir);
      fprintf (stderr, "mountpoint=%s\n", lo.mountpoint);
    }

  lo.uid_mappings = lo.uid_str ? read_mappings (lo.uid_str) : NULL;
  lo.gid_mappings = lo.gid_str ? read_mappings (lo.gid_str) : NULL;

  errno = 0;
  if (lo.timeout_str)
    {
      lo.timeout = strtod (lo.timeout_str, NULL);
      if (errno == ERANGE)
        error (EXIT_FAILURE, errno, "cannot convert %s", lo.timeout_str);
    }

  layers = read_dirs (lo.lowerdir, true, NULL);
  if (layers == NULL)
    {
      error (EXIT_FAILURE, errno, "cannot read lower dirs");
    }

  tmp_layer = read_dirs (lo.upperdir, false, layers);
  if (tmp_layer == NULL)
    error (EXIT_FAILURE, errno, "cannot read upper dir");
  lo.layers = layers = tmp_layer;

  lo.root = load_dir (&lo, NULL, get_upper_layer (&lo), ".", "");
  if (lo.root == NULL)
    error (EXIT_FAILURE, errno, "cannot read upper dir");
  lo.root->lookups = 2;

  if (lo.workdir == NULL)
    error (EXIT_FAILURE, 0, "workdir not specified");
  else
    {
      cleanup_free char *path = NULL;

      path = realpath (lo.workdir, NULL);
      if (path == NULL)
        goto err_out1;
      mkdir (path, 0700);
      strcat (path, "/work");
      mkdir (path, 0700);
      free (lo.workdir);
      lo.workdir = strdup (path);

      lo.workdir_fd = open (lo.workdir, O_DIRECTORY);
      if (lo.workdir_fd < 0)
        error (EXIT_FAILURE, errno, "cannot open workdir");
    }

  umask (0);

  se = fuse_session_new (&args, &ovl_oper, sizeof (ovl_oper), &lo);
  lo.se = se;
  if (se == NULL)
    {
      error (0, errno, "cannot create FUSE session");
      goto err_out1;
    }
  if (fuse_set_signal_handlers (se) != 0)
    {
      error (0, errno, "cannot set signal handler");
      goto err_out2;
    }
  if (fuse_session_mount (se, lo.mountpoint) != 0)
    {
      error (0, errno, "cannot mount");
      goto err_out3;
    }
  fuse_daemonize (opts.foreground);
  ret = fuse_session_loop (se);
  fuse_session_unmount (se);
err_out3:
  fuse_remove_signal_handlers (se);
err_out2:
  fuse_session_destroy (se);
err_out1:

  node_mark_all_free (lo.root);

  node_free (lo.root);

  free_mapping (lo.uid_mappings);
  free_mapping (lo.gid_mappings);

  close (lo.workdir_fd);

  fuse_opt_free_args (&args);

  return ret ? 1 : 0;
}
