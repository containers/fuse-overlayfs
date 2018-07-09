/* fuse-overlayfs: Overlay Filesystem in Userspace

   Copyright (C) 2018 Giuseppe Scrivano <giuseppe@scrivano.org>
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
#include <error.h>
#include <inttypes.h>
#include <fcntl.h>
#include <hash.h>
#include <sys/statvfs.h>
#include <sys/file.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <fts.h>
#include <sys/sysmacros.h>

#include <sys/xattr.h>

#ifndef RENAME_EXCHANGE
# define RENAME_EXCHANGE (1 << 1)
# define RENAME_NOREPLACE (1 << 2)
#endif

#define ATTR_TIMEOUT 1000000000.0
#define ENTRY_TIMEOUT 1000000000.0

#define REDIRECT_XATTR "user.fuseoverlayfs.redirect"

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
  struct ovl_layer *layer;
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
  char *lowerdir;
  char *context;
  char *upperdir;
  char *workdir;
  int workdir_fd;
  struct ovl_layer *layers;

  struct ovl_node *root;
};

static const struct fuse_opt ovl_opts[] = {
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
  FUSE_OPT_END
};

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
hide_node (struct ovl_data *lo, struct ovl_node *node, bool unlink_src)
{
  char dest[PATH_MAX];
  char *newpath;

  asprintf (&newpath, "%lu", get_next_wd_counter ());
  if (newpath == NULL)
    {
      unlink (dest);
      return -1;
    }

  /* Might be leftover from a previous run.  */
  unlinkat (lo->workdir_fd, newpath, 0);

  if (unlink_src)
    {
      if (renameat (node_dirfd (node), node->path, lo->workdir_fd, newpath) < 0)
        {
          free (newpath);
          return -1;
        }
    }
  else
    {
      if (linkat (node_dirfd (node), node->path, lo->workdir_fd, newpath, 0) < 0)
        {
          free (newpath);
          return -1;
        }
    }
  node->hidden_dirfd = lo->workdir_fd;
  free (node->path);
  node->path = newpath;
  node->hidden = 1;
  node->parent = NULL;

  if (node_dirp (node))
    node->do_rmdir = 1;
  else
    node->do_unlink = 1;
  return 0;
}

static unsigned int
find_mapping (unsigned int id, struct ovl_mapping *mapping, bool direct)
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
    return 65534;
}

static uid_t
get_uid (struct ovl_data *data, uid_t id)
{
  return find_mapping (id, data->uid_mappings, false);
}

static uid_t
get_gid (struct ovl_data *data, gid_t id)
{
  return find_mapping (id, data->gid_mappings, false);
}

static int
rpl_stat (fuse_req_t req, struct ovl_node *node, struct stat *st)
{
  int ret;
  struct ovl_data *data = ovl_data (req);

  ret = TEMP_FAILURE_RETRY (fstatat (node_dirfd (node), node->path, st, AT_SYMLINK_NOFOLLOW));
  if (ret < 0)
    return ret;

  st->st_uid = find_mapping (st->st_uid, data->uid_mappings, true);
  st->st_gid = find_mapping (st->st_gid, data->gid_mappings, true);

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

static struct ovl_node *
make_whiteout_node (const char *name)
{
  struct ovl_node *ret = calloc (1, sizeof (*ret));
  if (ret == NULL)
    {
      errno = ENOMEM;
      return NULL;
    }
  ret->name = strdup (name);
  if (ret->name == NULL)
    {
      free (ret);
      errno = ENOMEM;
      return NULL;
    }
  ret->whiteout = 1;
  return ret;
}

static struct ovl_node *
make_ovl_node (const char *path, struct ovl_layer *layer, const char *name, ino_t ino, bool dir_p)
{
  struct ovl_node *ret = malloc (sizeof (*ret));
  if (ret == NULL)
    {
      errno = ENOMEM;
      return NULL;
    }

  ret->parent = NULL;
  ret->lookups = 0;
  ret->do_unlink = 0;
  ret->hidden = 0;
  ret->do_rmdir = 0;
  ret->whiteout = 0;
  ret->layer = layer;
  ret->ino = ino;
  ret->present_lowerdir = 0;
  ret->name = strdup (name);
  ret->hidden_dirfd = 0;
  if (ret->name == NULL)
    {
      free (ret);
      errno = ENOMEM;
      return NULL;
    }

  if (has_prefix (path, "./") && path[2])
    path += 2;

  ret->path = strdup (path);
  if (ret->path == NULL)
    {
      free (ret->name);
      free (ret);
      errno = ENOMEM;
      return NULL;
    }

  if (!dir_p)
    ret->children = NULL;
  else
    {
      ret->children = hash_initialize (10, NULL, node_hasher, node_compare, node_free);
      if (ret->children == NULL)
        {
          free (ret->path);
          free (ret->name);
          free (ret);
          errno = ENOMEM;
          return NULL;
        }
    }

  if (ret->ino == 0)
    {
      struct stat st;
      struct ovl_layer *it;
      char path[PATH_MAX];

      strcpy (path, ret->path);
      for (it = layer; it; it = it->next)
        {
          ssize_t s;
          int fd = TEMP_FAILURE_RETRY (openat (it->fd, path, O_RDONLY));
          if (fd < 0)
            continue;

          if (fstat (fd, &st) == 0)
            ret->ino = st.st_ino;

          /* If a redirect is specified, use it for the next layer lookup.  */
          s = fgetxattr (fd, REDIRECT_XATTR, path, sizeof (path) - 1);
          if (s > 0)
            path[s] = '\0';

          close (fd);
        }
    }

  return ret;
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
  DIR *dp;
  struct dirent *dent;
  struct stat st;
  struct ovl_layer *it;

  if (!n)
    {
      n = make_ovl_node (path, layer, name, 0, true);
      if (n == NULL)
        return NULL;
    }

  for (it = lo->layers; it; it = it->next)
    {
      int fd = TEMP_FAILURE_RETRY (openat (it->fd, path, O_DIRECTORY));
      if (fd < 0)
        continue;

      dp = fdopendir (fd);
      if (dp == NULL)
        {
          close (fd);
          continue;
        }

      while (((dent = readdir (dp)) != NULL))
        {
          struct ovl_node key;
          const char *wh;
          char path[PATH_MAX + 1];
          struct ovl_node *child = NULL;

          key.name = dent->d_name;

          if ((strcmp (dent->d_name, ".") == 0) || strcmp (dent->d_name, "..") == 0)
            continue;

          if (TEMP_FAILURE_RETRY (fstatat (fd, dent->d_name, &st, AT_SYMLINK_NOFOLLOW)) < 0)
            {
              closedir (dp);
              return NULL;
            }

          child = hash_lookup (n->children, &key);
          if (child)
            continue;

          wh = get_whiteout_name (dent->d_name, &st);
          if (wh)
            {
              child = make_whiteout_node (wh);
              if (child == NULL)
                {
                  errno = ENOMEM;
                  closedir (dp);
                  return NULL;
                }
            }
          else
            {
              bool dirp = st.st_mode & S_IFDIR;

              sprintf (path, "%s/%s", n->path, dent->d_name);
              child = make_ovl_node (path, it, dent->d_name, 0, dirp);

              if (child == NULL)
                {
                  errno = ENOMEM;
                  closedir (dp);
                  return NULL;
                }
            }

            if (insert_node (n, child, false) == NULL)
            {
              errno = ENOMEM;
              return NULL;
            }
        }
      closedir (dp);
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

static struct ovl_layer *
read_dirs (char *path, bool low, struct ovl_layer *layers)
{
  char *buf = NULL, *saveptr = NULL, *it;

  if (path == NULL)
    return NULL;

  buf = strdup (path);
  if (buf == NULL)
    return NULL;

  for (it = strtok_r (path, ":", &saveptr); it; it = strtok_r (NULL, ":", &saveptr))
    {
      char full_path[PATH_MAX + 1];
      struct ovl_layer *l = NULL;

      if (realpath (it, full_path) < 0)
        return NULL;

      l = malloc (sizeof (*l));
      if (l == NULL)
        {
          free_layers (layers);
          return NULL;
        }

      l->path = strdup (full_path);
      if (l->path == NULL)
        {
          free (l);
          free_layers (layers);
          return NULL;
        }

      l->fd = open (l->path, O_DIRECTORY);
      if (l->fd < 0)
        {
          free (l->path);
          free (l);
          free_layers (layers);
          return NULL;
        }

      l->low = low;
      l->next = layers;
      layers = l;
    }
  free (buf);
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
      char path[PATH_MAX];
      struct ovl_layer *it;
      struct stat st;

      for (it = lo->layers; it; it = it->next)
        {
          sprintf (path, "%s/%s", pnode->path, name);
          ret = TEMP_FAILURE_RETRY (fstatat (it->fd, path, &st, AT_SYMLINK_NOFOLLOW));
          if (ret < 0)
            {
              int saved_errno = errno;

              if (errno == ENOENT)
                continue;

              if (node)
                node_free (node);

              errno = saved_errno;
              return NULL;
            }

          node = make_ovl_node (path, it, name, 0, st.st_mode & S_IFDIR);
          if (node == NULL)
            {
              errno = ENOMEM;
              return NULL;
            }
          if (insert_node (pnode, node, false) == NULL)
            {
              node_free (node);
              errno = ENOMEM;
              return NULL;
            }
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
  e.attr_timeout = ATTR_TIMEOUT;
  e.entry_timeout = ENTRY_TIMEOUT;
  fuse_reply_entry (req, &e);
}

struct ovl_dirp
{
  struct ovl_data *lo;
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

static void
ovl_do_readdir (fuse_req_t req, fuse_ino_t ino, size_t size,
	       off_t offset, struct fuse_file_info *fi, int plus)
{
  struct ovl_dirp *d = ovl_dirp (fi);
  size_t remaining = size;
  char *p, *buffer = calloc (size, 1);

  if (buffer == NULL)
    {
      fuse_reply_err (req, ENOMEM);
      return;
    }
  p = buffer;
  for (;remaining > 0 && offset < d->tbl_size; offset++)
      {
        int ret;
        size_t entsize;
        struct stat st;
        const char *name;
        struct ovl_node *node = d->tbl[offset];

        if (node == NULL || node->whiteout)
          continue;

        ret = rpl_stat (req, node, &st);
        if (ret < 0)
          {
            fuse_reply_err (req, errno);
            goto exit;
          }

        if (offset == 0)
          name = ".";
        else if (offset == 1)
          name = "..";
        else
          name = node->name;

        if (!plus)
          entsize = fuse_add_direntry (req, p, remaining, name, &st, offset + 1);
        else
          {
            struct fuse_entry_param e;

            memset (&e, 0, sizeof (e));
            e.attr_timeout = ATTR_TIMEOUT;
            e.entry_timeout = ENTRY_TIMEOUT;
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
 exit:
  free (buffer);
}

static void
ovl_readdir (fuse_req_t req, fuse_ino_t ino, size_t size,
	    off_t offset, struct fuse_file_info *fi)
{
  ovl_do_readdir (req, ino, size, offset, fi, 0);
}

static void
ovl_readdirplus (fuse_req_t req, fuse_ino_t ino, size_t size,
		off_t offset, struct fuse_file_info *fi)
{
  ovl_do_readdir (req, ino, size, offset, fi, 1);
}

static void
ovl_releasedir (fuse_req_t req, fuse_ino_t ino, struct fuse_file_info *fi)
{
  size_t s;
  struct ovl_dirp *d = ovl_dirp (fi);

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
  char *buf = NULL;
  int fd;

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

  fd = TEMP_FAILURE_RETRY (openat (node_dirfd (node), node->path, O_RDONLY));
  if (fd < 0)
    {
      free (buf);
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

  free (buf);
  close (fd);
}

static void
ovl_getxattr (fuse_req_t req, fuse_ino_t ino, const char *name, size_t size)
{
  ssize_t len;
  struct ovl_node *node;
  struct ovl_data *lo = ovl_data (req);
  char *buf = NULL;
  int fd;

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

  fd = TEMP_FAILURE_RETRY (openat (node_dirfd (node), node->path, O_RDONLY));
  if (fd < 0)
    {
      free (buf);
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

  free (buf);
  close (fd);
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

  xattr_len = flistxattr (sfd, buf, buf_size / 2);
  if (xattr_len > 0)
    {
      char *it;
      char *xattr_buf = buf + buf_size / 2;
      for (it = buf; it - buf < xattr_len; it += strlen (it) + 1)
        {
          ssize_t s = fgetxattr (sfd, it, xattr_buf, buf_size / 2);
          if (s < 0)
            return -1;

          if (fsetxattr (dfd, it, xattr_buf, s, 0) < 0)
            return -1;
        }
    }
  return 0;
}

static int
create_directory (struct ovl_data *lo, struct ovl_node *src)
{
  int ret;
  struct stat st;
  int sfd = -1, dfd = -1;
  char *buf = NULL;
  char wd_tmp_file_name[32];
  struct timespec times[2];

  if (src == NULL)
    return 0;

  if (src->layer == get_upper_layer (lo))
    return 0;

  sprintf (wd_tmp_file_name, "%lu", get_next_wd_counter ());

  ret = sfd = TEMP_FAILURE_RETRY (openat (node_dirfd (src), src->path, O_RDONLY));
  if (ret < 0)
    goto out;

  ret = TEMP_FAILURE_RETRY (fstat (sfd, &st));
  if (ret < 0)
    return ret;

  ret = mkdirat (lo->workdir_fd, wd_tmp_file_name, st.st_mode);
  if (ret < 0)
    goto out;

  ret = dfd = TEMP_FAILURE_RETRY (openat (lo->workdir_fd, wd_tmp_file_name, O_RDONLY));
  if (ret < 0)
    goto out;

  ret = fchown (dfd, st.st_uid, st.st_gid);
  if (ret < 0)
    goto out;

  times[0] = st.st_atim;
  times[1] = st.st_mtim;
  ret = futimens (dfd, times);
  if (ret < 0)
    goto out;

  if (ret == 0)
    {
      const size_t buf_size = 1 << 20;
      char *buf = malloc (buf_size);
      if (buf == NULL)
        {
          ret = -1;
          goto out;
        }

      ret = copy_xattr (sfd, dfd, buf, buf_size);
      if (ret < 0)
        goto out;
    }

  ret = renameat (lo->workdir_fd, wd_tmp_file_name, get_upper_layer (lo)->fd, src->path);
  if (ret < 0)
    {
      if (errno == ENOENT && src->parent)
        {
          ret = create_directory (lo, src->parent);
          if (ret != 0)
            goto out;
        }

      ret = renameat (lo->workdir_fd, wd_tmp_file_name, get_upper_layer (lo)->fd, src->path);
    }
out:
  if (sfd >= 0)
    close (sfd);
  if (dfd >= 0)
    close (dfd);
  if (buf)
    free (buf);

  if (ret < 0)
      unlinkat (lo->workdir_fd, wd_tmp_file_name, AT_REMOVEDIR);
  else
    {
      src->layer = get_upper_layer (lo);

      if (src->parent)
        {
          char wh[PATH_MAX];
          sprintf (wh, "%s/.wh.%s", src->path, src->name);
          unlinkat (node_dirfd (src), wh, 0);
        }
    }

  return ret;
}

static int
copyup (struct ovl_data *lo, struct ovl_node *node)
{
  int saved_errno;
  int ret = -1;
  int dfd = -1, sfd = -1;
  struct stat st;
  const size_t buf_size = 1 << 20;
  char *buf = NULL;
  struct timespec times[2];
  char wd_tmp_file_name[32];

  sprintf (wd_tmp_file_name, "%lu", get_next_wd_counter ());

  ret = TEMP_FAILURE_RETRY (fstatat (node_dirfd (node), node->path, &st, AT_SYMLINK_NOFOLLOW));
  if (ret < 0)
    return ret;

  if (node->parent)
    {
      ret = create_directory (lo, node->parent);
      if (ret < 0)
        return ret;

      char whpath[PATH_MAX + 10];
      sprintf (whpath, "%s/.wh.%s", node->parent->path, node->name);
      if (unlinkat (get_upper_layer (lo)->fd, whpath, 0) < 0 && errno != ENOENT)
        goto exit;
    }

  if ((st.st_mode & S_IFMT) == S_IFDIR)
    {
      ret = create_directory (lo, node);
      if (ret < 0)
        goto exit;
      goto success;
    }

  if ((st.st_mode & S_IFMT) == S_IFLNK)
    {
      char p[PATH_MAX + 1];
      ret = readlinkat (node_dirfd (node), node->path, p, sizeof (p) - 1);
      if (ret < 0)
        goto exit;
      p[ret] = '\0';
      ret = symlinkat (p, get_upper_layer (lo)->fd, node->path);
      if (ret < 0)
        goto exit;
      goto success;
    }

  sfd = TEMP_FAILURE_RETRY (openat (node_dirfd (node), node->path, O_RDONLY));
  if (sfd < 0)
    goto exit;

  dfd = TEMP_FAILURE_RETRY (openat (lo->workdir_fd, wd_tmp_file_name, O_CREAT|O_WRONLY, st.st_mode));
  if (dfd < 0)
    goto exit;

  ret = fchown (dfd, st.st_uid, st.st_gid);
  if (ret < 0)
      goto exit;

  buf = malloc (buf_size);
  if (buf == NULL)
    goto exit;
  for (;;)
    {
      int written;
      int nread;

      nread = TEMP_FAILURE_RETRY (read (sfd, buf, buf_size));
      if (nread < 0)
        goto exit;

      if (nread == 0)
        break;

      written = 0;
      {
        ret = TEMP_FAILURE_RETRY (write (dfd, buf + written, nread));
        if (ret < 0)
          goto exit;
        written += ret;
        nread -= ret;
      }
      while (nread);
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

 success:
  ret = 0;

  node->layer = get_upper_layer (lo);

 exit:
  saved_errno = errno;
  free (buf);
  if (sfd >= 0)
    close (sfd);
  if (dfd >= 0)
    close (dfd);
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
count_dir_entries (struct ovl_node *node)
{
  size_t c = 0;
  struct ovl_node *it;

  for (it = hash_get_first (node->children); it; it = hash_get_next (node->children, it))
    {
      if (it->whiteout)
        continue;
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

static void
do_rm (fuse_req_t req, fuse_ino_t parent, const char *name, bool dirp)
{
  struct ovl_node *node;
  struct ovl_data *lo = ovl_data (req);
  struct ovl_node *pnode;
  int fd;
  int ret = 0;
  char whiteout_path[PATH_MAX + 10];
  struct ovl_node key, *rm;

  node = do_lookup_file (lo, parent, name);
  if (node == NULL)
    {
      fuse_reply_err (req, ENOENT);
      return;
    }

  if (node->layer == get_upper_layer (lo))
    {
      node->hidden_dirfd = node->layer->fd;

      if (! dirp)
        node->do_unlink = 1;
      else
        {
          DIR *dp;
          size_t c = 0;
          int fd;

          fd = TEMP_FAILURE_RETRY (openat (get_upper_layer (lo)->fd, node->path, O_DIRECTORY));
          if (fd < 0)
            {
              fuse_reply_err (req, errno);
              return;
            }

          if (node->children)
            c = count_dir_entries (node);
          if (c)
            {
              close (fd);
              fuse_reply_err (req, ENOTEMPTY);
              return;
            }

          if (fd >= 0)
            {
              dp = fdopendir (fd);
              if (dp)
                {
                  struct dirent *dent;

                  while (dp && ((dent = readdir (dp)) != NULL))
                    {
                      if (strcmp (dent->d_name, ".") == 0)
                        continue;
                      if (strcmp (dent->d_name, "..") == 0)
                        continue;
                      if (unlinkat (dirfd (dp), dent->d_name, 0) < 0)
                        unlinkat (dirfd (dp), dent->d_name, AT_REMOVEDIR);
                    }

                  closedir (dp);
                }
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

  sprintf (whiteout_path, "%s/.wh.%s", pnode->path, name);
  fd = TEMP_FAILURE_RETRY (openat (get_upper_layer (lo)->fd, whiteout_path, O_CREAT|O_WRONLY, 0700));
  if (fd < 0 && errno != EEXIST)
    {
      fuse_reply_err (req, errno);
      return;
    }
  close (fd);

  ret = 0;

  key.name = (char *) name;
  rm = hash_delete (pnode->children, &key);
  if (rm)
    {
      hide_node (lo, rm, true);
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

  if (ovl_debug (req))
    fprintf (stderr, "ovl_setxattr(ino=%" PRIu64 "s, name=%s, value=%s, size=%zu, flags=%d)\n", ino, name,
             value, size, flags);

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

  if (setxattr (node->path, name, value, size, flags) < 0)
    {
      fuse_reply_err (req, errno);
      return;
    }

  fuse_reply_err (req, 0);
}

static void
ovl_removexattr (fuse_req_t req, fuse_ino_t ino, const char *name)
{
  struct ovl_node *node;
  struct ovl_data *lo = ovl_data (req);

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

  if (removexattr (node->path, name) < 0)
    {
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
  char path[PATH_MAX + 10];
  int fd;

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
  if (n && (flags & O_CREAT))
    {
      errno = EEXIST;
      return -1;
    }

  if (!n)
    {
      struct ovl_node *p;

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

      sprintf (path, "%s/.wh.%s", p->path, name);
      if (unlinkat (get_upper_layer (lo)->fd, path, 0) < 0 && errno != ENOENT)
        return -1;

      sprintf (path, "%s/%s", p->path, name);
      if (unlinkat (get_upper_layer (lo)->fd, path, 0) < 0 && errno != ENOENT)
        return -1;

      fd = TEMP_FAILURE_RETRY (openat (get_upper_layer (lo)->fd, path, flags, mode));
      if (fd < 0)
        return -1;

      n = make_ovl_node (path, get_upper_layer (lo), name, 0, false);
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
      return fd;
    }

  /* readonly, we can use both lowerdir and upperdir.  */
  if (readonly)
    {
      return TEMP_FAILURE_RETRY (openat (node_dirfd (n), n->path, flags, mode));
    }
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
  res = fuse_buf_copy (&out_buf, in_buf, 0);
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
  int err = 0;

  memset (e, 0, sizeof (*e));

  err = rpl_stat (req, node, &e->attr);
  if (err < 0)
    return err;

  e->ino = (fuse_ino_t) node;
  e->attr_timeout = ATTR_TIMEOUT;
  e->entry_timeout = ENTRY_TIMEOUT;

  return 0;
}

static void
ovl_create (fuse_req_t req, fuse_ino_t parent, const char *name,
	   mode_t mode, struct fuse_file_info *fi)
{
  int fd;
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
      close (fd);
      fuse_reply_err (req, errno);
      return;
    }
  fi->fh = fd;

  node->lookups++;
  fuse_reply_create (req, &e, fi);
}

static void
ovl_open (fuse_req_t req, fuse_ino_t ino, struct fuse_file_info *fi)
{
  int fd;

  if (ovl_debug (req))
    fprintf (stderr, "ovl_open(ino=%" PRIu64 "s)\n", ino);

  fd = ovl_do_open (req, ino, NULL, fi->flags, 0700);
  if (fd < 0)
    {
      fuse_reply_err (req, errno);
      return;
    }
  fi->fh = fd;
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

  fuse_reply_attr (req, &e.attr, ENTRY_TIMEOUT);
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
  if ((to_set & FUSE_SET_ATTR_SIZE))
    {
      int fd = TEMP_FAILURE_RETRY (openat (dirfd, node->path, O_WRONLY));
      if (fd < 0)
        {
          fuse_reply_err (req, errno);
          return;
        }

      if (ftruncate (fd, attr->st_size) < 0)
        {
          close (fd);
          fuse_reply_err (req, errno);
          return;
        }
      close (fd);
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

  fuse_reply_attr (req, &e.attr, ENTRY_TIMEOUT);
}

static void
ovl_link (fuse_req_t req, fuse_ino_t ino, fuse_ino_t newparent, const char *newname)
{
  struct ovl_data *lo = ovl_data (req);
  struct ovl_node *node, *newparentnode, *destnode;
  char path[PATH_MAX + 10];
  int ret;
  struct fuse_entry_param e;

  if (ovl_debug (req))
    fprintf (stderr, "ovl_link(ino=%" PRIu64 "s, newparent=%" PRIu64 "s, newname=%s)\n", ino, newparent, newname);

  node = do_lookup_file (lo, newparent, newname);
  if (node != NULL)
    {
      fuse_reply_err (req, EEXIST);
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

  newparentnode = do_lookup_file (lo, newparent, NULL);
  if (newparentnode == NULL)
    {
      fuse_reply_err (req, ENOENT);
      return;
    }

  destnode = do_lookup_file (lo, newparent, newname);
  if (destnode)
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

  sprintf (path, "%s/.wh.%s", newparentnode->path, newname);
  if (unlinkat (node_dirfd (newparentnode), path, 0) < 0 && errno != ENOENT)
    {
      fuse_reply_err (req, errno);
      return;
    }

  sprintf (path, "%s/%s", newparentnode->path, newname);
  if (linkat (node_dirfd (newparentnode), node->path, node_dirfd (newparentnode), path, 0) < 0)
    {
      fuse_reply_err (req, errno);
      return;
    }
  else
    {
      int dfd = TEMP_FAILURE_RETRY (openat (node_dirfd (newparentnode), path, O_WRONLY));
      if (dfd >= 0)
        {
          bool set = false;
          int sfd = TEMP_FAILURE_RETRY (openat (node_dirfd (node), node->path, O_RDONLY));
          if (sfd >= 0)
            {
              char redirect_path[PATH_MAX + 10];
              ssize_t s = fgetxattr (sfd, REDIRECT_XATTR, redirect_path, sizeof (redirect_path));
              if (s > 0)
                {
                  set = fsetxattr (dfd, REDIRECT_XATTR, redirect_path, s, 0) == 0;
                }
              close (sfd);
            }

          if (! set)
            fsetxattr (dfd, REDIRECT_XATTR, node->path, strlen (node->path), 0);
          close (dfd);
        }
    }

  node = make_ovl_node (path, get_upper_layer (lo), newname, node->ino, false);
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
  e.attr_timeout = ATTR_TIMEOUT;
  e.entry_timeout = ENTRY_TIMEOUT;
  fuse_reply_entry (req, &e);
}

static void
ovl_symlink (fuse_req_t req, const char *link, fuse_ino_t parent, const char *name)
{
  struct ovl_data *lo = ovl_data (req);
  struct ovl_node *pnode, *node;
  char path[PATH_MAX + 10];
  int ret;
  struct fuse_entry_param e;

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
  if (node != NULL)
    {
      fuse_reply_err (req, EEXIST);
      return;
    }

  sprintf (path, "%s/.wh.%s", pnode->path, name);
  if (unlinkat (get_upper_layer (lo)->fd, path, 0) < 0 && errno != ENOENT)
    {
      fuse_reply_err (req, errno);
      return;
    }

  sprintf (path, "%s/%s", pnode->path, name);
  ret = symlinkat (link, get_upper_layer (lo)->fd, path);
  if (ret < 0)
    {
      fuse_reply_err (req, errno);
      return;
    }

  node = make_ovl_node (path, get_upper_layer (lo), name, 0, false);
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
  e.attr_timeout = ATTR_TIMEOUT;
  e.entry_timeout = ENTRY_TIMEOUT;
  fuse_reply_entry (req, &e);
}

static void
ovl_flock (fuse_req_t req, fuse_ino_t ino,
          struct fuse_file_info *fi, int op)
{
  int ret, fd;

  if (ovl_debug (req))
    fprintf (stderr, "ovl_flock(ino=%" PRIu64 "s, op=%d)\n", ino, op);

  fd = fi->fh;

  ret = flock (fd, op);

  fuse_reply_err (req, ret == 0 ? 0 : errno);
}

static void
ovl_rename (fuse_req_t req, fuse_ino_t parent, const char *name,
           fuse_ino_t newparent, const char *newname,
           unsigned int flags)
{
  struct ovl_node *pnode, *node, *destnode, *destpnode;
  struct ovl_data *lo = ovl_data (req);
  int ret;
  int saved_errno;
  char path[PATH_MAX + 1];
  int srcfd = -1;
  int destfd = -1;
  struct ovl_node key, *rm = NULL;

  if (ovl_debug (req))
    fprintf (stderr, "ovl_rename(ino=%" PRIu64 "s, name=%s , ino=%" PRIu64 "s, name=%s)\n", parent, name, newparent, newname);

  node = do_lookup_file (lo, parent, name);
  if (node == NULL)
    {
      fuse_reply_err (req, ENOENT);
      return;
    }

  if (node_dirp (node) && node->present_lowerdir)
    {
      fuse_reply_err (req, EXDEV);
      return;
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

  if (flags & RENAME_EXCHANGE)
    {
      if (destnode == NULL)
        {
          errno = ENOENT;
          goto error;
        }
      destnode = get_node_up (lo, destnode);
      if (destnode == NULL)
        goto error;
    }
  else
    {
      key.name = (char *) newname;
      if (flags & RENAME_NOREPLACE)
        {
          rm = hash_lookup (destpnode->children, &key);
          if (rm)
            {
              errno = EEXIST;
              goto error;
            }

        }
      if (destnode != NULL && node_dirp (destnode))
        {
          errno = EISDIR;
          goto error;
        }

      rm = hash_lookup (destpnode->children, &key);
      if (rm)
        {
          if (rm->ino == node->ino)
            {
              fuse_reply_err (req, 0);
              return;
            }

          hash_delete (destpnode->children, rm);
          if (rm->lookups > 0)
            node_free (rm);
          else
            {
              node_free (rm);
              rm = NULL;
            }

          if (rm && hide_node (lo, rm, false) < 0)
            goto error;
        }
    }

  ret = syscall (SYS_renameat2, srcfd, name, destfd, newname, flags);
  if (ret < 0)
    goto error;

  if (flags & RENAME_EXCHANGE)
    {
      struct ovl_node *rm1, *rm2;
      char *tmp;

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
    }
  else
    {
      int fd;

      sprintf (path, ".wh.%s", name);
      fd = TEMP_FAILURE_RETRY (openat (srcfd, path, O_CREAT, 0700));
      if (fd < 0)
        goto error;
      close (fd);

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
    }

  sprintf (path, ".wh.%s", newname);
  if (unlinkat (destfd, path, 0) < 0 && errno != ENOENT)
    goto error;

 error:
  saved_errno = errno;
  if (srcfd >= 0)
    close (srcfd);
  if (destfd >= 0)
    close (destfd);
  errno = saved_errno;

  fuse_reply_err (req, ret == 0 ? 0 : errno);
}

static void
ovl_statfs (fuse_req_t req, fuse_ino_t ino)
{
  int ret;
  struct statvfs sfs;
  struct ovl_data *lo = ovl_data (req);

  if (ovl_debug (req))
    fprintf (stderr, "ovl_statfs(ino=%" PRIu64 "s)\n", ino);

  ret = statvfs (lo->upperdir, &sfs);
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
  struct ovl_node *node;
  struct ovl_data *lo = ovl_data (req);
  int ret = 0;
  char buf[PATH_MAX + 1];

  if (ovl_debug (req))
    fprintf (stderr, "ovl_readlink(ino=%" PRIu64 "s)\n", ino);

  node = do_lookup_file (lo, ino, NULL);
  if (node == NULL)
    {
      fuse_reply_err (req, ENOENT);
      return;
    }

  ret = readlinkat (node_dirfd (node), node->path, buf, sizeof (buf));
  if (ret == -1)
    {
      fuse_reply_err (req, errno);
      return;
    }
  if (ret == sizeof (buf))
    {
      fuse_reply_err (req, ENAMETOOLONG);
      return;
    }

  buf[ret] = '\0';
  fuse_reply_readlink (req, buf);
}

static int
hide_all (struct ovl_data *lo, struct ovl_node *node)
{
  char b[PATH_MAX];
  struct ovl_node *it;

  for (it = hash_get_first (node->children); it; it = hash_get_next (node->children, it))
    {
      int fd;

      sprintf (b, "%s/.wh.%s", node->path, it->name);

      fd = TEMP_FAILURE_RETRY (openat (get_upper_layer (lo)->fd, b, O_CREAT, 0700));
      if (fd < 0 && errno != EEXIST)
        return fd;
      close (fd);
    }
  return 0;
}

static void
ovl_mkdir (fuse_req_t req, fuse_ino_t parent, const char *name, mode_t mode)
{
  struct ovl_node *node;
  struct ovl_data *lo = ovl_data (req);
  struct ovl_node *pnode;
  int ret = 0;
  char path[PATH_MAX + 10];
  char whiteout_path[PATH_MAX + 16];
  struct fuse_entry_param e;

  if (ovl_debug (req))
    fprintf (stderr, "ovl_mkdir(ino=%" PRIu64 ", name=%s, mode=%d)\n",
	     parent, name, mode);

  node = do_lookup_file (lo, parent, name);
  if (node != NULL)
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
  sprintf (path, "%s/%s", pnode->path, name);

  unlinkat (get_upper_layer (lo)->fd, path, AT_REMOVEDIR);
  ret = mkdirat (get_upper_layer (lo)->fd, path, mode);
  if (ret < 0)
    {
      fuse_reply_err (req, errno);
      return;
    }

  node = make_ovl_node (path, get_upper_layer (lo), name, 0, true);
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

  sprintf (whiteout_path, "%s/.wh.%s", pnode->path, name);
  ret = unlinkat (get_upper_layer (lo)->fd, whiteout_path, 0);
  if (ret < 0 && errno != ENOENT)
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
  e.attr_timeout = ATTR_TIMEOUT;
  e.entry_timeout = ENTRY_TIMEOUT;
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
   .link = ovl_link,
   .fsync = ovl_fsync,
   .flock = ovl_flock,
  };

static int
fuse_opt_proc (void *data, const char *arg, int key, struct fuse_args *outargs)
{
  if (strcmp (arg, "-f") == 0)
    return 1;
  if (strcmp (arg, "--debug") == 0)
    return 1;

  /* Ignore unknown arguments.  */
  if (key == -1)
    return 0;

  return 1;
}

int
main (int argc, char *argv[])
{
  struct fuse_args args = FUSE_ARGS_INIT (argc, argv);
  struct fuse_session *se;
  struct fuse_cmdline_opts opts;
  struct ovl_data lo = {.debug = 0,
                       .uid_mappings = NULL,
                       .gid_mappings = NULL,
                       .uid_str = NULL,
                       .gid_str = NULL,
                       .root = NULL,
                       .lowerdir = NULL,
  };
  int ret = -1;

  if (fuse_opt_parse (&args, &lo, ovl_opts, fuse_opt_proc) == -1)
    return 1;
  if (fuse_parse_cmdline (&args, &opts) != 0)
    return 1;
  if (opts.show_help)
    {
      printf ("usage: %s [options] <mountpoint>\n\n", argv[0]);
      fuse_cmdline_help ();
      fuse_lowlevel_help ();
      ret = 0;
      goto err_out1;
    }
  else if (opts.show_version)
    {
      printf ("FUSE library version %s\n", fuse_pkgversion ());
      fuse_lowlevel_version ();
      ret = 0;
      goto err_out1;
    }

  lo.debug = opts.debug;

  if (lo.upperdir == NULL)
    error (EXIT_FAILURE, 0, "upperdir not specified");
  else
    {
      char full_path[PATH_MAX + 1];

      if (realpath (lo.upperdir, full_path) < 0)
        goto err_out1;

      lo.upperdir = strdup (full_path);
      if (lo.upperdir == NULL)
        goto err_out1;
    }

  printf ("UID=%s\n", lo.uid_str ? : "unchanged");
  printf ("GID=%s\n", lo.gid_str ? : "unchanged");
  printf ("UPPERDIR=%s\n", lo.upperdir);
  printf ("WORKDIR=%s\n", lo.workdir);
  printf ("LOWERDIR=%s\n", lo.lowerdir);
  printf ("MOUNTPOINT=%s\n", opts.mountpoint);

  lo.uid_mappings = lo.uid_str ? read_mappings (lo.uid_str) : NULL;
  lo.gid_mappings = lo.gid_str ? read_mappings (lo.gid_str) : NULL;

  lo.layers = read_dirs (lo.lowerdir, true, NULL);
  if (lo.layers == NULL)
    error (EXIT_FAILURE, errno, "cannot read lower dirs");

  lo.layers = read_dirs (lo.upperdir, false, lo.layers);
  if (lo.layers == NULL)
    error (EXIT_FAILURE, errno, "cannot read upper dir");

  lo.root = load_dir (&lo, NULL, get_upper_layer (&lo), ".", "");
  if (lo.root == NULL)
    error (EXIT_FAILURE, errno, "cannot read upper dir");
  lo.root->lookups = 2;

  if (lo.workdir == NULL)
    error (EXIT_FAILURE, 0, "workdir not specified");
  else
    {
      char path[PATH_MAX + 1];

      if (realpath (lo.workdir, path) < 0)
        goto err_out1;
      mkdir (path, 0700);
      strcat (path, "/work");
      mkdir (path, 0700);
      free (lo.workdir);
      lo.workdir = strdup (path);

      lo.workdir_fd = open (lo.workdir, O_DIRECTORY);
      if (lo.workdir_fd < 0)
        goto err_out1;
    }

  se = fuse_session_new (&args, &ovl_oper, sizeof (ovl_oper), &lo);
  lo.se = se;
  if (se == NULL)
    goto err_out1;
  if (fuse_set_signal_handlers (se) != 0)
    goto err_out2;
  if (fuse_session_mount (se, opts.mountpoint) != 0)
    goto err_out3;
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

  free_layers (lo.layers);
  free (opts.mountpoint);
  fuse_opt_free_args (&args);

  return ret ? 1 : 0;
}
