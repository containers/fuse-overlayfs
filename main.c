/* containers: Overlay Filesystem in Userspace

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

#include <sys/xattr.h>

#ifndef RENAME_EXCHANGE
# define RENAME_EXCHANGE (1 << 1)
# define RENAME_NOREPLACE (1 << 2)
#endif

#define ATTR_TIMEOUT 1000000000.0
#define ENTRY_TIMEOUT 1000000000.0

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

static size_t
str_hasher (const void *p, size_t s)
{
  const char *str = (const char *) p;

  return hash_string (str, s);
}

static bool
str_compare (const void *n1, const void *n2)
{
  const char *s1 = (const char *) n1;
  const char *s2 = (const char *) n2;

  return strcmp (s1, s2) == 0 ? true : false;
}

struct lo_mapping
{
  struct lo_mapping *next;
  unsigned int host;
  unsigned int to;
  unsigned int len;
};

struct lo_node
{
  struct lo_node *parent;
  struct lo_node *lowerdir;
  Hash_table *children;
  char *path;
  char *name;
  int lookups;
  unsigned int dirty : 1;
  unsigned int low : 1;
  unsigned int do_unlink : 1;
  unsigned int do_rmdir : 1;
  unsigned int hidden : 1;
  unsigned int not_exists : 1;
};

struct lo_data
{
  struct fuse_session *se;
  int debug;
  char *uid_str;
  char *gid_str;
  struct lo_mapping *uid_mappings;
  struct lo_mapping *gid_mappings;
  char *lowerdir;
  char *context;
  char *upperdir;
  char *workdir;
  struct lo_node *root_lower;
  struct lo_node *root_upper;
};

static const struct fuse_opt lo_opts[] = {
  {"context=%s",
   offsetof (struct lo_data, context), 0},
  {"lowerdir=%s",
   offsetof (struct lo_data, lowerdir), 0},
  {"upperdir=%s",
   offsetof (struct lo_data, upperdir), 0},
  {"workdir=%s",
   offsetof (struct lo_data, workdir), 0},
  {"uid=%s",
   offsetof (struct lo_data, uid_str), 0},
  {"gid=%s",
   offsetof (struct lo_data, gid_str), 0},
  FUSE_OPT_END
};

static struct lo_data *
lo_data (fuse_req_t req)
{
  return (struct lo_data *) fuse_req_userdata (req);
}

static struct lo_mapping *
read_mappings (const char *str)
{
  char *buf = NULL, *saveptr = NULL, *it, *endptr;
  struct lo_mapping *tmp, *ret = NULL;
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
free_mapping (struct lo_mapping *it)
{
  struct lo_mapping *next = NULL;
  for (; it; it = next)
    {
      next = it->next;
      free (it);
    }
}

/* Useful in a gdb session.  */
void
dump_directory (struct lo_node *node)
{
  struct lo_node *it;

  if (node->children == NULL)
    return;

  for (it = hash_get_first (node->children); it; it = hash_get_next (node->children, it))
    printf ("ENTRY: %s (%s)\n", it->name, it->path);
}

static bool
lo_debug (fuse_req_t req)
{
  return lo_data (req)->debug != 0;
}

static void
lo_init (void *userdata, struct fuse_conn_info *conn)
{
  conn->want |= FUSE_CAP_DONT_MASK | FUSE_CAP_SPLICE_READ | FUSE_CAP_SPLICE_MOVE;
  conn->want &= ~FUSE_CAP_PARALLEL_DIROPS;
}

static inline bool
node_dirp (struct lo_node *n)
{
  return n->children != NULL;
}

static char *
get_node_path (struct lo_node *node)
{
  if (node->not_exists)
    return node->lowerdir->path;
  return node->path;
}

static int
hide_node (struct lo_data *lo, struct lo_node *node, bool unlink_src)
{
  char dest[PATH_MAX];
  char *newpath;
  static unsigned long counter = 1;

  node->hidden = 1;
  node->parent = NULL;

  asprintf (&newpath, "%s/%lu", lo->workdir, counter++);
  if (newpath == NULL)
    {
      unlink (dest);
      return -1;
    }

  /* Might be leftover from a previous run.  */
  unlink (newpath);

  if (unlink_src)
    {
      if (rename (node->path, newpath) < 0)
        {
          free (newpath);
          return -1;
        }
    }
  else
    {
      if (link (node->path, newpath) < 0)
        {
          free (newpath);
          return -1;
        }
    }

  free (node->path);
  node->path = newpath;

  node->do_unlink = 1;
  return 0;
}

static unsigned int
find_mapping (unsigned int id, struct lo_mapping *mapping, bool direct)
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
get_uid (struct lo_data *data, uid_t id)
{
  return find_mapping (id, data->uid_mappings, false);
}

static uid_t
get_gid (struct lo_data *data, gid_t id)
{
  return find_mapping (id, data->gid_mappings, false);
}

static int
rpl_stat (fuse_req_t req, struct lo_node *node, struct stat *st)
{
  int ret;
  struct lo_data *data = lo_data (req);

  if (! node->not_exists)
    ret = lstat (node->path, st);
  else
    ret = lstat (node->lowerdir->path, st);

  if (ret < 0)
    return ret;

  st->st_uid = find_mapping (st->st_uid, data->uid_mappings, true);
  st->st_gid = find_mapping (st->st_gid, data->gid_mappings, true);

  st->st_ino = NODE_TO_INODE (node);

  if (ret == 0 && node_dirp (node))
    {
      struct lo_node *it;

      st->st_nlink = 2;

      for (it = hash_get_first (node->children); it; it = hash_get_next (node->children, it))
        {
          if (node_dirp (it))
            st->st_nlink++;
        }
      if (node->lowerdir)
        {
          for (it = hash_get_first (node->lowerdir->children); it; it = hash_get_next (node->lowerdir->children, it))
            {
              if (node_dirp (it) && it->lowerdir == NULL)
                st->st_nlink++;
            }
        }
    }

  return ret;
}

static void
node_mark_all_free (void *p)
{
  struct lo_node *it, *n = (struct lo_node *) p;

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
  struct lo_node *n = (struct lo_node *) p;
  if (n->parent)
    {
      if (hash_lookup (n->parent->children, n) == n)
        hash_delete (n->parent->children, n);
      n->parent->dirty = 1;
      n->parent = NULL;
    }

  if (n->lookups > 0)
    return;

  if (n->children)
    {
      struct lo_node *it;

      for (it = hash_get_first (n->children); it; it = hash_get_next (n->children, it))
        it->parent = NULL;

      hash_free (n->children);
      n->children = NULL;
    }

  if (! n->not_exists)
    {
      if (n->do_unlink)
        unlink (n->path);
      if (n->do_rmdir)
        rmdir (n->path);
    }

  free (n->name);
  free (n->path);
  free (n);
  return;
}

static void
do_forget (fuse_ino_t ino, uint64_t nlookup)
{
  struct lo_node *n;

  if (ino == FUSE_ROOT_ID)
    return;

  n = (struct lo_node *) ino;
  if (n->low)
    return;

  n->lookups -= nlookup;
  if (n->lookups <= 0)
    node_free (n);
}

static void
lo_forget (fuse_req_t req, fuse_ino_t ino, uint64_t nlookup)
{
  if (lo_debug (req))
    fprintf (stderr, "lo_forget(ino=%" PRIu64 ", nlookup=%lu)\n",
	     ino, nlookup);
  do_forget (ino, nlookup);
  fuse_reply_none (req);
}

static size_t
node_hasher (const void *p, size_t s)
{
  struct lo_node *n = (struct lo_node *) p;
  return hash_string (n->name, s);
}

static bool
file_exists_p (const char *path)
{
  return access (path, R_OK) == F_OK;
}

static bool
node_compare (const void *n1, const void *n2)
{
  struct lo_node *node1 = (struct lo_node *) n1;
  struct lo_node *node2 = (struct lo_node *) n2;

  return strcmp (node1->name, node2->name) == 0 ? true : false;
}

static struct lo_node *
make_lo_node (const char *path, const char *name, bool dir_p)
{
  struct lo_node *ret = malloc (sizeof (*ret));
  if (ret == NULL)
    {
      errno = ENOMEM;
      return NULL;
    }

  ret->lowerdir = NULL;
  ret->parent = NULL;
  ret->dirty = 0;
  ret->low = 0;
  ret->lookups = 0;
  ret->do_unlink = 0;
  ret->hidden = 0;
  ret->do_rmdir = 0;
  ret->not_exists = 0;

  ret->name = strdup (name);
  if (ret->name == NULL)
    {
      free (ret);
      errno = ENOMEM;
      return NULL;
    }

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

  return ret;
}

static struct lo_node *
insert_node (struct lo_node *parent, struct lo_node *item, bool replace)
{
  struct lo_node *old = NULL, *prev_parent = item->parent;
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

  if (parent->lowerdir && item->lowerdir == NULL)
    item->lowerdir = hash_lookup (parent->lowerdir->children, item);

  return item;
}

static struct lo_node *
traverse_dir (char * const dir, struct lo_node *lower, bool low)
{
  struct lo_node *root, *n, *parent;
  int ret = -1;
  char *const dirs[] = {dir, NULL};
  FTS *fts = fts_open (dirs, FTS_NOSTAT | FTS_COMFOLLOW, NULL);
  if (fts == NULL)
    return NULL;

  root = NULL;

  while (1)
    {
      FTSENT *ent = fts_read (fts);
      if (ent == NULL)
        {
          if (errno)
            goto err;
          break;
        }

      switch (ent->fts_info)
        {
        case FTS_D:
          if (root == NULL)
            {
              root = make_lo_node (dir, "/", true);
              root->lowerdir = lower;
              root->low = low ? 1 : 0;
              ent->fts_pointer = root;
            }
          else
            {
              n = make_lo_node (ent->fts_path, ent->fts_name, true);
              ent->fts_pointer = n;
              if (n == NULL)
                goto err;
              parent = (struct lo_node *) ent->fts_parent->fts_pointer;
              n = insert_node (parent, n, false);
              if (n == NULL)
                goto err;
              n->low = low ? 1 : 0;
            }
          break;

        case FTS_DP:
          break;

        case FTS_F:
        case FTS_SL:
        case FTS_SLNONE:
        case FTS_DEFAULT:
          n = make_lo_node (ent->fts_path, ent->fts_name, false);
          if (n == NULL)
            goto err;
          n->low = low ? 1 : 0;
          parent = (struct lo_node *) ent->fts_parent->fts_pointer;
          n = insert_node (parent, n, true);
          if (n == NULL)
            goto err;
          break;
        }
    }

  ret = 0;

 err:
  if (ret)
    {
      node_mark_all_free (root);
      node_free (root);
      root = NULL;
    }
  fts_close (fts);
  return root;
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

static struct lo_node *
merge_trees (struct lo_node *origin, struct lo_node *new)
{
  struct lo_node *it;
  struct lo_node **children;
  size_t i, s;

  if (!node_dirp (origin) || !node_dirp (new))
    {
      new = insert_node (origin->parent, new, true);
      if (new == NULL)
        return NULL;
      return origin;
    }

  s = sizeof (*children) * hash_get_n_entries (new->children);
  children = malloc (s);
  if (children == NULL)
    return NULL;

  s = hash_get_entries (new->children, (void **) children, s);
  for (i = s; i > 0; i--)
    {
      struct lo_node *prev;

      it = children[i - 1];
      prev = hash_lookup (origin->children, it);

      if (has_prefix (it->name, ".wh."))
        {
          struct lo_node *rm;
          char *name = it->name;

          it->name = it->name + 4;
          rm = hash_delete (origin->children, it);
          it->name = name;
          if (rm)
            node_free (rm);
          continue;
        }

      if (prev != NULL && node_dirp (origin) && node_dirp (it))
        {
          hash_delete (new->children, it);
          if (merge_trees (prev, it) == NULL)
            {
              free (children);
              return NULL;
            }
        }
      else
        {
          hash_delete (new->children, it);
          it = insert_node (origin, it, true);
          if (it == NULL)
            {
              free (children);
              return NULL;
            }
        }
    }

  node_free (new);

  free (children);
  return origin;
}

static struct lo_node *
reload_dir (struct lo_node *n, char *path, char *name, struct lo_node *lowerdir)
{
  DIR *dp;
  struct dirent *dent;
  char *it;
  int fd;
  struct stat st;
  struct lo_node *created = NULL;
  Hash_table *whiteouts = NULL;

  if (n)
    {
      n->path = path;
      if (n->not_exists)
        return n;
    }
  else
    {
      n = created = make_lo_node (path, name, true);
      if (n == NULL)
        return NULL;
    }

  n->lowerdir = lowerdir;
  dp = opendir (path);
  if (dp == NULL)
    {
      if (created)
        node_free (created);
      return NULL;
    }

  whiteouts = hash_initialize (10, NULL, str_hasher, str_compare, free);
  if (whiteouts == NULL)
    {
      if (created)
        node_free (created);
      closedir (dp);
      errno = ENOMEM;
      return NULL;
    }

  fd = dirfd (dp);
  while (dp && ((dent = readdir (dp)) != NULL))
    {
      bool dirp;
      struct lo_node *child;
      char b[PATH_MAX + 1];
      struct lo_node key;

      key.name = dent->d_name;
      if (hash_lookup (n->children, &key))
        continue;

      if ((strcmp (dent->d_name, ".") == 0) || strcmp (dent->d_name, "..") == 0)
          continue;

      if (fstatat (fd, dent->d_name, &st, AT_SYMLINK_NOFOLLOW) < 0)
        goto err;

      sprintf (b, "%s/%s", path, dent->d_name);
      dirp = st.st_mode & S_IFDIR;

      if (has_prefix (dent->d_name, ".wh."))
        {
          char *tmp, *name = strdup (dent->d_name + 4);
          if (name == NULL)
            {
              errno = ENOMEM;
              closedir (dp);
              hash_free (whiteouts);
              if (created)
                node_free (created);
              return NULL;
            }
          tmp = hash_insert (whiteouts, name);
          if (tmp == NULL)
            {
              free (name);
              errno = ENOMEM;
              closedir (dp);
              hash_free (whiteouts);
              if (created)
                node_free (created);
              return NULL;
            }
          continue;
        }
      else
        {
          if (hash_lookup (n->children, &key))
            continue;
        }

      child = make_lo_node (b, dent->d_name, dirp);
      if (!child)
        goto err;

      if (lowerdir)
        child->lowerdir = hash_lookup (lowerdir->children, &key);

      if (dirp)
        child->dirty = 1;

      child = insert_node (n, child, false);
      if (child == NULL)
        goto err;
    }
  closedir (dp);

  for (it = hash_get_first (whiteouts); it; it = hash_get_next (whiteouts, it))
    {
      struct lo_node key, *tmp;

      key.name = it;
      tmp = (struct lo_node *) hash_delete (n->children, &key);
      if (tmp)
        node_free (tmp);
    }
  hash_free (whiteouts);
  whiteouts = NULL;

  n->dirty = 0;
  return n;

 err:
  if (created)
    node_free (created);
  closedir (dp);
  return NULL;
}

static struct lo_node *
read_dirs (char *path, struct lo_node *lower, bool low)
{
  char *buf = NULL, *saveptr = NULL, *it;
  struct lo_node *root = NULL;

  if (path == NULL)
    return NULL;

  buf = strdup (path);
  if (buf == NULL)
    return NULL;

  for (it = strtok_r (path, ":", &saveptr); it; it = strtok_r (NULL, ":", &saveptr))
    {
      char full_path[PATH_MAX + 1];
      struct lo_node *node;

      if (realpath (it, full_path) < 0)
        return NULL;

      node = traverse_dir (full_path, lower, low);
      if (node == NULL)
        {
          free (buf);
          return NULL;
        }

      if (root == NULL)
        root = node;
      else
        {
          node = merge_trees (root, node);
          if (node == NULL)
            {
              free (buf);
              node_free (root);
              return NULL;
            }
          root = node;
        }
    }
  free (buf);
  return root;
}

static struct lo_node *
do_lookup_file (struct lo_data *lo, fuse_ino_t parent, const char *path)
{
  char *saveptr = NULL, *it;
  char *b;
  struct lo_node *node;
  struct lo_node *lowerdir;

  if (parent == FUSE_ROOT_ID)
    node = lo->root_upper;
  else
    node = (struct lo_node *) parent;

  if (path == NULL)
    return node;

  lowerdir = node->lowerdir;
  if (*path == '\0')
    return node;

  b = alloca (strlen (path) + 1);
  strcpy (b, path);

  for (it = strtok_r (b, "/", &saveptr); it; it = strtok_r (NULL, "/", &saveptr))
    {
      struct lo_node *next;
      struct lo_node tmp;

      if (node->dirty)
        {
          node = reload_dir (node, node->path, node->name, node->lowerdir);
          if (node == NULL)
            return node;
        }

      tmp.name = it;

      if (lowerdir && lowerdir->children)
        lowerdir = hash_lookup (lowerdir->children, &tmp);
      else
        lowerdir = NULL;

      if (node->children == NULL && lowerdir == NULL)
        return NULL;

      next = hash_lookup (node->children, &tmp);
      if (next != NULL)
          node = next;
      else
        {
          char b[PATH_MAX + 1];

          if (lowerdir == NULL)
            return NULL;

          sprintf (b, "%s/.wh.%s", node->path, lowerdir->name);
          if (file_exists_p (b))
            return NULL;

          sprintf (b, "%s/%s", node->path, lowerdir->name);
          next = make_lo_node (b, lowerdir->name, lowerdir->children != NULL);
          if (!next)
            return NULL;

          next->not_exists = 1;

          next = insert_node (node, next, false);
          if (next == NULL)
            return NULL;
        }

      node = next;

      if (lowerdir)
        assert (strcmp (node->name, lowerdir->name) == 0);

      node->lowerdir = lowerdir;
    }

  return node;
}

static void
lo_lookup (fuse_req_t req, fuse_ino_t parent, const char *name)
{
  struct fuse_entry_param e;
  int err = 0;
  struct lo_data *lo = lo_data (req);
  struct lo_node *node;

  if (lo_debug (req))
    fprintf (stderr, "lo_lookup(parent=%" PRIu64 ", name=%s)\n",
	     parent, name);

  memset (&e, 0, sizeof (e));

  node = do_lookup_file (lo, parent, name);
  if (node == NULL)
    {
      fuse_reply_err (req, ENOENT);
      return;
    }

  if (node->dirty && !node->not_exists)
    {
      node = reload_dir (node, get_node_path (node), node->name, node->lowerdir);
      if (node == NULL)
        {
          fuse_reply_err (req, ENOENT);
          return;
        }
    }

  err = rpl_stat (req, node, &e.attr);
  if (err)
    {
      fuse_reply_err (req, errno);
      return;
    }

  e.ino = (fuse_ino_t) node;
  node->lookups++;
  e.attr_timeout = ATTR_TIMEOUT;
  e.entry_timeout = ENTRY_TIMEOUT;
  fuse_reply_entry (req, &e);
}

struct lo_dirp
{
  struct lo_data *lo;
  fuse_ino_t parent;
  Hash_table *elements;
  char **tbl;
  size_t tbl_size;
  size_t offset;
};

static struct lo_dirp *
lo_dirp (struct fuse_file_info *fi)
{
  return (struct lo_dirp *) (uintptr_t) fi->fh;
}

static void
lo_opendir (fuse_req_t req, fuse_ino_t ino, struct fuse_file_info *fi)
{
  int error;
  DIR *dp = NULL;
  char *it;
  struct lo_node *node;
  struct lo_node *low = NULL;
  struct lo_data *lo = lo_data (req);
  struct lo_dirp *d = calloc (1, sizeof (struct lo_dirp));
  struct dirent *dent;
  Hash_table *whiteouts = NULL;

  node = do_lookup_file (lo, ino, NULL);
  if (node == NULL)
    {
      errno = ENOENT;
      goto out_errno;
    }

  if (node->dirty)
    {
      node = reload_dir (node, node->path, node->name, node->lowerdir);
      if (node == NULL)
        goto out_errno;
    }

  d->parent = ino;
  d->offset = 0;
  d->elements = hash_initialize (10, NULL, str_hasher, str_compare, free);
  if (d->elements == NULL)
    {
      errno = ENOMEM;
      goto out_errno;
    }

  if (node->lowerdir && node->lowerdir->children)
    low = node->lowerdir;
  else if (node->low && node->children)
    low = node;

  if (low)
    {
      struct lo_node *it;

      for (it = hash_get_first (low->children); it; it = hash_get_next (low->children, it))
        {
          char *i;
          char *el;
          struct lo_node *n;

          n = do_lookup_file (lo, ino, it->name);
          if (n == NULL)
            continue;

          el = strdup (it->name);
          if (el == NULL)
              {
                errno = ENOMEM;
                goto out_errno;
              }

          i = hash_insert (d->elements, el);
          if (i == NULL)
            {
              free (el);
              errno = ENOMEM;
              goto out_errno;
            }
          if (i != el)
            free (el);
        }
    }

  if (!node->low)
    {
      dp = opendir (node->path);
      if (dp == NULL && errno != ENOENT)
        goto out_errno;
      whiteouts = hash_initialize (10, NULL, str_hasher, str_compare, free);
      if (whiteouts == NULL)
        {
          errno = ENOMEM;
          goto out_errno;
        }

      while (dp && ((dent = readdir (dp)) != NULL))
        {
          char *el = NULL;
          char *prev;
          struct lo_node *l;

          if (strcmp (dent->d_name, ".") == 0)
            l = node;
          else if (strcmp (dent->d_name, "..") == 0)
            {
              if (node->parent)
                l = node->parent;
              else
                continue;
            }
          else
            {
              l = do_lookup_file (lo, NODE_TO_INODE (node), dent->d_name);
            }

          if (has_prefix (dent->d_name, ".wh."))
            {
              char *tmp, *name = strdup (dent->d_name + 4);
              if (name == NULL)
                {
                  errno = ENOMEM;
                  goto out_errno;
                }
              tmp = hash_insert (whiteouts, name);
              if (tmp == NULL)
                {
                  free (name);
                  errno = ENOMEM;
                  goto out_errno;
                }
              if (tmp != name)
                free (name);
              continue;
            }

          if (l == NULL)
            continue;

          el = strdup (dent->d_name);
          if (el == NULL)
            {
              errno = ENOMEM;
              goto out_errno;
            }

          prev = hash_insert (d->elements, el);
          if (prev == NULL)
            {
              errno = ENOMEM;
              goto out_errno;
            }
          if (prev != el)
            free (el);
        }
      if (dp)
        {
          closedir (dp);
          dp = NULL;
        }

      for (it = hash_get_first (whiteouts); it; it = hash_get_next (whiteouts, it))
        {
          char *tmp = hash_delete (d->elements, it);
          if (tmp)
            free (tmp);
        }
      hash_free (whiteouts);
      whiteouts = NULL;
    }

  d->tbl_size = hash_get_n_entries (d->elements);
  d->tbl = malloc (sizeof (char *) * d->tbl_size);
  if (d->tbl == NULL)
    {
      errno = ENOMEM;
      goto out_errno;
    }

  hash_get_entries (d->elements, (void **) d->tbl, d->tbl_size);

  fi->fh = (uintptr_t) d;

  fuse_reply_open (req, fi);
  return;

out_errno:
  error = errno;
  if (whiteouts)
    hash_free (whiteouts);
  if (dp)
    closedir (dp);
  if (d)
    {
      if (d->elements)
        hash_free (d->elements);
      if (d->tbl)
        free (d->tbl);
      free (d);
    }
  fuse_reply_err (req, error);
}

static void
lo_do_readdir (fuse_req_t req, fuse_ino_t ino, size_t size,
	       off_t offset, struct fuse_file_info *fi, int plus)
{
  struct lo_dirp *d = lo_dirp (fi);
  size_t remaining = size;
  char *p, *buffer = calloc (size, 1);
  struct lo_data *lo = lo_data (req);

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
        char *name = d->tbl[offset];
        struct lo_node *node;

        if (strcmp (name, ".") == 0)
          {
            node = do_lookup_file (lo, ino, NULL);
          }
        else if (strcmp (name, "..") == 0)
          {
            node = do_lookup_file (lo, ino, NULL);
            if (node->parent)
              node = node->parent;
            else
              continue;
          }
        else
          {
            node = do_lookup_file (lo, ino, name);
            if (node == NULL)
              continue;
          }

        ret = rpl_stat (req, node, &st);
        if (ret < 0)
          {
            fuse_reply_err (req, errno);
            goto exit;
          }

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
                if ((strcmp (name, ".") != 0) && (strcmp (name, "..") != 0))
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
lo_readdir (fuse_req_t req, fuse_ino_t ino, size_t size,
	    off_t offset, struct fuse_file_info *fi)
{
  lo_do_readdir (req, ino, size, offset, fi, 0);
}

static void
lo_readdirplus (fuse_req_t req, fuse_ino_t ino, size_t size,
		off_t offset, struct fuse_file_info *fi)
{
  lo_do_readdir (req, ino, size, offset, fi, 1);
}

static void
lo_releasedir (fuse_req_t req, fuse_ino_t ino, struct fuse_file_info *fi)
{
  struct lo_dirp *d = lo_dirp (fi);
  if (d->elements)
    hash_free (d->elements);
  free (d->tbl);
  free (d);
  fuse_reply_err (req, 0);
}

static void
lo_listxattr (fuse_req_t req, fuse_ino_t ino, size_t size)
{
  ssize_t len;
  struct lo_node *node;
  struct lo_data *lo = lo_data (req);
  char buf[1024];

  if (lo_debug (req))
    fprintf (stderr, "lo_listxattr(ino=%" PRIu64 ", size=%zu)\n", ino, size);

  node = do_lookup_file (lo, ino, NULL);
  if (node == NULL)
    {
      fuse_reply_err (req, ENOENT);
      return;
    }

  len = llistxattr (get_node_path (node), buf, sizeof (buf));
  if (len < 0)
    fuse_reply_err (req, errno);
  else if (size == 0)
    fuse_reply_xattr (req, len);
  else if (len <= size)
    fuse_reply_buf (req, buf, len);

}

static void
lo_getxattr (fuse_req_t req, fuse_ino_t ino, const char *name, size_t size)
{
  ssize_t len;
  struct lo_node *node;
  struct lo_data *lo = lo_data (req);
  char buf[1024];

  if (lo_debug (req))
    fprintf (stderr, "lo_getxattr(ino=%" PRIu64 ", name=%s, size=%zu)\n", ino, name, size);

  node = do_lookup_file (lo, ino, NULL);
  if (node == NULL)
    {
      fuse_reply_err (req, ENOENT);
      return;
    }

  len = lgetxattr (get_node_path (node), name, buf, sizeof (buf));
  if (len < 0)
    fuse_reply_err (req, errno);
  else if (size == 0)
    fuse_reply_xattr (req, len);
  else if (len <= size)
    fuse_reply_buf (req, buf, len);
}

static void
lo_access (fuse_req_t req, fuse_ino_t ino, int mask)
{
  int ret;
  struct lo_data *lo = lo_data (req);
  struct lo_node *n = do_lookup_file (lo, ino, NULL);

  if (lo_debug (req))
    fprintf (stderr, "lo_access(ino=%" PRIu64 ", mask=%d)\n",
	     ino, mask);

  ret = access (get_node_path (n), mask);
  fuse_reply_err (req, ret < 0 ? errno : 0);
}

static int
create_directory (struct lo_data *lo, struct lo_node *src)
{
  int ret;
  struct stat st;
  char *dest_path;

  if (src == NULL)
    return 0;

  if (! src->not_exists)
    return 0;

  dest_path = src->path;

  ret = lstat (src->lowerdir->path, &st);
  if (ret < 0)
    goto out;

  ret = mkdir (dest_path, st.st_mode);
  if (ret < 0 && errno == EEXIST)
    {
      ret = 0;
      goto out;
    }
  else if (ret < 0 && errno == ENOENT)
    {
      ret = create_directory (lo, src->parent);
      if (ret != 0)
        goto out;

      ret = mkdir (dest_path, st.st_mode);
      if (ret < 0)
        goto out;

      ret = chown (dest_path, st.st_uid, st.st_gid);
    }

out:
  if (ret == 0)
    {
      src->not_exists = 0;

      if (src->parent)
        {
          char wh[PATH_MAX];
          sprintf (wh, "%s/.wh.%s", src->parent->path, src->name);
          unlink (wh);
        }
    }

  return ret;
}

static int
copyup (struct lo_data *lo, struct lo_node *node)
{
  int saved_errno;
  int ret = -1;
  int dfd = -1, sfd = -1;
  struct stat st;
  int r;
  const char *src = node->lowerdir->path;
  const char *dst = node->path;
  struct timespec times[2];

  if (node->parent)
    {
      r = create_directory (lo, node->parent);
      if (r < 0)
        return r;
    }

  if (lstat (src, &st) < 0)
    goto exit;

  if (node->parent)
    {
      char whpath[PATH_MAX + 10];
      sprintf (whpath, "%s/.wh.%s", node->parent->path, node->name);
      if (unlink (whpath) < 0 && errno != ENOENT)
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
      ret = readlink (src, p, sizeof (p) - 1);
      if (ret < 0)
        goto exit;
      p[ret] = '\0';
      ret = symlink (p, dst);
      if (ret < 0)
        goto exit;
      goto success;
    }

  sfd = open (src, O_RDONLY);
  if (sfd < 0)
    goto exit;

  dfd = open (dst, O_WRONLY|O_CREAT, st.st_mode);
  if (dfd < 0)
    goto exit;

  ret = fchown (dfd, st.st_uid, st.st_gid);
  if (ret < 0)
      goto exit;

  for (;;)
    {
      int written;
      int nread;
      char buf[4096];

      nread = TEMP_FAILURE_RETRY (read (sfd, buf, sizeof (buf)));
      if (nread < 0)
        goto exit;

      if (nread == 0)
        break;

      written = 0;
      {
        r = TEMP_FAILURE_RETRY (write (dfd, buf + written, nread));
        if (r < 0)
          goto exit;

        written += r;
        nread -= r;
      }
      while (nread);
    }

  times[0] = st.st_atim;
  times[1] = st.st_mtim;
  if (futimens (dfd, times) < 0)
    goto exit;

 success:
  ret = 0;

  node->not_exists = 0;

 exit:
  saved_errno = errno;
  if (sfd >= 0)
    close (sfd);
  if (dfd >= 0)
    close (dfd);
  errno = saved_errno;

  return ret;
}

static struct lo_node *
get_node_up (struct lo_data *lo, struct lo_node *node)
{
  int ret;

  if (!node->lowerdir || !node->not_exists)
    return node;

  ret = copyup (lo, node);
  if (ret < 0)
    return NULL;

  assert (has_prefix (node->path, lo->upperdir));

  return node;
}

static size_t
count_dir_entries (struct lo_node *node)
{
  size_t c = 0;
  struct lo_node *it;

  for (it = hash_get_first (node->children); it; it = hash_get_next (node->children, it))
    {
      if (strcmp (it->name, ".") == 0)
        continue;
      if (strcmp (it->name, "..") == 0)
        continue;
      c++;
    }
  return c;
}

static int
update_paths (struct lo_node *node)
{
  struct lo_node *it;

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
  struct lo_node *node;
  struct lo_data *lo = lo_data (req);
  struct lo_node *pnode;
  int fd;
  int ret = 0;
  char whiteout_path[PATH_MAX + 10];
  struct lo_node key, *rm;

  node = do_lookup_file (lo, parent, name);
  if (node == NULL)
    {
      fuse_reply_err (req, ENOENT);
      return;
    }

  if (! node->low)
    {
      if (! dirp)
        node->do_unlink = 1;
      else
        {
          DIR *dp;
          size_t c = 0;

          if (node->dirty)
            {
              node = reload_dir (node, node->path, node->name, node->lowerdir);
              if (node == NULL)
                {
                  fuse_reply_err (req, errno);
                  return;
                }
            }

          if (node->children)
            c = count_dir_entries (node);
          if (c == 0 && node->lowerdir && node->lowerdir->children)
            c = count_dir_entries (node->lowerdir);
          if (c)
            {
              fuse_reply_err (req, ENOTEMPTY);
              return;
            }

          dp = opendir (node->path);
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

  sprintf (whiteout_path, "%s/.wh.%s", get_node_path (pnode), name);
  fd = creat (whiteout_path, 0700);
  if (fd < 0)
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
lo_unlink (fuse_req_t req, fuse_ino_t parent, const char *name)
{
  if (lo_debug (req))
    fprintf (stderr, "lo_unlink(parent=%" PRIu64 ", name=%s)\n",
	     parent, name);
  do_rm (req, parent, name, false);
}

static void
lo_rmdir (fuse_req_t req, fuse_ino_t parent, const char *name)
{
  if (lo_debug (req))
    fprintf (stderr, "lo_rmdir(parent=%" PRIu64 ", name=%s)\n",
	     parent, name);
  do_rm (req, parent, name, true);
}

static void
lo_setxattr (fuse_req_t req, fuse_ino_t ino, const char *name,
             const char *value, size_t size, int flags)
{
  struct lo_data *lo = lo_data (req);
  struct lo_node *node;

  if (lo_debug (req))
    fprintf (stderr, "lo_setxattr(ino=%" PRIu64 "s, name=%s, value=%s, size=%zu, flags=%d)\n", ino, name,
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
lo_removexattr (fuse_req_t req, fuse_ino_t ino, const char *name)
{
  struct lo_node *node;
  struct lo_data *lo = lo_data (req);

  if (lo_debug (req))
    fprintf (stderr, "lo_removexattr(ino=%" PRIu64 "s, name=%s)\n", ino, name);

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
lo_do_open (fuse_req_t req, fuse_ino_t parent, const char *name, int flags, mode_t mode)
{
  struct lo_data *lo = lo_data (req);
  struct lo_node *n;
  bool readonly = (flags & (O_APPEND | O_RDWR | O_WRONLY | O_CREAT | O_TRUNC)) == 0;
  char path[PATH_MAX + 10];
  int fd, ret;

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
      struct lo_node *p;

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
        {
          return -1;
        }

      sprintf (path, "%s/.wh.%s", p->path, name);
      unlink (path);

      sprintf (path, "%s/%s", p->path, name);
      unlink (path);
      fd = open (path, flags, mode);
      if (fd < 0)
        {
          return -1;
        }

      n = make_lo_node (path, name, false);
      if (n == NULL)
        {
          p->dirty = 1;
          errno = ENOMEM;
          close (fd);
          return -1;
        }
      n = insert_node (p, n, true);
      if (n == NULL)
        {
          p->dirty = 1;
          errno = ENOMEM;
          close (fd);
          return -1;
        }
      return fd;
    }

  /* readonly, we can use both lowerdir and upperdir.  */
  if (readonly)
    {
      ret = open (get_node_path (n), flags, mode);
      if (ret < 0)
        return ret;

      return ret;
    }
  else
    {
      n = get_node_up (lo, n);
      if (n == NULL)
        return -1;

      fd = open (n->path, flags, mode);
      if (fd < 0)
        return fd;

      return fd;
    }
}

static void
lo_read (fuse_req_t req, fuse_ino_t ino, size_t size,
	 off_t offset, struct fuse_file_info *fi)
{
  struct fuse_bufvec buf = FUSE_BUFVEC_INIT (size);
  if (lo_debug (req))
    fprintf (stderr, "lo_read(ino=%" PRIu64 ", size=%zd, "
	     "off=%lu)\n", ino, size, (unsigned long) offset);
  buf.buf[0].flags = FUSE_BUF_IS_FD | FUSE_BUF_FD_SEEK;
  buf.buf[0].fd = fi->fh;
  buf.buf[0].pos = offset;
  fuse_reply_data (req, &buf, FUSE_BUF_SPLICE_MOVE);
}

static void
lo_write_buf (fuse_req_t req, fuse_ino_t ino,
	      struct fuse_bufvec *in_buf, off_t off,
	      struct fuse_file_info *fi)
{
  (void) ino;
  ssize_t res;
  struct fuse_bufvec out_buf = FUSE_BUFVEC_INIT (fuse_buf_size (in_buf));
  out_buf.buf[0].flags = FUSE_BUF_IS_FD | FUSE_BUF_FD_SEEK;
  out_buf.buf[0].fd = fi->fh;
  out_buf.buf[0].pos = off;

  if (lo_debug (req))
    fprintf (stderr, "lo_write_buf(ino=%" PRIu64 ", size=%zd, off=%lu, fd=%d)\n",
	     ino, out_buf.buf[0].size, (unsigned long) off, (int) fi->fh);

  errno = 0;
  res = fuse_buf_copy (&out_buf, in_buf, 0);
  if (res < 0)
    fuse_reply_err (req, errno);
  else
    fuse_reply_write (req, (size_t) res);
}

static void
lo_release (fuse_req_t req, fuse_ino_t ino, struct fuse_file_info *fi)
{
  (void) ino;
  close (fi->fh);
  fuse_reply_err (req, 0);
}

static int
do_getattr (fuse_req_t req, struct fuse_entry_param *e, struct lo_node *node)
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
lo_create (fuse_req_t req, fuse_ino_t parent, const char *name,
	   mode_t mode, struct fuse_file_info *fi)
{
  int fd;
  struct fuse_entry_param e;
  struct lo_data *lo = lo_data (req);
  struct lo_node *node;

  if (lo_debug (req))
    fprintf (stderr, "lo_create(parent=%" PRIu64 ", name=%s)\n",
	     parent, name);

  fi->flags = fi->flags | O_CREAT;

  fd = lo_do_open (req, parent, name, fi->flags, mode);
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
lo_open (fuse_req_t req, fuse_ino_t ino, struct fuse_file_info *fi)
{
  int fd;

  if (lo_debug (req))
    fprintf (stderr, "lo_open(ino=%" PRIu64 "s)\n", ino);

  fd = lo_do_open (req, ino, NULL, fi->flags, 0700);
  if (fd < 0)
    {
      fuse_reply_err (req, errno);
      return;
    }
  fi->fh = fd;
  fuse_reply_open (req, fi);
}

static void
lo_getattr (fuse_req_t req, fuse_ino_t ino, struct fuse_file_info *fi)
{
  struct lo_data *lo = lo_data (req);
  struct lo_node *node;
  struct fuse_entry_param e;

  if (lo_debug (req))
    fprintf (stderr, "lo_getattr(ino=%" PRIu64 "s)\n", ino);

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
lo_setattr (fuse_req_t req, fuse_ino_t ino, struct stat *attr, int to_set, struct fuse_file_info *fi)
{
  struct lo_data *lo = lo_data (req);
  struct lo_node *node;
  struct fuse_entry_param e;
  struct stat old_st;
  struct timespec times[2];
  uid_t uid;
  gid_t gid;

  if (lo_debug (req))
    fprintf (stderr, "lo_setattr(ino=%" PRIu64 "s, to_set=%d)\n", ino, to_set);

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

  if (lstat (node->path, &old_st) < 0)
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
      if ((utimensat (AT_FDCWD, node->path, times, AT_SYMLINK_NOFOLLOW) < 0))
        {
          fuse_reply_err (req, errno);
          return;
        }
    }

  if ((to_set & FUSE_SET_ATTR_MODE) && chmod (node->path, attr->st_mode) < 0)
    {
      fuse_reply_err (req, errno);
      return;
    }
  if ((to_set & FUSE_SET_ATTR_SIZE) && truncate (node->path, attr->st_size) < 0)
    {
      fuse_reply_err (req, errno);
      return;
    }

  uid = old_st.st_uid;
  gid = old_st.st_gid;
  if (to_set & FUSE_SET_ATTR_UID)
    uid = get_uid (lo, attr->st_uid);
  if (to_set & FUSE_SET_ATTR_GID)
    gid = get_gid (lo, attr->st_gid);

  if (uid != old_st.st_uid || gid != old_st.st_gid)
    {
      if (lchown (node->path, uid, gid) < 0)
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
lo_link (fuse_req_t req, fuse_ino_t ino, fuse_ino_t newparent, const char *newname)
{
  struct lo_data *lo = lo_data (req);
  struct lo_node *node, *newparentnode, *destnode;
  char path[PATH_MAX + 10];
  int ret;
  struct fuse_entry_param e;

  if (lo_debug (req))
    fprintf (stderr, "lo_link(ino=%" PRIu64 "s, newparent=%" PRIu64 "s, newname=%s)\n", ino, newparent, newname);

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
  if (unlink (path) < 0 && errno != ENOENT)
    {
      fuse_reply_err (req, errno);
      return;
    }

  sprintf (path, "%s/%s", newparentnode->path, newname);
  if (link (get_node_path (node), path) < 0)
    {
      fuse_reply_err (req, errno);
      return;
    }

  node = make_lo_node (path, newname, false);
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

  e.ino = (fuse_ino_t) node;
  node->lookups++;
  e.attr_timeout = ATTR_TIMEOUT;
  e.entry_timeout = ENTRY_TIMEOUT;
  fuse_reply_entry (req, &e);
}

static void
lo_symlink (fuse_req_t req, const char *link, fuse_ino_t parent, const char *name)
{
  struct lo_data *lo = lo_data (req);
  struct lo_node *pnode, *node;
  char path[PATH_MAX + 10];
  int ret;
  struct fuse_entry_param e;

  if (lo_debug (req))
    fprintf (stderr, "lo_symlink(link=%s, ino=%" PRIu64 "s, name=%s)\n", link, parent, name);

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
  if (unlink (path) < 0 && errno != ENOENT)
    {
      fuse_reply_err (req, errno);
      return;
    }

  sprintf (path, "%s/%s", pnode->path, name);
  ret = symlink (link, path);
  if (ret < 0)
    {
      fuse_reply_err (req, errno);
      return;
    }

  node = make_lo_node (path, name, false);
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

  e.ino = (fuse_ino_t) node;
  node->lookups++;
  e.attr_timeout = ATTR_TIMEOUT;
  e.entry_timeout = ENTRY_TIMEOUT;
  fuse_reply_entry (req, &e);
}

static void
lo_flock (fuse_req_t req, fuse_ino_t ino,
          struct fuse_file_info *fi, int op)
{
  int ret, fd;

  if (lo_debug (req))
    fprintf (stderr, "lo_flock(ino=%" PRIu64 "s, op=%d)\n", ino, op);

  fd = fi->fh;

  ret = flock (fd, op);

  fuse_reply_err (req, ret == 0 ? 0 : errno);
}

static struct lo_node *
get_node_up_rec (struct lo_data *lo, struct lo_node *node)
{
  struct lo_node *it;
  struct lo_node *l;

  if (node->children)
    {
      for (it = hash_get_first (node->children); it; it = hash_get_next (node->children, it))
        {
          l = get_node_up_rec (lo, it);
          if (l == NULL)
            return NULL;
        }
    }
  if (node->lowerdir && node->lowerdir->children)
    {
      for (it = hash_get_first (node->lowerdir->children); it; it = hash_get_next (node->lowerdir->children, it))
        {
          l = do_lookup_file (lo, NODE_TO_INODE (node), it->name);
          if (l)
            {
              l = get_node_up_rec (lo, l);
              if (l == NULL)
                return NULL;
            }
        }
    }

  return get_node_up (lo, node);
}

static void
lo_rename (fuse_req_t req, fuse_ino_t parent, const char *name,
           fuse_ino_t newparent, const char *newname,
           unsigned int flags)
{
  struct lo_node *pnode, *node, *destnode, *destpnode;
  struct lo_data *lo = lo_data (req);
  int ret;
  int saved_errno;
  char path[PATH_MAX + 1];
  int srcfd = -1;
  int destfd = -1;
  struct lo_node key, *rm = NULL;

  if (lo_debug (req))
    fprintf (stderr, "lo_rename(ino=%" PRIu64 "s, name=%s , ino=%" PRIu64 "s, name=%s)\n", parent, name, newparent, newname);

  node = do_lookup_file (lo, parent, name);
  if (node == NULL)
    {
      fuse_reply_err (req, ENOENT);
      return;
    }

  pnode = node->parent;

  destpnode = do_lookup_file (lo, newparent, NULL);
  destnode = NULL;

  pnode = get_node_up (lo, pnode);
  if (pnode == NULL)
    goto error;

  ret = open (pnode->path, O_DIRECTORY);
  if (ret < 0)
    goto error;
  srcfd = ret;

  destpnode = get_node_up (lo, destpnode);
  if (destpnode == NULL)
    goto error;

  ret = open (destpnode->path, O_DIRECTORY);
  if (ret < 0)
    goto error;
  destfd = ret;

  destnode = do_lookup_file (lo, newparent, newname);

  node = get_node_up_rec (lo, node);
  if (node == NULL)
    goto error;

  if (flags & RENAME_EXCHANGE)
    {
      if (destnode == NULL)
        {
          errno = ENOENT;
          goto error;
        }
      destnode = get_node_up_rec (lo, destnode);
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
          hash_delete (destpnode->children, rm);
          if (rm->lookups > 0)
            node_free (rm);
          else
            {
              node_free (rm);
              rm = NULL;
            }

          if (rm && !rm->not_exists && hide_node (lo, rm, false) < 0)
            goto error;
        }
    }

  ret = syscall (SYS_renameat2, srcfd, name, destfd, newname, flags);
  if (ret < 0)
    {
      pnode->dirty = destpnode->dirty = 1;
      goto error;
    }

  if (flags & RENAME_EXCHANGE)
    {
      struct lo_node *rm1, *rm2;
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
      fd = openat (srcfd, path, O_CREAT, 0700);
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
lo_statfs (fuse_req_t req, fuse_ino_t ino)
{
  int ret;
  struct statvfs sfs;
  struct lo_data *lo = lo_data (req);

  if (lo_debug (req))
    fprintf (stderr, "lo_statfs(ino=%" PRIu64 "s)\n", ino);

  ret = statvfs (lo->upperdir, &sfs);
  if (ret < 0)
    {
      fuse_reply_err (req, errno);
      return;
    }
  fuse_reply_statfs (req, &sfs);
}

static void
lo_readlink (fuse_req_t req, fuse_ino_t ino)
{
  struct lo_node *node;
  struct lo_data *lo = lo_data (req);
  int ret = 0;
  char buf[PATH_MAX + 1];

  if (lo_debug (req))
    fprintf (stderr, "lo_readlink(ino=%" PRIu64 "s)\n", ino);

  node = do_lookup_file (lo, ino, NULL);
  if (node == NULL)
    {
      fuse_reply_err (req, ENOENT);
      return;
    }

  ret = readlink (get_node_path (node), buf, sizeof (buf));
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
hide_all (struct lo_node *node)
{
  char b[PATH_MAX];
  struct lo_node *it;

  if (node->lowerdir == NULL || node->lowerdir->children == NULL)
    return 0;

  for (it = hash_get_first (node->lowerdir->children); it; it = hash_get_next (node->lowerdir->children, it))
    {
      int fd;

      sprintf (b, "%s/.wh.%s", node->path, it->name);

      fd = open (b, O_CREAT, 0700);
      if (fd < 0 && errno != EEXIST)
        return fd;
      close (fd);
    }
  return 0;
}

static void
lo_mkdir (fuse_req_t req, fuse_ino_t parent, const char *name, mode_t mode)
{
  struct lo_node *node;
  struct lo_data *lo = lo_data (req);
  struct lo_node *pnode;
  int ret = 0;
  char path[PATH_MAX + 10];
  char whiteout_path[PATH_MAX + 16];
  struct fuse_entry_param e;

  if (lo_debug (req))
    fprintf (stderr, "lo_mkdir(ino=%" PRIu64 ", name=%s, mode=%d)\n",
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

  rmdir (path);
  ret = mkdir (path, mode);
  if (ret < 0)
    {
      fuse_reply_err (req, errno);
      return;
    }

  node = make_lo_node (path, name, true);
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
  ret = hide_all (node);
  if (ret < 0)
    {
      fuse_reply_err (req, errno);
      return;
    }

  sprintf (whiteout_path, "%s/.wh.%s", pnode->path, name);
  ret = unlink (whiteout_path);
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

  e.ino = (fuse_ino_t) node;
  e.attr_timeout = ATTR_TIMEOUT;
  e.entry_timeout = ENTRY_TIMEOUT;
  node->lookups++;
  fuse_reply_entry (req, &e);
}

static void
lo_fsync (fuse_req_t req, fuse_ino_t ino, int datasync, struct fuse_file_info *fi)
{
  int ret, fd;

  if (lo_debug (req))
    fprintf (stderr, "lo_fsync(ino=%" PRIu64 ", datasync=%d, fi=%p)\n",
             ino, datasync, fi);

  fd = fi->fh;
  ret = datasync ? fdatasync (fd) : fsync (fd);
  fuse_reply_err (req, ret == 0 ? 0 : errno);
}

static struct fuse_lowlevel_ops lo_oper = {
  .statfs = lo_statfs,
  .access = lo_access,
  .getxattr = lo_getxattr,
  .removexattr = lo_removexattr,
  .setxattr = lo_setxattr,
  .listxattr = lo_listxattr,
  .init = lo_init,
  .lookup = lo_lookup,
  .forget = lo_forget,
  .getattr = lo_getattr,
  .readlink = lo_readlink,
  .opendir = lo_opendir,
  .readdir = lo_readdir,
  .readdirplus = lo_readdirplus,
  .releasedir = lo_releasedir,
  .create = lo_create,
  .open = lo_open,
  .release = lo_release,
  .read = lo_read,
  .write_buf = lo_write_buf,
  .unlink = lo_unlink,
  .rmdir = lo_rmdir,
  .setattr = lo_setattr,
  .symlink = lo_symlink,
  .rename = lo_rename,
  .mkdir = lo_mkdir,
  .link = lo_link,
  .fsync = lo_fsync,
  .flock = lo_flock,
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
  struct lo_data lo = {.debug = 0,
                       .uid_mappings = NULL,
                       .gid_mappings = NULL,
                       .uid_str = NULL,
                       .gid_str = NULL,
                       .root_lower = NULL,
                       .root_upper = NULL,
                       .lowerdir = NULL,
  };
  int ret = -1;

  if (fuse_opt_parse (&args, &lo, lo_opts, fuse_opt_proc) == -1)
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

  lo.root_lower = read_dirs (lo.lowerdir, NULL, true);
  if (lo.root_lower == NULL)
    error (EXIT_FAILURE, errno, "cannot read lower dirs");

  lo.root_upper = reload_dir (NULL, lo.upperdir, "/", lo.root_lower);
  if (lo.root_upper == NULL)
    error (EXIT_FAILURE, errno, "cannot read upper dir");
  lo.root_upper->lookups = 2;
  lo.root_upper->lowerdir = lo.root_lower;

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
    }

  se = fuse_session_new (&args, &lo_oper, sizeof (lo_oper), &lo);
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

  node_mark_all_free (lo.root_lower);
  node_mark_all_free (lo.root_upper);

  node_free (lo.root_lower);
  node_free (lo.root_upper);

  free_mapping (lo.uid_mappings);
  free_mapping (lo.gid_mappings);

  free (opts.mountpoint);
  fuse_opt_free_args (&args);

  return ret ? 1 : 0;
}
