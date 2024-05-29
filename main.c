/* fuse-overlayfs: Overlay Filesystem in Userspace

   Copyright (C) 2018 Giuseppe Scrivano <giuseppe@scrivano.org>
   Copyright (C) 2018-2020 Red Hat Inc.
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
#define FUSE_USE_VERSION 32
#define _FILE_OFFSET_BITS 64

#include <config.h>

#include "fuse-overlayfs.h"

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
#include <linux/magic.h>
#include <err.h>
#include <sys/vfs.h>
#include <sys/ioctl.h>
#ifdef HAVE_SYS_SENDFILE_H
#  include <sys/sendfile.h>
#endif

#include <fuse_overlayfs_error.h>

#include <inttypes.h>
#include <fcntl.h>
#include <hash.h>
#include <sys/statvfs.h>
#include <sys/file.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/sysmacros.h>
#include <sys/xattr.h>
#include <linux/fs.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <pthread.h>

#include <utils.h>
#include <plugin.h>

#ifndef TEMP_FAILURE_RETRY
#  define TEMP_FAILURE_RETRY(expression) \
    (__extension__ ({ long int __result;                                                     \
       do __result = (long int) (expression);                                 \
       while (__result == -1L && errno == EINTR);                             \
       __result; }))
#endif

static bool disable_locking;
static pthread_mutex_t lock;

static int
enter_big_lock ()
{
  if (disable_locking)
    return 0;

  pthread_mutex_lock (&lock);
  return 1;
}

static int
release_big_lock ()
{
  if (disable_locking)
    return 0;

  pthread_mutex_unlock (&lock);
  return 0;
}

static inline void
cleanup_lockp (int *l)
{
  if (*l == 0)
    return;

  pthread_mutex_unlock (&lock);
  *l = 0;
}

#define cleanup_lock __attribute__ ((cleanup (cleanup_lockp)))

#ifndef HAVE_OPEN_BY_HANDLE_AT
struct file_handle
{
  unsigned int handle_bytes; /* Size of f_handle [in, out] */
  int handle_type;           /* Handle type [out] */
  unsigned char f_handle[0]; /* File identifier (sized by
                                caller) [out] */
};

int
open_by_handle_at (int mount_fd, struct file_handle *handle, int flags)
{
  return syscall (SYS_open_by_handle_at, mount_fd, handle, flags);
}
#endif

#ifndef RENAME_NOREPLACE
#  define RENAME_NOREPLACE (1 << 0)
#endif

#ifndef RENAME_EXCHANGE
#  define RENAME_EXCHANGE (1 << 1)
#endif

#ifndef RENAME_WHITEOUT
#  define RENAME_WHITEOUT (1 << 2)
#endif

#define XATTR_PREFIX "user.fuseoverlayfs."
#define ORIGIN_XATTR "user.fuseoverlayfs.origin"
#define OPAQUE_XATTR "user.fuseoverlayfs.opaque"
#define XATTR_CONTAINERS_PREFIX "user.containers."
#define UNPRIVILEGED_XATTR_PREFIX "user.overlay."
#define UNPRIVILEGED_OPAQUE_XATTR "user.overlay.opaque"
#define PRIVILEGED_XATTR_PREFIX "trusted.overlay."
#define PRIVILEGED_OPAQUE_XATTR "trusted.overlay.opaque"
#define PRIVILEGED_ORIGIN_XATTR "trusted.overlay.origin"
#define OPAQUE_WHITEOUT ".wh..wh..opq"
#define WHITEOUT_MAX_LEN (sizeof (".wh.") - 1)

#if ! defined FICLONE && defined __linux__
#  define FICLONE _IOW (0x94, 9, int)
#endif

#if defined(__GNUC__) && (__GNUC__ > 4 || __GNUC__ == 4 && __GNUC_MINOR__ >= 6) && ! defined __cplusplus
_Static_assert (sizeof (fuse_ino_t) >= sizeof (uintptr_t),
                "fuse_ino_t too small to hold uintptr_t values!");
#else
struct _uintptr_to_must_hold_fuse_ino_t_dummy_struct
{
  unsigned _uintptr_to_must_hold_fuse_ino_t : ((sizeof (fuse_ino_t) >= sizeof (uintptr_t)) ? 1 : -1);
};
#endif

static uid_t overflow_uid;
static gid_t overflow_gid;

static struct ovl_ino dummy_ino;

struct stats_s
{
  size_t nodes;
  size_t inodes;
};

static volatile struct stats_s stats;

static void
print_stats (int sig)
{
  char fmt[128];
  int l = snprintf (fmt, sizeof (fmt) - 1, "# INODES: %zu\n# NODES: %zu\n", stats.inodes, stats.nodes);
  fmt[l] = '\0';
  (void) write (STDERR_FILENO, fmt, l + 1);
}

static double
get_timeout (struct ovl_data *lo)
{
  return lo->timeout;
}

static const struct fuse_opt ovl_opts[] = {
  { "redirect_dir=%s",
    offsetof (struct ovl_data, redirect_dir), 0 },
  { "context=%s",
    offsetof (struct ovl_data, context), 0 },
  { "lowerdir=%s",
    offsetof (struct ovl_data, lowerdir), 0 },
  { "upperdir=%s",
    offsetof (struct ovl_data, upperdir), 0 },
  { "workdir=%s",
    offsetof (struct ovl_data, workdir), 0 },
  { "uidmapping=%s",
    offsetof (struct ovl_data, uid_str), 0 },
  { "gidmapping=%s",
    offsetof (struct ovl_data, gid_str), 0 },
  { "timeout=%s",
    offsetof (struct ovl_data, timeout_str), 0 },
  { "threaded=%d",
    offsetof (struct ovl_data, threaded), 0 },
  { "fsync=%d",
    offsetof (struct ovl_data, fsync), 1 },
  { "fast_ino=%d",
    offsetof (struct ovl_data, fast_ino_check), 0 },
  { "writeback=%d",
    offsetof (struct ovl_data, writeback), 1 },
  { "noxattrs=%d",
    offsetof (struct ovl_data, disable_xattrs), 1 },
  { "plugins=%s",
    offsetof (struct ovl_data, plugins), 0 },
  { "xattr_permissions=%d",
    offsetof (struct ovl_data, xattr_permissions), 0 },
  { "squash_to_root",
    offsetof (struct ovl_data, squash_to_root), 1 },
  { "squash_to_uid=%d",
    offsetof (struct ovl_data, squash_to_uid), 1 },
  { "squash_to_gid=%d",
    offsetof (struct ovl_data, squash_to_gid), 1 },
  { "static_nlink",
    offsetof (struct ovl_data, static_nlink), 1 },
  { "volatile", /* native overlay supports "volatile" to mean fsync=0.  */
    offsetof (struct ovl_data, volatile_mode), 1 },
  { "noacl",
    offsetof (struct ovl_data, noacl), 1 },
  FUSE_OPT_END
};

/* The current process has enough privileges to use mknod.  */
static bool can_mknod = true;

/* Kernel definitions.  */

typedef unsigned char u8;
typedef unsigned char uuid_t[16];

/* The type returned by overlay exportfs ops when encoding an ovl_fh handle */
#define OVL_FILEID 0xfb

/* On-disk and in-memory format for redirect by file handle */
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

static ino_t
node_to_inode (struct ovl_node *n)
{
  return (ino_t) n->ino;
}

static struct ovl_ino *
lookup_inode (struct ovl_data *lo, ino_t n)
{
  return (struct ovl_ino *) n;
}

static struct ovl_node *
inode_to_node (struct ovl_data *lo, ino_t n)
{
  return lookup_inode (lo, n)->node;
}

static void
check_writeable_proc ()
{
  struct statfs svfs;
  int ret;

  ret = statfs ("/proc", &svfs);
  if (ret < 0)
    {
      fprintf (stderr, "error stating /proc: %m\n");
      return;
    }

  if (svfs.f_type != PROC_SUPER_MAGIC)
    {
      fprintf (stderr, "invalid file system type found on /proc: %d, expected %d\n", svfs.f_fsid, PROC_SUPER_MAGIC);
      return;
    }

  if (svfs.f_flags & ST_RDONLY)
    {
      fprintf (stderr, "/proc seems to be mounted as readonly, it can lead to unexpected failures");
      return;
    }
}

static void
check_can_mknod (struct ovl_data *lo)
{
  int ret;
  char path[PATH_MAX];

  if (getenv ("FUSE_OVERLAYFS_DISABLE_OVL_WHITEOUT"))
    {
      can_mknod = false;
      return;
    }

  sprintf (path, "%lu", get_next_wd_counter ());

  ret = mknodat (lo->workdir_fd, path, S_IFCHR | 0700, makedev (0, 0));
  if (ret == 0)
    unlinkat (lo->workdir_fd, path, 0);
  if (ret < 0 && errno == EPERM)
    can_mknod = false;
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
  struct ovl_data *lo = (struct ovl_data *) userdata;

  if ((conn->capable & FUSE_CAP_WRITEBACK_CACHE) == 0)
    lo->writeback = 0;

  if ((lo->noacl == 0) && (conn->capable & FUSE_CAP_POSIX_ACL))
    conn->want |= FUSE_CAP_POSIX_ACL;

  conn->want |= FUSE_CAP_DONT_MASK | FUSE_CAP_SPLICE_READ | FUSE_CAP_SPLICE_WRITE | FUSE_CAP_SPLICE_MOVE;
  if (lo->writeback)
    conn->want |= FUSE_CAP_WRITEBACK_CACHE;
}

static struct ovl_layer *
get_first_layer (struct ovl_data *lo)
{
  return lo->layers;
}

static struct ovl_layer *
get_upper_layer (struct ovl_data *lo)
{
  if (lo->upperdir == NULL)
    return NULL;

  return lo->layers;
}

static struct ovl_layer *
get_lower_layers (struct ovl_data *lo)
{
  if (lo->upperdir == NULL)
    return lo->layers;

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

static bool
can_access_xattr (const char *name)
{
  return ! has_prefix (name, XATTR_PREFIX)
         && ! has_prefix (name, PRIVILEGED_XATTR_PREFIX)
         && ! has_prefix (name, UNPRIVILEGED_XATTR_PREFIX);
}

static ssize_t
write_permission_xattr (struct ovl_data *lo, int fd, const char *path, uid_t uid, gid_t gid, mode_t mode)
{
  char buf[64];
  size_t len;
  int ret;
  const char *name = NULL;

  switch (lo->xattr_permissions)
    {
    case 0:
      return 0;

    case 1:
      name = XATTR_PRIVILEGED_OVERRIDE_STAT;
      break;

    case 2:
      name = XATTR_OVERRIDE_STAT;
      break;

    default:
      errno = EINVAL;
      return -1;
    }

  if (path == NULL && fd < 0)
    {
      errno = EINVAL;
      return -1;
    }

  len = sprintf (buf, "%d:%d:%o", uid, gid, mode);
  if (fd >= 0)
    return fsetxattr (fd, name, buf, len, 0);

  ret = lsetxattr (path, name, buf, len, 0);
  /* Ignore EPERM in unprivileged mode.  */
  if (ret < 0 && lo->xattr_permissions == 2 && errno == EPERM)
    return 0;
  return ret;
}

static int
do_fchown (struct ovl_data *lo, int fd, uid_t uid, gid_t gid, mode_t mode)
{
  int ret;
  if (lo->xattr_permissions)
    ret = write_permission_xattr (lo, fd, NULL, uid, gid, mode);
  else
    ret = fchown (fd, uid, gid);
  return (lo->squash_to_root || lo->squash_to_uid != -1 || lo->squash_to_gid != -1) ? 0 : ret;
}
/* Make sure it is not used anymore.  */
#define fchown ERROR

static int
do_chown (struct ovl_data *lo, const char *path, uid_t uid, gid_t gid, mode_t mode)
{
  int ret;
  if (lo->xattr_permissions)
    ret = write_permission_xattr (lo, -1, path, uid, gid, mode);
  else
    ret = chown (path, uid, gid);
  return (lo->squash_to_root || lo->squash_to_uid != -1 || lo->squash_to_gid != -1) ? 0 : ret;
}
/* Make sure it is not used anymore.  */
#define chown ERROR

static int
do_fchownat (struct ovl_data *lo, int dfd, const char *path, uid_t uid, gid_t gid, mode_t mode, int flags)
{
  int ret;
  if (lo->xattr_permissions)
    {
      char proc_path[32];
      cleanup_close int fd = openat (dfd, path, O_NOFOLLOW | O_PATH);
      if (fd < 0)
        return fd;

      sprintf (proc_path, "/proc/self/fd/%d", fd);
      ret = write_permission_xattr (lo, -1, proc_path, uid, gid, mode);
    }
  else
    ret = fchownat (dfd, path, uid, gid, flags);
  return (lo->squash_to_root || lo->squash_to_uid != -1 || lo->squash_to_gid != -1) ? 0 : ret;
}
/* Make sure it is not used anymore.  */
#define fchownat ERROR

static int
do_stat (struct ovl_node *node, int fd, const char *path, struct stat *st)
{
  struct ovl_layer *l = node->layer;

  if (fd >= 0)
    return l->ds->fstat (l, fd, path, STATX_BASIC_STATS, st);

  if (path != NULL)
    return stat (path, st);

  if (node->hidden)
    return fstatat (node_dirfd (node), node->path, st, AT_SYMLINK_NOFOLLOW);

  return l->ds->statat (l, node->path, st, AT_SYMLINK_NOFOLLOW, STATX_BASIC_STATS);
}

static int
do_fchmod (struct ovl_data *lo, struct ovl_node *node, int fd, mode_t mode)
{
  if (lo->xattr_permissions)
    {
      struct stat st;

      st.st_uid = 0;
      st.st_gid = 0;
      if (do_stat (node, fd, NULL, &st) < 0)
        return -1;

      return write_permission_xattr (lo, fd, NULL, st.st_uid, st.st_gid, mode);
    }
  return fchmod (fd, mode);
}
/* Make sure it is not used anymore.  */
#define fchmod ERROR

static int
do_chmod (struct ovl_data *lo, struct ovl_node *node, const char *path, mode_t mode)
{
  if (lo->xattr_permissions)
    {
      struct stat st;

      st.st_uid = 0;
      st.st_gid = 0;
      if (do_stat (node, -1, path, &st) < 0)
        return -1;

      return write_permission_xattr (lo, -1, path, st.st_uid, st.st_gid, mode);
    }
  return chmod (path, mode);
}
/* Make sure it is not used anymore.  */
#define chmod ERROR

static int
set_fd_origin (int fd, const char *origin)
{
  cleanup_close int opq_whiteout_fd = -1;
  size_t len = strlen (origin) + 1;
  int ret;

  ret = fsetxattr (fd, ORIGIN_XATTR, origin, len, 0);
  if (ret < 0)
    {
      if (errno == ENOTSUP)
        return 0;
    }
  return ret;
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
      if (errno != EPERM || (fsetxattr (fd, OPAQUE_XATTR, "y", 1, 0) < 0 && errno != ENOTSUP))
        return -1;
    }
create_opq_whiteout:
  opq_whiteout_fd = TEMP_FAILURE_RETRY (safe_openat (fd, OPAQUE_WHITEOUT, O_CREAT | O_WRONLY | O_NONBLOCK, 0700));
  return (opq_whiteout_fd >= 0 || ret == 0) ? 0 : -1;
}

static int
is_directory_opaque (struct ovl_layer *l, const char *path)
{
  char b[16];
  ssize_t s;

  s = l->ds->getxattr (l, path, PRIVILEGED_OPAQUE_XATTR, b, sizeof (b));
  if (s < 0 && errno == ENODATA)
    s = l->ds->getxattr (l, path, UNPRIVILEGED_OPAQUE_XATTR, b, sizeof (b));
  if (s < 0 && errno == ENODATA)
    s = l->ds->getxattr (l, path, OPAQUE_XATTR, b, sizeof (b));

  if (s < 0)
    {
      if (errno == ENOTSUP || errno == ENODATA)
        {
          char whiteout_opq_path[PATH_MAX];

          strconcat3 (whiteout_opq_path, PATH_MAX, path, "/" OPAQUE_WHITEOUT, NULL);

          if (l->ds->file_exists (l, whiteout_opq_path) == 0)
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
  char whiteout_wh_path[PATH_MAX];
  cleanup_close int fd = -1;
  int ret;

  if (! force_create)
    {
      char path[PATH_MAX];
      struct ovl_layer *l;
      bool found = false;

      strconcat3 (path, PATH_MAX, parent->path, "/", name);

      for (l = get_lower_layers (lo); l; l = l->next)
        {
          ret = l->ds->file_exists (l, path);
          if (ret < 0 && errno == ENOENT)
            continue;

          found = true;
          break;
        }
      /* Not present in the lower layers, do not do anything.  */
      if (! found)
        return 0;
    }

  if (! skip_mknod && can_mknod)
    {
      char whiteout_path[PATH_MAX];

      strconcat3 (whiteout_path, PATH_MAX, parent->path, "/", name);

      ret = mknodat (get_upper_layer (lo)->fd, whiteout_path, S_IFCHR | 0700, makedev (0, 0));
      if (ret == 0)
        return 0;

      if (errno == EEXIST)
        {
          int saved_errno = errno;
          struct stat st;

          /* Check whether it is already a whiteout.  */
          if (TEMP_FAILURE_RETRY (fstatat (get_upper_layer (lo)->fd, whiteout_path, &st, AT_SYMLINK_NOFOLLOW)) == 0
              && (st.st_mode & S_IFMT) == S_IFCHR
              && major (st.st_rdev) == 0
              && minor (st.st_rdev) == 0)
            return 0;

          errno = saved_errno;
        }

      if (errno != EPERM && errno != ENOTSUP)
        return -1;

      /* if it fails with EPERM then do not attempt mknod again.  */
      can_mknod = false;
    }

  strconcat3 (whiteout_wh_path, PATH_MAX, parent->path, "/.wh.", name);

  fd = get_upper_layer (lo)->ds->openat (get_upper_layer (lo), whiteout_wh_path, O_CREAT | O_WRONLY | O_NONBLOCK, 0700);
  if (fd < 0 && errno != EEXIST)
    return -1;

  return 0;
}

static int
delete_whiteout (struct ovl_data *lo, int dirfd, struct ovl_node *parent, const char *name)
{
  struct stat st;

  if (can_mknod)
    {
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
          char whiteout_path[PATH_MAX];

          strconcat3 (whiteout_path, PATH_MAX, parent->path, "/", name);

          if (get_upper_layer (lo)->ds->statat (get_upper_layer (lo), whiteout_path, &st, AT_SYMLINK_NOFOLLOW, STATX_MODE | STATX_TYPE) == 0
              && (st.st_mode & S_IFMT) == S_IFCHR
              && major (st.st_rdev) == 0
              && minor (st.st_rdev) == 0)
            {
              if (unlinkat (get_upper_layer (lo)->fd, whiteout_path, 0) < 0)
                return -1;
            }
        }
    }

  /* Look for the .wh. alternative as well.  */

  if (dirfd >= 0)
    {
      char whiteout_path[PATH_MAX];

      strconcat3 (whiteout_path, PATH_MAX, ".wh.", name, NULL);

      if (unlinkat (dirfd, whiteout_path, 0) < 0 && errno != ENOENT)
        return -1;
    }
  else
    {
      char whiteout_path[PATH_MAX];

      strconcat3 (whiteout_path, PATH_MAX, parent->path, "/.wh.", name);

      if (unlinkat (get_upper_layer (lo)->fd, whiteout_path, 0) < 0 && errno != ENOENT)
        return -1;
    }

  return 0;
}

static unsigned int
find_mapping (unsigned int id, const struct ovl_data *data,
              bool direct, bool uid)
{
  const struct ovl_mapping *mapping = (uid ? data->uid_mappings
                                           : data->gid_mappings);

  if (direct && uid && data->squash_to_uid != -1)
    return data->squash_to_uid;
  if (direct && ! uid && data->squash_to_gid != -1)
    return data->squash_to_gid;
  if (direct && data->squash_to_root)
    return 0;

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
  return find_mapping (id, data, false, true);
}

static uid_t
get_gid (struct ovl_data *data, gid_t id)
{
  return find_mapping (id, data, false, false);
}

static int
rpl_stat (fuse_req_t req, struct ovl_node *node, int fd, const char *path, struct stat *st_in, struct stat *st)
{
  int ret = 0;
  struct ovl_layer *l = node->layer;
  struct ovl_data *data = ovl_data (req);

  if (st_in)
    memcpy (st, st_in, sizeof (*st));
  else
    ret = do_stat (node, fd, path, st);

  if (ret < 0)
    return ret;

  st->st_uid = find_mapping (st->st_uid, data, true, true);
  st->st_gid = find_mapping (st->st_gid, data, true, false);

  st->st_ino = node->tmp_ino;
  st->st_dev = node->tmp_dev;

  if (node->loaded && node->n_links > 0)
    st->st_nlink = node->n_links;
  else if (node_dirp (node))
    {
      if (data->static_nlink)
        st->st_nlink = 1;
      else
        {
          struct ovl_node *it;

          st->st_nlink = 2;

          for (it = hash_get_first (node->children); it; it = hash_get_next (node->children, it))
            {
              if (node_dirp (it))
                st->st_nlink++;
            }
        }

      node->n_links = st->st_nlink;
    }
  else
    {
      struct ovl_node *n;

      st->st_nlink = 0;
      for (n = node->ino->node; n; n = n->next_link)
        st->st_nlink++;
    }

  return ret;
}

static void
node_mark_all_free (void *p)
{
  struct ovl_node *it, *n = (struct ovl_node *) p;

  for (it = n->next_link; it; it = it->next_link)
    it->ino->lookups = 0;

  n->ino->lookups = 0;

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
      if (n->parent->children && hash_lookup (n->parent->children, n) == n)
        hash_delete (n->parent->children, n);
      n->parent->loaded = 0;
      n->parent = NULL;
    }

  if ((n->ino && n->ino != &dummy_ino) || n->node_lookups > 0)
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

  stats.nodes--;
  free (n->name);
  free (n->path);
  free (n);
}

static void
inode_free (void *p)
{
  struct ovl_node *n, *tmp;
  struct ovl_ino *i = (struct ovl_ino *) p;

  n = i->node;
  while (n)
    {
      tmp = n;
      n = n->next_link;

      tmp->ino = NULL;
      node_free (tmp);
    }

  stats.inodes--;
  free (i);
}

static void
drop_node_from_ino (Hash_table *inodes, struct ovl_node *node)
{
  struct ovl_ino *ino;
  struct ovl_node *it, *prev = NULL;

  ino = node->ino;

  if (ino->lookups == 0)
    {
      hash_delete (inodes, ino);
      inode_free (ino);
      return;
    }

  /* If it is the only node referenced by the inode, do not destroy it.  */
  if (ino->node == node && node->next_link == NULL)
    return;

  node->ino = NULL;

  for (it = ino->node; it; it = it->next_link)
    {
      if (it == node)
        {
          if (prev)
            prev->next_link = it->next_link;
          else
            ino->node = it->next_link;
          break;
        }
      prev = it;
    }
}

static int
direct_renameat2 (int olddirfd, const char *oldpath,
                  int newdirfd, const char *newpath, unsigned int flags)
{
  return syscall (SYS_renameat2, olddirfd, oldpath, newdirfd, newpath, flags);
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

  if (unlink_src)
    {
      bool moved = false;
      bool whiteout_created = false;
      bool needs_whiteout;

      needs_whiteout = (node->last_layer != get_upper_layer (lo)) && (node->parent && node->parent->last_layer != get_upper_layer (lo));
      if (! needs_whiteout && node_dirp (node))
        {
          ret = is_directory_opaque (get_upper_layer (lo), node->path);
          if (ret < 0)
            return ret;
          if (ret)
            needs_whiteout = true;
        }

      // if the parent directory is opaque, there's no need to put a whiteout in it.
      if (node->parent != NULL)
        needs_whiteout = needs_whiteout && (is_directory_opaque (get_upper_layer (lo), node->parent->path) < 1);

      if (needs_whiteout)
        {
          /* If the atomic rename+mknod failed, then fallback into doing it in two steps.  */
          if (can_mknod && syscall (SYS_renameat2, node_dirfd (node), node->path, lo->workdir_fd, newpath, RENAME_WHITEOUT) == 0)
            {
              whiteout_created = true;
              moved = true;
            }

          if (! whiteout_created)
            {
              if (node->parent)
                {
                  /* If we are here, it means we have no permissions to use mknod.  Also
                     since the file is not yet moved, creating a whiteout would fail on
                     the mknodat call.  */
                  if (create_whiteout (lo, node->parent, node->name, true, false) < 0)
                    return -1;
                }
            }
        }

      if (! moved)
        {
          if (renameat (node_dirfd (node), node->path, lo->workdir_fd, newpath) < 0)
            return -1;
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
  drop_node_from_ino (lo->inodes, node);

  node->hidden_dirfd = lo->workdir_fd;
  free (node->path);
  node->path = newpath;
  newpath = NULL; /* Do not auto cleanup.  */

  node->hidden = 1;
  if (node->parent)
    node->parent->loaded = 0;
  node->parent = NULL;

  if (node_dirp (node))
    node->do_rmdir = 1;
  else
    node->do_unlink = 1;
  return 0;
}

static size_t
node_inode_hasher (const void *p, size_t s)
{
  struct ovl_ino *n = (struct ovl_ino *) p;

  return (n->ino ^ n->dev) % s;
}

static bool
node_inode_compare (const void *n1, const void *n2)
{
  struct ovl_ino *i1 = (struct ovl_ino *) n1;
  struct ovl_ino *i2 = (struct ovl_ino *) n2;

  return i1->ino == i2->ino && i1->dev == i2->dev;
}

static size_t
node_hasher (const void *p, size_t s)
{
  struct ovl_node *n = (struct ovl_node *) p;
  return n->name_hash % s;
}

static bool
node_compare (const void *n1, const void *n2)
{
  struct ovl_node *node1 = (struct ovl_node *) n1;
  struct ovl_node *node2 = (struct ovl_node *) n2;

  if (node1->name_hash != node2->name_hash)
    return false;

  return strcmp (node1->name, node2->name) == 0 ? true : false;
}

static struct ovl_node *
register_inode (struct ovl_data *lo, struct ovl_node *n, mode_t mode)
{
  struct ovl_ino key;
  struct ovl_ino *ino = NULL;

  key.ino = n->tmp_ino;
  key.dev = n->tmp_dev;

  /* Already registered.  */
  if (n->ino)
    return n;

  ino = hash_lookup (lo->inodes, &key);
  if (ino)
    {
      struct ovl_node *it;

      for (it = ino->node; it; it = it->next_link)
        {
          if (node_dirp (it) || strcmp (n->path, it->path) == 0)
            {
              node_free (n);
              return it;
            }
        }

      n->next_link = ino->node;
      ino->node = n;
      ino->mode = mode;
      n->ino = ino;
      return n;
    }

  ino = calloc (1, sizeof (*ino));
  if (ino == NULL)
    return NULL;

  ino->ino = n->tmp_ino;
  ino->dev = n->tmp_dev;
  ino->node = n;
  n->ino = ino;
  ino->mode = mode;

  if (hash_insert (lo->inodes, ino) == NULL)
    {
      free (ino);
      node_free (n);
      return NULL;
    }

  stats.inodes++;
  return ino->node;
}

static bool
do_forget (struct ovl_data *lo, fuse_ino_t ino, uint64_t nlookup)
{
  struct ovl_ino *i;

  if (ino == FUSE_ROOT_ID || ino == 0)
    return false;

  i = lookup_inode (lo, ino);
  if (i == NULL || i == &dummy_ino)
    return false;

  i->lookups -= nlookup;
  if (i->lookups <= 0)
    {
      hash_delete (lo->inodes, i);
      inode_free (i);
    }
  return true;
}

/* cleanup any inode that has 0 lookups.  */
static void
cleanup_inodes (struct ovl_data *lo)
{
  cleanup_free struct ovl_ino **to_cleanup = NULL;
  size_t no_lookups = 0;
  struct ovl_ino *it;
  size_t i;

  /* Also attempt to cleanup any inode that has 0 lookups.  */
  for (it = hash_get_first (lo->inodes); it; it = hash_get_next (lo->inodes, it))
    {
      if (it->lookups == 0)
        no_lookups++;
    }
  if (no_lookups > 0)
    {
      to_cleanup = malloc (sizeof (*to_cleanup) * no_lookups);
      if (! to_cleanup)
        return;

      for (i = 0, it = hash_get_first (lo->inodes); it; it = hash_get_next (lo->inodes, it))
        {
          if (it->lookups == 0)
            to_cleanup[i++] = it;
        }
      for (i = 0; i < no_lookups; i++)
        do_forget (lo, (fuse_ino_t) to_cleanup[i], 0);
    }
}

static void
ovl_forget (fuse_req_t req, fuse_ino_t ino, uint64_t nlookup)
{
  cleanup_lock int l = enter_big_lock ();
  struct ovl_data *lo = ovl_data (req);

  if (UNLIKELY (ovl_debug (req)))
    fprintf (stderr, "ovl_forget(ino=%" PRIu64 ", nlookup=%lu)\n",
             ino, nlookup);
  do_forget (lo, ino, nlookup);
  fuse_reply_none (req);
}

static void
ovl_forget_multi (fuse_req_t req, size_t count, struct fuse_forget_data *forgets)
{
  size_t i;
  cleanup_lock int l = enter_big_lock ();
  struct ovl_data *lo = ovl_data (req);

  if (UNLIKELY (ovl_debug (req)))
    fprintf (stderr, "ovl_forget_multi(count=%zu, forgets=%p)\n",
             count, forgets);

  for (i = 0; i < count; i++)
    do_forget (lo, forgets[i].ino, forgets[i].nlookup);

  cleanup_inodes (lo);

  fuse_reply_none (req);
}

static inline void
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

#define cleanup_node_init __attribute__ ((cleanup (cleanup_node_initp)))

static void
node_set_name (struct ovl_node *node, char *name)
{
  node->name = name;
  if (name == NULL)
    node->name_hash = 0;
  else
    node->name_hash = hash_string (name, SIZE_MAX);
}

static struct ovl_node *
make_whiteout_node (const char *path, const char *name)
{
  cleanup_node_init struct ovl_node *ret = NULL;
  struct ovl_node *ret_xchg;
  char *new_name;

  ret = calloc (1, sizeof (*ret));
  if (ret == NULL)
    return NULL;

  new_name = strdup (name);
  if (new_name == NULL)
    return NULL;

  node_set_name (ret, new_name);

  ret->path = strdup (path);
  if (ret->path == NULL)
    return NULL;

  ret->whiteout = 1;
  ret->ino = &dummy_ino;

  ret_xchg = ret;
  ret = NULL;

  stats.nodes++;
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
      if (s >= 0 && s < current_size)
        break;

      if (s < 0 && errno != ERANGE)
        break;

      current_size *= 2;
      tmp = realloc (buffer, current_size + 1);
      if (tmp == NULL)
        return -1;

      buffer = tmp;
    }

  if (s <= 0)
    return s;

  buffer[s] = '\0';

  /* Change owner.  */
  *ret = buffer;
  buffer = NULL;

  return s;
}

static struct ovl_node *
make_ovl_node (struct ovl_data *lo, const char *path, struct ovl_layer *layer, const char *name, ino_t ino, dev_t dev, bool dir_p, struct ovl_node *parent, bool fast_ino_check)
{
  mode_t mode = 0;
  char *new_name;
  struct ovl_node *ret_xchg;
  bool has_origin = true;
  cleanup_node_init struct ovl_node *ret = NULL;

  ret = calloc (1, sizeof (*ret));
  if (ret == NULL)
    return NULL;

  ret->parent = parent;
  ret->layer = layer;
  ret->tmp_ino = ino;
  ret->tmp_dev = dev;
  ret->hidden_dirfd = -1;
  ret->inodes = lo->inodes;
  ret->next_link = NULL;
  ret->ino = NULL;
  ret->node_lookups = 0;

  new_name = strdup (name);
  if (new_name == NULL)
    return NULL;
  node_set_name (ret, new_name);

  if (has_prefix (path, "./") && path[2])
    path += 2;

  ret->path = strdup (path);
  if (ret->path == NULL)
    return NULL;

  if (! dir_p)
    ret->children = NULL;
  else
    {
      ret->children = hash_initialize (128, NULL, node_hasher, node_compare, node_free);
      if (ret->children == NULL)
        return NULL;
    }

  if (ret->tmp_ino == 0)
    {
      struct stat st;
      struct ovl_layer *it;
      cleanup_free char *npath = NULL;
      char whiteout_path[PATH_MAX];

      npath = strdup (ret->path);
      if (npath == NULL)
        return NULL;

      if (parent)
        strconcat3 (whiteout_path, PATH_MAX, parent->path, "/.wh.", name);
      else
        strconcat3 (whiteout_path, PATH_MAX, "/.wh.", name, NULL);

      for (it = layer; it; it = it->next)
        {
          ssize_t s;
          cleanup_free char *val = NULL;
          cleanup_free char *origin = NULL;
          cleanup_close int fd = -1;

          if (dir_p)
            {
              int r;

              r = it->ds->file_exists (it, whiteout_path);
              if (r < 0 && errno == EACCES)
                break;

              if (r < 0 && errno != ENOENT && errno != ENOTDIR && errno != ENAMETOOLONG)
                return NULL;

              if (r == 0)
                break;
            }

          if (! fast_ino_check)
            fd = it->ds->openat (it, npath, O_RDONLY | O_NONBLOCK | O_NOFOLLOW, 0755);

          if (fd < 0)
            {
              if (it->ds->statat (it, npath, &st, AT_SYMLINK_NOFOLLOW, STATX_TYPE | STATX_MODE | STATX_INO) == 0)
                {
                  if (has_origin)
                    {
                      ret->tmp_ino = st.st_ino;
                      ret->tmp_dev = st.st_dev;
                      if (mode == 0)
                        mode = st.st_mode;
                    }
                  ret->last_layer = it;
                }
              has_origin = false;
              goto no_fd;
            }

          /* It is an open FD, stat the file and read the origin xattrs.  */
          if (it->ds->fstat (it, fd, npath, STATX_TYPE | STATX_MODE | STATX_INO, &st) == 0)
            {
              if (has_origin)
                {
                  ret->tmp_ino = st.st_ino;
                  ret->tmp_dev = st.st_dev;
                  if (mode == 0)
                    mode = st.st_mode;
                }
              ret->last_layer = it;
            }

          s = safe_read_xattr (&val, fd, PRIVILEGED_ORIGIN_XATTR, PATH_MAX);
          if (s > 0)
            {
              char buf[512];
              struct ovl_fh *ofh = (struct ovl_fh *) val;
              size_t s = ofh->len - sizeof (*ofh);
              struct file_handle *fh = (struct file_handle *) buf;

              if (s < sizeof (buf) - sizeof (int) * 2)
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
                      if (it->ds->fstat (it, originfd, npath, STATX_TYPE | STATX_MODE | STATX_INO, &st) == 0)
                        {
                          ret->tmp_ino = st.st_ino;
                          ret->tmp_dev = st.st_dev;
                          mode = st.st_mode;
                          break;
                        }
                    }
                }
            }

          /* If an origin is specified, use it for the next layer lookup.  */
          s = safe_read_xattr (&origin, fd, ORIGIN_XATTR, PATH_MAX);
          if (s <= 0)
            has_origin = false;
          else
            {
              free (npath);
              npath = origin;
              origin = NULL;
            }

        no_fd:
          if (parent && parent->last_layer == it)
            break;
        }
    }

  ret_xchg = ret;
  ret = NULL;

  stats.nodes++;
  return register_inode (lo, ret_xchg, mode);
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
  if (st
      && (st->st_mode & S_IFMT) == S_IFCHR
      && major (st->st_rdev) == 0
      && minor (st->st_rdev) == 0)
    return name;
  return NULL;
}

static struct ovl_node *
load_dir (struct ovl_data *lo, struct ovl_node *n, struct ovl_layer *layer, char *path, char *name)
{
  struct dirent *dent;
  bool stop_lookup = false;
  struct ovl_layer *it, *upper_layer = get_upper_layer (lo);
  char parent_whiteout_path[PATH_MAX];

  if (! n)
    {
      n = make_ovl_node (lo, path, layer, name, 0, 0, true, NULL, lo->fast_ino_check);
      if (n == NULL)
        {
          errno = ENOMEM;
          return NULL;
        }
    }

  if (n->parent)
    strconcat3 (parent_whiteout_path, PATH_MAX, n->parent->path, "/.wh.", name);
  else
    strconcat3 (parent_whiteout_path, PATH_MAX, ".wh.", name, NULL);

  for (it = lo->layers; it && ! stop_lookup; it = it->next)
    {
      struct stat st;
      DIR *dp = NULL;
      int ret;

      if (n->last_layer == it)
        stop_lookup = true;

      ret = it->ds->file_exists (it, parent_whiteout_path);
      if (ret < 0 && errno != ENOENT && errno != ENOTDIR && errno != ENAMETOOLONG)
        return NULL;

      if (ret == 0)
        break;

      ret = it->ds->statat (it, path, &st, AT_SYMLINK_NOFOLLOW, STATX_TYPE);
      if (ret < 0)
        {
          if (errno == ENOENT || errno == ENOTDIR || errno == ENAMETOOLONG)
            continue;
          return NULL;
        }
      /* not a directory, stop lookup in lower layers.  */
      if ((st.st_mode & S_IFMT) != S_IFDIR)
        break;

      dp = it->ds->opendir (it, path);
      if (dp == NULL)
        continue;

      for (;;)
        {
          struct ovl_node key;
          struct ovl_node *child = NULL;
          char node_path[PATH_MAX];
          char whiteout_path[PATH_MAX];

          errno = 0;
          dent = it->ds->readdir (dp);
          if (dent == NULL)
            {
              if (errno)
                {
                  it->ds->closedir (dp);
                  return NULL;
                }

              break;
            }

          node_set_name (&key, dent->d_name);

          if ((strcmp (dent->d_name, ".") == 0) || strcmp (dent->d_name, "..") == 0)
            continue;

          child = hash_lookup (n->children, &key);
          if (child)
            {
              child->last_layer = it;
              if (! child->whiteout || it != upper_layer)
                continue;
              else
                {
                  hash_delete (n->children, child);
                  node_free (child);
                  child = NULL;
                }
            }

          strconcat3 (whiteout_path, PATH_MAX, path, "/.wh.", dent->d_name);

          strconcat3 (node_path, PATH_MAX, n->path, "/", dent->d_name);

          ret = it->ds->file_exists (it, whiteout_path);
          if (ret < 0 && errno == EACCES)
            continue;
          if (ret < 0 && errno != ENOENT && errno != ENOTDIR && errno != ENAMETOOLONG)
            {
              it->ds->closedir (dp);
              return NULL;
            }

          if (ret == 0)
            {
              child = make_whiteout_node (node_path, dent->d_name);
              if (child == NULL)
                {
                  errno = ENOMEM;
                  it->ds->closedir (dp);
                  return NULL;
                }
            }
          else
            {
              const char *wh = NULL;
              bool dirp = dent->d_type == DT_DIR;

              if ((dent->d_type != DT_CHR) && (dent->d_type != DT_UNKNOWN))
                wh = get_whiteout_name (dent->d_name, NULL);
              else
                {
                  /* A stat is required either if the type is not known, or if it is a character device as it could be
                     a whiteout file.  */
                  struct stat st;

                  ret = it->ds->statat (it, node_path, &st, AT_SYMLINK_NOFOLLOW, STATX_TYPE);
                  if (ret < 0)
                    {
                      it->ds->closedir (dp);
                      return NULL;
                    }

                  dirp = st.st_mode & S_IFDIR;
                  wh = get_whiteout_name (dent->d_name, &st);
                }

              if (wh)
                {
                  child = make_whiteout_node (node_path, wh);
                  if (child == NULL)
                    {
                      errno = ENOMEM;
                      it->ds->closedir (dp);
                      return NULL;
                    }
                }
              else
                {
                  ino_t ino = 0;

                  if (lo->fast_ino_check)
                    ino = dent->d_ino;

                  child = make_ovl_node (lo, node_path, it, dent->d_name, ino, 0, dirp, n, lo->fast_ino_check);
                  if (child == NULL)
                    {
                      errno = ENOMEM;
                      it->ds->closedir (dp);
                      return NULL;
                    }
                  child->last_layer = it;
                }
            }

          if (insert_node (n, child, false) == NULL)
            {
              errno = ENOMEM;
              it->ds->closedir (dp);
              return NULL;
            }
        }

      ret = is_directory_opaque (it, path);
      if (ret < 0)
        {
          it->ds->closedir (dp);
          return NULL;
        }
      if (ret > 0)
        {
          n->last_layer = it;
          stop_lookup = true;
        }
      it->ds->closedir (dp);
    }

  if (get_timeout (lo) > 0)
    n->loaded = 1;
  return n;
}

static struct ovl_node *
reload_dir (struct ovl_data *lo, struct ovl_node *node)
{
  if (! node->loaded)
    node = load_dir (lo, node, node->layer, node->path, node->name);
  return node;
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

#define cleanup_layer __attribute__ ((cleanup (cleanup_layerp)))

static struct ovl_layer *
read_dirs (struct ovl_data *lo, char *path, bool low, struct ovl_layer *layers)
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
      char *name, *data;
      char *it_path = it;
      int i, n_layers;
      cleanup_layer struct ovl_layer *l = NULL;
      struct data_source *ds;

      if (it[0] != '/' || it[1] != '/')
        {
          /* By default use the direct access data store.  */
          ds = &direct_access_ds;

          data = NULL;
          path = it_path;
        }
      else
        {
          struct ovl_plugin *p;
          char *plugin_data_sep, *plugin_sep;

          if (! low)
            {
              fprintf (stderr, "plugins are supported only with lower layers\n");
              return NULL;
            }

          plugin_sep = strchr (it + 2, '/');
          if (! plugin_sep)
            {
              fprintf (stderr, "invalid separator for plugin\n");
              return NULL;
            }

          *plugin_sep = '\0';

          name = it + 2;
          data = plugin_sep + 1;

          plugin_data_sep = strchr (data, '/');
          if (! plugin_data_sep)
            {
              fprintf (stderr, "invalid separator for plugin\n");
              return NULL;
            }

          *plugin_data_sep = '\0';
          path = plugin_data_sep + 1;

          p = plugin_find (lo->plugins_ctx, name);
          if (! p)
            {
              fprintf (stderr, "cannot find plugin %s\n", name);
              return NULL;
            }

          ds = p->load (data, path);
          if (ds == NULL)
            {
              fprintf (stderr, "cannot load plugin %s\n", name);
              return NULL;
            }
        }

      n_layers = ds->num_of_layers (data, path);
      if (n_layers < 0)
        {
          fprintf (stderr, "cannot retrieve number of layers for %s\n", path);
          return NULL;
        }

      for (i = 0; i < n_layers; i++)
        {
          l = calloc (1, sizeof (*l));
          if (l == NULL)
            return NULL;

          l->ds = ds;

          l->ovl_data = lo;

          l->path = NULL;
          l->fd = -1;

          if (l->ds->load_data_source (l, data, path, i) < 0)
            {
              fprintf (stderr, "cannot load store %s at %s\n", data, path);
              return NULL;
            }

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
    pnode = inode_to_node (lo, parent);

  if (name == NULL)
    {
      /* Prefer a version that is loaded.  */
      for (node = pnode; node; node = node->next_link)
        if (node->parent)
          return node;
      return pnode;
    }

  if (has_prefix (name, ".wh."))
    {
      errno = EINVAL;
      return NULL;
    }

  node_set_name (&key, (char *) name);
  node = hash_lookup (pnode->children, &key);
  if (node == NULL && ! pnode->loaded)
    {
      int ret;
      struct ovl_layer *it;
      struct stat st;
      bool stop_lookup = false;

      for (it = lo->layers; it && ! stop_lookup; it = it->next)
        {
          char path[PATH_MAX];
          char whpath[PATH_MAX];
          const char *wh_name;

          if (pnode->last_layer == it)
            stop_lookup = true;

          strconcat3 (path, PATH_MAX, pnode->path, "/", name);

          ret = it->ds->statat (it, path, &st, AT_SYMLINK_NOFOLLOW, STATX_TYPE | STATX_MODE | STATX_INO);
          if (ret < 0)
            {
              int saved_errno = errno;

              if (errno == ENOENT || errno == ENOTDIR || errno == EACCES)
                {
                  if (node)
                    continue;

                  strconcat3 (whpath, PATH_MAX, pnode->path, "/.wh.", name);

                  ret = it->ds->file_exists (it, whpath);
                  if (ret < 0 && errno != ENOENT && errno != ENOTDIR && errno != ENAMETOOLONG)
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
              node->tmp_ino = st.st_ino;
              node->tmp_dev = st.st_dev;
              node->last_layer = it;
              continue;
            }

          strconcat3 (whpath, PATH_MAX, pnode->path, "/.wh.", name);
          ret = it->ds->file_exists (it, whpath);
          if (ret < 0 && errno != ENOENT && errno != ENOTDIR && errno != ENAMETOOLONG)
            return NULL;
          if (ret == 0)
            node = make_whiteout_node (path, name);
          else
            {
              wh_name = get_whiteout_name (name, &st);
              if (wh_name)
                node = make_whiteout_node (path, wh_name);
              else
                node = make_ovl_node (lo, path, it, name, 0, 0, st.st_mode & S_IFDIR, pnode, lo->fast_ino_check);
            }
          if (node == NULL)
            {
              errno = ENOMEM;
              return NULL;
            }

          if (st.st_mode & S_IFDIR)
            {
              ret = is_directory_opaque (it, path);
              if (ret < 0)
                {
                  node_free (node);
                  return NULL;
                }
              if (ret > 0)
                {
                  node->last_layer = it;
                  stop_lookup = true;
                }
            }
        insert_node:
          if (insert_node (pnode, node, false) == NULL)
            {
              node_free (node);
              errno = ENOMEM;
              return NULL;
            }
        }
    }

  return node;
}

static void
ovl_lookup (fuse_req_t req, fuse_ino_t parent, const char *name)
{
  cleanup_lock int l = enter_big_lock ();
  struct fuse_entry_param e;
  int err = 0;
  struct ovl_data *lo = ovl_data (req);
  struct ovl_node *node;

  if (UNLIKELY (ovl_debug (req)))
    fprintf (stderr, "ovl_lookup(parent=%" PRIu64 ", name=%s)\n",
             parent, name);

  memset (&e, 0, sizeof (e));

  node = do_lookup_file (lo, parent, name);
  if (node == NULL || node->whiteout)
    {
      e.ino = 0;
      e.attr_timeout = get_timeout (lo);
      e.entry_timeout = get_timeout (lo);
      fuse_reply_entry (req, &e);
      return;
    }

  if (! lo->static_nlink && node_dirp (node))
    {
      node = reload_dir (lo, node);
      if (node == NULL)
        {
          fuse_reply_err (req, errno);
          return;
        }
    }

  err = rpl_stat (req, node, -1, NULL, NULL, &e.attr);
  if (err)
    {
      fuse_reply_err (req, errno);
      return;
    }

  e.ino = node_to_inode (node);
  node->ino->lookups++;
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

static int
reload_tbl (struct ovl_data *lo, struct ovl_dirp *d, struct ovl_node *node)
{
  size_t counter = 0;
  struct ovl_node *it;

  node = reload_dir (lo, node);
  if (node == NULL)
    return -1;

  if (d->tbl)
    free (d->tbl);

  d->offset = 0;
  d->parent = node;
  d->tbl_size = hash_get_n_entries (node->children) + 2;
  d->tbl = calloc (sizeof (struct ovl_node *), d->tbl_size);
  if (d->tbl == NULL)
    {
      errno = ENOMEM;
      return -1;
    }

  d->tbl[counter++] = node;
  d->tbl[counter++] = node->parent;

  for (it = hash_get_first (node->children); it; it = hash_get_next (node->children, it))
    {
      it->ino->lookups++;
      it->node_lookups++;
      d->tbl[counter++] = it;
    }

  return 0;
}

static void
ovl_opendir (fuse_req_t req, fuse_ino_t ino, struct fuse_file_info *fi)
{
  struct ovl_node *node;
  struct ovl_data *lo = ovl_data (req);
  struct ovl_dirp *d = calloc (1, sizeof (struct ovl_dirp));
  cleanup_lock int l = enter_big_lock ();

  if (UNLIKELY (ovl_debug (req)))
    fprintf (stderr, "ovl_opendir(ino=%" PRIu64 ")\n", ino);

  if (d == NULL)
    {
      errno = ENOMEM;
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

  d->parent = node;

  fi->fh = (uintptr_t) d;
  if (get_timeout (lo) > 0)
    {
      fi->keep_cache = 1;
#if HAVE_FUSE_CACHE_READDIR
      fi->cache_readdir = 1;
#endif
    }
  node->in_readdir++;
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

  node = reload_dir (lo, node);
  if (node == NULL)
    return -1;

  for (l = get_lower_layers (lo); l; l = l->next)
    {
      cleanup_dir DIR *dp = NULL;

      dp = l->ds->opendir (l, from);
      if (dp == NULL)
        {
          if (errno == ENOTDIR)
            break;
          if (errno == ENOENT)
            continue;
          return -1;
        }
      else
        {
          struct dirent *dent;

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
              if (has_prefix (dent->d_name, ".wh."))
                continue;

              node_set_name (&key, (char *) dent->d_name);

              n = hash_lookup (node->children, &key);
              if (n)
                {
                  if (node_dirp (n))
                    {
                      char c[PATH_MAX];

                      n = reload_dir (lo, n);
                      if (n == NULL)
                        return -1;

                      strconcat3 (c, PATH_MAX, from, "/", n->name);

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

  buffer = malloc (size);
  if (buffer == NULL)
    {
      fuse_reply_err (req, errno);
      return;
    }

  if (offset == 0 || d->tbl == NULL)
    {
      if (reload_tbl (lo, d, d->parent) < 0)
        {
          fuse_reply_err (req, errno);
          return;
        }
    }

  p = buffer;
  for (; remaining > 0 && offset < d->tbl_size; offset++)
    {
      int ret;
      size_t entsize;
      const char *name;
      struct ovl_node *node = d->tbl[offset];
      struct fuse_entry_param e;
      struct stat *st = &e.attr;

      if (node == NULL || node->whiteout || node->hidden)
        continue;

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

      if (! plus)
        {
          /* From the 'stbuf' argument the st_ino field and bits 12-15 of the
           * st_mode field are used.  The other fields are ignored.
           */
          st->st_ino = node->tmp_ino;
          st->st_dev = node->tmp_dev;
          st->st_mode = node->ino->mode;

          entsize = fuse_add_direntry (req, p, remaining, name, st, offset + 1);
        }
      else
        {
          if (! lo->static_nlink && node_dirp (node))
            {
              node = reload_dir (lo, node);
              if (node == NULL)
                {
                  fuse_reply_err (req, errno);
                  return;
                }
            }
          memset (&e, 0, sizeof (e));
          ret = rpl_stat (req, node, -1, NULL, NULL, st);
          if (ret < 0)
            {
              fuse_reply_err (req, errno);
              return;
            }

          e.attr_timeout = get_timeout (lo);
          e.entry_timeout = get_timeout (lo);
          e.ino = node_to_inode (node);
          entsize = fuse_add_direntry_plus (req, p, remaining, name, &e, offset + 1);
          if (entsize <= remaining)
            {
              /* First two entries are . and .. */
              if (offset >= 2)
                node->ino->lookups++;
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
  cleanup_lock int l = enter_big_lock ();
  if (UNLIKELY (ovl_debug (req)))
    fprintf (stderr, "ovl_readdir(ino=%" PRIu64 ", size=%zu, offset=%lo)\n", ino, size, offset);
  ovl_do_readdir (req, ino, size, offset, fi, 0);
}

static void
ovl_readdirplus (fuse_req_t req, fuse_ino_t ino, size_t size,
                 off_t offset, struct fuse_file_info *fi)
{
  cleanup_lock int l = enter_big_lock ();
  if (UNLIKELY (ovl_debug (req)))
    fprintf (stderr, "ovl_readdirplus(ino=%" PRIu64 ", size=%zu, offset=%lo)\n", ino, size, offset);
  ovl_do_readdir (req, ino, size, offset, fi, 1);
}

static void
ovl_releasedir (fuse_req_t req, fuse_ino_t ino, struct fuse_file_info *fi)
{
  cleanup_lock int l = enter_big_lock ();
  size_t s;
  struct ovl_dirp *d = ovl_dirp (fi);
  struct ovl_data *lo = ovl_data (req);
  struct ovl_node *node = NULL;

  if (UNLIKELY (ovl_debug (req)))
    fprintf (stderr, "ovl_releasedir(ino=%" PRIu64 ")\n", ino);

  for (s = 2; s < d->tbl_size; s++)
    {
      d->tbl[s]->node_lookups--;
      if (! do_forget (lo, (fuse_ino_t) d->tbl[s]->ino, 1))
        {
          if (d->tbl[s]->node_lookups == 0)
            node_free (d->tbl[s]);
        }
    }

  node = do_lookup_file (lo, ino, NULL);
  if (node)
    node->in_readdir--;

  free (d->tbl);
  free (d);
  fuse_reply_err (req, 0);
}

static int
inherit_acl (struct ovl_data *lo, struct ovl_node *parent, int targetfd, const char *path)
{
  cleanup_free char *v = NULL;
  cleanup_close int dfd = -1;
  int s;

  if (parent == NULL || lo->noacl)
    return 0;

  dfd = safe_openat (node_dirfd (parent), parent->path, O_DIRECTORY, 0);
  if (dfd < 0)
    return -1;

  s = safe_read_xattr (&v, dfd, ACL_XATTR, 4096);
  if (s < 0)
    {
      if (errno == ENODATA || errno == ENOTSUP)
        return 0;
      return -1;
    }
  if (targetfd >= 0)
    return fsetxattr (targetfd, ACL_XATTR, v, s, 0);

  return setxattr (path, ACL_XATTR, v, s, 0);
}

/* in-place filter xattrs that cannot be accessed.  */
static ssize_t
filter_xattrs_list (char *buf, ssize_t len)
{
  ssize_t ret = 0;
  char *it;

  if (buf == NULL)
    return len;

  it = buf;

  while (it < buf + len)
    {
      size_t it_len;

      it_len = strlen (it) + 1;

      if (can_access_xattr (it))
        {
          it += it_len;
          ret += it_len;
        }
      else
        {
          char *next = it + it_len;

          memmove (it, next, buf + len - next);
          len -= it_len;
        }
    }

  return ret;
}

static void
ovl_listxattr (fuse_req_t req, fuse_ino_t ino, size_t size)
{
  cleanup_lock int l = enter_big_lock ();
  ssize_t len;
  struct ovl_node *node;
  struct ovl_data *lo = ovl_data (req);
  cleanup_free char *buf = NULL;
  int ret;

  if (UNLIKELY (ovl_debug (req)))
    fprintf (stderr, "ovl_listxattr(ino=%" PRIu64 ", size=%zu)\n", ino, size);

  if (lo->disable_xattrs)
    {
      fuse_reply_err (req, ENOSYS);
      return;
    }

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
          fuse_reply_err (req, errno);
          return;
        }
    }

  if (! node->hidden)
    ret = node->layer->ds->listxattr (node->layer, node->path, buf, size);
  else
    {
      char path[PATH_MAX];
      strconcat3 (path, PATH_MAX, lo->workdir, "/", node->path);
      ret = listxattr (path, buf, size);
    }
  if (ret < 0)
    {
      fuse_reply_err (req, errno);
      return;
    }

  len = filter_xattrs_list (buf, ret);

  if (size == 0)
    fuse_reply_xattr (req, len);
  else if (len <= size)
    fuse_reply_buf (req, buf, len);
}

static void
ovl_getxattr (fuse_req_t req, fuse_ino_t ino, const char *name, size_t size)
{
  cleanup_lock int l = enter_big_lock ();
  ssize_t len;
  struct ovl_node *node;
  struct ovl_data *lo = ovl_data (req);
  cleanup_free char *buf = NULL;
  int ret;

  if (UNLIKELY (ovl_debug (req)))
    fprintf (stderr, "ovl_getxattr(ino=%" PRIu64 ", name=%s, size=%zu)\n", ino, name, size);

  if (lo->disable_xattrs)
    {
      fuse_reply_err (req, ENOSYS);
      return;
    }

  if (! can_access_xattr (name))
    {
      fuse_reply_err (req, ENODATA);
      return;
    }

  node = do_lookup_file (lo, ino, NULL);
  if (node == NULL || node->whiteout)
    {
      fuse_reply_err (req, ENOENT);
      return;
    }

  if (size > 0)
    {
      buf = malloc (size);
      if (buf == NULL)
        {
          fuse_reply_err (req, errno);
          return;
        }
    }

  if (! node->hidden)
    ret = node->layer->ds->getxattr (node->layer, node->path, name, buf, size);
  else
    {
      char path[PATH_MAX];
      strconcat3 (path, PATH_MAX, lo->workdir, "/", node->path);
      ret = getxattr (path, name, buf, size);
    }

  if (ret < 0)
    {
      fuse_reply_err (req, errno);
      return;
    }

  len = ret;

  if (size == 0)
    fuse_reply_xattr (req, len);
  else
    fuse_reply_buf (req, buf, len);
}

static void
ovl_access (fuse_req_t req, fuse_ino_t ino, int mask)
{
  cleanup_lock int l = enter_big_lock ();
  struct ovl_data *lo = ovl_data (req);
  struct ovl_node *n = do_lookup_file (lo, ino, NULL);

  if (UNLIKELY (ovl_debug (req)))
    fprintf (stderr, "ovl_access(ino=%" PRIu64 ", mask=%d)\n",
             ino, mask);

  if ((mask & n->ino->mode) == mask)
    fuse_reply_err (req, 0);
  else
    fuse_reply_err (req, EPERM);
}

static int
copy_xattr (int sfd, int dfd, char *buf, size_t buf_size)
{
  ssize_t xattr_len;

  xattr_len = flistxattr (sfd, buf, buf_size);
  if (xattr_len > 0)
    {
      char *it;
      for (it = buf; it - buf < xattr_len; it += strlen (it) + 1)
        {
          cleanup_free char *v = NULL;
          ssize_t s;

          if (! can_access_xattr (it))
            continue;

          s = safe_read_xattr (&v, sfd, it, 256);
          if (s < 0)
            {
              if (errno == EOVERFLOW)
                continue;
              return -1;
            }

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

static int
empty_dirfd (int fd)
{
  cleanup_dir DIR *dp = NULL;
  struct dirent *dent;

  dp = fdopendir (fd);
  if (dp == NULL)
    {
      close (fd);
      return -1;
    }

  for (;;)
    {
      int ret;

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

      ret = unlinkat (dirfd (dp), dent->d_name, 0);
      if (ret < 0 && errno == EISDIR)
        {
          ret = unlinkat (dirfd (dp), dent->d_name, AT_REMOVEDIR);
          if (ret < 0 && errno == ENOTEMPTY)
            {
              int dfd;

              dfd = safe_openat (dirfd (dp), dent->d_name, O_DIRECTORY, 0);
              if (dfd < 0)
                return -1;

              ret = empty_dirfd (dfd);
              if (ret < 0)
                return -1;

              ret = unlinkat (dirfd (dp), dent->d_name, AT_REMOVEDIR);
              if (ret < 0)
                return -1;

              continue;
            }
        }
      if (ret < 0)
        return ret;
    }

  return 0;
}

static int create_node_directory (struct ovl_data *lo, struct ovl_node *src);

static int
create_directory (struct ovl_data *lo, int dirfd, const char *name, const struct timespec *times,
                  struct ovl_node *parent, int xattr_sfd, uid_t uid, gid_t gid, mode_t mode, bool set_opaque, struct stat *st_out)
{
  int ret;
  int saved_errno;
  cleanup_close int dfd = -1;
  cleanup_free char *buf = NULL;
  char wd_tmp_file_name[32];
  bool need_rename;
  mode_t backing_file_mode = mode | (lo->xattr_permissions ? 0755 : 0);

  need_rename = set_opaque || times || xattr_sfd >= 0 || uid != lo->uid || gid != lo->gid || get_upper_layer (lo)->stat_override_mode != STAT_OVERRIDE_NONE;
  if (! need_rename)
    {
      /* mkdir can be used directly without a temporary directory in the working directory.  */
      ret = mkdirat (dirfd, name, mode);
      if (ret < 0)
        {
          if (errno == EEXIST)
            {
              unlinkat (dirfd, name, 0);
              ret = mkdirat (dirfd, name, mode);
            }
          if (ret < 0)
            return ret;
        }
      if (st_out)
        return fstatat (dirfd, name, st_out, AT_SYMLINK_NOFOLLOW);
      return 0;
    }

  sprintf (wd_tmp_file_name, "%lu", get_next_wd_counter ());

  ret = mkdirat (lo->workdir_fd, wd_tmp_file_name, backing_file_mode);
  if (ret < 0)
    goto out;

  ret = dfd = TEMP_FAILURE_RETRY (safe_openat (lo->workdir_fd, wd_tmp_file_name, O_RDONLY, 0));
  if (ret < 0)
    goto out;

  if (uid != lo->uid || gid != lo->gid || get_upper_layer (lo)->stat_override_mode != STAT_OVERRIDE_NONE)
    {
      ret = do_fchown (lo, dfd, uid, gid, mode);
      if (ret < 0)
        goto out;
    }

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

  if (set_opaque)
    {
      ret = set_fd_opaque (dfd);
      if (ret < 0)
        goto out;
    }

  if (st_out)
    {
      ret = fstat (dfd, st_out);
      if (ret < 0)
        goto out;
      st_out->st_mode = (st_out->st_mode & S_IFMT) | (mode & ~S_IFMT);
    }

  ret = inherit_acl (lo, parent, dfd, NULL);
  if (ret < 0)
    goto out;

  ret = renameat (lo->workdir_fd, wd_tmp_file_name, dirfd, name);
  if (ret < 0)
    {
      if (errno == EEXIST)
        {
          int dfd = -1;

          ret = direct_renameat2 (lo->workdir_fd, wd_tmp_file_name, dirfd, name, RENAME_EXCHANGE);
          if (ret < 0)
            goto out;

          dfd = TEMP_FAILURE_RETRY (safe_openat (lo->workdir_fd, wd_tmp_file_name, O_DIRECTORY, 0));
          if (dfd < 0)
            return -1;

          ret = empty_dirfd (dfd);
          if (ret < 0)
            goto out;

          return unlinkat (lo->workdir_fd, wd_tmp_file_name, AT_REMOVEDIR);
        }
      if (errno == ENOTDIR)
        unlinkat (dirfd, name, 0);
      if (errno == ENOENT && parent)
        {
          ret = create_node_directory (lo, parent);
          if (ret != 0)
            goto out;
        }

      ret = renameat (lo->workdir_fd, wd_tmp_file_name, dirfd, name);
    }
out:
  saved_errno = errno;
  if (ret < 0)
    unlinkat (lo->workdir_fd, wd_tmp_file_name, AT_REMOVEDIR);
  errno = saved_errno;

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

  ret = sfd = src->layer->ds->openat (src->layer, src->path, O_RDONLY | O_NONBLOCK, 0755);
  if (ret < 0)
    return ret;

  ret = TEMP_FAILURE_RETRY (fstat (sfd, &st));
  if (ret < 0)
    return ret;

  times[0] = st.st_atim;
  times[1] = st.st_mtim;

  if (override_mode (src->layer, sfd, NULL, NULL, &st) < 0 && errno != ENODATA && errno != EOPNOTSUPP)
    return -1;

  ret = create_directory (lo, get_upper_layer (lo)->fd, src->path, times, src->parent, sfd, st.st_uid, st.st_gid, st.st_mode, false, NULL);
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
      do
        {
          ret = TEMP_FAILURE_RETRY (write (dfd, buf + written, nread));
          if (ret < 0)
            return ret;
          nread -= ret;
          written += ret;
      } while (nread);
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
  mode_t mode;

  sprintf (wd_tmp_file_name, "%lu", get_next_wd_counter ());

  ret = node->layer->ds->statat (node->layer, node->path, &st, AT_SYMLINK_NOFOLLOW, STATX_BASIC_STATS);
  if (ret < 0)
    return ret;

  if (node->parent)
    {
      ret = create_node_directory (lo, node->parent);
      if (ret < 0)
        return ret;
    }

  mode = st.st_mode;
  if (lo->xattr_permissions)
    mode |= 0755;
  if (lo->euid > 0)
    mode |= 0200;

  if ((mode & S_IFMT) == S_IFDIR)
    {
      ret = create_node_directory (lo, node);
      if (ret < 0)
        goto exit;
      goto success;
    }

  if ((mode & S_IFMT) == S_IFLNK)
    {
      size_t current_size = PATH_MAX + 1;
      cleanup_free char *p = malloc (current_size);

      while (1)
        {
          char *new;

          ret = node->layer->ds->readlinkat (node->layer, node->path, p, current_size - 1);
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

  ret = sfd = node->layer->ds->openat (node->layer, node->path, O_RDONLY | O_NONBLOCK, 0);
  if (sfd < 0)
    goto exit;

  ret = dfd = TEMP_FAILURE_RETRY (safe_openat (lo->workdir_fd, wd_tmp_file_name, O_CREAT | O_WRONLY, mode));
  if (dfd < 0)
    goto exit;

  if (st.st_uid != lo->uid || st.st_gid != lo->gid || get_upper_layer (lo)->stat_override_mode != STAT_OVERRIDE_NONE)
    {
      ret = do_fchown (lo, dfd, st.st_uid, st.st_gid, mode);
      if (ret < 0)
        goto exit;
    }

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

  ret = set_fd_origin (dfd, node->path);
  if (ret < 0)
    goto exit;

  /* Finally, move the file to its destination.  */
  ret = renameat (lo->workdir_fd, wd_tmp_file_name, get_upper_layer (lo)->fd, node->path);
  if (ret < 0)
    goto exit;

  if (node->parent)
    {
      char whpath[PATH_MAX];

      strconcat3 (whpath, PATH_MAX, node->parent->path, "/.wh.", node->name);

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

  if (lo->upperdir == NULL)
    {
      errno = EROFS;
      return NULL;
    }

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
empty_dir (struct ovl_layer *l, const char *path)
{
  cleanup_close int cleanup_fd = -1;
  int ret;

  cleanup_fd = TEMP_FAILURE_RETRY (safe_openat (l->fd, path, O_DIRECTORY, 0));
  if (cleanup_fd < 0)
    return -1;

  if (set_fd_opaque (cleanup_fd) < 0)
    return -1;

  ret = empty_dirfd (cleanup_fd);

  cleanup_fd = -1;

  return ret;
}

static void
do_rm (fuse_req_t req, fuse_ino_t parent, const char *name, bool dirp)
{
  struct ovl_node *node;
  struct ovl_data *lo = ovl_data (req);
  struct ovl_node *pnode;
  int ret = 0;
  size_t whiteouts = 0;
  struct ovl_node key, *rm;

  node = do_lookup_file (lo, parent, name);
  if (node == NULL || node->whiteout)
    {
      fuse_reply_err (req, ENOENT);
      return;
    }

  if (dirp)
    {
      size_t c;

      /* Re-load the directory.  */
      node = reload_dir (lo, node);
      if (node == NULL)
        {
          fuse_reply_err (req, errno);
          return;
        }

      c = count_dir_entries (node, &whiteouts);
      if (c)
        {
          fuse_reply_err (req, ENOTEMPTY);
          return;
        }
    }

  if (node->layer == get_upper_layer (lo))
    {
      if (! dirp)
        node->do_unlink = 1;
      else
        {
          if (whiteouts > 0)
            {
              if (empty_dir (get_upper_layer (lo), node->path) < 0)
                {
                  fuse_reply_err (req, errno);
                  return;
                }
            }

          node->do_rmdir = 1;
        }
    }

  pnode = do_lookup_file (lo, parent, NULL);
  if (pnode == NULL || pnode->whiteout)
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

  /* If the node is still accessible then be sure we
     can write to it.  Fix it to be done when a write is
     really done, not now.  */
  node = get_node_up (lo, node);
  if (node == NULL)
    {
      fuse_reply_err (req, errno);
      return;
    }

  node_set_name (&key, (char *) name);

  rm = hash_delete (pnode->children, &key);
  fuse_lowlevel_notify_inval_inode (lo->se, node_to_inode (node), -1, 0);
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
  cleanup_lock int l = enter_big_lock ();
  if (UNLIKELY (ovl_debug (req)))
    fprintf (stderr, "ovl_unlink(parent=%" PRIu64 ", name=%s)\n",
             parent, name);
  do_rm (req, parent, name, false);
}

static void
ovl_rmdir (fuse_req_t req, fuse_ino_t parent, const char *name)
{
  cleanup_lock int l = enter_big_lock ();
  if (UNLIKELY (ovl_debug (req)))
    fprintf (stderr, "ovl_rmdir(parent=%" PRIu64 ", name=%s)\n",
             parent, name);
  do_rm (req, parent, name, true);
}

static int
direct_setxattr (struct ovl_layer *l, const char *path, const char *name, const char *buf, size_t size, int flags)
{
  cleanup_close int fd = -1;
  char full_path[PATH_MAX];
  int ret;

  full_path[0] = '\0';
  ret = open_fd_or_get_path (l, path, full_path, &fd, O_WRONLY);
  if (ret < 0)
    return ret;

  if (fd >= 0)
    return fsetxattr (fd, name, buf, size, flags);

  return setxattr (full_path, name, buf, size, flags);
}

static void
ovl_setxattr (fuse_req_t req, fuse_ino_t ino, const char *name,
              const char *value, size_t size, int flags)
{
  cleanup_lock int l = enter_big_lock ();
  struct ovl_data *lo = ovl_data (req);
  struct ovl_node *node;
  int ret;

  if (UNLIKELY (ovl_debug (req)))
    fprintf (stderr, "ovl_setxattr(ino=%" PRIu64 ", name=%s, value=%s, size=%zu, flags=%d)\n", ino, name,
             value, size, flags);

  if (lo->disable_xattrs)
    {
      fuse_reply_err (req, ENOSYS);
      return;
    }

  if (has_prefix (name, PRIVILEGED_XATTR_PREFIX) || has_prefix (name, XATTR_PREFIX) || has_prefix (name, XATTR_CONTAINERS_PREFIX))
    {
      fuse_reply_err (req, EPERM);
      return;
    }

  node = do_lookup_file (lo, ino, NULL);
  if (node == NULL || node->whiteout)
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

  if (! node->hidden)
    ret = direct_setxattr (node->layer, node->path, name, value, size, flags);
  else
    {
      char path[PATH_MAX];
      strconcat3 (path, PATH_MAX, lo->workdir, "/", node->path);
      ret = setxattr (path, name, value, size, flags);
    }
  if (ret < 0)
    {
      fuse_reply_err (req, errno);
      return;
    }

  fuse_reply_err (req, 0);
}

static int
direct_removexattr (struct ovl_layer *l, const char *path, const char *name)
{
  cleanup_close int fd = -1;
  char full_path[PATH_MAX];
  int ret;

  full_path[0] = '\0';
  ret = open_fd_or_get_path (l, path, full_path, &fd, O_WRONLY);
  if (ret < 0)
    return ret;

  if (fd >= 0)
    return fremovexattr (fd, name);

  return lremovexattr (full_path, name);
}

static void
ovl_removexattr (fuse_req_t req, fuse_ino_t ino, const char *name)
{
  cleanup_lock int l = enter_big_lock ();
  struct ovl_node *node;
  struct ovl_data *lo = ovl_data (req);
  int ret;

  if (UNLIKELY (ovl_debug (req)))
    fprintf (stderr, "ovl_removexattr(ino=%" PRIu64 ", name=%s)\n", ino, name);

  node = do_lookup_file (lo, ino, NULL);
  if (node == NULL || node->whiteout)
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

  if (! node->hidden)
    ret = direct_removexattr (node->layer, node->path, name);
  else
    {
      char path[PATH_MAX];
      strconcat3 (path, PATH_MAX, lo->workdir, "/", node->path);
      ret = removexattr (path, name);
    }

  if (ret < 0)
    {
      fuse_reply_err (req, errno);
      return;
    }

  fuse_reply_err (req, 0);
}

static int
direct_create_file (struct ovl_layer *l, int dirfd, const char *path, uid_t uid, gid_t gid, int flags, mode_t mode)
{
  struct ovl_data *lo = l->ovl_data;
  mode_t backing_file_mode = mode | (lo->xattr_permissions ? 0755 : 0);
  cleanup_close int fd = -1;
  char wd_tmp_file_name[32];
  int ret;

  /* try to create directly the file if it doesn't need to be chowned.  */
  if (uid == lo->uid && gid == lo->gid && l->stat_override_mode == STAT_OVERRIDE_NONE)
    {
      ret = TEMP_FAILURE_RETRY (safe_openat (get_upper_layer (lo)->fd, path, flags, backing_file_mode));
      if (ret >= 0)
        return ret;
      /* if it fails (e.g. there is a whiteout) then fallback to create it in
         the working dir + rename.  */
    }

  sprintf (wd_tmp_file_name, "%lu", get_next_wd_counter ());

  fd = TEMP_FAILURE_RETRY (safe_openat (lo->workdir_fd, wd_tmp_file_name, flags, backing_file_mode));
  if (fd < 0)
    return -1;
  if (uid != lo->uid || gid != lo->gid || l->stat_override_mode != STAT_OVERRIDE_NONE)
    {
      if (do_fchown (lo, fd, uid, gid, mode) < 0)
        {
          unlinkat (lo->workdir_fd, wd_tmp_file_name, 0);
          return -1;
        }
    }

  if (renameat (lo->workdir_fd, wd_tmp_file_name, get_upper_layer (lo)->fd, path) < 0)
    {
      unlinkat (lo->workdir_fd, wd_tmp_file_name, 0);
      return -1;
    }

  ret = fd;
  fd = -1;
  return ret;
}

static int
ovl_do_open (fuse_req_t req, fuse_ino_t parent, const char *name, int flags, mode_t mode, struct ovl_node **retnode, struct stat *st)
{
  struct ovl_data *lo = ovl_data (req);
  struct ovl_node *n;
  bool readonly = (flags & (O_APPEND | O_RDWR | O_WRONLY | O_CREAT | O_TRUNC)) == 0;
  cleanup_free char *path = NULL;
  cleanup_close int fd = -1;
  uid_t uid;
  gid_t gid;
  bool need_delete_whiteout = true;
  bool is_whiteout = false;

  flags |= O_NOFOLLOW;

  flags &= ~O_DIRECT;

  if (lo->writeback)
    {
      if ((flags & O_ACCMODE) == O_WRONLY)
        {
          flags &= ~O_ACCMODE;
          flags |= O_RDWR;
        }
      if (flags & O_APPEND)
        flags &= ~O_APPEND;
    }

  if (name && has_prefix (name, ".wh."))
    {
      errno = EINVAL;
      return -1;
    }

  n = do_lookup_file (lo, parent, name);
  if (n && n->hidden)
    {
      if (retnode)
        *retnode = n;

      return openat (n->hidden_dirfd, n->path, flags, mode);
    }
  if (n && ! n->whiteout && (flags & O_CREAT))
    {
      errno = EEXIST;
      return -1;
    }
  if (n && n->whiteout)
    {
      n = NULL;
      is_whiteout = true;
    }

  if (! n)
    {
      int ret;
      struct ovl_node *p;
      const struct fuse_ctx *ctx = fuse_req_ctx (req);
      char wd_tmp_file_name[32];
      struct stat st_tmp;

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

      if (p->loaded && ! is_whiteout)
        need_delete_whiteout = false;

      sprintf (wd_tmp_file_name, "%lu", get_next_wd_counter ());

      ret = asprintf (&path, "%s/%s", p->path, name);
      if (ret < 0)
        return ret;

      uid = get_uid (lo, ctx->uid);
      gid = get_gid (lo, ctx->gid);

      fd = direct_create_file (get_upper_layer (lo), get_upper_layer (lo)->fd, path, uid, gid, flags, mode & ~ctx->umask);
      if (fd < 0)
        return fd;

      ret = inherit_acl (lo, n, fd, NULL);
      if (ret < 0)
        return ret;

      if (need_delete_whiteout && delete_whiteout (lo, -1, p, name) < 0)
        return -1;

      if (st == NULL)
        st = &st_tmp;

      if (get_upper_layer (lo)->ds->fstat (get_upper_layer (lo), fd, path, STATX_BASIC_STATS, st) < 0)
        return -1;

      n = make_ovl_node (lo, path, get_upper_layer (lo), name, st->st_ino, st->st_dev, false, p, lo->fast_ino_check);
      if (n == NULL)
        {
          errno = ENOMEM;
          return -1;
        }
      if (! is_whiteout)
        n->last_layer = get_upper_layer (lo);

      n = insert_node (p, n, true);
      if (n == NULL)
        {
          errno = ENOMEM;
          return -1;
        }
      ret = fd;
      fd = -1; /*  We use a temporary variable so we don't close it at cleanup.  */
      if (retnode)
        *retnode = n;
      return ret;
    }

  /* readonly, we can use both lowerdir and upperdir.  */
  if (readonly)
    {
      struct ovl_layer *l = n->layer;
      if (retnode)
        *retnode = n;
      return l->ds->openat (l, n->path, flags, mode);
    }
  else
    {
      struct ovl_layer *l;

      n = get_node_up (lo, n);
      if (n == NULL)
        return -1;

      if (retnode)
        *retnode = n;

      l = n->layer;

      return l->ds->openat (l, n->path, flags, mode);
    }
}

static void
ovl_read (fuse_req_t req, fuse_ino_t ino, size_t size,
          off_t offset, struct fuse_file_info *fi)
{
  struct fuse_bufvec buf = FUSE_BUFVEC_INIT (size);
  if (UNLIKELY (ovl_debug (req)))
    fprintf (stderr, "ovl_read(ino=%" PRIu64 ", size=%zd, "
                     "off=%lu)\n",
             ino, size, (unsigned long) offset);
  buf.buf[0].flags = FUSE_BUF_IS_FD | FUSE_BUF_FD_SEEK | FUSE_BUF_FD_RETRY;
  buf.buf[0].fd = fi->fh;
  buf.buf[0].pos = offset;
  fuse_reply_data (req, &buf, 0);
}

static void
ovl_write_buf (fuse_req_t req, fuse_ino_t ino,
               struct fuse_bufvec *in_buf, off_t off,
               struct fuse_file_info *fi)
{
  struct ovl_data *lo = ovl_data (req);
  ssize_t res;
  struct ovl_ino *inode;
  int saved_errno;
  struct fuse_bufvec out_buf = FUSE_BUFVEC_INIT (fuse_buf_size (in_buf));

  out_buf.buf[0].flags = FUSE_BUF_IS_FD | FUSE_BUF_FD_SEEK | FUSE_BUF_FD_RETRY;
  out_buf.buf[0].fd = fi->fh;
  out_buf.buf[0].pos = off;

  if (UNLIKELY (ovl_debug (req)))
    fprintf (stderr, "ovl_write_buf(ino=%" PRIu64 ", size=%zd, off=%lu, fd=%d)\n",
             ino, out_buf.buf[0].size, (unsigned long) off, (int) fi->fh);

  inode = lookup_inode (lo, ino);

  errno = 0;
  res = fuse_buf_copy (&out_buf, in_buf, 0);
  saved_errno = errno;

  /* if it is a writepage request, make sure to restore the setuid bit.  */
  if (fi->writepage && (inode->mode & (S_ISUID | S_ISGID)))
    {
      if (do_fchmod (lo, inode->node, fi->fh, inode->mode) < 0)
        {
          fuse_reply_err (req, errno);
          return;
        }
    }

  if (res < 0)
    fuse_reply_err (req, saved_errno);
  else
    fuse_reply_write (req, (size_t) res);
}

static void
ovl_release (fuse_req_t req, fuse_ino_t ino, struct fuse_file_info *fi)
{
  int ret;
  (void) ino;

  if (UNLIKELY (ovl_debug (req)))
    fprintf (stderr, "ovl_release(ino=%" PRIu64 ")\n", ino);

  ret = close (fi->fh);
  fuse_reply_err (req, ret == 0 ? 0 : errno);
}

static int
do_getattr (fuse_req_t req, struct fuse_entry_param *e, struct ovl_node *node, int fd, const char *path)
{
  struct ovl_data *lo = ovl_data (req);
  int err = 0;

  memset (e, 0, sizeof (*e));

  err = rpl_stat (req, node, fd, path, NULL, &e->attr);
  if (err < 0)
    return err;

  e->ino = node_to_inode (node);
  e->attr_timeout = get_timeout (lo);
  e->entry_timeout = get_timeout (lo);

  return 0;
}

static int
do_statfs (struct ovl_data *lo, struct statvfs *sfs)
{
  int ret, fd;

  fd = get_first_layer (lo)->fd;

  if (fd >= 0)
    ret = fstatvfs (fd, sfs);
  else
    ret = statvfs (lo->mountpoint, sfs);
  if (ret < 0)
    return ret;

  sfs->f_namemax -= WHITEOUT_MAX_LEN;
  return 0;
}

static short
get_fs_namemax (struct ovl_data *lo)
{
  static short namemax = 0;
  if (namemax == 0)
    {
      struct statvfs sfs;
      int ret;

      ret = do_statfs (lo, &sfs);
      /* On errors use a sane default.  */
      if (ret < 0)
        namemax = 255 - WHITEOUT_MAX_LEN;
      else
        namemax = sfs.f_namemax;
    }
  return namemax;
}

static void
ovl_create (fuse_req_t req, fuse_ino_t parent, const char *name,
            mode_t mode, struct fuse_file_info *fi)
{
  cleanup_lock int l = enter_big_lock ();
  cleanup_close int fd = -1;
  struct fuse_entry_param e;
  struct ovl_node *p, *node = NULL;
  struct ovl_data *lo = ovl_data (req);
  struct stat st;

  if (UNLIKELY (ovl_debug (req)))
    fprintf (stderr, "ovl_create(parent=%" PRIu64 ", name=%s)\n",
             parent, name);

  if (strlen (name) > get_fs_namemax (lo))
    {
      fuse_reply_err (req, ENAMETOOLONG);
      return;
    }

  fi->flags = fi->flags | O_CREAT;

  fd = ovl_do_open (req, parent, name, fi->flags, mode, &node, &st);
  if (fd < 0)
    {
      fuse_reply_err (req, errno);
      return;
    }

  p = do_lookup_file (lo, parent, NULL);
  /* Make sure the cache is invalidated, if the parent is in the middle of a readdir. */
  if (p && p->in_readdir)
    fuse_lowlevel_notify_inval_inode (lo->se, parent, 0, 0);

  if (node == NULL || do_getattr (req, &e, node, fd, NULL) < 0)
    {
      fuse_reply_err (req, errno);
      return;
    }

  fi->fh = fd;
  fd = -1; /* Do not clean it up.  */

  node->ino->lookups++;
  fuse_reply_create (req, &e, fi);
}

static void
ovl_open (fuse_req_t req, fuse_ino_t ino, struct fuse_file_info *fi)
{
  struct ovl_data *lo = ovl_data (req);
  cleanup_lock int l = enter_big_lock ();
  cleanup_close int fd = -1;

  if (UNLIKELY (ovl_debug (req)))
    fprintf (stderr, "ovl_open(ino=%" PRIu64 ")\n", ino);

  fd = ovl_do_open (req, ino, NULL, fi->flags, 0700, NULL, NULL);
  if (fd < 0)
    {
      fuse_reply_err (req, errno);
      return;
    }
  fi->fh = fd;
  if (get_timeout (lo) > 0)
    fi->keep_cache = 1;
  fd = -1; /* Do not clean it up.  */
  fuse_reply_open (req, fi);
}

static void
ovl_getattr (fuse_req_t req, fuse_ino_t ino, struct fuse_file_info *fi)
{
  cleanup_lock int l = enter_big_lock ();
  struct ovl_data *lo = ovl_data (req);
  struct ovl_node *node;
  struct fuse_entry_param e;

  if (UNLIKELY (ovl_debug (req)))
    fprintf (stderr, "ovl_getattr(ino=%" PRIu64 ")\n", ino);

  node = do_lookup_file (lo, ino, NULL);
  if (node == NULL || node->whiteout)
    {
      fuse_reply_err (req, ENOENT);
      return;
    }

  if (do_getattr (req, &e, node, -1, NULL) < 0)
    {
      fuse_reply_err (req, errno);
      return;
    }

  fuse_reply_attr (req, &e.attr, get_timeout (lo));
}

static void
ovl_setattr (fuse_req_t req, fuse_ino_t ino, struct stat *attr, int to_set, struct fuse_file_info *fi)
{
  cleanup_lock int l = enter_big_lock ();
  struct ovl_data *lo = ovl_data (req);
  cleanup_close int cleaned_up_fd = -1;
  struct ovl_node *node;
  struct fuse_entry_param e;
  struct timespec times[2];
  uid_t uid;
  gid_t gid;
  int ret;
  int fd = -1;
  char path[PATH_MAX];

  if (UNLIKELY (ovl_debug (req)))
    fprintf (stderr, "ovl_setattr(ino=%" PRIu64 ", to_set=%d)\n", ino, to_set);

  node = do_lookup_file (lo, ino, NULL);
  if (node == NULL || node->whiteout)
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

  if (to_set & FUSE_SET_ATTR_CTIME)
    {
      /* Ignore request.  */
    }

  uid = -1;
  gid = -1;
  if (to_set & FUSE_SET_ATTR_UID)
    uid = get_uid (lo, attr->st_uid);
  if (to_set & FUSE_SET_ATTR_GID)
    gid = get_gid (lo, attr->st_gid);

  if (fi != NULL)
    fd = fi->fh; // use existing fd if fuse_file_info is available
  else
    {
      mode_t mode = node->ino->mode;
      int dirfd = node_dirfd (node);

      if (mode == 0)
        {
          struct stat st;

          ret = fstatat (dirfd, node->path, &st, AT_SYMLINK_NOFOLLOW);
          if (ret < 0)
            {
              fuse_reply_err (req, errno);
              return;
            }
          node->ino->mode = mode = st.st_mode;
        }

      switch (mode & S_IFMT)
        {
        case S_IFREG:
          cleaned_up_fd = fd = TEMP_FAILURE_RETRY (safe_openat (dirfd, node->path, O_NOFOLLOW | O_NONBLOCK | (to_set & FUSE_SET_ATTR_SIZE ? O_WRONLY : 0), 0));
          if (fd < 0)
            strconcat3 (path, PATH_MAX, get_upper_layer (lo)->path, "/", node->path);
          break;

        case S_IFDIR:
          cleaned_up_fd = fd = TEMP_FAILURE_RETRY (safe_openat (dirfd, node->path, O_NOFOLLOW | O_NONBLOCK, 0));
          if (fd < 0)
            {
              if (errno != ELOOP)
                strconcat3 (path, PATH_MAX, get_upper_layer (lo)->path, "/", node->path);
            }
          break;

        case S_IFLNK:
          cleaned_up_fd = TEMP_FAILURE_RETRY (safe_openat (dirfd, node->path, O_PATH | O_NOFOLLOW | O_NONBLOCK, 0));
          if (cleaned_up_fd < 0)
            {
              fuse_reply_err (req, errno);
              return;
            }
          sprintf (path, "/proc/self/fd/%d", cleaned_up_fd);
          break;

        default:
          strconcat3 (path, PATH_MAX, get_upper_layer (lo)->path, "/", node->path);
          break;
        }
    }

  l = release_big_lock ();

  memset (times, 0, sizeof (times));
  times[0].tv_nsec = UTIME_OMIT;
  times[1].tv_nsec = UTIME_OMIT;
  if (to_set & FUSE_SET_ATTR_ATIME)
    {
      times[0] = attr->st_atim;
      if (to_set & FUSE_SET_ATTR_ATIME_NOW)
        times[0].tv_nsec = UTIME_NOW;
    }

  if (to_set & FUSE_SET_ATTR_MTIME)
    {
      times[1] = attr->st_mtim;
      if (to_set & FUSE_SET_ATTR_MTIME_NOW)
        times[1].tv_nsec = UTIME_NOW;
    }

  if (times[0].tv_nsec != UTIME_OMIT || times[1].tv_nsec != UTIME_OMIT)
    {
      if (fd >= 0)
        ret = futimens (fd, times);
      else
        ret = utimensat (AT_FDCWD, path, times, 0);
      if (ret < 0)
        {
          fuse_reply_err (req, errno);
          return;
        }
    }

  if (to_set & FUSE_SET_ATTR_MODE)
    {
      if (fd >= 0)
        ret = do_fchmod (lo, node, fd, attr->st_mode);
      else
        ret = do_chmod (lo, node, path, attr->st_mode);
      if (ret < 0)
        {
          fuse_reply_err (req, errno);
          return;
        }
      node->ino->mode = attr->st_mode;
    }

  if (to_set & FUSE_SET_ATTR_SIZE)
    {
      if (fd >= 0)
        ret = ftruncate (fd, attr->st_size);
      else
        ret = truncate (path, attr->st_size);
      if (ret < 0)
        {
          fuse_reply_err (req, errno);
          return;
        }
    }

  if (uid != -1 || gid != -1)
    {
      if (fd >= 0)
        ret = do_fchown (lo, fd, uid, gid, node->ino->mode);
      else
        ret = do_chown (lo, path, uid, gid, node->ino->mode);
      if (ret < 0)
        {
          fuse_reply_err (req, errno);
          return;
        }
    }

  if (do_getattr (req, &e, node, fd, path) < 0)
    {
      fuse_reply_err (req, errno);
      return;
    }

  fuse_reply_attr (req, &e.attr, get_timeout (lo));
}

static int
direct_linkat (struct ovl_layer *l, const char *oldpath, const char *newpath, int flags)
{
  return linkat (l->fd, oldpath, l->fd, newpath, 0);
}

static void
ovl_link (fuse_req_t req, fuse_ino_t ino, fuse_ino_t newparent, const char *newname)
{
  cleanup_lock int l = enter_big_lock ();
  struct ovl_data *lo = ovl_data (req);
  struct ovl_node *node, *newparentnode, *destnode;
  cleanup_free char *path = NULL;
  int ret;
  struct fuse_entry_param e;
  char wd_tmp_file_name[32];

  if (UNLIKELY (ovl_debug (req)))
    fprintf (stderr, "ovl_link(ino=%" PRIu64 ", newparent=%" PRIu64 ", newname=%s)\n", ino, newparent, newname);

  if (strlen (newname) > get_fs_namemax (lo))
    {
      fuse_reply_err (req, ENAMETOOLONG);
      return;
    }

  node = do_lookup_file (lo, ino, NULL);
  if (node == NULL || node->whiteout)
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
  if (newparentnode == NULL || newparentnode->whiteout)
    {
      fuse_reply_err (req, ENOENT);
      return;
    }

  destnode = do_lookup_file (lo, newparent, newname);
  if (destnode && ! destnode->whiteout)
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

  ret = direct_linkat (get_upper_layer (lo), node->path, path, 0);
  if (ret < 0)
    {
      fuse_reply_err (req, errno);
      return;
    }

  node = make_ovl_node (lo, path, get_upper_layer (lo), newname, node->tmp_ino, node->tmp_dev, false, newparentnode, lo->fast_ino_check);
  if (node == NULL)
    {
      fuse_reply_err (req, ENOMEM);
      return;
    }
  if (destnode && ! destnode->whiteout)
    node->last_layer = get_upper_layer (lo);

  node = insert_node (newparentnode, node, true);
  if (node == NULL)
    {
      fuse_reply_err (req, ENOMEM);
      return;
    }

  memset (&e, 0, sizeof (e));

  ret = rpl_stat (req, node, -1, NULL, NULL, &e.attr);
  if (ret)
    {
      fuse_reply_err (req, errno);
      return;
    }

  e.ino = node_to_inode (node);
  node->ino->lookups++;
  e.attr_timeout = get_timeout (lo);
  e.entry_timeout = get_timeout (lo);
  fuse_reply_entry (req, &e);
}

static int
direct_symlinkat (struct ovl_layer *l, const char *target, const char *linkpath, uid_t uid, gid_t gid)
{
  struct ovl_data *lo = l->ovl_data;
  char wd_tmp_file_name[32];
  int ret;

  sprintf (wd_tmp_file_name, "%lu", get_next_wd_counter ());

  unlinkat (lo->workdir_fd, wd_tmp_file_name, 0);
  ret = symlinkat (linkpath, lo->workdir_fd, wd_tmp_file_name);
  if (ret < 0)
    return ret;

  if (uid != lo->uid || gid != lo->gid || l->stat_override_mode != STAT_OVERRIDE_NONE)
    {
      ret = do_fchownat (lo, lo->workdir_fd, wd_tmp_file_name, uid, gid, 0755, AT_SYMLINK_NOFOLLOW);
      if (ret < 0)
        {
          unlinkat (lo->workdir_fd, wd_tmp_file_name, 0);
          return ret;
        }
    }

  ret = renameat (lo->workdir_fd, wd_tmp_file_name, get_upper_layer (lo)->fd, target);
  if (ret < 0)
    {
      unlinkat (lo->workdir_fd, wd_tmp_file_name, 0);
      return ret;
    }

  return 0;
}

static void
ovl_symlink (fuse_req_t req, const char *link, fuse_ino_t parent, const char *name)
{
  cleanup_lock int l = enter_big_lock ();
  struct ovl_data *lo = ovl_data (req);
  struct ovl_node *pnode, *node;
  int ret;
  struct fuse_entry_param e;
  const struct fuse_ctx *ctx = fuse_req_ctx (req);
  char wd_tmp_file_name[32];
  bool need_delete_whiteout = true;
  cleanup_free char *path = NULL;

  if (UNLIKELY (ovl_debug (req)))
    fprintf (stderr, "ovl_symlink(link=%s, ino=%" PRIu64 ", name=%s)\n", link, parent, name);

  if (strlen (name) > get_fs_namemax (lo))
    {
      fuse_reply_err (req, ENAMETOOLONG);
      return;
    }

  pnode = do_lookup_file (lo, parent, NULL);
  if (pnode == NULL || pnode->whiteout)
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
  if (node != NULL && ! node->whiteout)
    {
      fuse_reply_err (req, EEXIST);
      return;
    }

  if (pnode->loaded && node == NULL)
    need_delete_whiteout = false;

  ret = asprintf (&path, "%s/%s", pnode->path, name);
  if (ret < 0)
    {
      fuse_reply_err (req, ENOMEM);
      return;
    }

  ret = direct_symlinkat (get_upper_layer (lo), path, link, get_uid (lo, ctx->uid), get_gid (lo, ctx->gid));
  if (ret < 0)
    {
      fuse_reply_err (req, ENOMEM);
      return;
    }

  if (need_delete_whiteout && delete_whiteout (lo, -1, pnode, name) < 0)
    {
      unlinkat (lo->workdir_fd, wd_tmp_file_name, 0);
      fuse_reply_err (req, errno);
      return;
    }

  node = make_ovl_node (lo, path, get_upper_layer (lo), name, 0, 0, false, pnode, lo->fast_ino_check);
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

  ret = rpl_stat (req, node, -1, NULL, NULL, &e.attr);
  if (ret)
    {
      fuse_reply_err (req, errno);
      return;
    }

  e.ino = node_to_inode (node);
  node->ino->lookups++;
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
  cleanup_close int srcfd = -1;
  cleanup_close int destfd = -1;
  struct ovl_node *rm1, *rm2;
  char *tmp;

  node = do_lookup_file (lo, parent, name);
  if (node == NULL || node->whiteout)
    {
      fuse_reply_err (req, ENOENT);
      return;
    }

  if (node_dirp (node))
    {
      node = reload_dir (lo, node);
      if (node == NULL)
        {
          fuse_reply_err (req, errno);
          return;
        }

      if (node->layer != get_upper_layer (lo) || node->last_layer != get_upper_layer (lo))
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

  ret = TEMP_FAILURE_RETRY (safe_openat (node_dirfd (pnode), pnode->path, O_DIRECTORY, 0));
  if (ret < 0)
    goto error;
  srcfd = ret;

  destpnode = get_node_up (lo, destpnode);
  if (destpnode == NULL)
    goto error;

  ret = TEMP_FAILURE_RETRY (safe_openat (node_dirfd (destpnode), destpnode->path, O_DIRECTORY, 0));
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
  if (node_dirp (node) && destnode->last_layer != get_upper_layer (lo))
    {
      fuse_reply_err (req, EXDEV);
      return;
    }
  destnode = get_node_up (lo, destnode);
  if (destnode == NULL)
    goto error;

  ret = direct_renameat2 (srcfd, name, destfd, newname, flags);
  if (ret < 0)
    goto error;

  rm1 = hash_delete (destpnode->children, destnode);
  rm2 = hash_delete (pnode->children, node);

  tmp = node->path;
  node->path = destnode->path;
  destnode->path = tmp;

  tmp = node->name;
  node_set_name (node, destnode->name);
  node_set_name (destnode, tmp);

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
  cleanup_close int srcfd = -1;
  cleanup_close int destfd = -1;
  struct ovl_node key;
  bool destnode_is_whiteout = false;

  pnode = do_lookup_file (lo, parent, NULL);
  if (pnode == NULL || pnode->whiteout)
    {
      fuse_reply_err (req, ENOENT);
      return;
    }

  node = do_lookup_file (lo, parent, name);
  if (node == NULL || node->whiteout)
    {
      fuse_reply_err (req, ENOENT);
      return;
    }

  if (node_dirp (node))
    {
      node = reload_dir (lo, node);
      if (node == NULL)
        {
          fuse_reply_err (req, errno);
          return;
        }

      if (node->layer != get_upper_layer (lo) || node->last_layer != get_upper_layer (lo))
        {
          fuse_reply_err (req, EXDEV);
          return;
        }
    }

  destpnode = do_lookup_file (lo, newparent, NULL);
  destnode = NULL;

  pnode = get_node_up (lo, pnode);
  if (pnode == NULL)
    goto error;

  ret = TEMP_FAILURE_RETRY (safe_openat (node_dirfd (pnode), pnode->path, O_DIRECTORY, 0));
  if (ret < 0)
    goto error;
  srcfd = ret;

  destpnode = get_node_up (lo, destpnode);
  if (destpnode == NULL)
    goto error;

  ret = TEMP_FAILURE_RETRY (safe_openat (node_dirfd (destpnode), destpnode->path, O_DIRECTORY, 0));
  if (ret < 0)
    goto error;
  destfd = ret;

  node_set_name (&key, (char *) newname);
  destnode = hash_lookup (destpnode->children, &key);

  node = get_node_up (lo, node);
  if (node == NULL)
    goto error;

  /* If NOREPLACE flag is given, check if we should throw an error now.
     If not, just remove the flag as it might cause problems with replacing whiteouts later.  */
  if (flags & RENAME_NOREPLACE && destnode && ! destnode->whiteout)
    {
      errno = EEXIST;
      goto error;
    }
  else
    flags = flags & ~RENAME_NOREPLACE;

  if (destnode)
    {
      size_t destnode_whiteouts = 0;

      errno = EINVAL;
      if (! destnode->whiteout && destnode->tmp_ino == node->tmp_ino && destnode->tmp_dev == node->tmp_dev)
        goto error;

      destnode_is_whiteout = destnode->whiteout;

      if (! destnode->whiteout && node_dirp (destnode))
        {
          destnode = reload_dir (lo, destnode);
          if (destnode == NULL)
            goto error;

          if (count_dir_entries (destnode, &destnode_whiteouts) > 0)
            {
              errno = ENOTEMPTY;
              goto error;
            }
          if (destnode_whiteouts && empty_dir (get_upper_layer (lo), destnode->path) < 0)
            goto error;
        }

      if (node_dirp (node) && create_missing_whiteouts (lo, node, destnode->path) < 0)
        goto error;

      if (destnode->ino->lookups > 0)
        node_free (destnode);
      else
        {
          node_free (destnode);
          destnode = NULL;
        }

      if (destnode && ! destnode_is_whiteout)
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

          if (hide_node (lo, destnode, true) < 0)
            goto error;
        }
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

  bool src_needs_whiteout = (node->last_layer != get_upper_layer (lo));

  if (src_needs_whiteout)
    {
      /* Trying to atomically both rename and create the whiteout.
         If destination is a whiteout, we can EXCHANGE source and destination and reuse the old whiteout.
         If not, we can try to atomically create one with the WHITEOUT flag.  */
      if (destnode_is_whiteout)
        ret = direct_renameat2 (srcfd, name, destfd, newname, flags | RENAME_EXCHANGE);
      else
        {
          if (! can_mknod)
            {
              ret = -1;
              errno = EPERM;
            }
          else
            ret = direct_renameat2 (srcfd, name, destfd, newname, flags | RENAME_WHITEOUT);
        }

      /* If atomic whiteout creation failed, fall back to separate rename and whiteout creation.  */
      if (ret < 0)
        {
          ret = direct_renameat2 (srcfd, name, destfd, newname, flags);
          if (ret < 0)
            goto error;

          ret = create_whiteout (lo, pnode, name, false, true);
          if (ret < 0)
            goto error;
        }
    }
  else
    {
      ret = direct_renameat2 (srcfd, name, destfd, newname, flags);
      if (ret < 0)
        goto error;
    }

  pnode->loaded = 0;

  /* If the destination was .wh. style whiteout, it was not replaced automatically, so delete it.  */
  if (delete_whiteout (lo, destfd, NULL, newname) < 0)
    goto error;

  hash_delete (pnode->children, node);

  free (node->name);
  node_set_name (node, strdup (newname));
  if (node->name == NULL)
    goto error;

  node = insert_node (destpnode, node, true);
  if (node == NULL)
    goto error;
  if (update_paths (node) < 0)
    goto error;

  node->loaded = 0;

  ret = 0;
  fuse_reply_err (req, 0);
  return;

error:
  ret = -1;
  fuse_reply_err (req, errno);
}

static void
ovl_rename (fuse_req_t req, fuse_ino_t parent, const char *name,
            fuse_ino_t newparent, const char *newname,
            unsigned int flags)
{
  struct ovl_node *p;
  cleanup_lock int l = enter_big_lock ();
  struct ovl_data *lo = ovl_data (req);

  if (UNLIKELY (ovl_debug (req)))
    fprintf (stderr, "ovl_rename(ino=%" PRIu64 ", name=%s , ino=%" PRIu64 ", name=%s)\n", parent, name, newparent, newname);

  if (strlen (newname) > get_fs_namemax (lo))
    {
      fuse_reply_err (req, ENAMETOOLONG);
      return;
    }

  if (flags & RENAME_EXCHANGE)
    ovl_rename_exchange (req, parent, name, newparent, newname, flags);
  else
    ovl_rename_direct (req, parent, name, newparent, newname, flags);

  /* Make sure the cache is invalidated, if the parent is in the middle of a readdir. */
  p = do_lookup_file (lo, parent, NULL);
  if (p && p->in_readdir)
    fuse_lowlevel_notify_inval_inode (lo->se, parent, 0, 0);
  p = do_lookup_file (lo, newparent, NULL);
  if (p && p->in_readdir)
    fuse_lowlevel_notify_inval_inode (lo->se, newparent, 0, 0);
}

static void
ovl_statfs (fuse_req_t req, fuse_ino_t ino)
{
  int ret;
  struct statvfs sfs;
  struct ovl_data *lo = ovl_data (req);

  ret = do_statfs (lo, &sfs);
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
  cleanup_lock int l = enter_big_lock ();
  struct ovl_data *lo = ovl_data (req);
  cleanup_free char *buf = NULL;
  struct ovl_node *node;
  size_t current_size;
  int ret = 0;

  if (UNLIKELY (ovl_debug (req)))
    fprintf (stderr, "ovl_readlink(ino=%" PRIu64 ")\n", ino);

  node = do_lookup_file (lo, ino, NULL);
  if (node == NULL || node->whiteout)
    {
      fuse_reply_err (req, ENOENT);
      return;
    }

  current_size = PATH_MAX + 1;
  buf = malloc (current_size);
  if (buf == NULL)
    {
      fuse_reply_err (req, errno);
      return;
    }

  while (1)
    {
      char *tmp;

      ret = node->layer->ds->readlinkat (node->layer, node->path, buf, current_size - 1);
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

  node = reload_dir (lo, node);
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
          free (nodes);
          return ret;
        }
    }

  free (nodes);
  return 0;
}

static void
ovl_mknod (fuse_req_t req, fuse_ino_t parent, const char *name, mode_t mode, dev_t rdev)
{
  cleanup_lock int l = enter_big_lock ();
  struct ovl_node *node;
  struct ovl_data *lo = ovl_data (req);
  struct ovl_node *pnode;
  int ret = 0;
  cleanup_free char *path = NULL;
  struct fuse_entry_param e;
  const struct fuse_ctx *ctx = fuse_req_ctx (req);
  char wd_tmp_file_name[32];
  mode_t backing_file_mode = mode | (lo->xattr_permissions ? 0755 : 0);

  if (UNLIKELY (ovl_debug (req)))
    fprintf (stderr, "ovl_mknod(ino=%" PRIu64 ", name=%s, mode=%d, rdev=%lu)\n",
             parent, name, mode, rdev);

  if (strlen (name) > get_fs_namemax (lo))
    {
      fuse_reply_err (req, ENAMETOOLONG);
      return;
    }

  mode = mode & ~ctx->umask;

  node = do_lookup_file (lo, parent, name);
  if (node != NULL && ! node->whiteout)
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
  ret = mknodat (lo->workdir_fd, wd_tmp_file_name, backing_file_mode, rdev);
  if (ret < 0)
    {
      fuse_reply_err (req, errno);
      return;
    }

  if (do_fchownat (lo, lo->workdir_fd, wd_tmp_file_name, get_uid (lo, ctx->uid), get_gid (lo, ctx->gid), mode, 0) < 0)
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

  ret = inherit_acl (lo, pnode, -1, path);
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

  node = make_ovl_node (lo, path, get_upper_layer (lo), name, 0, 0, false, pnode, lo->fast_ino_check);
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

  ret = rpl_stat (req, node, -1, NULL, NULL, &e.attr);
  if (ret)
    {
      fuse_reply_err (req, errno);
      return;
    }

  /* Make sure the cache is invalidated, if the parent is in the middle of a readdir. */
  if (pnode->in_readdir)
    fuse_lowlevel_notify_inval_inode (lo->se, parent, 0, 0);

  e.ino = node_to_inode (node);
  e.attr_timeout = get_timeout (lo);
  e.entry_timeout = get_timeout (lo);
  node->ino->lookups++;
  fuse_reply_entry (req, &e);
}

static void
ovl_mkdir (fuse_req_t req, fuse_ino_t parent, const char *name, mode_t mode)
{
  const struct fuse_ctx *ctx = fuse_req_ctx (req);
  struct ovl_data *lo = ovl_data (req);
  struct fuse_entry_param e;
  bool parent_upperdir_only;
  struct ovl_node *pnode;
  struct ovl_node *node;
  struct stat st;
  ino_t ino = 0;
  dev_t dev = 0;
  int ret = 0;
  cleanup_free char *path = NULL;
  bool need_delete_whiteout = true;
  cleanup_lock int l = enter_big_lock ();

  if (UNLIKELY (ovl_debug (req)))
    fprintf (stderr, "ovl_mkdir(ino=%" PRIu64 ", name=%s, mode=%d)\n",
             parent, name, mode);

  if (strlen (name) > get_fs_namemax (lo))
    {
      fuse_reply_err (req, ENAMETOOLONG);
      return;
    }

  node = do_lookup_file (lo, parent, name);
  if (node != NULL && ! node->whiteout)
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

  if (pnode->loaded && node == NULL)
    need_delete_whiteout = false;

  parent_upperdir_only = pnode->last_layer == get_upper_layer (lo);

  ret = asprintf (&path, "%s/%s", pnode->path, name);
  if (ret < 0)
    {
      fuse_reply_err (req, errno);
      return;
    }

  ret = create_directory (lo, get_upper_layer (lo)->fd, path, NULL, pnode, -1,
                          get_uid (lo, ctx->uid), get_gid (lo, ctx->gid), mode & ~ctx->umask,
                          true, &st);
  if (ret < 0)
    {
      fuse_reply_err (req, errno);
      return;
    }

  if (need_delete_whiteout && delete_whiteout (lo, -1, pnode, name) < 0)
    {
      fuse_reply_err (req, errno);
      return;
    }

  /* if the parent is on the upper layer, it doesn't need to lookup the ino in the lower layers.  */
  if (parent_upperdir_only)
    {
      ino = st.st_ino;
      dev = st.st_dev;
    }

  node = make_ovl_node (lo, path, get_upper_layer (lo), name, ino, dev, true, pnode, lo->fast_ino_check);
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

  if (parent_upperdir_only)
    {
      node->last_layer = pnode->last_layer;
      if (get_timeout (lo) > 0)
        node->loaded = 1;
    }
  else
    {
      ret = hide_all (lo, node);
      if (ret < 0)
        {
          fuse_reply_err (req, errno);
          return;
        }
    }

  memset (&e, 0, sizeof (e));

  ret = rpl_stat (req, node, -1, NULL, parent_upperdir_only ? &st : NULL, &e.attr);
  if (ret)
    {
      fuse_reply_err (req, errno);
      return;
    }

  e.ino = node_to_inode (node);
  e.attr_timeout = get_timeout (lo);
  e.entry_timeout = get_timeout (lo);
  node->ino->lookups++;
  pnode->n_links++;
  fuse_reply_entry (req, &e);
}

static int
direct_fsync (struct ovl_layer *l, int fd, const char *path, int datasync)
{
  cleanup_close int cfd = -1;

  if (fd < 0)
    {
      cfd = safe_openat (l->fd, path, O_NOFOLLOW | O_DIRECTORY, 0);
      if (cfd < 0)
        return cfd;
      fd = cfd;
    }

  return datasync ? fdatasync (fd) : fsync (fd);
}

static void
do_fsync (fuse_req_t req, fuse_ino_t ino, int datasync, int fd)
{
  int ret = 0;
  bool do_fsync;
  struct ovl_node *node;
  struct ovl_data *lo = ovl_data (req);
  cleanup_lock int l = 0;

  if (! lo->fsync)
    {
      fuse_reply_err (req, ENOSYS);
      return;
    }

  l = enter_big_lock ();

  node = do_lookup_file (lo, ino, NULL);
  if (node == NULL || node->whiteout)
    {
      fuse_reply_err (req, ENOENT);
      return;
    }

  /* Skip fsync for lower layers.  */
  do_fsync = node && node->layer == get_upper_layer (lo);

  if (node->layer == NULL)
    {
      fuse_reply_err (req, ENOENT);
      return;
    }

  if (! do_fsync)
    {
      fuse_reply_err (req, 0);
      return;
    }

  if (do_fsync)
    ret = direct_fsync (node->layer, fd, node->path, datasync);

  fuse_reply_err (req, ret == 0 ? 0 : errno);
}

static void
ovl_fsync (fuse_req_t req, fuse_ino_t ino, int datasync, struct fuse_file_info *fi)
{
  if (UNLIKELY (ovl_debug (req)))
    fprintf (stderr, "ovl_fsync(ino=%" PRIu64 ", datasync=%d, fi=%p)\n",
             ino, datasync, fi);

  return do_fsync (req, ino, datasync, fi->fh);
}

static void
ovl_fsyncdir (fuse_req_t req, fuse_ino_t ino, int datasync, struct fuse_file_info *fi)
{
  if (UNLIKELY (ovl_debug (req)))
    fprintf (stderr, "ovl_fsyncdir(ino=%" PRIu64 ", datasync=%d, fi=%p)\n",
             ino, datasync, fi);

  return do_fsync (req, ino, datasync, -1);
}

static void
ovl_ioctl (fuse_req_t req, fuse_ino_t ino, int cmd, void *arg,
           struct fuse_file_info *fi, unsigned int flags,
           const void *in_buf, size_t in_bufsz, size_t out_bufsz)
{
  cleanup_lock int l = enter_big_lock ();
  struct ovl_data *lo = ovl_data (req);
  cleanup_close int cleaned_fd = -1;
  struct ovl_node *node;
  int fd = -1;
  int r = 0;

  if (flags & FUSE_IOCTL_COMPAT)
    {
      fuse_reply_err (req, ENOSYS);
      return;
    }

  if (UNLIKELY (ovl_debug (req)))
    fprintf (stderr, "ovl_ioctl(ino=%" PRIu64 ", cmd=%d, arg=%p, fi=%p, flags=%d, buf=%p, in_bufsz=%zu, out_bufsz=%zu)\n",
             ino, cmd, arg, fi, flags, in_buf, in_bufsz, out_bufsz);

  node = do_lookup_file (lo, ino, NULL);
  if (node == NULL || node->whiteout)
    {
      fuse_reply_err (req, ENOENT);
      return;
    }

  switch (cmd)
    {
    case FS_IOC_GETVERSION:
    case FS_IOC_GETFLAGS:
      if (! node_dirp (node))
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
      fd = cleaned_fd = node->layer->ds->openat (node->layer, node->path, O_RDONLY | O_NONBLOCK, 0755);
      if (fd < 0)
        {
          fuse_reply_err (req, errno);
          return;
        }
    }

  l = release_big_lock ();

  if (ioctl (fd, cmd, &r, sizeof (r)) < 0)
    fuse_reply_err (req, errno);
  else
    fuse_reply_ioctl (req, 0, &r, out_bufsz ? sizeof (r) : 0);
}

static int
direct_fallocate (struct ovl_layer *l, int fd, int mode, off_t offset, off_t len)
{
  return fallocate (fd, mode, offset, len);
}

static void
ovl_fallocate (fuse_req_t req, fuse_ino_t ino, int mode, off_t offset, off_t length, struct fuse_file_info *fi)
{
  cleanup_lock int l = enter_big_lock ();
  struct ovl_data *lo = ovl_data (req);
  cleanup_close int fd = -1;
  struct ovl_node *node;
  int dirfd;
  int ret;

  if (UNLIKELY (ovl_debug (req)))
    fprintf (stderr, "ovl_fallocate(ino=%" PRIu64 ", mode=%d, offset=%lo, length=%lu, fi=%p)\n",
             ino, mode, offset, length, fi);

  node = do_lookup_file (lo, ino, NULL);
  if (node == NULL || node->whiteout)
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
  fd = safe_openat (dirfd, node->path, O_NONBLOCK | O_NOFOLLOW | O_WRONLY, 0);
  if (fd < 0)
    {
      fuse_reply_err (req, errno);
      return;
    }

  l = release_big_lock ();

  ret = direct_fallocate (node->layer, fd, mode, offset, length);
  fuse_reply_err (req, ret < 0 ? errno : 0);
}

#ifdef HAVE_COPY_FILE_RANGE

static ssize_t
direct_copy_file_range (struct ovl_layer *l, int fd_in, off_t *off_in,
                        int fd_out, off_t *off_out,
                        size_t len, unsigned int flags)
{
  return copy_file_range (fd_in, off_in, fd_out, off_out, len, flags);
}

static void
ovl_copy_file_range (fuse_req_t req, fuse_ino_t ino_in, off_t off_in, struct fuse_file_info *fi_in, fuse_ino_t ino_out, off_t off_out, struct fuse_file_info *fi_out, size_t len, int flags)
{
  cleanup_lock int l = enter_big_lock ();
  struct ovl_data *lo = ovl_data (req);
  struct ovl_node *node, *dnode;
  cleanup_close int fd_dest = -1;
  cleanup_close int fd = -1;
  ssize_t ret;

  if (UNLIKELY (ovl_debug (req)))
    fprintf (stderr, "ovl_copy_file_range(ino_in=%" PRIu64 ", off_in=%lo, fi_in=%p, ino_out=%" PRIu64 ", off_out=%lo, fi_out=%p, size=%zu, flags=%d)\n",
             ino_in, off_in, fi_in, ino_out, off_out, fi_out, len, flags);

  node = do_lookup_file (lo, ino_in, NULL);
  if (node == NULL || node->whiteout)
    {
      fuse_reply_err (req, ENOENT);
      return;
    }

  dnode = do_lookup_file (lo, ino_out, NULL);
  if (dnode == NULL || dnode->whiteout)
    {
      fuse_reply_err (req, ENOENT);
      return;
    }

  dnode = get_node_up (lo, dnode);
  if (dnode == NULL)
    {
      fuse_reply_err (req, errno);
      return;
    }

  if (node->hidden)
    fd = openat (node->hidden_dirfd, node->path, O_NONBLOCK | O_NOFOLLOW | O_RDONLY, 0755);
  else
    fd = node->layer->ds->openat (node->layer, node->path, O_NONBLOCK | O_NOFOLLOW | O_RDONLY, 0755);
  if (fd < 0)
    {
      fuse_reply_err (req, errno);
      return;
    }

  fd_dest = TEMP_FAILURE_RETRY (safe_openat (node_dirfd (dnode), dnode->path, O_NONBLOCK | O_NOFOLLOW | O_WRONLY, 0));
  if (fd_dest < 0)
    {
      fuse_reply_err (req, errno);
      return;
    }

  l = release_big_lock ();

  ret = direct_copy_file_range (node->layer, fd, &off_in, fd_dest, &off_out, len, flags);
  if (ret < 0)
    fuse_reply_err (req, errno);
  else
    fuse_reply_write (req, ret);
}
#endif

static struct fuse_lowlevel_ops ovl_oper = {
  .statfs = ovl_statfs,
  .access = ovl_access,
  .getxattr = ovl_getxattr,
  .removexattr = ovl_removexattr,
  .setxattr = ovl_setxattr,
  .listxattr = ovl_listxattr,
  .init = ovl_init,
  .lookup = ovl_lookup,
  .forget = ovl_forget,
  .forget_multi = ovl_forget_multi,
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
  .fsyncdir = ovl_fsyncdir,
  .ioctl = ovl_ioctl,
  .fallocate = ovl_fallocate,
#if HAVE_COPY_FILE_RANGE && HAVE_FUSE_COPY_FILE_RANGE
  .copy_file_range = ovl_copy_file_range,
#endif
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
  if ((strcmp (arg, "--debug") == 0) || (strcmp (arg, "-d") == 0) || (strcmp (arg, "debug") == 0))
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
  if (strcmp (arg, "atime") == 0)
    return 1;
  if (strcmp (arg, "noatime") == 0)
    return 1;
  if (strcmp (arg, "diratime") == 0)
    return 1;
  if (strcmp (arg, "nodiratime") == 0)
    return 1;
  if (strcmp (arg, "splice_write") == 0)
    return 1;
  if (strcmp (arg, "splice_read") == 0)
    return 1;
  if (strcmp (arg, "splice_move") == 0)
    return 1;
  if (strcmp (arg, "kernel_cache") == 0)
    return 1;
  if (strcmp (arg, "max_write") == 0)
    return 1;
  if (strcmp (arg, "ro") == 0)
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
    {
      fprintf (stderr, "unknown argument ignored: %s\n", arg);
      return 0;
    }

  return 1;
}

char **
get_new_args (int *argc, char **argv)
{
  int i;
  char **newargv;

  newargv = malloc (sizeof (char *) * (*argc + 2));
  if (newargv == NULL)
    error (EXIT_FAILURE, 0, "error allocating memory");

  newargv[0] = argv[0];
  if (geteuid () == 0)
    newargv[1] = "-odefault_permissions,allow_other,suid,noatime,lazytime";
  else
    newargv[1] = "-odefault_permissions,noatime";
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
    error (EXIT_FAILURE, errno, "cannot read nofile rlimit");

  /* Set the soft limit to the hard limit.  */
  l.rlim_cur = l.rlim_max;

  if (setrlimit (RLIMIT_NOFILE, &l) < 0)
    error (EXIT_FAILURE, errno, "cannot set nofile rlimit");
}

static char *
load_default_plugins ()
{
  DIR *dp = NULL;
  char *plugins = strdup ("");

  dp = opendir (PKGLIBEXECDIR);
  if (dp == NULL)
    return plugins;

  for (;;)
    {
      struct dirent *dent;

      dent = readdir (dp);
      if (dent == NULL)
        break;
      if (dent->d_type != DT_DIR)
        {
          char *new_plugins = NULL;
          if (asprintf (&new_plugins, "%s/%s:%s", PKGLIBEXECDIR, dent->d_name, plugins) < 0)
            {
              free (plugins);
              closedir (dp);
              return NULL;
            }
          free (plugins);
          plugins = new_plugins;
        }
    }
  closedir (dp);

  return plugins;
}

int
main (int argc, char *argv[])
{
  struct fuse_session *se;
  struct fuse_cmdline_opts opts;
  char **newargv = get_new_args (&argc, argv);
  struct ovl_data lo = {
    .debug = 0,
    .uid_mappings = NULL,
    .gid_mappings = NULL,
    .uid_str = NULL,
    .gid_str = NULL,
    .root = NULL,
    .lowerdir = NULL,
    .redirect_dir = NULL,
    .mountpoint = NULL,
    .fsync = 1,
    .noacl = 0,
    .squash_to_uid = -1,
    .squash_to_gid = -1,
    .static_nlink = 0,
    .xattr_permissions = 0,
    .euid = geteuid (),
    .timeout = 1000000000.0,
    .timeout_str = NULL,
    .writeback = 1,
    .volatile_mode = 0,
  };
  struct fuse_loop_config fuse_conf = {
    .clone_fd = 1,
    .max_idle_threads = 10,
  };
  int ret = -1;
  cleanup_layer struct ovl_layer *layers = NULL;
  struct ovl_layer *tmp_layer = NULL;
  struct fuse_args args = FUSE_ARGS_INIT (argc, newargv);

  memset (&opts, 0, sizeof (opts));
  if (fuse_opt_parse (&args, &lo, ovl_opts, fuse_opt_proc) == -1)
    error (EXIT_FAILURE, 0, "error parsing options");
  if (fuse_parse_cmdline (&args, &opts) != 0)
    error (EXIT_FAILURE, 0, "error parsing cmdline");

  if (opts.mountpoint)
    free (opts.mountpoint);

  read_overflowids ();

  pthread_mutex_init (&lock, PTHREAD_MUTEX_DEFAULT);

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

  lo.uid = geteuid ();
  lo.gid = getegid ();

  if (lo.redirect_dir && strcmp (lo.redirect_dir, "off"))
    error (EXIT_FAILURE, 0, "fuse-overlayfs only supports redirect_dir=off");

  if (lo.mountpoint == NULL)
    error (EXIT_FAILURE, 0, "no mountpoint specified");

  if (lo.upperdir != NULL)
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
  check_can_mknod (&lo);
  check_writeable_proc ();

  if (lo.volatile_mode)
    lo.fsync = 0;

  if (lo.debug)
    {
      fprintf (stderr, "uid=%s\n", lo.uid_str ?: "unchanged");
      fprintf (stderr, "gid=%s\n", lo.gid_str ?: "unchanged");
      fprintf (stderr, "upperdir=%s\n", lo.upperdir ? lo.upperdir : "NOT USED");
      fprintf (stderr, "workdir=%s\n", lo.workdir ? lo.workdir : "NOT USED");
      fprintf (stderr, "lowerdir=%s\n", lo.lowerdir);
      fprintf (stderr, "mountpoint=%s\n", lo.mountpoint);
      fprintf (stderr, "plugins=%s\n", lo.plugins ? lo.plugins : "<none>");
      fprintf (stderr, "fsync=%s\n", lo.fsync ? "enabled" : "disabled");
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

  if (lo.plugins == NULL)
    lo.plugins = load_default_plugins ();

  lo.plugins_ctx = load_plugins (lo.plugins);

  layers = read_dirs (&lo, lo.lowerdir, true, NULL);
  if (layers == NULL)
    {
      error (EXIT_FAILURE, errno, "cannot read lower dirs");
    }

  if (lo.upperdir != NULL)
    {
      tmp_layer = read_dirs (&lo, lo.upperdir, false, layers);
      if (tmp_layer == NULL)
        error (EXIT_FAILURE, errno, "cannot read upper dir");
      layers = tmp_layer;
    }

  lo.layers = layers;

  for (tmp_layer = layers; ! lo.noacl && tmp_layer; tmp_layer = tmp_layer->next)
    {
      if (! tmp_layer->ds->support_acls (tmp_layer))
        lo.noacl = 1;
    }

  if (lo.upperdir)
    {
      if (lo.xattr_permissions)
        {
          const char *name = NULL;
          char data[64];
          ssize_t s;
          if (lo.xattr_permissions == 1)
            {
              get_upper_layer (&lo)->stat_override_mode = STAT_OVERRIDE_PRIVILEGED;
              name = XATTR_PRIVILEGED_OVERRIDE_STAT;
            }
          else if (lo.xattr_permissions == 2)
            {
              get_upper_layer (&lo)->stat_override_mode = STAT_OVERRIDE_USER;
              name = XATTR_OVERRIDE_STAT;
            }
          else
            error (EXIT_FAILURE, 0, "invalid value for xattr_permissions");

          s = fgetxattr (get_upper_layer (&lo)->fd, name, data, sizeof (data));
          if (s < 0)
            {
              bool found = false;
              struct ovl_layer *l;

              if (errno != ENODATA)
                error (EXIT_FAILURE, errno, "read xattr `%s` from upperdir", name);

              for (l = get_lower_layers (&lo); l; l = l->next)
                {
                  s = fgetxattr (l->fd, name, data, sizeof (data));
                  if (s < 0 && errno != ENODATA)
                    error (EXIT_FAILURE, errno, "fgetxattr mode from lower layer");
                  if (s < 0 && lo.xattr_permissions == 2)
                    {
                      s = fgetxattr (l->fd, XATTR_OVERRIDE_CONTAINERS_STAT, data, sizeof (data));
                      if (s < 0 && errno != ENODATA)
                        error (EXIT_FAILURE, errno, "fgetxattr mode from lower layer");
                    }
                  if (s > 0)
                    {
                      ret = fsetxattr (get_upper_layer (&lo)->fd, name, data, s, 0);
                      if (ret < 0)
                        error (EXIT_FAILURE, errno, "fsetxattr mode to upper layer");
                      found = true;
                      break;
                    }
                }
              if (! found)
                {
                  /* If the mode is missing, set a standard value.  */
                  ret = write_permission_xattr (&lo, get_upper_layer (&lo)->fd, lo.upperdir, 0, 0, 0555);
                  if (ret < 0)
                    error (EXIT_FAILURE, errno, "write xattr `%s` to upperdir", name);
                }
            }
        }
    }

  lo.inodes = hash_initialize (2048, NULL, node_inode_hasher, node_inode_compare, inode_free);

  lo.root = load_dir (&lo, NULL, lo.layers, ".", "");
  if (lo.root == NULL)
    error (EXIT_FAILURE, errno, "cannot read upper dir");
  lo.root->ino->lookups = 2;

  if (lo.workdir == NULL && lo.upperdir != NULL)
    error (EXIT_FAILURE, 0, "workdir not specified");

  if (lo.workdir)
    {
      int dfd;
      cleanup_free char *path = NULL;

      path = realpath (lo.workdir, NULL);
      if (path == NULL)
        goto err_out1;
      mkdir (path, 0700);
      path = realloc (path, strlen (path) + strlen ("/work") + 1);
      if (! path)
        error (EXIT_FAILURE, errno, "allocating workdir path");
      strcat (path, "/work");
      mkdir (path, 0700);
      free (lo.workdir);
      lo.workdir = strdup (path);
      if (lo.workdir == NULL)
        error (EXIT_FAILURE, errno, "allocating workdir path");

      lo.workdir_fd = open (lo.workdir, O_DIRECTORY);
      if (lo.workdir_fd < 0)
        error (EXIT_FAILURE, errno, "cannot open workdir");

      dfd = dup (lo.workdir_fd);
      if (dfd < 0)
        error (EXIT_FAILURE, errno, "dup workdir file descriptor");
      empty_dirfd (dfd);
    }

  umask (0);
  disable_locking = ! lo.threaded;

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

  signal (SIGUSR1, print_stats);

  if (fuse_session_mount (se, lo.mountpoint) != 0)
    {
      error (0, errno, "cannot mount");
      goto err_out3;
    }
  fuse_daemonize (opts.foreground);

  if (lo.threaded)
    ret = fuse_session_loop_mt (se, &fuse_conf);
  else
    ret = fuse_session_loop (se);

  fuse_session_unmount (se);
err_out3:
  fuse_remove_signal_handlers (se);
err_out2:
  fuse_session_destroy (se);
err_out1:

  for (tmp_layer = lo.layers; tmp_layer; tmp_layer = tmp_layer->next)
    tmp_layer->ds->cleanup (tmp_layer);

  node_mark_all_free (lo.root);

  hash_free (lo.inodes);

  plugin_free_all (lo.plugins_ctx);

  free_mapping (lo.uid_mappings);
  free_mapping (lo.gid_mappings);

  close (lo.workdir_fd);

  fuse_opt_free_args (&args);

  exit (ret ? EXIT_FAILURE : EXIT_SUCCESS);
  return 1;
}
