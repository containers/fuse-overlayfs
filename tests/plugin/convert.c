#define _GNU_SOURCE

#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/xattr.h>
#include <dirent.h>
#include <error.h>
#include <string.h>
#include <errno.h>

void
convert (int dfd)
{
  DIR *d;
  struct dirent *de;
  int fd;
  char p[64];
  char b[64];

  d = fdopendir (dfd);
  if (d == NULL)
    {
      close (dfd);
      error (EXIT_FAILURE, errno, "cannot open directory");
    }

  for (de = readdir (d); de; de = readdir (d))
    {
      struct stat st;
      mode_t newmode;

      if (strcmp (de->d_name, ".") == 0 || strcmp (de->d_name, "..") == 0)
        continue;

      printf ("convert %s\n", de->d_name);

      if (fstatat (dirfd (d), de->d_name, &st, AT_SYMLINK_NOFOLLOW) < 0)
        error (EXIT_FAILURE, errno, "stat");

      sprintf (b, "%o:%d:%d", st.st_mode & 0777, st.st_uid, st.st_gid);

      newmode = (st.st_mode & ~0777) | 0755;

      switch (st.st_mode & S_IFMT)
        {
        case S_IFDIR:
          fd = openat (dirfd (d), de->d_name, O_DIRECTORY);
          if (fd < 0)
            error (EXIT_FAILURE, errno, "open directory %s", de->d_name);

          if (fsetxattr (fd, "user.original-permissions", b, strlen (b) + 1, XATTR_CREATE) < 0 && errno != EEXIST)
            error (EXIT_FAILURE, errno, "cannot set xattr for dir %s", de->d_name);
          if (fchmod (fd, newmode) < 0)
            error (EXIT_FAILURE, errno, "cannot set fchmod %s", de->d_name);

          convert (fd);

          break;

        default:
          fd = openat (dirfd (d), de->d_name, O_PATH | O_NOFOLLOW);
          if (fd < 0)
            error (EXIT_FAILURE, errno, "open %s", de->d_name);

          sprintf (p, "/proc/self/fd/%d", fd);

          if (setxattr (p, "user.original-permissions", b, strlen (b) + 1, XATTR_CREATE) < 0 && errno != EEXIST && errno != EPERM)
            error (EXIT_FAILURE, errno, "cannot set xattr %s", de->d_name);

          if (chmod (p, newmode) < 0 && errno != ENOTSUP)
            error (EXIT_FAILURE, errno, "cannot chmod %s", de->d_name);

          close (fd);
          break;
        }
    }
  closedir (d);
}

int
main (int argc, char **argv)
{
  int fd;

  if (argc < 1)
    error (EXIT_FAILURE, 0, "specify a path");

  fd = open (argv[1], O_DIRECTORY | O_NOFOLLOW);
  if (fd < 0)
    error (EXIT_FAILURE, 0, "open %s", argv[1]);
  convert (fd);
  return 0;
}
