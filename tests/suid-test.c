#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>

int
main ()
{
  int fd;

  unlink ("suid");
  unlink ("nosuid");

  fd = open ("suid", O_WRONLY|O_CREAT|O_EXCL);
  write (fd, "1", 1);
  fchown (fd, 0, 0);
  fchmod (fd, S_ISUID | 0755);
  close (fd);

  fd = open ("nosuid", O_WRONLY|O_CREAT|O_EXCL);
  write (fd, "1", 1);
  fchown (fd, 0, 0);
  fchmod (fd, S_ISUID | 0755);
  write (fd, "2", 1);
  close (fd);
  return 0;
}
