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
#ifndef UTILS_H
# define UTILS_H

void
cleanup_freep (void *p)
{
  void **pp = (void **) p;
  free (*pp);
}

void
cleanup_filep (FILE **f)
{
  FILE *file = *f;
  if (file)
    (void) fclose (file);
}

void
cleanup_closep (void *p)
{
  int *pp = p;
  if (*pp >= 0)
    close (*pp);
}

void
cleanup_dirp (DIR **p)
{
  DIR *dir = *p;
  if (dir)
    closedir (dir);
}

# define cleanup_file __attribute__((cleanup (cleanup_filep)))
# define cleanup_free __attribute__((cleanup (cleanup_freep)))
# define cleanup_close __attribute__((cleanup (cleanup_closep)))
# define cleanup_dir __attribute__((cleanup (cleanup_dirp)))

# define LIKELY(x) __builtin_expect((x),1)
# define UNLIKELY(x) __builtin_expect((x),0)

#endif
