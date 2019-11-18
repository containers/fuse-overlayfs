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

#ifndef FUSE_OVERLAYFS_ERROR_H
# define FUSE_OVERLAYFS_ERROR_H

# include <config.h>

# ifdef HAVE_ERROR_H
#  include <error.h>
# else
#  define error(status, errno, fmt, ...) do {                           \
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
# endif

#endif
