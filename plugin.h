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

#ifndef PLUGIN_H
# define PLUGIN_H
# include <config.h>

# include <utils.h>
# include <fuse-overlayfs.h>

typedef struct data_source *(*plugin_load_data_source)(const char *opaque, const char *path);
typedef int (*plugin_release)();
typedef const char *(*plugin_name)();
typedef int (*plugin_version)();

struct ovl_plugin
{
  struct ovl_plugin *next;
  const char *name;
  void *handle;

  plugin_load_data_source load;
  plugin_release release;
};

#endif
