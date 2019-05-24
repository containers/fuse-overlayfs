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

# include <dlfcn.h>

enum
  {
   LAYER_MODE_METADATA  = 1 << 0,
   LAYER_MODE_DIRECTORY = 1 << 1,
   LAYER_MODE_FILE      = 1 << 2,
  };

typedef void *(*plugin_init)(const char *data, const char *workdir, int workdirfd, const char *target, int dirfd);
typedef int (*plugin_fetch)(void *opaque, const char *parentdir, const char *path, int mode);
typedef int (*plugin_release)(void *opaque);
typedef const char *(*plugin_name)();
typedef int (*plugin_version)();

struct ovl_plugin
{
  struct ovl_plugin *next;
  const char *name;
  void *handle;

  plugin_init init;
  plugin_fetch fetch;
  plugin_release release;
};

struct ovl_plugin_context
{
  struct ovl_plugin *plugins;
};

void plugin_load (struct ovl_plugin_context *context, const char *path);
int plugin_free (struct ovl_plugin_context *context);
struct ovl_plugin *plugin_find (struct ovl_plugin_context *context, const char *name);

#endif
