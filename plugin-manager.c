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
#define _GNU_SOURCE
#define _FILE_OFFSET_BITS 64

#include <config.h>
#include <plugin.h>
#include <stdlib.h>
#include <fuse_overlayfs_error.h>
#include <errno.h>
#include <string.h>

struct ovl_plugin_context *
load_plugins (const char *plugins)
{
  char *saveptr = NULL, *it;
  cleanup_free char *buf = NULL;
  struct ovl_plugin_context *ctx;

  ctx = calloc (1, sizeof (*ctx));
  if (ctx == NULL)
    error (EXIT_FAILURE, errno, "cannot allocate context");

  buf = strdup (plugins);
  if (buf == NULL)
    error (EXIT_FAILURE, errno, "cannot allocate memory");

  for (it = strtok_r (buf, ":", &saveptr); it; it = strtok_r (NULL, ":", &saveptr))
    plugin_load_one (ctx, it);

  return ctx;
}

void
plugin_load_one (struct ovl_plugin_context *context, const char *path)
{
  plugin_name name;
  struct ovl_plugin *p;
  plugin_version version;
  void *handle = dlopen (path, RTLD_NOW|RTLD_LOCAL);
  if (! handle)
    error (EXIT_FAILURE, 0, "cannot load plugin %s: %s", path, dlerror());

  p = calloc (1, sizeof (*p));
  if (p == NULL)
    error (EXIT_FAILURE, errno, "cannot load plugin %s", path);
  p->next = context->plugins;

  version = dlsym (handle, "plugin_version");
  if (version == NULL)
    error (EXIT_FAILURE, 0, "cannot find symbol `plugin_version` in plugin %s", path);

  if (version () != 1)
    error (EXIT_FAILURE, 0, "invalid plugin version for %s", path);

  p->handle = handle;
  name = dlsym (handle, "plugin_name");
  if (name == NULL)
    error (EXIT_FAILURE, 0, "cannot find symbol `plugin_name` in plugin %s", path);

  p->name = name ();

  if (plugin_find (context, p->name))
    error (EXIT_FAILURE, 0, "plugin %s added twice", p->name);

  p->load = dlsym (handle, "plugin_load");
  if (p->load == NULL)
    error (EXIT_FAILURE, 0, "cannot find symbol `plugin_load` in plugin %s", path);

  p->release = dlsym (handle, "plugin_release");
  if (p->release == NULL)
    error (EXIT_FAILURE, 0, "cannot find symbol `plugin_release` in plugin %s", path);

  context->plugins = p;
}

struct ovl_plugin *
plugin_find (struct ovl_plugin_context *context, const char *name)
{
  struct ovl_plugin *it;

  for (it = context->plugins; it; it = it->next)
    {
      if (strcmp (name, it->name) == 0)
        return it;
    }
  return NULL;
}

int
plugin_free_all (struct ovl_plugin_context *context)
{
  struct ovl_plugin *it, *next;

  it = context->plugins;
  while (it)
    {
      next = it->next;

      it->release ();

      /* Skip dlclose (it->handle) as it causes plugins written in Go to crash.  */

      free (it);

      it = next;
    }

  free (context);

  return 0;
}
