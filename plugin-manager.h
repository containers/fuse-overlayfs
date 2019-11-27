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

#ifndef PLUGIN_MANAGER_H
# define PLUGIN_MANAGER_H
# include <config.h>

# include <dlfcn.h>

struct ovl_plugin_context
{
  struct ovl_plugin *plugins;
};

void plugin_load_one (struct ovl_plugin_context *context, const char *path);
int plugin_free_all (struct ovl_plugin_context *context);
struct ovl_plugin *plugin_find (struct ovl_plugin_context *context, const char *name);
struct ovl_plugin_context *load_plugins (const char *plugins);

#endif

/* taken from glibc unistd.h and fixes musl */
#ifndef TEMP_FAILURE_RETRY
#define TEMP_FAILURE_RETRY(expression) \
  (__extension__                                                              \
    ({ long int __result;                                                     \
       do __result = (long int) (expression);                                 \
       while (__result == -1L && errno == EINTR);                             \
       __result; }))
#endif
