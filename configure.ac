AC_PREREQ([2.69])
AC_INIT([fuse-overlayfs], [0.6.3], [giuseppe@scrivano.org])
AC_CONFIG_SRCDIR([main.c])
AC_CONFIG_HEADERS([config.h])

AC_CONFIG_AUX_DIR([build-aux])

AM_INIT_AUTOMAKE([1.9 foreign])

AC_PROG_CC

gl_EARLY
gl_INIT

AC_CHECK_HEADERS([fcntl.h inttypes.h limits.h stddef.h stdint.h stdlib.h string.h unistd.h sys/sendfile.h])

AC_PROG_RANLIB

AC_CHECK_HEADER_STDBOOL
AC_TYPE_MODE_T
AC_FUNC_OBSTACK
AC_TYPE_OFF_T
AC_TYPE_SIZE_T
AC_TYPE_SSIZE_T
AC_TYPE_UINT16_T
AC_TYPE_UINT32_T
AC_TYPE_UINT64_T
AC_TYPE_UINT8_T
AC_CHECK_TYPES([ptrdiff_t])

AC_DEFINE([USE_DIFF_HASH], 1, [Use the same hashing function as GNU diff])

PKG_CHECK_MODULES([FUSE], [fuse3 >= 3.2.1], [AC_DEFINE([HAVE_FUSE], 1, [Define if libfuse is available])], [AC_MSG_ERROR([*** libfuse not found])]])

old_CFLAGS=$CFLAGS
old_LDFLAGS=$LDFLAGS
CFLAGS=$pkg_cv_FUSE_CFLAGS
LDFLAGS=$pkg_cv_FUSE_LDFLAGS
AC_COMPILE_IFELSE(
[
AC_LANG_SOURCE([
#define FUSE_USE_VERSION 32
#include <fuse_lowlevel.h>
void foo()
{
        struct fuse_file_info fi;
        fi.cache_readdir = 1;
}])
],
[cache_readdir=1],
[cache_readdir=0])
CFLAGS=$old_CFLAGS
LDFLAGS=$old_LDFLAGS

AC_DEFINE_UNQUOTED([HAVE_FUSE_CACHE_READDIR], $cache_readdir, [Define if libfuse is available])


AC_FUNC_ERROR_AT_LINE
AC_FUNC_MALLOC
AC_CHECK_FUNCS([open_by_handle_at error memset strdup copy_file_range])

AC_CONFIG_FILES([Makefile lib/Makefile])
AC_OUTPUT
