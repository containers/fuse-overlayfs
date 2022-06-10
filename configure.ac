AC_PREREQ([2.69])
AC_INIT([fuse-overlayfs], [1.10-dev], [giuseppe@scrivano.org])
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


AC_COMPILE_IFELSE(
[
AC_LANG_SOURCE([
#define FUSE_USE_VERSION 32
#include <fuse_lowlevel.h>
void foo()
{
        struct fuse_lowlevel_ops ops;
        ops.copy_file_range = 0;
}])
],
[fuse_has_copy_file_range=1],
[fuse_has_copy_file_range=0])


CFLAGS=$old_CFLAGS
LDFLAGS=$old_LDFLAGS

AC_PATH_PROG(MD2MAN, go-md2man)
AM_CONDITIONAL([HAVE_MD2MAN], [test "x$ac_cv_path_MD2MAN" != x])

AC_DEFINE_UNQUOTED([HAVE_FUSE_CACHE_READDIR], $cache_readdir, [Define if libfuse cache_readdir is available])
AC_DEFINE_UNQUOTED([HAVE_FUSE_COPY_FILE_RANGE], $fuse_has_copy_file_range, [Define if libfuse has copy_file_range is available])

AC_SEARCH_LIBS([dlopen], [dl], [], [AC_MSG_ERROR([unable to find dlopen()])])

AC_FUNC_ERROR_AT_LINE
AC_CHECK_FUNCS([malloc open_by_handle_at error memset strdup copy_file_range statx])

AC_CONFIG_FILES([Makefile lib/Makefile])
AC_OUTPUT
