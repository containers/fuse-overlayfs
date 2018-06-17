SUBDIRS = lib

bin_PROGRAMS = containerfs

ACLOCAL_AMFLAGS = -Im4

EXTRA_DIST = m4/gnulib-cache.m4

containerfs_CFLAGS = -I . -I lib $(FUSE_CFLAGS)
containerfs_LDFLAGS = $(FUSE_LIBS)
containerfs_LDADD = lib/libgnu.a
containerfs_SOURCES = main.c
