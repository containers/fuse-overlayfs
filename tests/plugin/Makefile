all: shared-storage-plugin.so convert

# Files that we copy from fuse-overlayfs for the purposes of this test.
IMPORT_FILES = utils.c utils.h fuse-overlayfs.h plugin-manager.h config.h

# These are the V1 versions of the plugin definitions. We want to compile the
# plugin with these specific versions to ensure that we maintain backwards
# compatibility.
fuse-overlayfs.h plugin-manager.h utils.h utils.c:
	git show v1.16:$@ >$@

config.h:
	cp ../../$@ .

shared-storage-plugin.so: shared-storage-plugin.c $(IMPORT_FILES)
	gcc -fPIC -I. -shared -o shared-storage-plugin.so shared-storage-plugin.c utils.c

convert: convert.c
	gcc convert.c -o convert

clean:
	rm $(IMPORT_FILES) shared-storage-plugin.so convert
