/*
  FUSE: Filesystem in Userspace
  Copyright (C) 2001-2007  Miklos Szeredi <miklos@szeredi.hu>

  Minor modifications and note by Andy Sayler (2012) <www.andysayler.com>
  
  More modifications by Taylor Andrews (2014) <github.com/taylorjandrews>

  Source: fuse-2.8.7.tar.gz examples directory
  http://sourceforge.net/projects/fuse/files/fuse-2.X/

  This program can be distributed under the terms of the GNU GPL.
  See the file COPYING.

  gcc -Wall `pkg-config fuse --cflags` fuseencfs.c -o fuseencfs `pkg-config fuse --libs`

  Note: This implementation is largely stateless and does not maintain
        open file handels between open and release calls (fi->fh).
        Instead, files are opened and closed as necessary inside read(), write(),
        etc calls. As such, the functions that rely on maintaining file handles are
        not implmented (fgetattr(), etc). Those seeking a more efficient and
        more complete implementation may wish to add fi->fh support to minimize
        open() and close() calls and support fh dependent functions.

*/

#define FUSE_USE_VERSION 28
#define AES_ENCRYPT 1
#define AES_DECRYPT 0
#define AES_PASSTHRU -1
#define HAVE_SETXATTR

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#ifdef linux
/* For pread()/pwrite() */
#define _XOPEN_SOURCE 500
#endif

#include <fuse.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <dirent.h>
#include <errno.h>
#include <sys/time.h>
#include <stddef.h>
#include <sys/types.h>
#include <unistd.h>
#include <limits.h>
#include <sys/xattr.h>

#ifdef HAVE_SETXATTR
#include <sys/xattr.h>
#endif

#include "aes-crypt.h"

typedef struct {
    char *rootdir;
    char *passPhrase;
} encfs_state;


static void encfs_fullpath(char fpath[PATH_MAX], const char *path)
{
    encfs_state *state = (encfs_state *) (fuse_get_context()->private_data);
    strcpy(fpath, state->rootdir);
    strncat(fpath, path, PATH_MAX); 
}


static int encfs_getattr(const char *path, struct stat *stbuf)
{
	int res;
	char fpath[PATH_MAX];
	
	encfs_fullpath(fpath, path);

	res = lstat(fpath, stbuf);
	if (res == -1)
		return -errno;

	return 0;
}

static int encfs_access(const char *path, int mask)
{
	int res;
	char fpath[PATH_MAX];
	
	encfs_fullpath(fpath, path);

	res = access(fpath, mask);
	if (res == -1)
		return -errno;

	return 0;
}

static int encfs_readlink(const char *path, char *buf, size_t size)
{
	int res;
	char fpath[PATH_MAX];
	
	encfs_fullpath(fpath, path);

	res = readlink(fpath, buf, size - 1);
	if (res == -1)
		return -errno;

	buf[res] = '\0';
	return 0;
}

static int encfs_readdir(const char *path, void *buf, fuse_fill_dir_t filler,
		       off_t offset, struct fuse_file_info *fi)
{
	DIR *dp;
	struct dirent *de;
	
	char fpath[PATH_MAX];
	
	encfs_fullpath(fpath, path);

	(void) offset;
	(void) fi;

	dp = opendir(fpath);
	if (dp == NULL)
		return -errno;

	while ((de = readdir(dp)) != NULL) {
		struct stat st;
		memset(&st, 0, sizeof(st));
		st.st_ino = de->d_ino;
		st.st_mode = de->d_type << 12;
		if (filler(buf, de->d_name, &st, 0))
			break;
	}

	closedir(dp);
	return 0;
}

static int encfs_mknod(const char *path, mode_t mode, dev_t rdev)
{
	int res;
	char fpath[PATH_MAX];
	
	encfs_fullpath(fpath, path);

	/* On Linux this could just be 'mknod(path, mode, rdev)' but this
	   is more portable */
	if (S_ISREG(mode)) {
		res = open(fpath, O_CREAT | O_EXCL | O_WRONLY, mode);
		if (res >= 0)
			res = close(res);
	} else if (S_ISFIFO(mode))
		res = mkfifo(fpath, mode);
	else
		res = mknod(fpath, mode, rdev);
	if (res == -1)
		return -errno;

	return 0;
}

static int encfs_mkdir(const char *path, mode_t mode)
{
	int res;
	char fpath[PATH_MAX];
	
	encfs_fullpath(fpath, path);

	res = mkdir(fpath, mode);
	if (res == -1)
		return -errno;

	return 0;
}

static int encfs_unlink(const char *path)
{
	int res;
	char fpath[PATH_MAX];
	
	encfs_fullpath(fpath, path);

	res = unlink(fpath);
	if (res == -1)
		return -errno;

	return 0;
}

static int encfs_rmdir(const char *path)
{
	int res;
	char fpath[PATH_MAX];
	
	encfs_fullpath(fpath, path);

	res = rmdir(fpath);
	if (res == -1)
		return -errno;

	return 0;
}

static int encfs_symlink(const char *from, const char *to)
{
	int res;

	res = symlink(from, to);
	if (res == -1)
		return -errno;

	return 0;
}

static int encfs_rename(const char *from, const char *to)
{
	int res;

	res = rename(from, to);
	if (res == -1)
		return -errno;

	return 0;
}

static int encfs_link(const char *from, const char *to)
{
	int res;

	res = link(from, to);
	if (res == -1)
		return -errno;

	return 0;
}

static int encfs_chmod(const char *path, mode_t mode)
{
	int res;
	char fpath[PATH_MAX];
	
	encfs_fullpath(fpath, path);

	res = chmod(fpath, mode);
	if (res == -1)
		return -errno;

	return 0;
}

static int encfs_chown(const char *path, uid_t uid, gid_t gid)
{
	int res;
	char fpath[PATH_MAX];
	
	encfs_fullpath(fpath, path);

	res = lchown(fpath, uid, gid);
	if (res == -1)
		return -errno;

	return 0;
}

static int encfs_truncate(const char *path, off_t size)
{
	int res;
	char fpath[PATH_MAX];
	
	encfs_fullpath(fpath, path);

	res = truncate(fpath, size);
	if (res == -1)
		return -errno;

	return 0;
}

static int encfs_utimens(const char *path, const struct timespec ts[2])
{
	int res;
	struct timeval tv[2];
	char fpath[PATH_MAX];
	
	encfs_fullpath(fpath, path);

	tv[0].tv_sec = ts[0].tv_sec;
	tv[0].tv_usec = ts[0].tv_nsec / 1000;
	tv[1].tv_sec = ts[1].tv_sec;
	tv[1].tv_usec = ts[1].tv_nsec / 1000;

	res = utimes(fpath, tv);
	if (res == -1)
		return -errno;

	return 0;
}

static int encfs_open(const char *path, struct fuse_file_info *fi)
{
	int res;
	char fpath[PATH_MAX];
	
	encfs_fullpath(fpath, path);

	res = open(fpath, fi->flags);
	if (res == -1)
		return -errno;

	close(res);
	return 0;
}

static int encfs_read(const char *path, char *buf, size_t size, off_t offset,
		    struct fuse_file_info *fi)
{
	FILE *f, *memfile;
	char *memtext;
	size_t memsize;
	int res;
	int doCrypt = AES_ENCRYPT;
	char fpath[PATH_MAX];
	
	encfs_fullpath(fpath, path);

	(void) fi;
	
	f = fopen (fpath, "r");
	memfile = open_memstream(&memtext, &memsize);
	
	if((f == NULL) || (memfile == NULL))
		return -errno;
	
	encfs_state *state = (encfs_state *) (fuse_get_context()->private_data);
	do_crypt(f, memfile, doCrypt, state->passPhrase);
	
	fclose(f);
	
	fflush(memfile);
	fseek(memfile, offset, SEEK_SET);
	res = fread(buf, 1, size, memfile);
	fclose(memfile);
	
	if(res == -1)
		return -errno;
		
	return res;
}

static int encfs_write(const char *path, const char *buf, size_t size,
		     off_t offset, struct fuse_file_info *fi)
{
	FILE *f, *memfile;
	char *memtext;
	size_t memsize;
	int res;
	char fpath[PATH_MAX];
	
	encfs_fullpath(fpath, path);
	
	(void) fi;
	
	encfs_state *state = (encfs_state *) (fuse_get_context()->private_data);

	f = fopen(fpath, "r");
	memfile = open_memstream(&memtext, &memsize);
	
	if((f == NULL) || (memfile == NULL))
		return -errno;
	
	do_crypt(f, memfile, AES_DECRYPT, state->passPhrase);
	fclose(f);
	
	fseek(memfile, offset, SEEK_SET);

	res = fwrite(buf, 1, size, memfile);
	if (res == -1)
		res = -errno;
		
	fflush(memfile);
	
	f = fopen(fpath, "w");
	fseek(memfile, 0, SEEK_SET);
	do_crypt(memfile, f, AES_ENCRYPT, state->passPhrase);
	
	fclose(memfile);
	fclose(f);
	
	return res;
}

static int encfs_statfs(const char *path, struct statvfs *stbuf)
{
	int res;
	char fpath[PATH_MAX];
	
	encfs_fullpath(fpath, path);

	res = statvfs(fpath, stbuf);
	if (res == -1)
		return -errno;

	return 0;
}

static int encfs_create(const char* path, mode_t mode, struct fuse_file_info* fi) {
	(void) fi;
	(void) mode;
	
	char fpath[PATH_MAX];
	FILE *res, *temp = tmpfile();
	encfs_state *state = (encfs_state *) (fuse_get_context()->private_data);
	
	encfs_fullpath(fpath, path);
	res = fopen(fpath, "w");

	if(res == NULL)
		return -errno;
		
	do_crypt(temp, res, AES_ENCRYPT, state->passPhrase);
	fclose(temp);
	fclose(res);	

    return 0;
}


static int encfs_release(const char *path, struct fuse_file_info *fi)
{
	/* Just a stub.	 This method is optional and can safely be left
	   unimplemented */

	(void) path;
	(void) fi;
	return 0;
}

static int encfs_fsync(const char *path, int isdatasync,
		     struct fuse_file_info *fi)
{
	/* Just a stub.	 This method is optional and can safely be left
	   unimplemented */

	(void) path;
	(void) isdatasync;
	(void) fi;
	return 0;
}

#ifdef HAVE_SETXATTR
static int encfs_setxattr(const char *path, const char *name, const char *value,
			size_t size, int flags)
{
	int res;
	char fpath[PATH_MAX];
	
	encfs_fullpath(fpath, path);
	
	res = lsetxattr(fpath, name, value, size, flags);
	if (res == -1)
		return -errno;
	return 0;
}

static int encfs_getxattr(const char *path, const char *name, char *value,
			size_t size)
{
	int res;
	char fpath[PATH_MAX];
	
	encfs_fullpath(fpath, path);
	res = lgetxattr(fpath, name, value, size);
	if (res == -1)
		return -errno;
	return res;
}

static int encfs_listxattr(const char *path, char *list, size_t size)
{
	int res;
	char fpath[PATH_MAX];
	
	encfs_fullpath(fpath, path);
	res = llistxattr(fpath, list, size);
	if (res == -1)
		return -errno;
	return res;
}

static int encfs_removexattr(const char *path, const char *name)
{
	int res;
	char fpath[PATH_MAX];
	
	encfs_fullpath(fpath, path);
	res = lremovexattr(fpath, name);
	if (res == -1)
		return -errno;
	return 0;
}
#endif /* HAVE_SETXATTR */

static struct fuse_operations encfs_oper = {
	.getattr	= encfs_getattr,
	.access		= encfs_access,
	.readlink	= encfs_readlink,
	.readdir	= encfs_readdir,
	.mknod		= encfs_mknod,
	.mkdir		= encfs_mkdir,
	.symlink	= encfs_symlink,
	.unlink		= encfs_unlink,
	.rmdir		= encfs_rmdir,
	.rename		= encfs_rename,
	.link		= encfs_link,
	.chmod		= encfs_chmod,
	.chown		= encfs_chown,
	.truncate	= encfs_truncate,
	.utimens	= encfs_utimens,
	.open		= encfs_open,
	.read		= encfs_read,
	.write		= encfs_write,
	.statfs		= encfs_statfs,
	.create         = encfs_create,
	.release	= encfs_release,
	.fsync		= encfs_fsync,
#ifdef HAVE_SETXATTR
	.setxattr	= encfs_setxattr,
	.getxattr	= encfs_getxattr,
	.listxattr	= encfs_listxattr,
	.removexattr	= encfs_removexattr,
#endif
};

int main(int argc, char *argv[])
{
	umask(0);	
	encfs_state state;
	
	if(argc < 4)
	{
		fprintf(stderr, "usage: %s %s\n", argv[0],
		    "<Encrypt Action> <Key Phrase> <Mirrow Directory> <Mount Point>");
		 return 1;
	 }
	 
	state.rootdir = realpath(argv[3], NULL);
	state.passPhrase = argv[1];
	
	return fuse_main(argc - 3, argv + 3, &encfs_oper, &state);
}
