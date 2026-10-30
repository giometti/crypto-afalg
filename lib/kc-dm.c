/*
 * kc-dm.c - dm-crypt devices through the ioctls of device-mapper
 *	     (libkcrypto)
 *
 * Copyright (C) 2026 Rodolfo Giometti <giometti@enneenne.com>
 *
 *   This program is free software: you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation, either version 3 of the License, or
 *   any later version.
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <linux/dm-ioctl.h>
#include <linux/fs.h>
#include <keyutils.h>
#include "kc-internal.h"
#include "kc-backend.h"

#define DM_NODE_DIR		"/dev/" DM_DIR
#define DM_CONTROL_PATH		DM_NODE_DIR "/" DM_CONTROL_NODE
#define DM_ALIGN(n)		(((n) + 7) & ~(size_t) 7)
#define DM_HEADER_SIZE		DM_ALIGN(sizeof(struct dm_ioctl))
#define SECTOR_SHIFT		9
#define DM_REMOVE_TRIES		20
#define DM_REMOVE_WAIT_US	100000

/*
 * The key types dm-crypt looks a key up by (Linux 6.18,
 * crypt_set_keyring_key())
 */
static const char *const key_types[] = {
	"logon", "user", "encrypted", "trusted",
};

/*
 * White space as the kernel counts it, whatever the locale of the caller:
 * the isspace() of its lib/ctype.c takes 0xa0 too
 */
static bool is_kernel_space(char c)
{
	return c == ' ' || (c >= '\t' && c <= '\r') ||
	       (unsigned char) c == 0xa0;
}

/*
 * A word of the table as dm_split_args() reads it: it splits the table at
 * white space, and a backslash quotes the character after it
 */
static bool is_word(const char *s)
{
	if (!s || !*s)
		return false;
	for (; *s; s++)
		if (is_kernel_space(*s) || *s == '\\')
			return false;
	return true;
}

/*
 * What device-mapper takes as a name, and /dev/mapper can hold as the
 * name of a node: dm_ioctl.c refuses '/', ".", ".." and "control" itself
 */
static int check_name(const char *name, struct kc_error *e)
{
	const char *p;

	if (!name || !*name || strlen(name) >= DM_NAME_LEN)
		return kc_fail(e, KC_USAGE, EINVAL, "the name of a device is "
			       "1 to %d characters long", DM_NAME_LEN - 1);
	for (p = name; *p; p++)
		if (is_kernel_space(*p) || (unsigned char) *p < 0x20 ||
		    *p == 0x7f)
			return kc_fail(e, KC_USAGE, EINVAL, "the name of a "
				       "device has no white space nor control "
				       "characters");
	if (strchr(name, '/') || strcmp(name, ".") == 0 ||
	    strcmp(name, "..") == 0 || strcmp(name, DM_CONTROL_NODE) == 0)
		return kc_fail(e, KC_USAGE, EINVAL, "\"%s\" cannot name a "
			       "device of %s", name, DM_NODE_DIR);
	return KC_OK;
}

/* A buffer for one ioctl, len bytes of data after the header, zeroed */
static struct dm_ioctl *dm_buffer(const char *name, size_t len,
				  struct kc_error *e)
{
	struct dm_ioctl *io;

	io = calloc(1, DM_HEADER_SIZE + len);
	if (!io) {
		kc_fail(e, KC_FAILED, ENOMEM, "%s", strerror(ENOMEM));
		return NULL;
	}
	io->version[0] = DM_VERSION_MAJOR;
	io->data_size = DM_HEADER_SIZE + len;
	io->data_start = DM_HEADER_SIZE;
	snprintf(io->name, sizeof(io->name), "%s", name);
	return io;
}

/* An ioctl with no data, by name; the header comes back in *io */
static int dm_simple(int fd, unsigned long cmd, const char *name,
		     struct dm_ioctl *io)
{
	memset(io, 0, sizeof(*io));
	io->version[0] = DM_VERSION_MAJOR;
	io->data_size = sizeof(*io);
	io->data_start = sizeof(*io);
	snprintf(io->name, sizeof(io->name), "%s", name);
	return ioctl(fd, cmd, io) < 0 ? errno : 0;
}

static int open_control(int *fd, struct kc_error *e)
{
	int err;

	*fd = open(DM_CONTROL_PATH, O_RDWR | O_CLOEXEC);
	if (*fd < 0) {
		err = errno;
		return kc_fail(e, KC_FAILED, err, "cannot open %s: %s%s",
			       DM_CONTROL_PATH, strerror(err), err == ENOENT ?
			       " (device-mapper not in the kernel or not "
			       "loaded, or devtmpfs not mounted on /dev?)" :
			       "");
	}
	return KC_OK;
}

/*
 * The type and the description the kernel gives the key, from its
 * "<type>;<uid>;<gid>;<perm>;<description>"; *buf is the caller's to free
 */
static int describe(const struct kc_key *k, char **buf, const char **type,
		    const char **desc, struct kc_error *e)
{
	char *p;
	int i, err;

	if (keyctl_describe_alloc(k->serial, buf) < 0) {
		err = errno;
		return kc_fail(e, KC_FAILED, err, "cannot describe the key "
			       "%d: %s", k->serial, strerror(err));
	}
	*type = p = *buf;
	for (i = 0; i < 4; i++) {
		p = strchr(p, ';');
		if (!p) {
			free(*buf);
			return kc_fail(e, KC_FAILED, EINVAL, "the kernel "
				       "describes the key %d oddly",
				       k->serial);
		}
		*p++ = '\0';
	}
	*desc = p;
	return KC_OK;
}

/*
 * The key goes into the table by its type and description, which
 * dm-crypt looks up with request_key() for the process that loads the
 * table: the same search, from user space, says whether it reaches this
 * key, and only this one.
 */
static int key_string(const struct kc_key *k, unsigned int key_size,
		      char **out, struct kc_error *e)
{
	const char *type = NULL, *desc = NULL;
	key_serial_t found;
	char *buf;
	size_t i;
	int err, status;

	if (!k || k->type != KC_KEY_SERIAL)
		return kc_fail(e, KC_USAGE, EINVAL, "not a keyring key");
	status = describe(k, &buf, &type, &desc, e);
	if (status)
		return status;
	for (i = 0; i < sizeof(key_types) / sizeof(key_types[0]); i++)
		if (strcmp(type, key_types[i]) == 0)
			break;
	if (i == sizeof(key_types) / sizeof(key_types[0])) {
		status = kc_fail(e, KC_FAILED, EINVAL, "the key %d is of type "
				 "%s: dm-crypt takes logon, user, encrypted "
				 "and trusted keys", k->serial, type);
		goto out;
	}
	if (!is_word(desc)) {
		status = kc_fail(e, KC_FAILED, EINVAL, "the key %d has white "
				 "space or a backslash in its description, "
				 "which dm-crypt does not take", k->serial);
		goto out;
	}
	found = request_key(type, desc, NULL, 0);
	if (found < 0) {
		err = errno;
		status = kc_fail(e, KC_FAILED, err, "the %s key %s cannot be "
				 "reached from the keyrings of this process: "
				 "%s", type, desc, strerror(err));
		goto out;
	}
	if (found != k->serial) {
		status = kc_fail(e, KC_FAILED, ENOTUNIQ, "the %s key %s that "
				 "dm-crypt would take is %d, not %d", type,
				 desc, found, k->serial);
		goto out;
	}
	if (asprintf(out, ":%u:%s:%s", key_size, type, desc) < 0) {
		status = kc_fail(e, KC_FAILED, ENOMEM, "%s", strerror(ENOMEM));
		goto out;
	}
	status = KC_OK;
out:
	free(buf);
	return status;
}

/*
 * The device, by its number, and its length in sectors of 512 bytes.
 * O_EXCL opens a block device for this process alone, so one mounted, or
 * mapped already, is refused; O_NONBLOCK does not wait on a FIFO, and
 * O_NOCTTY takes no terminal, before the type is known.
 */
static int block_device(const char *path, dev_t *dev, uint64_t *sectors,
			struct kc_error *e)
{
	struct stat st;
	uint64_t bytes;
	int fd, err;

	fd = open(path, O_RDONLY | O_EXCL | O_NONBLOCK | O_NOCTTY | O_CLOEXEC);
	if (fd < 0) {
		err = errno;
		return kc_fail(e, KC_FAILED, err, "cannot open %s: %s%s", path,
			       strerror(err), err == EBUSY ?
			       " (mounted, or mapped already?)" : "");
	}
	if (fstat(fd, &st) < 0)
		err = errno;
	else if (!S_ISBLK(st.st_mode))
		err = ENOTBLK;
	else if (ioctl(fd, BLKGETSIZE64, &bytes) < 0)
		err = errno;
	else
		err = 0;
	close(fd);
	if (err)
		return kc_fail(e, KC_FAILED, err, "%s: %s", path,
			       strerror(err));
	if (bytes >> SECTOR_SHIFT == 0)
		return kc_fail(e, KC_FAILED, EINVAL, "%s has no sector of %d "
			       "bytes", path, 1 << SECTOR_SHIFT);
	*dev = st.st_rdev;
	*sectors = bytes >> SECTOR_SHIFT;
	return KC_OK;
}

/*
 * The parameters of the crypt target. The device goes by its number, so
 * that a path with white space cannot split the table, and dm opens the
 * device that was measured.
 */
static int crypt_params(const char *cipher, const char *key, dev_t dev,
			const char *const *opts, char **out,
			struct kc_error *e)
{
	size_t len, n = 0, i;
	char *p;

	len = strlen(cipher) + strlen(key) + 64;
	for (; opts && opts[n]; n++)
		len += strlen(opts[n]) + 1;
	*out = p = malloc(len);
	if (!p)
		return kc_fail(e, KC_FAILED, ENOMEM, "%s", strerror(ENOMEM));
	p += sprintf(p, "%s %s 0 %u:%u 0", cipher, key, major(dev),
		     minor(dev));
	if (n) {
		p += sprintf(p, " %zu", n);
		for (i = 0; i < n; i++)
			p += sprintf(p, " %s", opts[i]);
	}
	return KC_OK;
}

static int load_table(int fd, const char *name, const char *cipher,
		      uint64_t sectors, const char *params, struct kc_error *e)
{
	struct dm_target_spec *spec;
	struct dm_ioctl *io;
	size_t len;
	int err;

	len = DM_ALIGN(sizeof(*spec) + strlen(params) + 1);
	io = dm_buffer(name, len, e);
	if (!io)
		return KC_FAILED;
	io->target_count = 1;
	spec = (struct dm_target_spec *) ((char *) io + io->data_start);
	spec->sector_start = 0;
	spec->length = sectors;
	spec->next = len;
	snprintf(spec->target_type, sizeof(spec->target_type), "crypt");
	strcpy((char *) (spec + 1), params);
	err = ioctl(fd, DM_TABLE_LOAD, io) < 0 ? errno : 0;
	free(io);
	/* ENOENT: the crypto API has no such cipher, or no driver of it yet */
	if (err == ENOENT)
		return kc_fail(e, KC_FAILED, err, "the kernel does not take "
			       "the table of %s: %s (no cipher %s in the "
			       "kernel, or its driver not registered yet?)",
			       name, strerror(err), cipher);
	if (err)
		return kc_fail(e, KC_FAILED, err, "the kernel does not take "
			       "the table of %s: %s (its log may say why)",
			       name, strerror(err));
	return KC_OK;
}

/*
 * /dev/mapper/<name>, which udev would make: the node of dev, or a link
 * to it, is taken as it is, what is left of a device of before replaced,
 * and anything else refused. udev may make it meanwhile, hence the
 * second try.
 */
static int make_node(const char *name, dev_t dev, struct kc_error *e)
{
	char path[sizeof(DM_NODE_DIR) + DM_NAME_LEN];
	struct stat st;
	int tries, err;

	snprintf(path, sizeof(path), "%s/%s", DM_NODE_DIR, name);
	if (mkdir(DM_NODE_DIR, 0755) < 0 && errno != EEXIST) {
		err = errno;
		goto fail;
	}
	for (tries = 0; tries < 2; tries++) {
		if (stat(path, &st) == 0 && S_ISBLK(st.st_mode) &&
		    st.st_rdev == dev)
			return KC_OK;
		if (lstat(path, &st) == 0) {
			if (!S_ISBLK(st.st_mode) && !S_ISCHR(st.st_mode) &&
			    !S_ISLNK(st.st_mode))
				return kc_fail(e, KC_FAILED, EEXIST, "%s is "
					       "there and is not a device "
					       "node", path);
			if (unlink(path) < 0 && errno != ENOENT) {
				err = errno;
				goto fail;
			}
		} else if (errno != ENOENT) {
			err = errno;
			goto fail;
		}
		if (mknod(path, S_IFBLK | 0600, dev) == 0)
			return KC_OK;
		err = errno;
		if (err != EEXIST)
			goto fail;
	}
fail:
	return kc_fail(e, KC_FAILED, err, "cannot make %s: %s", path,
		       strerror(err));
}

/*
 * Whether /dev/mapper/<name> is the node of dev, or a link to it, as
 * kc_dm_open() leaves it: asked while the device is there, since a link
 * to its /dev/dm-<n> leads nowhere once it is removed
 */
static bool is_node_of(const char *name, dev_t dev)
{
	char path[sizeof(DM_NODE_DIR) + DM_NAME_LEN];
	struct stat st;

	snprintf(path, sizeof(path), "%s/%s", DM_NODE_DIR, name);
	return stat(path, &st) == 0 && S_ISBLK(st.st_mode) &&
	       st.st_rdev == dev;
}

static int remove_node(const char *name, struct kc_error *e)
{
	char path[sizeof(DM_NODE_DIR) + DM_NAME_LEN];
	int err;

	snprintf(path, sizeof(path), "%s/%s", DM_NODE_DIR, name);
	if (unlink(path) < 0 && errno != ENOENT) {
		err = errno;
		return kc_fail(e, KC_FAILED, err, "%s is removed, but not %s: "
			       "%s", name, path, strerror(err));
	}
	return KC_OK;
}

/* A device just closed may be held a moment longer, as by udev's probe */
static int dm_remove(int fd, const char *name, struct dm_ioctl *io)
{
	int tries, err;

	for (tries = 1;; tries++) {
		err = dm_simple(fd, DM_DEV_REMOVE, name, io);
		if (err != EBUSY || tries == DM_REMOVE_TRIES)
			return err;
		usleep(DM_REMOVE_WAIT_US);
	}
}

KC_EXPORT int kc_dm_check(const char *name, const char *cipher,
			  unsigned int key_size, const char *const *opts,
			  unsigned int flags, struct kc_error *e)
{
	size_t i;
	int status;

	if (flags)
		return kc_fail(e, KC_USAGE, EINVAL, "no flag is defined yet");
	status = check_name(name, e);
	if (status)
		return status;
	if (!is_word(cipher))
		return kc_fail(e, KC_USAGE, EINVAL, "the cipher is one word, "
			       "with no white space nor backslash");
	/* dm-crypt reads the size into an int */
	if (!key_size || key_size > INT_MAX)
		return kc_fail(e, KC_USAGE, EINVAL, "the key size is 1 to %d "
			       "bytes", INT_MAX);
	for (i = 0; opts && opts[i]; i++)
		if (!is_word(opts[i]))
			return kc_fail(e, KC_USAGE, EINVAL, "a parameter of "
				       "dm-crypt is one word, with no white "
				       "space nor backslash");
	return kc_ok(e);
}

KC_EXPORT int kc_dm_open(const char *name, const char *device,
			 const char *cipher, const struct kc_key *k,
			 unsigned int key_size, const char *const *opts,
			 unsigned int flags, struct kc_error *e)
{
	char *key = NULL, *params = NULL;
	struct dm_ioctl io;
	uint64_t sectors = 0;
	dev_t dev = 0, mapped;
	int fd = -1, err, status;

	status = kc_dm_check(name, cipher, key_size, opts, flags, e);
	if (status)
		return status;
	if (!device)
		return kc_fail(e, KC_USAGE, EINVAL, "no device");

	status = key_string(k, key_size, &key, e);
	if (status)
		return status;
	status = block_device(device, &dev, &sectors, e);
	if (status)
		goto out;
	status = crypt_params(cipher, key, dev, opts, &params, e);
	if (status)
		goto out;
	status = open_control(&fd, e);
	if (status)
		goto out;

	err = dm_simple(fd, DM_DEV_CREATE, name, &io);
	if (err) {
		status = kc_fail(e, KC_FAILED, err, "cannot create %s: %s%s",
				 name, strerror(err), err == EBUSY ?
				 " (the name is in use; closing it frees one "
				 "left over)" : "");
		goto out;
	}
	mapped = makedev(major(io.dev), minor(io.dev));
	status = load_table(fd, name, cipher, sectors, params, e);
	if (!status) {
		err = dm_simple(fd, DM_DEV_SUSPEND, name, &io);
		if (err)
			status = kc_fail(e, KC_FAILED, err, "cannot resume "
					 "%s: %s", name, strerror(err));
	}
	if (!status)
		status = make_node(name, mapped, e);
	if (status) {
		/* Nothing half made: the next try finds the name free */
		err = dm_remove(fd, name, &io);
		if (err && err != ENXIO && e)
			snprintf(e->msg + strlen(e->msg),
				 sizeof(e->msg) - strlen(e->msg),
				 "; and %s stays: %s", name, strerror(err));
	}
out:
	if (fd >= 0)
		close(fd);
	free(params);
	free(key);
	return status ? status : kc_ok(e);
}

KC_EXPORT int kc_dm_close(const char *name, struct kc_error *e)
{
	struct dm_ioctl io;
	bool node;
	dev_t dev;
	int fd, err, status;

	status = check_name(name, e);
	if (status)
		return status;
	status = open_control(&fd, e);
	if (status)
		return status;
	err = dm_simple(fd, DM_DEV_STATUS, name, &io);
	if (err) {
		close(fd);
		return kc_fail(e, KC_FAILED, err, "%s: %s", name, err == ENXIO ?
			       "no such device" : strerror(err));
	}
	dev = makedev(major(io.dev), minor(io.dev));
	node = is_node_of(name, dev);
	err = dm_remove(fd, name, &io);
	close(fd);
	if (err)
		return kc_fail(e, KC_FAILED, err, "cannot remove %s: %s%s",
			       name, strerror(err), err == EBUSY ?
			       " (it is in use, mounted or open)" : "");
	status = node ? remove_node(name, e) : KC_OK;
	return status ? status : kc_ok(e);
}
