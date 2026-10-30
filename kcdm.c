/*
 * kcdm.c - open and close a dm-crypt device with a keyring key
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
#include <getopt.h>
#include <limits.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "kcrypto.h"
#include "misc.h"

/* Exit statuses */
#define KCDM_OK			0
#define KCDM_USAGE		2
#define KCDM_FAILED		3	/* key, device, kernel */

/* Report an error, giving the exit status it ends with */
#define kcdm_err(status, fmt, args...)					\
	({								\
		err(fmt, ## args);					\
		(status);						\
	})

int debug_level;

static void usage(FILE *f)
{
	fprintf(f,
		"usage: %s -help | -version | <command> [ <arguments> ]\n"
		"commands:\n"
		"  open <device> <name> -cipher <cipher> -key <key>\n"
		"       -key-size <bytes> [ -opt <parameter> ]...\n"
		"      map the block device to /dev/mapper/<name> through\n"
		"      dm-crypt, with the key of the keyring\n"
		"  close <name>\n"
		"      remove the device <name> and /dev/mapper/<name>\n"
		"where:\n"
		"  <cipher> is a cipher of dm-crypt, e.g. capi:cbc(aes)-plain\n"
		"  <key> is a keyring key of type logon, user, encrypted or\n"
		"        trusted: a serial number, or\n"
		"        [<keyring>,]<type>,<description> (keyring @u or @s,\n"
		"        @u when not given)\n"
		"  <bytes> is the length of the key, 1 to %d\n"
		"  <parameter> is an optional parameter of dm-crypt, one\n"
		"        word, e.g. sector_size:512; one -opt for each\n"
		"exit status: 0 done, 2 wrong usage, 3 could not (key,\n"
		"  device, name, kernel)\n",
		NAME, INT_MAX);
}

static void version(void)
{
	printf("%s %s\n", NAME, __CRYPTO_AFALG_VERSION__);
	printf("Copyright (C) 2026 Rodolfo Giometti <giometti@enneenne.com>\n");
	printf("This is free software, and you are welcome to redistribute it under\n"
		"terms of the GNU General Public License as published by the Free Software\n"
		"Foundation, either version 3 of the License, or any later version.\n");
	printf("*** This program comes with ABSOLUTELY NO WARRANTY. ***\n");
}

/* As craf: no file opened later takes the place of a closed stderr */
static int open_stderr(void)
{
	int fd;

	if (fcntl(STDERR_FILENO, F_GETFD) >= 0)
		return KCDM_OK;
	fd = open("/dev/null", O_WRONLY);
	if (fd < 0)
		return KCDM_FAILED;
	if (fd != STDERR_FILENO) {
		if (dup2(fd, STDERR_FILENO) < 0) {
			close(fd);
			return KCDM_FAILED;
		}
		close(fd);
	}
	return KCDM_OK;
}

static int exit_status(int status)
{
	return status == KC_USAGE ? KCDM_USAGE : KCDM_FAILED;
}

/* Decimal digits only: no sign, no space, no base other than ten */
static int parse_key_size(const char *arg, unsigned int *size)
{
	unsigned long n;
	char *end;

	if (*arg < '0' || *arg > '9')
		goto fail;
	errno = 0;
	n = strtoul(arg, &end, 10);
	if (*end || errno || n < 1 || n > INT_MAX)
		goto fail;
	*size = n;
	return KCDM_OK;
fail:
	return kcdm_err(KCDM_USAGE, "-key-size: \"%s\" is not a number of "
			"bytes from 1 to %d", arg, INT_MAX);
}

static bool is_help(const char *arg)
{
	return strcmp(arg, "-help") == 0 || strcmp(arg, "--help") == 0;
}

static int kcdm_open(int argc, char *argv[])
{
	static const struct option options[] = {
		{ "cipher",		required_argument,	NULL, 'c' },
		{ "key",		required_argument,	NULL, 'k' },
		{ "key-size",		required_argument,	NULL, 's' },
		{ "opt",		required_argument,	NULL, 'o' },
		{ "help",		no_argument,		NULL, 'h' },
		{ 0, 0, 0, 0 }
	};
	const char *device, *name, *cipher = NULL, *spec = NULL;
	const char *size_arg = NULL, *twice;
	const char **opts;
	unsigned int key_size;
	struct kc_key *k;
	struct kc_error e;
	int opt, n = 0, status;

	if (argc > 1 && is_help(argv[1])) {
		usage(stdout);
		return KCDM_OK;
	}
	if (argc < 3 || argv[1][0] == '-' || argv[2][0] == '-')
		return kcdm_err(KCDM_USAGE, "open: <device> and <name> come "
				"first, then the options; see -help");
	device = argv[1];
	name = argv[2];

	/* At most one parameter for each word left, and a NULL */
	opts = calloc(argc, sizeof(*opts));
	if (!opts)
		return kcdm_err(KCDM_FAILED, "open: %m");

	/* The options follow the name, openssl style: -cipher, -key, ... */
	opterr = 0;
	optind = 0;
	while ((opt = getopt_long_only(argc - 2, argv + 2, "+", options,
				       NULL)) >= 0) {
		switch (opt) {
		case 'c':
			if (cipher) {
				twice = "cipher";
				goto dup;
			}
			cipher = optarg;
			break;
		case 'k':
			if (spec) {
				twice = "key";
				goto dup;
			}
			spec = optarg;
			break;
		case 's':
			if (size_arg) {
				twice = "key-size";
				goto dup;
			}
			size_arg = optarg;
			break;
		case 'o':
			opts[n++] = optarg;
			break;
		case 'h':
			free(opts);
			usage(stdout);
			return KCDM_OK;
		default:
			status = kcdm_err(KCDM_USAGE, "open: unknown option or "
					  "missing value \"%s\", see -help",
					  argv[2 + optind - 1]);
			goto out;
		}
	}
	if (optind < argc - 2) {
		status = kcdm_err(KCDM_USAGE, "open: unexpected argument "
				  "\"%s\"", argv[2 + optind]);
		goto out;
	}
	if (!cipher || !spec || !size_arg) {
		status = kcdm_err(KCDM_USAGE, "open: -%s is required",
				  !cipher ? "cipher" : !spec ? "key" :
				  "key-size");
		goto out;
	}
	status = parse_key_size(size_arg, &key_size);
	if (status)
		goto out;

	/* What is wrong in the command line comes before the key */
	if (kc_dm_check(name, cipher, key_size, opts, 0, &e)) {
		status = kcdm_err(exit_status(e.status), "open: %s", e.msg);
		goto out;
	}
	if (kc_key_spec(&k, spec, &e)) {
		status = kcdm_err(exit_status(e.status), "-key: %s", e.msg);
		goto out;
	}
	if (kc_dm_open(name, device, cipher, k, key_size, opts, 0, &e))
		status = kcdm_err(exit_status(e.status), "open: %s", e.msg);
	else
		status = KCDM_OK;
	kc_key_free(k);
out:
	free(opts);
	return status;
dup:
	free(opts);
	return kcdm_err(KCDM_USAGE, "open: -%s given twice", twice);
}

static int kcdm_close(int argc, char *argv[])
{
	struct kc_error e;

	if (argc > 1 && is_help(argv[1])) {
		usage(stdout);
		return KCDM_OK;
	}
	if (argc != 2)
		return kcdm_err(KCDM_USAGE, "close: give the name only, see "
				"-help");
	if (kc_dm_close(argv[1], &e))
		return kcdm_err(exit_status(e.status), "close: %s", e.msg);
	return KCDM_OK;
}

int main(int argc, char *argv[])
{
	const char *cmd;

	if (open_stderr())
		return KCDM_FAILED;
	if (argc < 2) {
		usage(stderr);
		return KCDM_USAGE;
	}
	cmd = argv[1];
	if (strcmp(cmd, "-help") == 0 || strcmp(cmd, "help") == 0) {
		usage(stdout);
		return KCDM_OK;
	}
	if (strcmp(cmd, "-version") == 0 || strcmp(cmd, "version") == 0) {
		version();
		return KCDM_OK;
	}
	if (strcmp(cmd, "open") == 0)
		return kcdm_open(argc - 1, argv + 1);
	if (strcmp(cmd, "close") == 0)
		return kcdm_close(argc - 1, argv + 1);
	return kcdm_err(KCDM_USAGE, "unknown command \"%s\", see -help", cmd);
}
