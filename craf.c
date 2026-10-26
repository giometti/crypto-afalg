/*
 * craf.c - single-file encrypted archives over AF_ALG
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

#include <fcntl.h>
#include <getopt.h>
#include <string.h>
#include <sys/stat.h>
#include "craf.h"
#include "craf-keys.h"

int debug_level;

static void usage(FILE *f)
{
	fprintf(f,
		"usage: %s -help | -version | <command> [ <options> ]\n"
		"commands:\n"
		"  seal [ -in <file> ] [ -out <file> ]\n"
		"       -cipher-driver <driver> | -cipher-algo %s\n"
		"       -enc-key <key> | -enc-blob <file>\n"
		"      encrypt the input into an archive\n"
		"  unseal [ -in <file> ] [ -out <file> ]\n"
		"       [ -cipher-driver <driver> | -any-driver ] [ -enc-key <key> ]\n"
		"      decrypt an archive; -enc-key for one sealed with -enc-key\n"
		"where:\n"
		"  <driver> is a kernel driver of %s, e.g. cbc-aes-ce\n"
		"  <key> is a keyring key: a serial number, or\n"
		"        [<keyring>,]<type>,<description> (keyring @u or @s)\n"
		"  <file> of -enc-blob holds the blob of a trusted key in hex,\n"
		"        as keyctl pipe writes it; the archive carries it\n"
		"exit status: 0 done, 1 refused (format, truncation, bad decrypt),\n"
		"  2 wrong usage, 3 could not (driver, key, input, output);\n"
		"  the output is valid only with exit status 0\n",
		NAME, CRAF_CIPHER_ALGO, CRAF_CIPHER_ALGO);
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

/* A driver name goes into the header as it is, and to bind() */
static int check_driver_name(const char *name)
{
	size_t i, len = strlen(name);

	if (len == 0 || len > KC_NAME_MAX)
		return craf_err(CRAF_USAGE,
				"-cipher-driver: the length must be 1 to %d",
				KC_NAME_MAX);
	for (i = 0; i < len; i++)
		if (name[i] < 0x21 || name[i] > 0x7e)
			return craf_err(CRAF_USAGE,
					"-cipher-driver: \"%s\" is not printable ASCII",
					name);
	return CRAF_OK;
}

static int check_options(const char *cmd, const struct craf_driver_opts *drv,
			 const struct craf_key_opts *keys)
{
	if (strcmp(cmd, "unseal") == 0) {
		/* Whether -enc-key is needed, the archive says */
		if (keys->enc_blob)
			return craf_err(CRAF_USAGE,
					"unseal: -enc-blob is for seal only");
		if (drv->cipher_algo)
			return craf_err(CRAF_USAGE,
					"unseal: -cipher-algo is for seal only");
		if (drv->cipher_driver && drv->any_driver)
			return craf_err(CRAF_USAGE, "unseal: give -cipher-driver "
					"or -any-driver, not both");
		if (drv->cipher_driver)
			return check_driver_name(drv->cipher_driver);
		return CRAF_OK;
	}
	if (!keys->enc_key && !keys->enc_blob)
		return craf_err(CRAF_USAGE,
				"seal: -enc-key or -enc-blob is required");
	if (keys->enc_key && keys->enc_blob)
		return craf_err(CRAF_USAGE,
				"seal: give -enc-key or -enc-blob, not both");
	if (drv->any_driver)
		return craf_err(CRAF_USAGE,
				"seal: -any-driver is for unseal only");
	if (!drv->cipher_driver && !drv->cipher_algo)
		return craf_err(CRAF_USAGE,
				"seal: -cipher-driver or -cipher-algo is required");
	if (drv->cipher_driver && drv->cipher_algo)
		return craf_err(CRAF_USAGE, "seal: give -cipher-driver "
				"or -cipher-algo, not both");
	if (drv->cipher_algo &&
	    strcmp(drv->cipher_algo, CRAF_CIPHER_ALGO) != 0)
		return craf_err(CRAF_USAGE,
				"-cipher-algo: unsupported \"%s\", only %s",
				drv->cipher_algo, CRAF_CIPHER_ALGO);
	if (drv->cipher_driver)
		return check_driver_name(drv->cipher_driver);
	return CRAF_OK;
}

/*
 * A closed stderr is given /dev/null, so that no file opened later takes
 * its place and receives the messages; a closed stdin or stdout stays
 * closed, to fail as such
 */
static int open_stderr(void)
{
	int fd;

	if (fcntl(STDERR_FILENO, F_GETFD) >= 0)
		return CRAF_OK;
	fd = open("/dev/null", O_WRONLY);
	if (fd < 0)
		return CRAF_FAILED;
	if (fd != STDERR_FILENO) {
		if (dup2(fd, STDERR_FILENO) < 0) {
			close(fd);
			return CRAF_FAILED;
		}
		close(fd);
	}
	return CRAF_OK;
}

/*
 * The output is opened without truncating it, so that a file that is
 * also the input is refused before it is lost; then it behaves as the
 * shell's ">" would.
 */
static int open_output(const char *path, FILE *in, FILE **out)
{
	struct stat si, so;
	int fd;

	if (path) {
		fd = open(path, O_WRONLY | O_CREAT, 0666);
		if (fd < 0)
			return craf_err(CRAF_FAILED, "cannot open %s: %m",
					path);
	} else
		fd = STDOUT_FILENO;
	if (fstat(fileno(in), &si) < 0 || fstat(fd, &so) < 0) {
		err("cannot check the input and the output: %m");
		goto fail;
	}
	if (S_ISREG(si.st_mode) && S_ISREG(so.st_mode) &&
	    si.st_dev == so.st_dev && si.st_ino == so.st_ino) {
		err("the input and the output are the same file");
		if (path)
			close(fd);
		return CRAF_USAGE;
	}
	if (!path) {
		*out = stdout;
		return CRAF_OK;
	}
	if (S_ISREG(so.st_mode) && ftruncate(fd, 0) < 0) {
		err("cannot truncate %s: %m", path);
		goto fail;
	}
	*out = fdopen(fd, "w");
	if (*out)
		return CRAF_OK;
	err("cannot open %s: %m", path);
fail:
	if (path)
		close(fd);
	return CRAF_FAILED;
}

/*
 * The output is truncated before the key is prepared, so a -out that is
 * also the -enc-blob file would lose the blob before it is read. A file
 * that cannot be looked at here is left to the reading, which reports it.
 */
static int check_blob_output(const char *blob, const char *out)
{
	struct stat sb, so;

	if (!blob || !out || stat(blob, &sb) < 0 || stat(out, &so) < 0)
		return CRAF_OK;
	if (S_ISREG(sb.st_mode) && S_ISREG(so.st_mode) &&
	    sb.st_dev == so.st_dev && sb.st_ino == so.st_ino)
		return craf_err(CRAF_USAGE,
				"the output and the -enc-blob file are the same file");
	return CRAF_OK;
}

int main(int argc, char *argv[])
{
	static struct option options[] = {
		{ "in",			required_argument,	NULL, 'i' },
		{ "out",		required_argument,	NULL, 'o' },
		{ "cipher-driver",	required_argument,	NULL, 'd' },
		{ "cipher-algo",	required_argument,	NULL, 'a' },
		{ "any-driver",		no_argument,		NULL, 'n' },
		{ "enc-key",		required_argument,	NULL, 'e' },
		{ "enc-blob",		required_argument,	NULL, 'b' },
		{ "help",		no_argument,		NULL, 'h' },
		{ 0, 0, 0, 0 }
	};
	struct craf_driver_opts drv = {};
	struct craf_key_opts keys = {};
	const char *cmd, *in_path = NULL, *out_path = NULL;
	FILE *in = stdin, *out = stdout;
	int opt, status;

	if (open_stderr())
		return CRAF_FAILED;
	if (argc < 2) {
		usage(stderr);
		return CRAF_USAGE;
	}
	cmd = argv[1];
	if (strcmp(cmd, "-help") == 0 || strcmp(cmd, "help") == 0) {
		usage(stdout);
		return CRAF_OK;
	}
	if (strcmp(cmd, "-version") == 0 || strcmp(cmd, "version") == 0) {
		version();
		return CRAF_OK;
	}
	if (strcmp(cmd, "seal") != 0 && strcmp(cmd, "unseal") != 0)
		return craf_err(CRAF_USAGE, "unknown command \"%s\", see -help",
				cmd);

	/* The options follow the command, openssl style: -in, -out, ... */
	opterr = 0;
	optind = 0;
	while ((opt = getopt_long_only(argc - 1, argv + 1, "+", options,
				       NULL)) >= 0) {
		switch (opt) {
		case 'i':
			in_path = optarg;
			break;
		case 'o':
			out_path = optarg;
			break;
		case 'd':
			drv.cipher_driver = optarg;
			break;
		case 'a':
			drv.cipher_algo = optarg;
			break;
		case 'n':
			drv.any_driver = true;
			break;
		case 'e':
			keys.enc_key = optarg;
			break;
		case 'b':
			keys.enc_blob = optarg;
			break;
		case 'h':
			usage(stdout);
			return CRAF_OK;
		default:
			return craf_err(CRAF_USAGE,
					"unknown option or missing value \"%s\", see -help",
					argv[optind]);
		}
	}
	if (optind < argc - 1)
		return craf_err(CRAF_USAGE, "unexpected argument \"%s\"",
				argv[optind + 1]);
	status = check_options(cmd, &drv, &keys);
	if (status)
		return status;

	if (in_path) {
		in = fopen(in_path, "r");
		if (!in)
			return craf_err(CRAF_FAILED, "cannot open %s: %m",
					in_path);
	}
	status = check_blob_output(keys.enc_blob, out_path);
	if (status)
		return status;
	status = open_output(out_path, in, &out);
	if (status)
		return status;

	if (strcmp(cmd, "seal") == 0)
		status = craf_seal(in, out, &drv, &keys);
	else
		status = craf_unseal(in, out, &drv, &keys);

	if ((fflush(out) != 0 || ferror(out)) && status == CRAF_OK)
		status = craf_err(CRAF_FAILED, "cannot write output: %m");
	if (out_path && fclose(out) != 0 && status == CRAF_OK)
		status = craf_err(CRAF_FAILED, "cannot write %s: %m", out_path);
	return status;
}
