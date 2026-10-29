/*
 * craf-dgst.c - the digest of openssl dgst, in the kernel (craf)
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

#include <ctype.h>
#include <errno.h>
#include <getopt.h>
#include <string.h>
#include <strings.h>
#include "craf.h"

#define HASH_DEFAULT		"sha256"

/* What openssl prints for its default hash, which it names otherwise */
#define LABEL_DEFAULT		"SHA256"

/* A hash of openssl whose kernel name the general rule does not give */
struct exception {
	const char *openssl;
	const char *kernel;
	const char *label;		/* what openssl prints for it */
};

/* What openssl prints for a hash it names its own way */
struct label {
	const char *kernel;
	const char *label;
};

/* None yet */
static const struct exception exceptions[] = {
	{ NULL, NULL, NULL },
};

static const struct label labels[] = {
	{ "md5",	"MD5" },
	{ "sha1",	"SHA1" },
	{ "sha224",	"SHA2-224" },
	{ "sha256",	"SHA2-256" },
	{ "sha384",	"SHA2-384" },
	{ "sha512",	"SHA2-512" },
	{ "sha3-224",	"SHA3-224" },
	{ "sha3-256",	"SHA3-256" },
	{ "sha3-384",	"SHA3-384" },
	{ "sha3-512",	"SHA3-512" },
	{ "sm3",	"SM3" },
};

/*
 * Whether word, which getopt did not take, is a mistyped option: the
 * beginning of one, an ambiguous abbreviation among them, or one with
 * more after it, where a one-letter option does not count, so that
 * crc32c and rmd160 stay names of hashes
 */
static bool option_word(const struct option *options, const char *word)
{
	size_t len = strlen(word), n;

	for (; options->name; options++) {
		n = strlen(options->name);
		if (len < n && strncmp(options->name, word, len) == 0)
			return true;
		if (n > 1 && strncmp(word, options->name, n) == 0)
			return true;
	}
	return false;
}

/*
 * The kernel name of an openssl hash: the table first, then the name as
 * it is. 0 when word is no name of a hash, which makes it an unknown
 * option.
 */
static int translate(const struct option *options, const char *word,
		     struct craf_dgst_opts *o)
{
	size_t i;

	if (!*word || option_word(options, word))
		return 0;
	for (i = 0; word[i]; i++)
		if (!islower((unsigned char) word[i]) &&
		    !isdigit((unsigned char) word[i]) && word[i] != '-')
			return 0;
	for (i = 0; exceptions[i].openssl; i++)
		if (strcmp(word, exceptions[i].openssl) == 0) {
			snprintf(o->kname, sizeof(o->kname), "%s",
				 exceptions[i].kernel);
			o->label = exceptions[i].label;
			warn("-%s taken as %s", word, o->kname);
			return 1;
		}
	snprintf(o->kname, sizeof(o->kname), "%s", word);
	return 1;
}

int craf_dgst_parse(int argc, char *argv[], struct craf_dgst_opts *o)
{
	static const struct option options[] = {
		{ "digest-algo",	required_argument,	NULL, 'a' },
		{ "hex",		no_argument,		NULL, 'x' },
		{ "binary",		no_argument,		NULL, 'b' },
		{ "keyform",		required_argument,	NULL, 'K' },
		{ "help",		no_argument,		NULL, 'h' },
		/* What openssl dgst takes and craf dgst does not */
		{ "sign",		required_argument,	NULL, 'U' },
		{ "prverify",		required_argument,	NULL, 'U' },
		{ "sigopt",		required_argument,	NULL, 'U' },
		{ "out",		required_argument,	NULL, 'U' },
		{ "r",			no_argument,		NULL, 'U' },
		{ "c",			no_argument,		NULL, 'U' },
		{ "verify",		required_argument,	NULL, 'U' },
		{ "signature",		required_argument,	NULL, 'U' },
		{ "list",		no_argument,		NULL, 'U' },
		{ "engine",		required_argument,	NULL, 'U' },
		{ "engine_impl",	no_argument,		NULL, 'U' },
		{ "passin",		required_argument,	NULL, 'U' },
		{ "xoflen",		required_argument,	NULL, 'U' },
		{ "d",			no_argument,		NULL, 'U' },
		{ "debug",		no_argument,		NULL, 'U' },
		{ "hmac",		required_argument,	NULL, 'U' },
		{ "mac",		required_argument,	NULL, 'U' },
		{ "macopt",		required_argument,	NULL, 'U' },
		{ "fips-fingerprint",	no_argument,		NULL, 'U' },
		{ "rand",		required_argument,	NULL, 'U' },
		{ "writerand",		required_argument,	NULL, 'U' },
		{ "provider-path",	required_argument,	NULL, 'U' },
		{ "provider",		required_argument,	NULL, 'U' },
		{ "propquery",		required_argument,	NULL, 'U' },
		{ 0, 0, 0, 0 }
	};
	const char *word, *p;
	int opt, idx, prev;

	memset(o, 0, sizeof(*o));
	opterr = 0;
	optind = 0;
	for (;;) {
		prev = optind ? optind : 1;
		idx = -1;
		opt = getopt_long_only(argc, argv, "+:", options, &idx);
		if (opt < 0)
			break;
		/* getopt takes an abbreviation, openssl does not */
		if (idx >= 0 && !craf_typed_exactly(argv[prev],
						    options[idx].name))
			return craf_err(CRAF_USAGE,
					"unknown option or missing value \"%s\", see -help",
					argv[prev]);
		switch (opt) {
		case 'a':
			o->digest_algo = optarg;
			break;
		case 'x':
			o->binary = false;
			break;
		case 'b':
			o->binary = true;
			break;
		case 'K':
			/* As openssl, which takes them in any case */
			if (strcasecmp(optarg, "PEM") != 0 &&
			    strcasecmp(optarg, "DER") != 0)
				return craf_err(CRAF_USAGE, "-keyform: \"%s\" is "
						"not PEM or DER", optarg);
			o->keyform = optarg;
			break;
		case 'h':
			o->help = true;
			return CRAF_OK;
		case 'U':
			return craf_err(CRAF_USAGE,
					"dgst: -%s is not implemented by craf",
					options[idx].name);
		case ':':
			if (craf_exact_option(options, argv[prev]))
				return craf_err(CRAF_USAGE,
						"missing value for \"%s\"",
						argv[prev]);
			/* An abbreviation with no value: unknown, as above */
			/* fallthrough */
		default:
			/* As openssl: a word it does not know may be a hash */
			word = argv[prev] + (argv[prev][1] == '-' ? 2 : 1);
			if (argv[prev][0] != '-' || !translate(options, word, o))
				return craf_err(CRAF_USAGE,
						"unknown option or missing value \"%s\", see -help",
						argv[prev]);
			o->hash = word;
			break;
		}
	}
	o->files = argv + optind;
	o->nfiles = argc - optind;

	if (o->hash && o->digest_algo)
		return craf_err(CRAF_USAGE, "dgst: give -%s or -digest-algo, "
				"not both", o->hash);
	if (o->keyform)
		warn("-keyform has no effect without -verify");
	if (o->digest_algo) {
		if (!*o->digest_algo || strlen(o->digest_algo) > KC_NAME_MAX)
			return craf_err(CRAF_USAGE,
					"-digest-algo: the length must be 1 to %d",
					KC_NAME_MAX);
		/* A word, which the parameters of a signature can take */
		for (p = o->digest_algo; *p; p++)
			if (!isgraph((unsigned char) *p) || *p == '=')
				return craf_err(CRAF_USAGE, "-digest-algo: \"%s\" "
						"is not the name of a hash",
						o->digest_algo);
		snprintf(o->kname, sizeof(o->kname), "%s", o->digest_algo);
	} else if (!o->hash)
		snprintf(o->kname, sizeof(o->kname), "%s", HASH_DEFAULT);
	else if (strlen(o->hash) > KC_NAME_MAX)
		return craf_err(CRAF_USAGE, "dgst: -%s gives a kernel name "
				"longer than %d characters", o->hash,
				KC_NAME_MAX);
	return CRAF_OK;
}

/* The label of the digest, as openssl prints it */
static const char *label_of(const struct craf_dgst_opts *o)
{
	size_t i;

	if (o->digest_algo)
		return o->kname;
	if (!o->hash)
		return LABEL_DEFAULT;
	if (o->label)
		return o->label;
	for (i = 0; i < ARRAY_SIZE(labels); i++)
		if (strcmp(o->kname, labels[i].kernel) == 0)
			return labels[i].label;
	return o->kname;
}

static int open_hash(const char *kname, struct kc_hash **h)
{
	struct kc_error e;
	int status;

	status = kc_hash_open(h, kname, NULL, &e);
	if (status == KC_REFUSED)
		return craf_err(CRAF_FAILED, "dgst: %s not available: %s",
				kname, strerror(e.errnum));
	if (status)
		return craf_err(CRAF_FAILED, "dgst: cannot open %s: %s",
				kname, e.msg);
	return CRAF_OK;
}

/* The digest of in, which what names; the hash is ended and freed */
static int hash_stream(struct kc_hash *h, FILE *in, const char *what,
		       uint8_t *md, size_t *md_len)
{
	uint8_t buf[CRAF_BUF_SIZE];
	struct kc_error e;
	size_t n;
	int status = CRAF_OK;

	do {
		n = fread(buf, 1, sizeof(buf), in);
		if (n < sizeof(buf) && ferror(in)) {
			status = craf_err(CRAF_FAILED,
					  "dgst: cannot read %s: %m", what);
			goto out;
		}
		if (n > 0 && kc_hash_update(h, buf, n, &e)) {
			status = craf_err(CRAF_FAILED, "dgst: %s", e.msg);
			goto out;
		}
	} while (n > 0);
	*md_len = KC_HASH_MAX;
	if (kc_hash_final(h, md, md_len, &e))
		status = craf_err(CRAF_FAILED, "dgst: %s", e.msg);
out:
	kc_hash_free(h);
	return status;
}

/*
 * One line per file, or the bytes with -binary, as openssl; a file that
 * cannot be read is told and the others go on, the exit status says so,
 * but a hash the kernel cannot open stops them all
 */
static int digest(const struct craf_dgst_opts *o, const char *path,
		  bool *stop)
{
	uint8_t md[KC_HASH_MAX];
	const char *what = path ? path : "stdin";
	struct kc_hash *h;
	size_t md_len, i;
	FILE *in = stdin;
	int status;

	status = open_hash(o->kname, &h);
	if (status) {
		*stop = true;
		return status;
	}
	if (path) {
		in = fopen(path, "r");
		if (!in) {
			status = craf_err(CRAF_FAILED, "dgst: cannot open %s: %m",
					  path);
			kc_hash_free(h);
			return status;
		}
	}
	status = hash_stream(h, in, what, md, &md_len);
	if (path)
		fclose(in);	/* intentionally ignored: read only */
	if (status)
		return status;
	if (o->binary) {
		fwrite(md, 1, md_len, stdout);	/* checked at the end */
		return CRAF_OK;
	}
	printf("%s(%s)= ", label_of(o), what);
	for (i = 0; i < md_len; i++)
		printf("%02x", md[i]);
	printf("\n");
	return CRAF_OK;
}

int craf_dgst(const struct craf_dgst_opts *o)
{
	bool stop = false;
	int i, status, ret = CRAF_OK;

	/* A driver is no name of a hash, as for openssl */
	if (o->hash || o->digest_algo) {
		status = craf_check_algo_name("dgst", "hash", o->digest_algo ?
					      "-digest-algo" : "the hash",
					      o->kname, NULL);
		if (status)
			return status;
	}
	if (o->nfiles == 0)
		ret = digest(o, NULL, &stop);
	for (i = 0; i < o->nfiles && !stop; i++) {
		status = digest(o, o->files[i], &stop);
		if (status)
			ret = status;
	}
	/* An earlier write error leaves no errno to tell */
	if (fflush(stdout) != 0) {
		if (ret == CRAF_OK)
			ret = craf_err(CRAF_FAILED, "cannot write output: %m");
	} else if (ferror(stdout) && ret == CRAF_OK)
		ret = craf_err(CRAF_FAILED, "cannot write output");
	return ret;
}
