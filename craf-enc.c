/*
 * craf-enc.c - craf enc -d: the files of openssl enc -pbkdf2
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
#include <fcntl.h>
#include <getopt.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include "craf.h"

/* How much of the first line openssl takes: -kfile, then file: and fd: */
#define KFILE_MAX		127
#define PASS_FILE_MAX		1023

#define ITER_DEFAULT		10000
#define MD_DEFAULT		"sha256"
#define MD_MAX			(KC_NAME_MAX - 6)	/* in "hmac()" */

/* A cipher of openssl whose kernel name the general rule does not give */
struct exception {
	const char *openssl;
	const char *kernel;
	size_t key_len;
};

static const struct exception exceptions[] = {
	{ "des-ede3-cbc",	"cbc(des3_ede)",	24 },
};

/*
 * The modes the format of openssl enc has no room for, which openssl enc
 * refuses too: AEAD (no room for the tag), XTS (a tweak per sector), key
 * wrap. As the end of a name of openssl, and as a template of the kernel.
 */
static const char *const openssl_unportable[] = {
	"-gcm", "-ccm", "-ocb", "-siv", "-poly1305", "-xts", "-wrap",
	"-wrap-pad", "-wrap-inv",
};

static const char *const kernel_unportable[] = {
	"gcm", "ccm", "rfc4106", "rfc4309", "rfc4543", "rfc7539",
	"rfc7539esp", "xts", "kw",
};

/* A word that begins as an option of craf is a mistyped one, no cipher */
static const char *const not_ciphers[] = {
	"cipher-", "in", "out", "pass", "kfile", "iter", "md", "pbkdf2",
};

static bool ends_with(const char *s, const char *end)
{
	size_t len = strlen(s), elen = strlen(end);

	return len > elen && strcmp(s + len - elen, end) == 0;
}

static bool all_of(const char *s, size_t len, int (*is)(int))
{
	size_t i;

	if (len == 0)
		return false;
	for (i = 0; i < len; i++)
		if (!is((unsigned char) s[i]) || isupper((unsigned char) s[i]))
			return false;
	return true;
}

/*
 * The kernel name of an openssl cipher: the table first, then
 * <alg>-<bits>-<mode> or <alg>-<mode> as <mode>(<alg>). 0 when word is no
 * name of a cipher, which makes it an unknown option.
 */
static int translate(const char *word, struct craf_enc_opts *o)
{
	const char *d1, *d2;
	size_t i, bits;

	for (i = 0; i < ARRAY_SIZE(not_ciphers); i++)
		if (strncmp(word, not_ciphers[i], strlen(not_ciphers[i])) == 0)
			return 0;
	for (i = 0; i < ARRAY_SIZE(exceptions); i++)
		if (strcmp(word, exceptions[i].openssl) == 0) {
			snprintf(o->kname, sizeof(o->kname), "%s",
				 exceptions[i].kernel);
			o->key_len = exceptions[i].key_len;
			return 1;
		}
	for (i = 0; i < ARRAY_SIZE(openssl_unportable); i++)
		if (ends_with(word, openssl_unportable[i]))
			return -1;

	d1 = strchr(word, '-');
	if (!d1)
		return 0;
	d2 = strchr(d1 + 1, '-');
	if (!all_of(word, d1 - word, isalnum))
		return 0;
	if (!d2) {
		if (!all_of(d1 + 1, strlen(d1 + 1), isalnum))
			return 0;
		o->key_len = 0;
	} else {
		if (strchr(d2 + 1, '-') ||
		    !all_of(d1 + 1, d2 - d1 - 1, isdigit) ||
		    !all_of(d2 + 1, strlen(d2 + 1), isalnum))
			return 0;
		bits = strtoul(d1 + 1, NULL, 10);
		if (bits == 0 || bits % 8)
			return 0;
		o->key_len = bits / 8;
	}
	snprintf(o->kname, sizeof(o->kname), "%s(%.*s)",
		 d2 ? d2 + 1 : d1 + 1, (int) (d1 - word), word);
	return 1;
}

/* A number of 1 to max, in base (0 as strtol() takes it), no sign */
static bool parse_count(const char *s, int base, long max, long *v)
{
	char *end;

	if (*s < '0' || *s > '9')
		return false;
	errno = 0;
	*v = strtol(s, &end, base);
	return errno == 0 && *end == '\0' && *v >= 1 && *v <= max;
}

/*
 * The descriptor of -pass fd:, checked before craf opens a file of its
 * own, which could take the number of one the caller forgot to give
 */
static int parse_fd(const char *s, int *fd)
{
	char *end;
	long v;

	errno = 0;
	v = strtol(s, &end, 10);
	if (*s < '0' || *s > '9' || *end || errno || v > INT_MAX)
		return craf_err(CRAF_USAGE, "-pass: \"%s\" is not a descriptor",
				s);
	if (fcntl(v, F_GETFD) < 0)
		return craf_err(CRAF_FAILED, "-pass: cannot read descriptor "
				"%s: %m", s);
	*fd = v;
	return CRAF_OK;
}

int craf_enc_parse(int argc, char *argv[], struct craf_enc_opts *o)
{
	static const struct option options[] = {
		{ "d",			no_argument,		NULL, 'd' },
		{ "e",			no_argument,		NULL, 'e' },
		{ "in",			required_argument,	NULL, 'i' },
		{ "out",		required_argument,	NULL, 'o' },
		{ "pbkdf2",		no_argument,		NULL, 'P' },
		{ "iter",		required_argument,	NULL, 'I' },
		{ "md",			required_argument,	NULL, 'm' },
		{ "salt",		no_argument,		NULL, 's' },
		{ "kfile",		required_argument,	NULL, 'f' },
		{ "k",			required_argument,	NULL, 'k' },
		{ "pass",		required_argument,	NULL, 'p' },
		{ "cipher-algo",	required_argument,	NULL, 'a' },
		{ "cipher-key-len",	required_argument,	NULL, 'l' },
		{ "cipher-driver",	required_argument,	NULL, 'D' },
		{ "help",		no_argument,		NULL, 'h' },
		/* What openssl enc takes and craf enc does not */
		{ "a",			no_argument,		NULL, 'U' },
		{ "base64",		no_argument,		NULL, 'U' },
		{ "nosalt",		no_argument,		NULL, 'U' },
		{ "K",			required_argument,	NULL, 'U' },
		{ "iv",			required_argument,	NULL, 'U' },
		{ "S",			required_argument,	NULL, 'U' },
		{ "nopad",		no_argument,		NULL, 'U' },
		{ "p",			no_argument,		NULL, 'U' },
		{ "P",			no_argument,		NULL, 'U' },
		{ "v",			no_argument,		NULL, 'U' },
		{ "bufsize",		required_argument,	NULL, 'U' },
		{ "none",		no_argument,		NULL, 'U' },
		{ "z",			no_argument,		NULL, 'U' },
		{ 0, 0, 0, 0 }
	};
	enum craf_pass_from key_from = CRAF_PASS_NONE;
	const char *word, *key = NULL, *spec = NULL;
	int opt, idx, prev, ret, status;
	long v;

	memset(o, 0, sizeof(*o));
	o->md = MD_DEFAULT;
	o->pass_fd = -1;
	opterr = 0;
	optind = 0;
	for (;;) {
		prev = optind ? optind : 1;
		idx = -1;
		opt = getopt_long_only(argc, argv, "+:", options, &idx);
		if (opt < 0)
			break;
		/* getopt takes an abbreviation, openssl does not */
		if (idx >= 0 && !craf_typed_exactly(argv[prev], options[idx].name))
			opt = '?';
		switch (opt) {
		case 'd':
			o->decrypt = true;
			break;
		case 'e':
			o->decrypt = false;
			break;
		case 'i':
			o->in = optarg;
			break;
		case 'o':
			o->out = optarg;
			break;
		case 'P':
			o->pbkdf2 = true;
			break;
		case 'I':
			/* As openssl, in octal and in hex too */
			if (!parse_count(optarg, 0, INT_MAX, &o->iter))
				return craf_err(CRAF_USAGE,
						"-iter: \"%s\" is not a count of 1 or more",
						optarg);
			o->pbkdf2 = true;
			break;
		case 'm':
			o->md = optarg;
			break;
		case 's':
			warn("-salt has no effect when decrypting");
			break;
		case 'f':
			key_from = CRAF_PASS_KFILE;
			key = optarg;
			break;
		case 'k':
			key_from = CRAF_PASS_TEXT;
			key = optarg;
			break;
		case 'p':
			spec = optarg;
			break;
		case 'a':
			o->cipher_algo = optarg;
			break;
		case 'l':
			if (!parse_count(optarg, 10, KC_OPENSSL_KEY_MAX, &v))
				return craf_err(CRAF_USAGE,
						"-cipher-key-len: \"%s\" is not 1 to %d",
						optarg, KC_OPENSSL_KEY_MAX);
			o->cipher_key_len = v;
			break;
		case 'D':
			o->cipher_driver = optarg;
			break;
		case 'h':
			o->help = true;
			return CRAF_OK;
		case 'U':
			return craf_err(CRAF_USAGE,
					"enc: -%s is not supported by craf",
					options[idx].name);
		case ':':
			if (craf_exact_option(options, argv[prev]))
				return craf_err(CRAF_USAGE,
						"missing value for \"%s\"",
						argv[prev]);
			/* An abbreviation with no value: unknown, as above */
			/* fallthrough */
		default:
			/* As openssl: a word it does not know may be a cipher */
			word = argv[prev] + (argv[prev][1] == '-' ? 2 : 1);
			ret = argv[prev][0] == '-' ? translate(word, o) : 0;
			if (ret < 0)
				return craf_err(CRAF_USAGE,
						"enc: the format of openssl enc has no room for -%s",
						word);
			if (ret == 0)
				return craf_err(CRAF_USAGE,
						"unknown option or missing value \"%s\", see -help",
						argv[prev]);
			o->openssl_name = word;
			break;
		}
	}
	if (optind < argc)
		return craf_err(CRAF_USAGE, "unexpected argument \"%s\"",
				argv[optind]);

	if (!o->decrypt)
		return craf_err(CRAF_USAGE, "enc: craf only decrypts, give -d");
	if (o->openssl_name && o->cipher_algo)
		return craf_err(CRAF_USAGE, "enc: give -%s or -cipher-algo, "
				"not both", o->openssl_name);
	if (!o->openssl_name && !o->cipher_algo)
		return craf_err(CRAF_USAGE, "enc: a cipher is required, as "
				"-aes-256-cbc or -cipher-algo");
	if (o->cipher_key_len && !o->cipher_algo)
		return craf_err(CRAF_USAGE,
				"enc: -cipher-key-len is for -cipher-algo");
	if (o->cipher_algo) {
		if (!*o->cipher_algo || strlen(o->cipher_algo) > KC_NAME_MAX)
			return craf_err(CRAF_USAGE,
					"-cipher-algo: the length must be 1 to %d",
					KC_NAME_MAX);
		snprintf(o->kname, sizeof(o->kname), "%s", o->cipher_algo);
		o->key_len = o->cipher_key_len;
	} else if (strlen(o->kname) > KC_NAME_MAX)
		return craf_err(CRAF_USAGE, "enc: -%s gives a kernel name "
				"longer than %d characters", o->openssl_name,
				KC_NAME_MAX);
	if (!*o->md || strlen(o->md) > MD_MAX)
		return craf_err(CRAF_USAGE, "-md: the length must be 1 to %d",
				MD_MAX);
	if (!o->pbkdf2)
		return craf_err(CRAF_USAGE, "enc: only -pbkdf2 (or -iter) is "
				"supported, not the deprecated derivation");

	/* As openssl: -k and -kfile win over -pass, whatever the order */
	if (key_from != CRAF_PASS_NONE) {
		o->pass_from = key_from;
		o->pass = key;
	} else if (spec) {
		o->pass_from = CRAF_PASS_SPEC;
		o->pass = spec;
	} else
		return craf_err(CRAF_USAGE, "enc: a passphrase is required, "
				"from -kfile, -k or -pass");
	if (o->pass_from == CRAF_PASS_SPEC && strncmp(spec, "fd:", 3) == 0) {
		status = parse_fd(spec + 3, &o->pass_fd);
		if (status)
			return status;
	}
	if (o->cipher_driver)
		return craf_check_driver_name(o->cipher_driver);
	return CRAF_OK;
}

/* The file of the passphrase, which the output must not be */
void craf_enc_key_file(const struct craf_enc_opts *o,
		       struct craf_key_file *kf)
{
	kf->what = o->pass_from == CRAF_PASS_KFILE ? "-kfile" : "-pass";
	kf->path = NULL;
	kf->fd = o->pass_fd;
	if (o->pass_from == CRAF_PASS_KFILE)
		kf->path = o->pass;
	else if (o->pass_from == CRAF_PASS_SPEC &&
		 strncmp(o->pass, "file:", 5) == 0)
		kf->path = o->pass + 5;
}

/* The outermost template of a kernel name, none for a plain cipher */
static size_t mode_of(const char *kname, const char **mode)
{
	const char *p = strchr(kname, '(');

	*mode = kname;
	return p ? (size_t) (p - kname) : 0;
}

/* A mode the format of openssl enc has no room for is a wrong usage */
static int check_portable(const struct craf_enc_opts *o)
{
	const char *mode;
	size_t len, i;

	len = mode_of(o->kname, &mode);
	for (i = 0; i < ARRAY_SIZE(kernel_unportable); i++)
		if (strlen(kernel_unportable[i]) == len &&
		    strncmp(mode, kernel_unportable[i], len) == 0)
			return craf_err(CRAF_USAGE,
					"enc: the format of openssl enc has no room for %s",
					o->kname);
	return CRAF_OK;
}

/*
 * The one place where the shape of the cipher is chosen, from its mode
 * and the sizes the kernel gives: CBC is what craf decrypts, any other
 * mode is not yet. A driver named is the only name bound, as in seal.
 */
static int cipher_shape(struct craf_enc_opts *o, size_t *iv_len)
{
	size_t block, key_min, key_max, len;
	const char *mode, *shown = o->openssl_name ? o->openssl_name :
				   o->kname;
	const char *name = o->cipher_driver ? o->cipher_driver : o->kname;
	struct kc_error e;
	int status;

	len = mode_of(o->kname, &mode);
	status = check_portable(o);
	if (status)
		return status;
	if (o->cipher_driver) {
		status = craf_driver_check("-cipher-driver", o->cipher_driver,
					   o->kname, CRAF_USAGE);
		if (status)
			return status;
	}
	if (kc_cipher_sizes(name, &block, iv_len, &key_min, &key_max, &e)) {
		if (e.status == KC_REFUSED && e.errnum)
			return craf_err(CRAF_FAILED,
					"enc: cipher %s (%s) not available: %s",
					shown, name, strerror(e.errnum));
		return craf_err(e.status == KC_USAGE ? CRAF_USAGE :
				CRAF_FAILED, "enc: %s", e.msg);
	}
	if (o->cipher_algo && !o->cipher_driver) {
		status = craf_check_algo_name("enc", "skcipher", "-cipher-algo",
					      o->kname, "-cipher-driver");
		if (status)
			return status;
	}
	if (len != 3 || strncmp(mode, "cbc", 3) != 0 || block < 2 ||
	    *iv_len != block)
		return craf_err(CRAF_FAILED, "enc: craf does not decrypt %s "
				"yet", o->kname);

	if (o->key_len == 0 && key_min != key_max && o->openssl_name)
		return craf_err(CRAF_USAGE, "enc: %s takes %zu to %zu bytes "
				"of key, which -%s does not say: give "
				"-cipher-algo '%s' -cipher-key-len <bytes>",
				o->kname, key_min, key_max, o->openssl_name,
				o->kname);
	if (o->key_len == 0 && key_min != key_max)
		return craf_err(CRAF_USAGE, "enc: give -cipher-key-len, %s "
				"takes %zu to %zu bytes", o->kname, key_min,
				key_max);
	if (o->key_len == 0)
		o->key_len = key_min;
	if (o->key_len < key_min || o->key_len > key_max)
		return craf_err(CRAF_USAGE, "enc: a %zu-byte key is not one %s "
				"takes, %zu to %zu bytes", o->key_len, o->kname,
				key_min, key_max);
	if (o->openssl_name)
		warn("-%s taken as %s with a %zu-byte key",
		     o->openssl_name, o->kname, o->key_len);
	return CRAF_OK;
}

/*
 * The first line of f, as openssl reads it: at most max characters, the
 * rest of a longer one left; -kfile strips up to two of \n and \r at its
 * end, file: and fd: the \n only
 */
static int read_line(FILE *f, const char *what, size_t max, bool kfile,
		     char *buf, size_t *len)
{
	int c, i;

	if (!fgets(buf, max + 1, f)) {
		if (ferror(f))
			return craf_err(CRAF_FAILED, "%s: cannot read: %m",
					what);
		return craf_err(CRAF_USAGE, "%s: no passphrase in it", what);
	}
	*len = strlen(buf);
	if (*len == max && buf[max - 1] != '\n') {
		/* Only the end of the line -kfile strips is no cut */
		c = fgetc(f);
		if (kfile && c == '\r')
			c = fgetc(f);
		if (c != EOF && c != '\n')
			warn("%s: the passphrase is cut to %zu characters, "
			     "as openssl does", what, max);
	}
	for (i = 0; i < 2 && *len > 0; i++) {
		if (buf[*len - 1] != '\n' && !(kfile && buf[*len - 1] == '\r'))
			break;
		buf[--*len] = '\0';
		if (!kfile)
			break;
	}
	if (kfile && *len == 0)
		return craf_err(CRAF_USAGE, "%s: an empty passphrase", what);
	return CRAF_OK;
}

/*
 * The first line of f through a buffer of craf's own, cleared after it:
 * the one stdio would allocate is freed with the passphrase still in it
 */
static int read_pass_stream(FILE *f, const char *what, size_t max,
			    bool kfile, char *buf, size_t *len)
{
	char iobuf[BUFSIZ];
	int status;

	if (setvbuf(f, iobuf, _IOFBF, sizeof(iobuf)) != 0) {
		fclose(f);	/* intentionally ignored */
		return craf_err(CRAF_FAILED, "%s: cannot set a buffer", what);
	}
	status = read_line(f, what, max, kfile, buf, len);
	fclose(f);		/* intentionally ignored */
	explicit_bzero(iobuf, sizeof(iobuf));
	return status;
}

static int read_pass_file(const char *path, const char *what, size_t max,
			  bool kfile, char *buf, size_t *len)
{
	FILE *f;

	f = fopen(path, "r");
	if (!f)
		return craf_err(CRAF_FAILED, "%s: cannot open %s: %m", what,
				path);
	return read_pass_stream(f, what, max, kfile, buf, len);
}

/*
 * The passphrase: in buf when read from a file, else where it already is,
 * on the command line or in the environment, which craf cannot clear
 */
static int get_pass(const struct craf_enc_opts *o, char *buf,
		    const char **pass, size_t *len)
{
	const char *spec = o->pass, *colon;
	int fd;
	FILE *f;

	*pass = buf;
	if (o->pass_from == CRAF_PASS_KFILE)
		return read_pass_file(spec, "-kfile", KFILE_MAX, true, buf,
				      len);
	if (o->pass_from == CRAF_PASS_TEXT || strncmp(spec, "pass:", 5) == 0) {
		*pass = o->pass_from == CRAF_PASS_TEXT ? spec : spec + 5;
		*len = strlen(*pass);
		return CRAF_OK;
	}
	if (strncmp(spec, "env:", 4) == 0) {
		*pass = getenv(spec + 4);
		if (!*pass)
			return craf_err(CRAF_USAGE, "-pass: no variable %s in "
					"the environment", spec + 4);
		*len = strlen(*pass);
		return CRAF_OK;
	}
	if (strncmp(spec, "file:", 5) == 0)
		return read_pass_file(spec + 5, "-pass", PASS_FILE_MAX, false,
				      buf, len);
	if (o->pass_fd >= 0) {
		fd = dup(o->pass_fd);
		f = fd < 0 ? NULL : fdopen(fd, "r");
		if (!f) {
			err("-pass: cannot read descriptor %d: %m", o->pass_fd);
			if (fd >= 0)
				close(fd);
			return CRAF_FAILED;
		}
		return read_pass_stream(f, "-pass", PASS_FILE_MAX, false, buf,
					len);
	}

	/* What is no source may be a passphrase: it is not repeated */
	if (strcmp(spec, "stdin") == 0)
		return craf_err(CRAF_USAGE, "-pass: \"stdin\" is not "
				"supported, stdin carries the data");
	colon = strchr(spec, ':');
	if (colon)
		return craf_err(CRAF_USAGE, "-pass: \"%.*s\" is not supported, "
				"give pass:, file:, env: or fd:",
				(int) (colon - spec + 1), spec);
	return craf_err(CRAF_USAGE, "-pass: a source is required, as pass:, "
			"file:, env: or fd:");
}

static int read_input(FILE *in, uint8_t *p, size_t size, size_t *n)
{
	*n = fread(p, 1, size, in);
	if (*n < size && ferror(in))
		return craf_err(CRAF_FAILED, "cannot read input: %m");
	return CRAF_OK;
}

static int write_output(FILE *out, const uint8_t *p, size_t len)
{
	if (len > 0 && fwrite(p, 1, len, out) != len)
		return craf_err(CRAF_FAILED, "cannot write output: %m");
	return CRAF_OK;
}

/* The key and the IV, from the passphrase cleared as soon as it is used */
static int derive(const struct craf_enc_opts *o, const uint8_t *salt,
		  struct kc_key **k, uint8_t *iv, size_t iv_len)
{
	char buf[PASS_FILE_MAX + 2], hmac[CRAF_STR_MAX + 1];
	const char *pass;
	struct kc_error e;
	size_t len;
	int status;

	snprintf(hmac, sizeof(hmac), "hmac(%s)", o->md);
	status = get_pass(o, buf, &pass, &len);
	if (!status && kc_openssl_derive(hmac, pass, len, salt,
					 o->iter ? o->iter : ITER_DEFAULT,
					 o->key_len, k, iv, iv_len, &e)) {
		if (e.status == KC_REFUSED && e.errnum)
			status = craf_err(CRAF_FAILED, "enc: -md %s: %s not "
					  "available: %s", o->md, hmac,
					  strerror(e.errnum));
		else
			status = craf_err(e.status == KC_USAGE ? CRAF_USAGE :
					  CRAF_FAILED, "enc: %s", e.msg);
	}
	explicit_bzero(buf, sizeof(buf));
	return status;
}

/* -pass fd: on the input would take the passphrase from the data */
static int check_pass_input(const struct craf_enc_opts *o, FILE *in)
{
	struct stat sp, si;

	if (o->pass_fd < 0)
		return CRAF_OK;
	if (fstat(o->pass_fd, &sp) < 0 || fstat(fileno(in), &si) < 0)
		return craf_err(CRAF_FAILED, "-pass: cannot check descriptor "
				"%d against the input: %m", o->pass_fd);
	if (o->pass_fd == fileno(in) ||
	    (sp.st_dev == si.st_dev && sp.st_ino == si.st_ino))
		return craf_err(CRAF_USAGE, "-pass: descriptor %d is the "
				"input, which carries the data", o->pass_fd);
	return CRAF_OK;
}

int craf_enc(FILE *in, FILE *out, struct craf_enc_opts *o)
{
	uint8_t hdr[KC_OPENSSL_HEADER_LEN], salt[KC_OPENSSL_SALT_LEN];
	uint8_t iv[KC_BLOCK_MAX], buf[CRAF_BUF_SIZE];
	uint8_t plain[CRAF_BUF_SIZE + KC_BLOCK_MAX];
	const char *name;
	struct kc_cipher *c = NULL;
	struct kc_key *k = NULL;
	struct kc_error e;
	size_t iv_len, n, len;
	int status;

	status = cipher_shape(o, &iv_len);
	if (!status)
		status = check_pass_input(o, in);
	if (status)
		return status;

	/* As openssl: a header refused, and nothing goes out */
	status = read_input(in, hdr, sizeof(hdr), &n);
	if (status)
		return status;
	if (kc_openssl_header(hdr, n, salt, &e))
		return craf_err(CRAF_REFUSED, "%s", e.msg);

	status = derive(o, salt, &k, iv, iv_len);
	if (status)
		return status;
	name = o->cipher_driver ? o->cipher_driver : o->kname;
	status = kc_cipher_open(&c, name, k, 0, iv, iv_len, &e);
	kc_key_free(k);
	explicit_bzero(iv, sizeof(iv));
	if (status == KC_REFUSED)
		return craf_err(CRAF_FAILED, "enc: %s not available: %s",
				name, strerror(e.errnum));
	if (status)
		return craf_err(CRAF_FAILED, "enc: cannot open %s: %s", name,
				e.msg);

	/* The library holds back the last block, which carries the padding */
	do {
		status = read_input(in, buf, sizeof(buf), &n);
		if (status)
			goto out;
		if (kc_cipher_update(c, buf, n, plain, &len, &e)) {
			status = craf_err(CRAF_FAILED, "%s", e.msg);
			goto out;
		}
		status = write_output(out, plain, len);
		if (status)
			goto out;
	} while (n > 0);

	/*
	 * A wrong length still gives the last whole block, which goes out
	 * before the refusal, as with openssl
	 */
	if (kc_cipher_final(c, plain, &len, &e)) {
		write_output(out, plain, len);	/* intentionally ignored */
		status = craf_err(e.status == KC_REFUSED ? CRAF_REFUSED :
				  CRAF_FAILED, "%s", e.msg);
	} else
		status = write_output(out, plain, len);
out:
	kc_cipher_free(c);
	return status;
}
