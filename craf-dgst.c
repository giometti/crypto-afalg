/*
 * craf-dgst.c - the digest and the signature check of openssl dgst, in
 *		the kernel (craf)
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
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include "craf.h"

#define HASH_DEFAULT		"sha256"
#define KEY_FILE_MAX		65536	/* more than any public key file */
#define KEY_BITS_MIN		2048	/* fewer is warned of */
#define RSA_KEY_MAX		16384	/* no RSA key is longer */
#define PARAMS_MAX		(KC_NAME_MAX + 32)

/* DER tags */
#define DER_INTEGER		0x02
#define DER_BIT_STRING		0x03
#define DER_NULL		0x05
#define DER_OID			0x06
#define DER_SEQUENCE		0x30
#define DER_EXPLICIT_0		0xa0

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

/* What a file of -verify holds */
enum key_kind {
	KEY_SPKI,			/* a public key, SubjectPublicKeyInfo */
	KEY_RSA,			/* a public key, PKCS#1 RSAPublicKey */
	KEY_CERT,			/* an X.509 certificate */
};

/* The PEM labels taken, as openssl takes them, and a certificate too */
struct pem_label {
	const char *label;
	enum key_kind kind;
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

static const struct pem_label pem_labels[] = {
	{ "PUBLIC KEY",		KEY_SPKI },
	{ "RSA PUBLIC KEY",	KEY_RSA },
	{ "CERTIFICATE",	KEY_CERT },
};

/* rsaEncryption, 1.2.840.113549.1.1.1, with its tag and length */
static const uint8_t rsa_oid[] = {
	DER_OID, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01,
};

/* Hashes too weak for a signature: warned of, not refused, as openssl */
static const char *const weak_hashes[] = {
	"md5", "sha1",
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

/*
 * A type written in the spec of -verify-key is seen on the command line:
 * one other than asymmetric verifies nothing. A serial is left to the
 * kernel, which says what the key is.
 */
static int check_key_type(const char *spec)
{
	const char *comma, *type, *end;

	comma = strchr(spec, ',');
	if (!comma)
		return CRAF_OK;
	type = spec;
	end = comma;
	if (strchr(comma + 1, ',')) {
		type = comma + 1;
		end = strchr(type, ',');
	}
	if ((size_t) (end - type) != strlen("asymmetric") ||
	    strncmp(type, "asymmetric", end - type) != 0)
		return craf_err(CRAF_USAGE, "-verify-key: a key of type "
				"\"%.*s\", only asymmetric verifies",
				(int) (end - type), type);
	return CRAF_OK;
}

int craf_dgst_parse(int argc, char *argv[], struct craf_dgst_opts *o)
{
	static const struct option options[] = {
		{ "digest-algo",	required_argument,	NULL, 'a' },
		{ "hex",		no_argument,		NULL, 'x' },
		{ "binary",		no_argument,		NULL, 'b' },
		{ "keyform",		required_argument,	NULL, 'K' },
		{ "verify",		required_argument,	NULL, 'v' },
		{ "verify-key",		required_argument,	NULL, 'k' },
		{ "signature",		required_argument,	NULL, 's' },
		{ "help",		no_argument,		NULL, 'h' },
		/* What openssl dgst takes and craf dgst does not */
		{ "sign",		required_argument,	NULL, 'U' },
		{ "prverify",		required_argument,	NULL, 'U' },
		{ "sigopt",		required_argument,	NULL, 'U' },
		{ "out",		required_argument,	NULL, 'U' },
		{ "r",			no_argument,		NULL, 'U' },
		{ "c",			no_argument,		NULL, 'U' },
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
	bool format = false;
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
			format = true;
			break;
		case 'b':
			o->binary = true;
			format = true;
			break;
		case 'v':
			o->verify = optarg;
			break;
		case 'k':
			o->verify_key = optarg;
			break;
		case 's':
			o->signature = optarg;
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
	if (o->verify && o->verify_key)
		return craf_err(CRAF_USAGE, "dgst: give -verify or -verify-key, "
				"not both");
	if (o->signature && !o->verify && !o->verify_key)
		return craf_err(CRAF_USAGE,
				"dgst: -signature needs a key to verify with");
	if (o->verify && !o->signature)
		return craf_err(CRAF_USAGE, "dgst: -verify needs -signature");
	if (o->verify_key && !o->signature)
		return craf_err(CRAF_USAGE, "dgst: -verify-key needs -signature");
	if (o->signature && o->nfiles > 1)
		return craf_err(CRAF_USAGE, "dgst: only one file can be "
				"verified, as with openssl");
	if (o->signature && format)
		warn("-hex and -binary have no effect when verifying");
	if (o->keyform && !o->verify)
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
	if (o->verify_key)
		return check_key_type(o->verify_key);
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

/* The length of a DER element at p, of tag, within len bytes; 0 if none */
static size_t der_element(const uint8_t *p, size_t len, uint8_t tag,
			  size_t *hdr_len)
{
	size_t n, i, clen;

	if (len < 2 || p[0] != tag)
		return 0;
	if (p[1] < 0x80) {
		*hdr_len = 2;
		clen = p[1];
	} else {
		n = p[1] & 0x7f;
		if (n == 0 || n > 3 || len < 2 + n)
			return 0;
		for (clen = 0, i = 0; i < n; i++)
			clen = clen << 8 | p[2 + i];
		*hdr_len = 2 + n;
	}
	if (clen > len - *hdr_len)
		return 0;
	return *hdr_len + clen;
}

/*
 * A DER length, in the shortest form; the number of bytes written. Below
 * 0x10000, which RSA_KEY_MAX keeps it.
 */
static size_t der_length(uint8_t *p, size_t len)
{
	if (len < 0x80) {
		p[0] = len;
		return 1;
	}
	if (len < 0x100) {
		p[0] = 0x81;
		p[1] = len;
		return 2;
	}
	p[0] = 0x82;
	p[1] = len >> 8;
	p[2] = len & 0xff;
	return 3;
}

/*
 * What DER bytes are, from their shape: a SEQUENCE whose first element is
 * a SEQUENCE that begins with an OID is a SubjectPublicKeyInfo; one that
 * begins with a version or a serial number is the body of a certificate;
 * a SEQUENCE of two INTEGERs is a PKCS#1 RSA key. -1 for anything else.
 * The bytes after the SEQUENCE are left out of *len, as openssl leaves
 * them.
 */
static int der_kind(const uint8_t *der, size_t *len)
{
	size_t outer, inner, n, e, hl1, hl2, hl3;

	outer = der_element(der, *len, DER_SEQUENCE, &hl1);
	if (!outer)
		return -1;
	*len = outer;
	n = der_element(der + hl1, outer - hl1, DER_INTEGER, &hl2);
	if (n) {
		e = der_element(der + hl1 + n, outer - hl1 - n, DER_INTEGER,
				&hl3);
		return e && hl1 + n + e == outer ? KEY_RSA : -1;
	}
	inner = der_element(der + hl1, outer - hl1, DER_SEQUENCE, &hl2);
	if (!inner || inner == hl2)
		return -1;
	switch (der[hl1 + hl2]) {
	case DER_OID:
		return KEY_SPKI;
	case DER_EXPLICIT_0:
	case DER_INTEGER:
		return KEY_CERT;
	}
	return -1;
}

/* Whether a SubjectPublicKeyInfo holds an RSA key: the OID of its algorithm */
static bool spki_is_rsa(const uint8_t *der, size_t len)
{
	size_t alg, hl1, hl2;

	if (!der_element(der, len, DER_SEQUENCE, &hl1))
		return false;
	alg = der_element(der + hl1, len - hl1, DER_SEQUENCE, &hl2);
	return alg && alg - hl2 >= sizeof(rsa_oid) &&
	       memcmp(der + hl1 + hl2, rsa_oid, sizeof(rsa_oid)) == 0;
}

/*
 * A PKCS#1 RSAPublicKey in a SubjectPublicKeyInfo, as openssl reads one:
 * the algorithm rsaEncryption with no parameters, the key in a BIT STRING
 */
static int rsa_to_spki(const uint8_t *rsa, size_t len, uint8_t **spki,
		       size_t *spki_len)
{
	uint8_t alg[sizeof(rsa_oid) + 4], bits[4], seq[4], *p;
	size_t alen, blen, slen, total;

	alg[0] = DER_SEQUENCE;
	alg[1] = sizeof(rsa_oid) + 2;
	memcpy(alg + 2, rsa_oid, sizeof(rsa_oid));
	alg[2 + sizeof(rsa_oid)] = DER_NULL;
	alg[3 + sizeof(rsa_oid)] = 0;
	alen = sizeof(alg);
	bits[0] = DER_BIT_STRING;
	blen = 1 + der_length(bits + 1, len + 1);
	seq[0] = DER_SEQUENCE;
	total = alen + blen + 1 + len;
	slen = 1 + der_length(seq + 1, total);
	*spki = malloc(slen + total);
	if (!*spki)
		return craf_err(CRAF_FAILED, "dgst: %s", strerror(ENOMEM));
	p = *spki;
	memcpy(p, seq, slen);
	p += slen;
	memcpy(p, alg, alen);
	p += alen;
	memcpy(p, bits, blen);
	p += blen;
	*p++ = 0;		/* no unused bits */
	memcpy(p, rsa, len);
	*spki_len = slen + total;
	return CRAF_OK;
}

/* A base64 digit, -1 for any other character */
static int b64_value(int c)
{
	if (c >= 'A' && c <= 'Z')
		return c - 'A';
	if (c >= 'a' && c <= 'z')
		return c - 'a' + 26;
	if (c >= '0' && c <= '9')
		return c - '0' + 52;
	if (c == '+')
		return 62;
	if (c == '/')
		return 63;
	return -1;
}

/* The base64 of text, white space skipped, '=' at the end only */
static bool b64_decode(const char *text, size_t len, uint8_t *out,
		       size_t *out_len)
{
	unsigned int acc = 0;
	size_t i, n = 0, bits = 0;
	bool end = false;
	int v;

	for (i = 0; i < len; i++) {
		if (isspace((unsigned char) text[i]))
			continue;
		if (text[i] == '=') {
			end = true;
			continue;
		}
		v = b64_value((unsigned char) text[i]);
		if (v < 0 || end)
			return false;
		acc = acc << 6 | v;
		bits += 6;
		if (bits >= 8) {
			bits -= 8;
			out[n++] = acc >> bits;
		}
	}
	*out_len = n;
	return true;
}

/*
 * The DER of a PEM file, of one of the labels taken; -1 when buf is no
 * PEM of them, which the caller reports
 */
static int pem_decode(char *buf, size_t len, uint8_t *der, size_t *der_len,
		      const char **label)
{
	char begin[64], end[64], *b, *e;
	size_t i;

	for (i = 0; i < ARRAY_SIZE(pem_labels); i++) {
		snprintf(begin, sizeof(begin), "-----BEGIN %s-----",
			 pem_labels[i].label);
		snprintf(end, sizeof(end), "-----END %s-----",
			 pem_labels[i].label);
		b = memmem(buf, len, begin, strlen(begin));
		if (!b)
			continue;
		b += strlen(begin);
		e = memmem(b, buf + len - b, end, strlen(end));
		if (!e || !b64_decode(b, e - b, der, der_len))
			return -1;
		*label = pem_labels[i].label;
		return pem_labels[i].kind;
	}
	return -1;
}

/*
 * The public key of a file of -verify, as openssl takes it: PEM or DER, a
 * SubjectPublicKeyInfo or a PKCS#1 RSA key; or a certificate, which
 * openssl does not take. RSA only: what the kernel does with the key is
 * PKCS#1 v1.5.
 */
static int load_key_file(const char *path, const char *keyform,
			 struct kc_key **k)
{
	uint8_t *der = NULL, *spki = NULL;
	char *buf = NULL;
	const char *label = "DER";
	struct kc_error e;
	size_t len, der_len = 0;
	int kind, status;
	bool pem;
	FILE *f;

	f = fopen(path, "r");
	if (!f)
		return craf_err(CRAF_FAILED, "dgst: cannot open %s: %m", path);
	buf = malloc(KEY_FILE_MAX + 1);
	der = malloc(KEY_FILE_MAX);
	if (!buf || !der) {
		status = craf_err(CRAF_FAILED, "dgst: %s", strerror(ENOMEM));
		goto out;
	}
	len = fread(buf, 1, KEY_FILE_MAX + 1, f);
	if (ferror(f)) {
		status = craf_err(CRAF_FAILED, "dgst: cannot read %s: %m",
				  path);
		goto out;
	}
	if (len > KEY_FILE_MAX) {
		status = craf_err(CRAF_FAILED, "dgst: %s is longer than any "
				  "public key file", path);
		goto out;
	}

	kind = -1;
	pem = memmem(buf, len, "-----BEGIN ", 11) != NULL;
	if (keyform && (strcasecmp(keyform, "PEM") == 0) != pem)
		warn("-keyform %s, but %s is %s, read as such", keyform, path,
		     pem ? "PEM" : "DER");
	if (pem) {
		kind = pem_decode(buf, len, der, &der_len, &label);
		if (kind >= 0 && der_kind(der, &der_len) != kind)
			kind = -1;
	} else if (len > 0) {
		memcpy(der, buf, len);
		der_len = len;
		kind = der_kind(der, &der_len);
	}
	if (kind == KEY_RSA) {
		if (der_len > RSA_KEY_MAX) {
			status = craf_err(CRAF_FAILED, "dgst: %s: an RSA key "
					  "longer than %d bytes", path,
					  RSA_KEY_MAX);
			goto out;
		}
		status = rsa_to_spki(der, der_len, &spki, &der_len);
		if (status)
			goto out;
		kind = KEY_SPKI;
	}
	if (kind == KEY_SPKI && der_kind(spki ? spki : der, &der_len) !=
	    KEY_SPKI)
		kind = -1;
	if (kind < 0) {
		status = craf_err(CRAF_FAILED, "dgst: %s: not a public key or "
				  "a certificate", path);
		goto out;
	}
	if (kind == KEY_SPKI && !spki_is_rsa(spki ? spki : der, der_len)) {
		status = craf_err(CRAF_FAILED, "dgst: %s: not an RSA key", path);
		goto out;
	}

	if (kind == KEY_CERT)
		status = kc_key_cert(k, der, der_len, &e);
	else
		status = kc_key_pubkey(k, spki ? spki : der, der_len, &e);
	if (status)
		status = craf_err(CRAF_FAILED, "dgst: cannot load the key of "
				  "%s (%s): %s", path, label, e.msg);
out:
	fclose(f);		/* intentionally ignored: read only */
	free(spki);
	free(der);
	free(buf);
	return status;
}

/* A key of the keyring, by serial or by name, as -enc-key takes it */
static int load_keyring_key(const char *spec, struct kc_key **k)
{
	struct kc_error e;

	if (kc_key_spec(k, spec, &e))
		return craf_err(e.status == KC_USAGE ? CRAF_USAGE : CRAF_FAILED,
				"-verify-key: %s", e.msg);
	return CRAF_OK;
}

/*
 * The one place where the key to verify with is chosen, and where a new
 * source goes
 */
static int verify_key(const struct craf_dgst_opts *o, struct kc_key **k)
{
	if (o->verify_key)
		return load_keyring_key(o->verify_key, k);
	return load_key_file(o->verify, o->keyform, k);
}

/*
 * What openssl takes without a word: a weak hash, a short key. The
 * verification goes on; the policy is the verifier's.
 */
static void warn_weak(const struct craf_dgst_opts *o,
		      const struct kc_pkey_info *info)
{
	size_t i;

	for (i = 0; i < ARRAY_SIZE(weak_hashes); i++)
		if (strcmp(o->kname, weak_hashes[i]) == 0)
			warn("%s is a weak hash for a signature", o->kname);
	if (info->key_size < KEY_BITS_MIN)
		warn("the key has %u bits, fewer than %d", info->key_size,
		     KEY_BITS_MIN);
}

/*
 * The one place where the parameters of the signature are chosen: PKCS#1
 * v1.5 over the hash of the digest, by the same name, so that the digest
 * has the length hash= wants
 */
static void pkcs1_params(const struct craf_dgst_opts *o, char *params,
			 size_t size)
{
	snprintf(params, size, "enc=pkcs1 hash=%s", o->kname);
}

/*
 * At most the length of the key's signatures, as openssl reads it: a
 * longer file is taken for its first bytes
 */
static int read_signature(const char *path, size_t max, uint8_t *sig,
			  size_t *len)
{
	int status;
	FILE *f;

	f = fopen(path, "r");
	if (!f)
		return craf_err(CRAF_FAILED, "dgst: cannot open %s: %m", path);
	*len = fread(sig, 1, max, f);
	if (*len < max && ferror(f)) {
		status = craf_err(CRAF_FAILED, "dgst: cannot read %s: %m",
				  path);
		fclose(f);	/* intentionally ignored: read only */
		return status;
	}
	fclose(f);		/* intentionally ignored: read only */
	return CRAF_OK;
}

/* The verdict on stdout, as openssl; the cause on stderr */
static int verdict(int status, const char *cause)
{
	if (status == CRAF_OK)
		printf("Verified OK\n");
	else {
		if (cause)
			err("dgst: %s", cause);
		printf("Verification failure\n");
	}
	return status;
}

/*
 * The key is asked first, with the parameters of the verification, so a
 * refusal of them is no forged signature and costs no reading of the data
 */
static int verify(const struct craf_dgst_opts *o)
{
	char params[PARAMS_MAX];
	uint8_t md[KC_HASH_MAX], *sig = NULL;
	struct kc_pkey_info info;
	struct kc_hash *h = NULL;
	struct kc_key *k = NULL;
	struct kc_error e;
	const char *path = o->nfiles ? o->files[0] : NULL;
	size_t md_len, sig_len;
	FILE *in = stdin;
	int status;

	pkcs1_params(o, params, sizeof(params));
	status = verify_key(o, &k);
	if (status)
		return status;
	if (kc_pkey_query(k, params, &info, &e)) {
		status = craf_err(CRAF_FAILED, "dgst: the key cannot be used "
				  "with \"%s\": %s", params, e.msg);
		goto out;
	}
	/* What the kernel cannot verify with is no forged signature */
	if (!(info.ops & KC_PKEY_VERIFY) || !info.max_sig) {
		status = craf_err(CRAF_FAILED, "dgst: the key cannot verify "
				  "with \"%s\"", params);
		goto out;
	}
	warn_weak(o, &info);
	sig = malloc(info.max_sig);
	if (!sig) {
		status = craf_err(CRAF_FAILED, "dgst: %s", strerror(ENOMEM));
		goto out;
	}
	status = read_signature(o->signature, info.max_sig, sig, &sig_len);
	if (status)
		goto out;
	if (sig_len == 0) {
		status = verdict(CRAF_REFUSED, "the signature file is empty");
		goto out;
	}

	status = open_hash(o->kname, &h);
	if (status)
		goto out;
	if (path) {
		in = fopen(path, "r");
		if (!in) {
			status = craf_err(CRAF_FAILED,
					  "dgst: cannot open %s: %m", path);
			goto out;
		}
	}
	status = hash_stream(h, in, path ? path : "stdin", md, &md_len);
	h = NULL;		/* freed by hash_stream() */
	if (path)
		fclose(in);	/* intentionally ignored: read only */
	if (status)
		goto out;

	switch (kc_pkey_verify(k, params, md, md_len, sig, sig_len, &e)) {
	case KC_OK:
		status = verdict(CRAF_OK, NULL);
		break;
	case KC_REFUSED:
		status = verdict(CRAF_REFUSED, e.msg);
		break;
	default:
		status = craf_err(CRAF_FAILED, "dgst: %s", e.msg);
	}
out:
	kc_hash_free(h);
	free(sig);
	kc_key_free(k);
	return status;
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
	if (o->signature) {
		ret = verify(o);
		goto out;
	}
	if (o->nfiles == 0)
		ret = digest(o, NULL, &stop);
	for (i = 0; i < o->nfiles && !stop; i++) {
		status = digest(o, o->files[i], &stop);
		if (status)
			ret = status;
	}
out:
	/* An earlier write error leaves no errno to tell */
	if (fflush(stdout) != 0) {
		if (ret == CRAF_OK)
			ret = craf_err(CRAF_FAILED, "cannot write output: %m");
	} else if (ferror(stdout) && ret == CRAF_OK)
		ret = craf_err(CRAF_FAILED, "cannot write output");
	return ret;
}
