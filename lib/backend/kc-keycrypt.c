/*
 * kc-keycrypt.c - the keycrypt backend: keys user space uses but never
 * reads, through an operation context of KEYCTL_CRYPT_OPEN (libkcrypto)
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
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/syscall.h>
#include <linux/keyctl.h>
#include "kc-backend.h"

/*
 * The interface of keycrypt, from its uapi headers, where the system has
 * none: only what is used here
 */
#ifndef KEYCTL_CRYPT_OPEN
#define KEYCTL_CRYPT_OPEN	33
#endif

#if __has_include(<linux/keycrypt.h>)
#include <linux/keycrypt.h>
#else
#define KEYCRYPT_OP_ENCRYPT		1
#define KEYCRYPT_OP_DECRYPT		2
#define KEYCRYPT_ALG_AES256_CBC		1
#define KEYCRYPT_OPEN_CALLER_IV		0x0001
#define KEYCRYPT_UPDATE_MAX		65536

struct keycrypt_open_params {
	uint32_t op;
	uint32_t accepted_min_tier;
	uint32_t flags;
	uint32_t __reserved;
	uint8_t iv[16];
};

struct keycrypt_update {
	uint64_t in;
	uint64_t out;
	uint32_t len;
	uint32_t flags;
};

struct keycrypt_final {
	uint64_t out;
	uint32_t len;
	uint32_t flags;
};

struct keycrypt_info {
	uint32_t op;
	uint32_t alg;
	uint32_t purpose;
	uint32_t tier;
	uint32_t origin;
	uint32_t accepted_min_tier;
	uint32_t __reserved[2];
	char backend[32];
};

#define KEYCRYPT_IOC_MAGIC	0xBB
#define KEYCRYPT_IOC_UPDATE	_IOW(KEYCRYPT_IOC_MAGIC, 1, struct keycrypt_update)
#define KEYCRYPT_IOC_FINAL	_IOWR(KEYCRYPT_IOC_MAGIC, 2, struct keycrypt_final)
#define KEYCRYPT_IOC_INFO	_IOR(KEYCRYPT_IOC_MAGIC, 4, struct keycrypt_info)
#endif

_Static_assert(sizeof(struct keycrypt_open_params) == 32,
	       "KEYCRYPT_OPEN_PARAMS_SIZE_VER0");
_Static_assert(sizeof(struct keycrypt_info) == 64, "struct keycrypt_info");

/* Where the series' own header is there, what this file assumes of it */
#if __has_include(<linux/keycrypt.h>)
_Static_assert(KEYCRYPT_TIER_KERNEL == KC_TIER_KERNEL &&
	       KEYCRYPT_TIER_ENGINE == KC_TIER_ENGINE &&
	       KEYCRYPT_TIER_TEE == KC_TIER_TEE &&
	       KEYCRYPT_TIER_HSM == KC_TIER_HSM, "KC_TIER_*");
_Static_assert(KEYCRYPT_BACKEND_NAME_MAX == KC_KEYCRYPT_BACKEND_MAX,
	       "KC_KEYCRYPT_BACKEND_MAX");
#endif
_Static_assert(sizeof(((struct keycrypt_open_params *) 0)->iv) ==
	       KC_KEYCRYPT_IV_LEN, "KC_KEYCRYPT_IV_LEN");
_Static_assert(offsetof(struct keycrypt_open_params, iv) == 16 &&
	       offsetof(struct keycrypt_info, backend) == 32,
	       "the layout of the uapi");

struct kc_kcrypt {
	int fd;
	int32_t serial;
	int encrypt;
	uint32_t alg;
	unsigned char iv[KC_KEYCRYPT_IV_LEN];
	char backend[KC_KEYCRYPT_BACKEND_MAX + 1];
};

/*
 * What the kernel's errno says, where it says more than its name: the
 * same at the opening and on every later call
 */
static const char *cause(int err, int encrypt)
{
	switch (err) {
	case EKEYREJECTED:
		return encrypt ?
			"the purpose of the key does not allow encryption" :
			"the purpose of the key does not allow decryption";
	case EPERM:
		return "not permitted: the tier of the key is below the "
			"minimum asked or the system's "
			"(kernel.keys.keycrypt_system_tier), or a policy "
			"refuses it";
	case ENODEV:
		return "the backend of the key is gone, or has no operations: "
			"load the key again";
	case EACCES:
		return "no Search permission on the key";
	case ENOMEM:
		return "out of memory, or no free operation context in the "
			"backend of the key";
	default:
		return NULL;
	}
}

static int fail(struct kc_error *e, int err, int32_t serial, int encrypt)
{
	const char *c = cause(err, encrypt);

	return kc_fail(e, KC_FAILED, err, "keycrypt, key %d: %s", serial,
		       c ? c : strerror(err));
}

static bool all_zero(const unsigned char *p, size_t len)
{
	size_t i;

	for (i = 0; i < len; i++)
		if (p[i])
			return false;
	return true;
}

/* Lower case, digits, '_' and '-', NUL terminated within the field */
static bool backend_name_ok(const char *name, size_t size)
{
	size_t i;

	for (i = 0; i < size && name[i]; i++)
		if (!((name[i] >= 'a' && name[i] <= 'z') ||
		      (name[i] >= '0' && name[i] <= '9') ||
		      name[i] == '_' || name[i] == '-'))
			return false;
	return i > 0 && i <= KC_KEYCRYPT_BACKEND_MAX && i < size;
}

int kc_keycrypt_open(struct kc_kcrypt **x, int32_t serial, int encrypt,
		     const void *iv, unsigned int min_tier, struct kc_error *e)
{
	struct keycrypt_open_params p = {};
	struct keycrypt_info info = {};
	struct kc_kcrypt *kx;
	unsigned int op;
	int fd, err;

	*x = NULL;
	p.op = encrypt ? KEYCRYPT_OP_ENCRYPT : KEYCRYPT_OP_DECRYPT;
	p.accepted_min_tier = min_tier;
	if (iv) {
		memcpy(p.iv, iv, sizeof(p.iv));
		if (encrypt)
			p.flags = KEYCRYPT_OPEN_CALLER_IV;
	}

	/* ENOSYS too, from a filter that refuses the command */
	fd = syscall(SYS_keyctl, KEYCTL_CRYPT_OPEN, serial, &p, sizeof(p), 0);
	if (fd < 0) {
		err = errno;
		if (err == EOPNOTSUPP || err == ENOSYS)
			return kc_fail(e, KC_REFUSED, err,
				       "the key %d is not a keycrypt key, or the kernel has no keycrypt",
				       serial);
		return fail(e, err, serial, encrypt);
	}

	/*
	 * Which key the kernel opened: its algorithm and its backend. A
	 * descriptor that does not answer may be no context at all (keyctl
	 * KEYCTL_CRYPT_OPEN being another command on this kernel): it is
	 * left open rather than close one this library did not open.
	 */
	if (ioctl(fd, KEYCRYPT_IOC_INFO, &info) < 0) {
		err = errno;
		if (err == ENOTTY)
			return kc_fail(e, KC_FAILED, err,
				       "keyctl %d on key %d gave descriptor %d, which does not answer KEYCRYPT_IOC_INFO: a keycrypt without it, or another command; left open",
				       KEYCTL_CRYPT_OPEN, serial, fd);
		close(fd);
		return kc_fail(e, KC_FAILED, err,
			       "keycrypt, key %d: cannot read its information: %s",
			       serial, strerror(err));
	}
	if (!backend_name_ok(info.backend, sizeof(info.backend))) {
		close(fd);
		return kc_fail(e, KC_FAILED, EPROTO,
			       "keycrypt, key %d: the kernel names its backend with characters other than [a-z0-9_-], or with none",
			       serial);
	}

	/*
	 * A kernel of another interface may not have done what was asked,
	 * compared with the caller's values: the kernel writes into p
	 */
	op = encrypt ? KEYCRYPT_OP_ENCRYPT : KEYCRYPT_OP_DECRYPT;
	if (info.op != op || info.accepted_min_tier != min_tier) {
		close(fd);
		return kc_fail(e, KC_FAILED, EPROTO,
			       "keycrypt, key %d: the kernel opened it for operation %u with minimum tier %u, not %u with %u",
			       serial, info.op, info.accepted_min_tier, op,
			       min_tier);
	}

	/* An IV the kernel did not give back would be lost with the data */
	if (encrypt && (iv ? memcmp(p.iv, iv, sizeof(p.iv)) != 0 :
			all_zero(p.iv, sizeof(p.iv)))) {
		close(fd);
		return kc_fail(e, KC_FAILED, EPROTO,
			       "keycrypt, key %d: the kernel gave back %s",
			       serial, iv ? "another IV than the one given" :
			       "no IV");
	}

	kx = calloc(1, sizeof(*kx));
	if (!kx) {
		close(fd);
		return kc_fail(e, KC_FAILED, ENOMEM, "%s", strerror(ENOMEM));
	}
	kx->fd = fd;
	kx->serial = serial;
	kx->encrypt = encrypt;
	kx->alg = info.alg;
	memcpy(kx->iv, p.iv, sizeof(kx->iv));
	strcpy(kx->backend, info.backend);
	*x = kx;
	return kc_ok(e);
}

/* The kernel's name of the key's algorithm, NULL for one not a cipher here */
const char *kc_keycrypt_algo(const struct kc_kcrypt *x)
{
	return x->alg == KEYCRYPT_ALG_AES256_CBC ? "cbc(aes)" : NULL;
}

/* The bytes of the key's algorithm, which the key's metadata fix */
size_t kc_keycrypt_key_len(const struct kc_kcrypt *x)
{
	return x->alg == KEYCRYPT_ALG_AES256_CBC ? 32 : 0;
}

const unsigned char *kc_keycrypt_iv(const struct kc_kcrypt *x)
{
	return x->iv;
}

const char *kc_keycrypt_backend(const struct kc_kcrypt *x)
{
	return x->backend;
}

int kc_keycrypt_update(struct kc_kcrypt *x, const void *in, void *out,
		       size_t len, struct kc_error *e)
{
	struct keycrypt_update u = {};
	size_t n;

	while (len > 0) {
		n = len > KEYCRYPT_UPDATE_MAX ? KEYCRYPT_UPDATE_MAX : len;
		u.in = (uintptr_t) in;
		u.out = (uintptr_t) out;
		u.len = n;
		if (ioctl(x->fd, KEYCRYPT_IOC_UPDATE, &u) < 0)
			return fail(e, errno, x->serial, x->encrypt);
		in = (const unsigned char *) in + n;
		out = (unsigned char *) out + n;
		len -= n;
	}
	return kc_ok(e);
}

int kc_keycrypt_final(struct kc_kcrypt *x, struct kc_error *e)
{
	struct keycrypt_final f = {};

	if (ioctl(x->fd, KEYCRYPT_IOC_FINAL, &f) < 0)
		return fail(e, errno, x->serial, x->encrypt);
	/* A cipher's final gives nothing back */
	if (f.len != 0)
		return kc_fail(e, KC_FAILED, EPROTO,
			       "keycrypt, key %d: the final gave back %u bytes",
			       x->serial, (unsigned) f.len);
	return kc_ok(e);
}

void kc_keycrypt_close(struct kc_kcrypt *x)
{
	if (!x)
		return;
	close(x->fd);
	explicit_bzero(x, sizeof(*x));
	free(x);
}
