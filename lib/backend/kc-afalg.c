/*
 * kc-afalg.c - the AF_ALG backend of libkcrypto
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
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <linux/if_alg.h>
#include "kc-backend.h"

/* Both fields keep their terminating NUL; too long is a wrong argument */
static int fill_sockaddr(struct sockaddr_alg *sa, const char *type,
			 const char *name, struct kc_error *e)
{
	memset(sa, 0, sizeof(*sa));
	sa->salg_family = AF_ALG;
	if (strlen(type) >= sizeof(sa->salg_type) ||
	    strlen(name) >= sizeof(sa->salg_name))
		return kc_fail(e, KC_USAGE, ENAMETOOLONG, "bind(): %s",
			       strerror(ENAMETOOLONG));
	strcpy((char *) sa->salg_type, type);
	strcpy((char *) sa->salg_name, name);
	return KC_OK;
}

/*
 * The kernel decides, with a bind(): a template such as hmac(sha256) is
 * listed in /proc/crypto only once something has used it since the boot,
 * and a bind() is what builds it. ENOENT is its "no"; another failure,
 * such as ENOMEM, is no answer.
 */
static int afalg_available(const char *type, const char *name,
			   struct kc_error *e)
{
	struct sockaddr_alg sa;
	int s, ret, err, status;

	status = fill_sockaddr(&sa, type, name, e);
	if (status)
		return status;
	s = socket(AF_ALG, SOCK_SEQPACKET, 0);
	if (s < 0) {
		err = errno;
		return kc_fail(e, KC_FAILED, err, "socket(AF_ALG): %s",
			       strerror(err));
	}
	ret = bind(s, (struct sockaddr *) &sa, sizeof(sa));
	err = errno;
	close(s);		/* intentionally ignored */
	if (ret < 0)
		return kc_fail(e, err == ENOENT ? KC_REFUSED : KC_FAILED, err,
			       "bind(): %s", strerror(err));
	return kc_ok(e);
}

const struct kc_backend kc_afalg_backend = {
	.available	= afalg_available,
};
