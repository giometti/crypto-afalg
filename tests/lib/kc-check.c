/*
 * kc-check.c - drive libkcrypto from the tests
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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/resource.h>
#include "kcrypto.h"

/* Not a kc_status: the command line of kc-check itself was wrong */
#define EXIT_USAGE		64

static void __attribute__((noreturn)) usage(void)
{
	fprintf(stderr,
		"usage: kc-check [exhaust] <command> <args...>\n"
		"  available <type> <name>\n"
		"  driver <type> <driver> <algo>\n"
		"exhaust: no file descriptor left before the command\n"
		"exit status: the kc_status, %d for a wrong command line\n",
		EXIT_USAGE);
	exit(EXIT_USAGE);
}

/*
 * Takes every free file descriptor under a limit lowered for this, so
 * that the next open fails; they go back before the exit, which
 * AddressSanitizer needs some for
 */
#define FD_LIMIT		64

static struct rlimit saved;
static int taken[FD_LIMIT];
static int ntaken;

static void exhaust(void)
{
	struct rlimit low;
	int fd;

	if (getrlimit(RLIMIT_NOFILE, &saved) < 0) {
		perror("kc-check: getrlimit");
		exit(EXIT_USAGE);
	}
	low = saved;
	if (low.rlim_cur > FD_LIMIT)
		low.rlim_cur = FD_LIMIT;
	if (setrlimit(RLIMIT_NOFILE, &low) < 0) {
		perror("kc-check: setrlimit");
		exit(EXIT_USAGE);
	}
	while (ntaken < FD_LIMIT && (fd = dup(STDERR_FILENO)) >= 0)
		taken[ntaken++] = fd;
}

static void release(void)
{
	if (ntaken == 0)
		return;
	while (ntaken > 0)
		close(taken[--ntaken]);	/* intentionally ignored */
	setrlimit(RLIMIT_NOFILE, &saved);	/* intentionally ignored */
}

/*
 * The status is the exit status; a failure also prints what the library
 * filled in, which must agree with what it returned
 */
static int report(int status, const struct kc_error *e)
{
	if ((int) e->status != status) {
		fprintf(stderr, "kc-check: returned %d, filled in %d\n",
			status, e->status);
		return EXIT_USAGE;
	}
	if (status != KC_OK)
		fprintf(stderr, "kc-check: status=%d errnum=%d: %s\n",
			status, e->errnum, e->msg);
	return status;
}

int main(int argc, char *argv[])
{
	struct kc_error e;
	int status;

	/* A status left from before must be overwritten, KC_OK too */
	memset(&e, 0x5a, sizeof(e));
	if (argc > 1 && strcmp(argv[1], "exhaust") == 0) {
		argc--;
		argv++;
		exhaust();
	}
	if (argc < 2)
		usage();

	if (strcmp(argv[1], "available") == 0 && argc == 4)
		status = kc_algo_available(argv[2], argv[3], &e);
	else if (strcmp(argv[1], "driver") == 0 && argc == 5)
		status = kc_driver_check(argv[2], argv[3], argv[4], &e);
	else
		usage();
	release();

	return report(status, &e);
}
