#!/bin/bash
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Rodolfo Giometti <giometti@enneenne.com>
#
# git-version.sh - print the version string per programming-rules.md:
# git describe --tags --long --match "v*" --dirty, with graceful fallbacks.
#
# The value printed here is UNTRUSTED INPUT, and that is the reason for the
# check at the end. It is derived from a git ref name in the repository being
# built, and git permits characters in a ref name that are syntax everywhere
# this value is then used: a quote, a backtick, a dollar-parenthesis, a
# semicolon, and the characters people pick as sed delimiters.
#
# Every stamping form (the version-stamping skill) puts this string into the
# text of a PROGRAM -- into shell source through an @VERSION@ placeholder, into
# the replacement half of a sed substitution, into a compiler command line as
# -DVERSION="...". So a value carrying a quote does not merely look wrong: in
# the shell form it closes the string and what follows is parsed as commands,
# in the sed form it can close the s command and the remainder is read as
# further sed commands, and in the -D form it ends the string literal and the
# rest becomes preprocessor input.
#
# The victim's command line is the documented one. Cloning a repository and
# building it is the most ordinary thing anyone does with a tool, and the
# payload travels inside the repository, in a place nobody inspects.
#
# Validating HERE is what makes the fix portable: this is the one place the
# value is produced, so the check acts before it reaches any of the three
# forms. Quoting each substitution site instead would need three different
# remedies and would have to be repeated at every new site, forever.
#
# The grammar is not invented here -- it is the one programming-rules.md
# publishes, and the same expression the test suite has always asserted. It
# lived only there, which is the one place that cannot protect an install: the
# suite runs on the developer's machine, never on the machine building a clone.
#
# Exit status -- three outcomes, and the caller must keep them apart:
#   0  the version is on stdout: a real one, or the reserved all-zeros value
#      v0.0.0-0-g0000000, which means "no version specified"
#   1  a version was computed and REFUSED: it does not match the format
#   2  the version COULD NOT BE DETERMINED -- git absent, HEAD unreadable, the
#      tree refused over its ownership check. Never degraded into the
#      all-zeros value, which asserts a fact ("this tree is not a
#      repository") that was never established.

set -u

# the published format (see the Version section of programming-rules.md)
FORMAT='^v[0-9]+\.[0-9]+\.[0-9]+-[0-9]+-g[0-9a-f]+(-dirty)?$'
NO_VERSION=v0.0.0-0-g0000000

# The format is written with range classes, and in =~ a range follows the
# locale: under en_US.UTF-8, [0-9] takes an Arabic-Indic digit and [0-9a-f]
# an accented letter. Pinned here, at the one door every match goes through,
# and not for the whole script: git's own children keep the operator's
# locale, so the -dirty reported is the one their own git describe reports.
is_version() { # <string>
	local LC_ALL=C

	[[ $1 =~ $FORMAT ]]
}

self=$(readlink -f "$0") || exit 2
root=${self%/*/*} # <project>/tools/<script>

# The line above strips two components on the strength of a layout nothing
# has checked. Get that wrong and root lands on some other directory -- and
# if that one happens to be a git toplevel, the comparison below is
# satisfied by coincidence and the helper reports a stranger's version,
# well-formed and status 0. Refusing here is the difference between a tool
# that is in the wrong place and a tool that lies about where it is.
#
# The IMMEDIATE parent is what is asserted, not the mere presence of a
# `tools` component somewhere in the path: at <project>/tools/sub/<script>
# a looser test passes while root lands on <project>/tools, which is the
# guess this refusal exists to prevent.
parent=${self%/*}
if [ "${parent##*/}" != tools ]; then
	printf '%s: refusing to guess: expected <project>/tools/%s, got %s\n' \
		"${self##*/}" "${self##*/}" "$self" >&2
	exit 2
fi

fail() {
	printf '%s: %s\n' "${self##*/}" "$1" >&2
	exit 2
}

refuse() {
	printf '%s: refusing the version string %q\n' "${self##*/}" "$1" >&2
	printf '  it does not match the published format -- see the Version\n' >&2
	printf '  section of programming-rules.md. The value comes from a git\n' >&2
	printf '  ref name and is stamped into program text, so a tag carrying\n' >&2
	printf '  shell or sed syntax would be code by the time it is installed.\n' >&2
	exit 1
}

command -v git > /dev/null 2>&1 ||
	fail "cannot determine the version: git not found"

# `git -C` picks a DIRECTORY, and these outrank it: with GIT_DIR pointing
# elsewhere and GIT_WORK_TREE pointing here, the toplevel comparison below is
# satisfied and describe answers from the stranger's object store -- a
# well-formed foreign version at status 0, which is the defect the anchoring
# exists to close, reached through the environment instead of the tree. No
# attacker is needed: a git hook, `git rebase --exec` and `git bisect run` all
# export them, and GIT_INDEX_FILE alone perturbs the -dirty determination.
unset GIT_DIR GIT_WORK_TREE GIT_COMMON_DIR GIT_OBJECT_DIRECTORY \
	GIT_INDEX_FILE GIT_CEILING_DIRECTORIES

# Which repository git answers for is decided by the directory tree and by the
# environment just cleared, not by this project: git walks upwards, so an
# unpacked copy sitting inside another repository would be stamped with THAT
# repository's version. The value is
# well-formed, so nothing downstream objects, and it names a commit holding
# none of this code -- and the cross-check the rule prescribes against a wrong
# stamp (run --version, compare with git describe) consults the same enclosing
# repository, agrees, and can never catch it.
#
# Interrogating $root rather than the working directory is the second half of
# the same fix: otherwise the helper describes wherever it was invoked from,
# and is correct only because make happens to run it from the project root.
#
# LC_ALL=C is load-bearing: the branch below distinguishes "no repository"
# from "git could not answer" by reading git's message, and git localises
# it. Without the pin, a tree with no repository at all is reported as
# could-not-determine on any machine whose locale is not English -- two of
# the three outcomes collapsed, which is what this file exists to prevent.
#
# stderr is kept OUT of the value: git chatters on stderr while exiting 0 --
# a trace facility switched on, an unreadable .gitconfig under the changed
# HOME of a privileged install. Merged in, that text prefixes the toplevel,
# the comparison below cannot match, and a real repository is stamped with
# the reserved value at status 0. Silently, and in the reassuring direction.
top=$(LC_ALL=C git -C "$root" rev-parse --show-toplevel 2> /dev/null)
case $? in
0) ;;
*)
	err=$(LC_ALL=C git -C "$root" rev-parse --show-toplevel 2>&1 > /dev/null)
	[[ $err == *"not a git repository"* ]] ||
		fail "cannot determine the version: $err"
	# That message does not carry the distinction it looks like it
	# carries: git says it both for "there is no repository here" and
	# for "there is one here and it is broken" -- a corrupt, missing or
	# unreadable HEAD, a deleted objects/. Measured: all four damaged
	# fixtures produce it byte for byte, identical to the no-repository
	# case.
	#
	# So the filesystem is asked instead. Something git-shaped at $root
	# means the second case, and nothing was established about this
	# tree -- while the reserved value would assert that it HAS no
	# version, which is the reassuring direction and the one nobody
	# checks. The test is -e and not -d because a worktree and a
	# submodule carry .git as a FILE.
	#
	# Written as an if: `[ -e … ] && fail` is correct only while
	# nothing needs the status of that line, so it is one `set -e` away
	# from exiting 1 on the ordinary path where $root/.git is simply
	# absent.
	if [ -e "$root/.git" ]; then
		fail "cannot determine the version: $root/.git is unusable"
	fi
	top=
	;;
esac

if [ -z "$top" ] || [ "$(readlink -f "$top")" != "$root" ]; then
	printf '%s\n' "$NO_VERSION" # no repository of our own
	exit 0
fi

if v=$(git -C "$root" describe --tags --long --match "v*" --dirty \
	2> /dev/null); then
	is_version "$v" || refuse "$v"
else
	# A repository without a v* tag: synthesize from the commit count and
	# the hash. An error in either is status 2, never the all-zeros value:
	# a real repository with an unreadable HEAD is not a tree without a
	# repository. --short=7 pins the width that bare --short leaves to
	# git's adaptive abbreviation.
	c=$(git -C "$root" rev-list --count HEAD 2> /dev/null) ||
		fail "cannot determine the version: HEAD is unreadable"
	h=$(git -C "$root" rev-parse --short=7 HEAD 2> /dev/null) ||
		fail "cannot determine the version: HEAD is unreadable"
	# -dirty must flag a staged change too: a worktree reverted after a
	# git add still differs from HEAD.
	d=$(git -C "$root" diff --quiet HEAD 2> /dev/null &&
		git -C "$root" diff --cached --quiet 2> /dev/null || echo -dirty)
	v="v0.0.0-$c-g$h$d"
	is_version "$v" || refuse "$v"
fi

printf '%s\n' "$v"
