TARGET = crypto-afalg
OBJS = crypto-afalg.o crypto-cipher.o crypto-hash.o
DEPS := $(OBJS:.o=.d)

# The directory of this Makefile: the version belongs to the source tree it
# lives in, also when the build runs elsewhere (make -C <dir> -f <this>)
TOPDIR := $(dir $(lastword $(MAKEFILE_LIST)))

# The helper validates the string and reports a refusal through its exit
# status, which $(shell) would otherwise drop; override keeps a command-line
# VERSION= from replacing the validated value. Only clean and uninstall need
# no version, so it is skipped when nothing else was asked for; no goal at
# all is the default one, which needs it
ifneq ($(if $(MAKECMDGOALS),$(filter-out clean uninstall,$(MAKECMDGOALS)),all),)
override VERSION := $(shell $(TOPDIR)tools/git-version.sh)
ifeq ($(.SHELLSTATUS),1)
$(error refusing to build: the version string was rejected)
else ifneq ($(.SHELLSTATUS),0)
$(error refusing to build: the version string could not be determined)
endif
endif

CFLAGS += -O -Wall -Werror -D_GNU_SOURCE
CFLAGS += -D__CRYPTO_AFALG_VERSION__=\"$(VERSION)\"
LDLIBS += -lkeyutils

PREFIX ?= /usr/bin

all: $(TARGET)

%.o: %.c
	$(CC) $(CFLAGS) -MMD -MP $< -o $@ -c

# Rewritten only when the version changes, so that a new commit rebuilds
# the object that carries the version string
.version: FORCE
	@echo '$(VERSION)' | cmp -s - $@ || echo '$(VERSION)' > $@
crypto-afalg.o: .version

$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) -o $(TARGET) $(OBJS) $(LFLAGS) $(LDFLAGS) $(LDLIBS)

tests:
	@make --no-print-directory -C tests tests

install: $(TARGET)
	mkdir -p $(DESTDIR)$(PREFIX)
	cp $< $(DESTDIR)$(PREFIX)/$(TARGET)

uninstall:
	rm -f $(DESTDIR)$(PREFIX)/$(TARGET)

clean:
	rm -f $(OBJS) $(TARGET) $(DEPS) .version
	@make --no-print-directory -C tests clean

FORCE:

.PHONY: all tests install uninstall clean
-include $(DEPS)
