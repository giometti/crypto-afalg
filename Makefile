TARGET = crypto-afalg
OBJS = crypto-afalg.o crypto-cipher.o crypto-hash.o
CRAF = craf
CRAF_OBJS = craf.o craf-archive.o craf-keys.o craf-driver.o craf-seal.o \
	craf-enc.o
KC = libkcrypto.so.0
KC_OBJS = lib/kc-error.o lib/kc-driver.o lib/kc-key.o lib/kc-hash.o \
	lib/kc-cipher.o lib/kc-openssl.o lib/backend/kc-afalg.o
KC_CHECK = kc-check
KC_CHECK_OBJS = tests/lib/kc-check.o
DEPS := $(OBJS:.o=.d) $(CRAF_OBJS:.o=.d) $(KC_OBJS:.o=.d) \
	$(KC_CHECK_OBJS:.o=.d)

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
CFLAGS += -Ilib

# make tests ASAN=1 reaches the build of each test through MAKEFLAGS;
# override, since a CFLAGS given on the command line replaces the += above
ifeq ($(ASAN),1)
override CFLAGS += -fsanitize=address -fno-omit-frame-pointer -g
endif
KC_LDLIBS = -lkeyutils
CRAF_LDLIBS = -lkeyutils
KC_CHECK_LDLIBS = -lkeyutils

PREFIX ?= /usr/bin
LIBDIR ?= /usr/lib
INCLUDEDIR ?= /usr/include

all: $(TARGET) $(CRAF)

%.o: %.c
	$(CC) $(CFLAGS) -MMD -MP $< -o $@ -c

# A shared object needs -fPIC also when CFLAGS comes from the command line;
# hidden visibility leaves out of the interface what kcrypto.h does not
# declare, and the backends' interface is the library's only, not its users'
$(KC_OBJS): override CFLAGS += -fPIC -fvisibility=hidden -Ilib/backend

# Rewritten only when the version changes, so that a new commit rebuilds
# the objects that carry the version string
.version: FORCE
	@echo '$(VERSION)' | cmp -s - $@ || echo '$(VERSION)' > $@
crypto-afalg.o craf.o: .version

# The same for ASAN, so that make ASAN=1 after a plain make rebuilds all
.asan: FORCE
	@echo '$(ASAN)' | cmp -s - $@ || echo '$(ASAN)' > $@
$(OBJS) $(CRAF_OBJS) $(KC_OBJS) $(KC_CHECK_OBJS): .asan

$(KC): $(KC_OBJS)
	$(CC) $(CFLAGS) -shared -Wl,-soname,$(KC) -o $@ $(KC_OBJS) \
		$(LFLAGS) $(LDFLAGS) $(KC_LDLIBS)

$(TARGET): $(OBJS) $(KC)
	$(CC) $(CFLAGS) -o $(TARGET) $(OBJS) $(KC) $(LFLAGS) $(LDFLAGS) $(LDLIBS)

$(CRAF): $(CRAF_OBJS) $(KC)
	$(CC) $(CFLAGS) -o $(CRAF) $(CRAF_OBJS) $(KC) $(LFLAGS) $(LDFLAGS) \
		$(LDLIBS) $(CRAF_LDLIBS)

# The program the tests drive the library with, not installed
$(KC_CHECK): $(KC_CHECK_OBJS) $(KC)
	$(CC) $(CFLAGS) -o $@ $(KC_CHECK_OBJS) $(KC) $(LFLAGS) $(LDFLAGS) \
		$(LDLIBS) $(KC_CHECK_LDLIBS)

tests:
	@make --no-print-directory -C tests tests

# install(1) replaces the library instead of writing into it, so a process
# that has it mapped keeps its pages
install: $(TARGET) $(CRAF) $(KC)
	mkdir -p $(DESTDIR)$(PREFIX) $(DESTDIR)$(LIBDIR) $(DESTDIR)$(INCLUDEDIR)
	cp $(TARGET) $(DESTDIR)$(PREFIX)/$(TARGET)
	cp $(CRAF) $(DESTDIR)$(PREFIX)/$(CRAF)
	install -m 0755 $(KC) $(DESTDIR)$(LIBDIR)/$(KC)
	ln -sf $(KC) $(DESTDIR)$(LIBDIR)/libkcrypto.so
	install -m 0644 lib/kcrypto.h $(DESTDIR)$(INCLUDEDIR)/kcrypto.h

# Also libafalg, which libkcrypto replaces, as an older version installed it
uninstall:
	rm -f $(DESTDIR)$(PREFIX)/$(TARGET)
	rm -f $(DESTDIR)$(PREFIX)/$(CRAF)
	rm -f $(DESTDIR)$(LIBDIR)/$(KC) $(DESTDIR)$(LIBDIR)/libkcrypto.so
	rm -f $(DESTDIR)$(INCLUDEDIR)/kcrypto.h
	rm -f $(DESTDIR)$(LIBDIR)/libafalg.so.0 $(DESTDIR)$(LIBDIR)/libafalg.so
	rm -f $(DESTDIR)$(INCLUDEDIR)/afalg.h

# Also libafalg.so.0, which a build of an older version left here
clean:
	rm -f $(OBJS) $(CRAF_OBJS) $(TARGET) $(CRAF) $(DEPS) .version
	rm -f .asan
	rm -f $(KC_OBJS) $(KC) $(KC_CHECK_OBJS) $(KC_CHECK)
	rm -f libafalg.so.0
	@make --no-print-directory -C tests clean

FORCE:

.PHONY: all tests install uninstall clean
-include $(DEPS)
