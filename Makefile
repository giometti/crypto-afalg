TARGET = crypto-afalg
OBJS = crypto-afalg.o crypto-cipher.o crypto-hash.o
CRAF = craf
CRAF_OBJS = craf.o craf-archive.o craf-keys.o craf-driver.o craf-seal.o
LIB = libafalg.so.0
LIB_OBJS = afalg.o
KC = libkcrypto.so.0
KC_OBJS = lib/kc-error.o lib/kc-driver.o lib/backend/kc-afalg.o
KC_CHECK = kc-check
KC_CHECK_OBJS = tests/lib/kc-check.o
DEPS := $(OBJS:.o=.d) $(CRAF_OBJS:.o=.d) $(LIB_OBJS:.o=.d) \
	$(KC_OBJS:.o=.d) $(KC_CHECK_OBJS:.o=.d)

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
LIB_LDLIBS = -lkeyutils
CRAF_LDLIBS = -lkeyutils

PREFIX ?= /usr/bin
LIBDIR ?= /usr/lib
INCLUDEDIR ?= /usr/include

all: $(TARGET) $(CRAF)

%.o: %.c
	$(CC) $(CFLAGS) -MMD -MP $< -o $@ -c

# A shared object needs -fPIC also when CFLAGS comes from the command line;
# hidden visibility leaves out of the interface what afalg.c does not mark
$(LIB_OBJS): override CFLAGS += -fPIC -fvisibility=hidden

# The backends' interface is the library's only, not its users'
$(KC_OBJS): override CFLAGS += -fPIC -fvisibility=hidden -Ilib/backend

# Rewritten only when the version changes, so that a new commit rebuilds
# the objects that carry the version string
.version: FORCE
	@echo '$(VERSION)' | cmp -s - $@ || echo '$(VERSION)' > $@
crypto-afalg.o craf.o: .version

# The same for ASAN, so that make ASAN=1 after a plain make rebuilds all
.asan: FORCE
	@echo '$(ASAN)' | cmp -s - $@ || echo '$(ASAN)' > $@
$(OBJS) $(CRAF_OBJS) $(LIB_OBJS) $(KC_OBJS) $(KC_CHECK_OBJS): .asan

$(LIB): $(LIB_OBJS)
	$(CC) $(CFLAGS) -shared -Wl,-soname,$(LIB) -o $@ $(LIB_OBJS) \
		$(LFLAGS) $(LDFLAGS) $(LIB_LDLIBS)

$(KC): $(KC_OBJS)
	$(CC) $(CFLAGS) -shared -Wl,-soname,$(KC) -o $@ $(KC_OBJS) \
		$(LFLAGS) $(LDFLAGS)

$(TARGET): $(OBJS) $(LIB) $(KC)
	$(CC) $(CFLAGS) -o $(TARGET) $(OBJS) $(LIB) $(KC) $(LFLAGS) $(LDFLAGS) \
		$(LDLIBS)

$(CRAF): $(CRAF_OBJS) $(LIB)
	$(CC) $(CFLAGS) -o $(CRAF) $(CRAF_OBJS) $(LIB) $(LFLAGS) $(LDFLAGS) \
		$(LDLIBS) $(CRAF_LDLIBS)

# The program the tests drive the library with, not installed
$(KC_CHECK): $(KC_CHECK_OBJS) $(KC)
	$(CC) $(CFLAGS) -o $@ $(KC_CHECK_OBJS) $(KC) $(LFLAGS) $(LDFLAGS) \
		$(LDLIBS)

tests:
	@make --no-print-directory -C tests tests

# install(1) replaces the library instead of writing into it, so a process
# that has it mapped keeps its pages
install: $(TARGET) $(CRAF) $(LIB) $(KC)
	mkdir -p $(DESTDIR)$(PREFIX) $(DESTDIR)$(LIBDIR) $(DESTDIR)$(INCLUDEDIR)
	cp $(TARGET) $(DESTDIR)$(PREFIX)/$(TARGET)
	cp $(CRAF) $(DESTDIR)$(PREFIX)/$(CRAF)
	install -m 0755 $(LIB) $(DESTDIR)$(LIBDIR)/$(LIB)
	ln -sf $(LIB) $(DESTDIR)$(LIBDIR)/libafalg.so
	install -m 0644 afalg.h $(DESTDIR)$(INCLUDEDIR)/afalg.h
	install -m 0755 $(KC) $(DESTDIR)$(LIBDIR)/$(KC)
	ln -sf $(KC) $(DESTDIR)$(LIBDIR)/libkcrypto.so
	install -m 0644 lib/kcrypto.h $(DESTDIR)$(INCLUDEDIR)/kcrypto.h

uninstall:
	rm -f $(DESTDIR)$(PREFIX)/$(TARGET)
	rm -f $(DESTDIR)$(PREFIX)/$(CRAF)
	rm -f $(DESTDIR)$(LIBDIR)/$(LIB) $(DESTDIR)$(LIBDIR)/libafalg.so
	rm -f $(DESTDIR)$(INCLUDEDIR)/afalg.h
	rm -f $(DESTDIR)$(LIBDIR)/$(KC) $(DESTDIR)$(LIBDIR)/libkcrypto.so
	rm -f $(DESTDIR)$(INCLUDEDIR)/kcrypto.h

clean:
	rm -f $(OBJS) $(CRAF_OBJS) $(LIB_OBJS) $(TARGET) $(CRAF) $(LIB) $(DEPS) .version
	rm -f .asan
	rm -f $(KC_OBJS) $(KC) $(KC_CHECK_OBJS) $(KC_CHECK)
	@make --no-print-directory -C tests clean

FORCE:

.PHONY: all tests install uninstall clean
-include $(DEPS)
