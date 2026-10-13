TARGET = crypto-afalg
OBJS = crypto-afalg.o crypto-cipher.o crypto-hash.o
CRAF = craf
CRAF_OBJS = craf.o craf-archive.o craf-keys.o craf-driver.o craf-seal.o
LIB = libafalg.so.0
LIB_OBJS = afalg.o
DEPS := $(OBJS:.o=.d) $(CRAF_OBJS:.o=.d) $(LIB_OBJS:.o=.d)

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

# Rewritten only when the version changes, so that a new commit rebuilds
# the objects that carry the version string
.version: FORCE
	@echo '$(VERSION)' | cmp -s - $@ || echo '$(VERSION)' > $@
crypto-afalg.o craf.o: .version

$(LIB): $(LIB_OBJS)
	$(CC) $(CFLAGS) -shared -Wl,-soname,$(LIB) -o $@ $(LIB_OBJS) \
		$(LFLAGS) $(LDFLAGS) $(LIB_LDLIBS)

$(TARGET): $(OBJS) $(LIB)
	$(CC) $(CFLAGS) -o $(TARGET) $(OBJS) $(LIB) $(LFLAGS) $(LDFLAGS) $(LDLIBS)

$(CRAF): $(CRAF_OBJS) $(LIB)
	$(CC) $(CFLAGS) -o $(CRAF) $(CRAF_OBJS) $(LIB) $(LFLAGS) $(LDFLAGS) \
		$(LDLIBS) $(CRAF_LDLIBS)

tests:
	@make --no-print-directory -C tests tests

# install(1) replaces the library instead of writing into it, so a process
# that has it mapped keeps its pages
install: $(TARGET) $(CRAF) $(LIB)
	mkdir -p $(DESTDIR)$(PREFIX) $(DESTDIR)$(LIBDIR) $(DESTDIR)$(INCLUDEDIR)
	cp $(TARGET) $(DESTDIR)$(PREFIX)/$(TARGET)
	cp $(CRAF) $(DESTDIR)$(PREFIX)/$(CRAF)
	install -m 0755 $(LIB) $(DESTDIR)$(LIBDIR)/$(LIB)
	ln -sf $(LIB) $(DESTDIR)$(LIBDIR)/libafalg.so
	install -m 0644 afalg.h $(DESTDIR)$(INCLUDEDIR)/afalg.h

uninstall:
	rm -f $(DESTDIR)$(PREFIX)/$(TARGET)
	rm -f $(DESTDIR)$(PREFIX)/$(CRAF)
	rm -f $(DESTDIR)$(LIBDIR)/$(LIB) $(DESTDIR)$(LIBDIR)/libafalg.so
	rm -f $(DESTDIR)$(INCLUDEDIR)/afalg.h

clean:
	rm -f $(OBJS) $(CRAF_OBJS) $(LIB_OBJS) $(TARGET) $(CRAF) $(LIB) $(DEPS) .version
	@make --no-print-directory -C tests clean

FORCE:

.PHONY: all tests install uninstall clean
-include $(DEPS)
