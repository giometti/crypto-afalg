TARGET = crypto-afalg
OBJS = crypto-afalg.o crypto-cipher.o crypto-hash.o
DEPS := $(OBJS:.o=.d)

VERSION := $(shell git describe --tags --long 2>/dev/null || echo v0.0.0-0-g0000000)

CFLAGS += -O -Wall -Werror -D_GNU_SOURCE
CFLAGS += -D__CRYPTO_AFALG_VERSION__=\"$(VERSION)\"
LDLIBS += -lkeyutils

PREFIX ?= /usr/bin

all: $(TARGET)

%.o: %.c
	$(CC) $(CFLAGS) -MMD -MP $< -o $@ -c

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
	rm -f $(OBJS) $(TARGET) $(DEPS)
	@make --no-print-directory -C tests clean

.PHONY: all tests install uninstall clean
-include $(DEPS)
