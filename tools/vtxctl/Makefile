CC ?= cc
CFLAGS ?= -O2 -g
CFLAGS += -std=gnu11 -Wall -Wextra -Wshadow -Wformat=2 -Wno-unused-parameter -D_FORTIFY_SOURCE=2 -fstack-protector-strong
LDFLAGS ?=
STATIC ?=

OBJS := vtxctl.o fmt.o ksyms.o

all: vtxctl

vtxctl: $(OBJS)
	$(CC) $(CFLAGS) $(STATIC) -o $@ $(OBJS) $(LDFLAGS)

%.o: %.c fmt.h ksyms.h ../../include/uapi/vtxhv.h
	$(CC) $(CFLAGS) -c -o $@ $<

install: vtxctl
	install -D -m 0755 vtxctl $(DESTDIR)/usr/local/sbin/vtxctl

clean:
	rm -f vtxctl $(OBJS)

.PHONY: all install clean
