CC       ?= gcc
CFLAGS   ?= -O2
# Required flags are kept separate so overriding CFLAGS does not drop them.
override CFLAGS += -std=gnu11 -Wall -Wextra -Wno-unused-parameter -MMD -MP

PREFIX     ?= /usr
BINDIR     ?= $(PREFIX)/bin
SBINDIR    ?= $(PREFIX)/sbin
MANDIR     ?= $(PREFIX)/share/man
SYSCONFDIR ?= /etc
USERSFILE  ?= $(SYSCONFDIR)/mactelnetd.users

# Run this with make LIBS=-lrt if you want to compile on kfreebsd

BINS  = macping mndp mactelnet mactelnetd
OBJS  = protocol.o interfaces.o md5.o console.o users.o mndp_client.o

.PHONY: all clean distclean potclean dist install install-strip install-docs pot

all: $(BINS)

# Link rules
mactelnet: mactelnet.o protocol.o console.o interfaces.o users.o md5.o mndp_client.o
mactelnetd: mactelnetd.o protocol.o console.o interfaces.o users.o md5.o
mndp: mndp.o protocol.o
macping: macping.o interfaces.o protocol.o

$(BINS):
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $^ $(LIBS)

# The credentials file path is compiled into users.o
users.o: CPPFLAGS += -DUSERSFILE='"$(USERSFILE)"'

# mactelnet embeds the MNDP discovery code from mndp.c
mndp_client.o: mndp.c
	$(CC) $(CPPFLAGS) $(CFLAGS) -DFROM_MACTELNET -c -o $@ $<

%.o: %.c
	$(CC) $(CPPFLAGS) $(CFLAGS) -c -o $@ $<

clean:
	rm -f $(BINS) *.o *.d

distclean: clean

potclean:
	rm -f po/*.pot

dist: distclean potclean pot

# Ownership is left to the caller; packagers use DESTDIR, root installs
# can pass INSTALL_OWNER="-o root".
INSTALL_OWNER ?=

install: all install-docs
	install -d $(DESTDIR)$(BINDIR) $(DESTDIR)$(SBINDIR) $(DESTDIR)$(SYSCONFDIR)
	install $(INSTALL_STRIP) mndp macping mactelnet $(DESTDIR)$(BINDIR)/
	install $(INSTALL_STRIP) $(INSTALL_OWNER) mactelnetd $(DESTDIR)$(SBINDIR)/
	@if [ -e "$(DESTDIR)$(USERSFILE)" ]; then \
		echo "keeping existing $(DESTDIR)$(USERSFILE)"; \
	else \
		install -m 600 $(INSTALL_OWNER) config/mactelnetd.users $(DESTDIR)$(USERSFILE); \
	fi

install-strip:
	$(MAKE) install INSTALL_STRIP=-s

install-docs:
	install -d $(DESTDIR)$(MANDIR)/man1/
	install -m 644 docs/*.1 $(DESTDIR)$(MANDIR)/man1/

pot: po/mactelnet.pot

po/mactelnet.pot: *.c
	xgettext --package-name=mactelnet --msgid-bugs-address=haakon.nessjoen@gmail.com -d mactelnet -C -c_ -k_ -kgettext_noop *.c -o po/mactelnet.pot

-include $(wildcard *.d)
