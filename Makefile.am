AM_MAKEFLAGS = --no-print-directory

AM_CFLAGS = $(WARNING_CFLAGS) $(BUILD_CFLAGS)
AM_LDFLAGS = $(BUILD_LDFLAGS)

dbusdir = @DBUS_CONFDIR@/dbus-1/system.d
dbus_DATA = src/nrf24.conf

bin_PROGRAMS = src/nrfd
noinst_PROGRAMS =

noinst_LTLIBRARIES = ell/libell-internal.la

ell_sources = ell/ell.h ell/private.h ell/missing.h \
			ell/util.h ell/util.c \
			ell/test.h ell/test.c \
			ell/queue.h ell/queue.c \
			ell/hashmap.h ell/hashmap.c \
			ell/ringbuf.h ell/ringbuf.c \
			ell/string.h ell/string.c \
			ell/settings.h ell/settings.c \
			ell/main.h ell/main.c \
			ell/idle.h ell/idle.c \
			ell/signal.h ell/signal.c \
			ell/timeout.h ell/timeout.c \
			ell/io.h ell/io.c \
			ell/log.h ell/log.c \
			ell/plugin.h ell/plugin.c \
			ell/checksum.h ell/checksum.c \
			ell/netlink-private.h \
			ell/netlink.h ell/netlink.c \
			ell/genl-private.h \
			ell/genl.h ell/genl.c \
			ell/dbus-private.h \
			ell/dbus.h ell/dbus.c \
			ell/dbus-util.c \
			ell/dbus-message.c \
			ell/dbus-service.h ell/dbus-service.c \
			ell/dbus-filter.c \
			ell/dbus-name-cache.c \
			ell/gvariant-private.h \
			ell/gvariant-util.c \
			ell/siphash-private.h \
			ell/siphash.c \
			ell/hwdb.h ell/hwdb.c \
			ell/cipher.h ell/cipher.c \
			ell/random.h ell/random.c \
			ell/uintset.h ell/uintset.c \
			ell/base64.h ell/base64.c \
			ell/pem.h ell/pem.c \
			ell/tls-private.h \
			ell/tls.h ell/tls.c \
			ell/tls-record.c \
			ell/uuid.h ell/uuid.c \
			ell/key.h ell/key.c \
			ell/asn1-private.h \
			ell/pkcs5.h ell/pkcs5.c \
			ell/pkcs5-private.h \
			ell/file.h ell/file.c \
			ell/dbus-client.h ell/dbus-client.c

ell_libell_internal_la_SOURCES = $(ell_sources)

src_nrfd_SOURCES = src/main.c \
		   src/settings.h src/settings.c \
		   src/manager.h src/manager.c \
		   src/adapter.h src/adapter.c \
		   src/device.h src/device.c \
		   src/storage.h src/storage.c \
		   src/dbus.h src/dbus.c

src_nrfd_LDADD = @JSON_LIBS@ \
		ell/libell-internal.la -lm

src_nrfd_LDFLAGS = $(AM_LDFLAGS)
src_nrfd_CFLAGS = $(AM_CFLAGS) @JSON_CFLAGS@

BUILT_SOURCES = ell/internal

ell/internal: Makefile
	$(AM_V_at)$(MKDIR_P) ell
	$(AM_V_GEN)for f in $(ell_sources) ; do \
		if [ ! -f $$f ] ; then \
			$(LN_S) -t ell -f $(abs_srcdir)/../ell.git/$$f ; \
		fi \
	done > $@
	$(AM_V_at)$(MKDIR_P) linux
	$(AM_V_GEN)for f in $(ell_linux_headers) ; do \
		if [ ! -f $$f ] ; then \
			$(LN_S) -t linux -f $(abs_srcdir)/../ell.git/$$f ; \
		fi \
	done > $@

EXTRA_DIST = src/nrf24.conf

DISTCLEANFILES =

MAINTAINERCLEANFILES = Makefile.in \
	aclocal.m4 configure config.h.in config.sub config.guess \
	ltmain.sh depcomp compile missing install-sh

maintainer-clean-local:
	$(RM) -rf ell

clean-local:
	$(RM) src/nrfd
