AM_MAKEFLAGS = --no-print-directory

AM_CFLAGS = $(WARNING_CFLAGS) $(BUILD_CFLAGS)
AM_LDFLAGS = $(BUILD_LDFLAGS)

dbusdir = @DBUS_CONFDIR@/dbus-1/system.d
dbus_DATA = src/nrf24.conf

knotconfigdir = @KNOTCONFIGDIR@
knotconfig_DATA = src/nrf24-keys.conf src/nrf24-radio.conf

bin_PROGRAMS = src/nrfd
noinst_PROGRAMS =

src_nrfd_SOURCES = src/main.c \
		   src/settings.h src/settings.c \
		   src/manager.h src/manager.c \
		   src/adapter.h src/adapter.c \
		   src/device.h src/device.c \
		   src/storage.h src/storage.c \
		   src/dbus.h src/dbus.c

src_nrfd_LDADD = @ELL_LIBS@ @KNOTHAL_LIBS@

src_nrfd_LDFLAGS = $(AM_LDFLAGS)
src_nrfd_CFLAGS = $(AM_CFLAGS) @ELL_CFLAGS@ @KNOTHAL_CFLAGS@

EXTRA_DIST = src/nrf24.conf

DISTCLEANFILES =

MAINTAINERCLEANFILES = Makefile.in \
	aclocal.m4 configure config.h.in config.sub config.guess \
	ltmain.sh depcomp compile missing install-sh

clean-local:
	$(RM) src/nrfd
