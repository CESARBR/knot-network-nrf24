AC_PREREQ(2.60)
AC_INIT(nrfd, 0.0)

AC_CONFIG_HEADERS(config.h)

AM_INIT_AUTOMAKE([subdir-objects foreign color-tests silent-rules])

m4_ifdef([AM_SILENT_RULES], [AM_SILENT_RULES([yes])])

AM_MAINTAINER_MODE

AC_PREFIX_DEFAULT(/usr/local)

PKG_PROG_PKG_CONFIG

COMPILER_WARNING_CFLAGS
COMPILER_BUILD_CFLAGS

AC_LANG_C

AC_PROG_CC
AC_PROG_CC_PIE
AC_PROG_INSTALL
AC_PROG_MKDIR_P
AC_PROG_LN_S

LT_PREREQ(2.2)
LT_INIT([disable-static])

PKG_CHECK_MODULES(ELL, ell,
  [AC_DEFINE([HAVE_ELL],[1],[Use ELL])],
  [AC_MSG_ERROR("ell missing")])
AC_SUBST(ELL_CFLAGS)
AC_SUBST(ELL_LIBS)

PKG_CHECK_MODULES(KNOTHAL, hal,
  [AC_DEFINE([HAVE_KNOTHAL],[1],[Use KNOTHAL])],
  [AC_MSG_ERROR("KNoT-HAL missing")])
AC_SUBST(KNOTHAL_CFLAGS)
AC_SUBST(KNOTHAL_LIBS)

if (test "$sysconfdir" = '${prefix}/etc'); then
	knotconfigdir="${prefix}/etc/knot"
else
	knotconfigdir="${sysconfdir}/knot"
fi

AC_ARG_WITH([dbusconfdir], AC_HELP_STRING([--with-dbusconfdir=DIR],
                                [path to D-Bus configuration directory]),
                                        [path_dbusconfdir=${withval}])
if (test -z "${path_dbusconfdir}"); then
        AC_MSG_CHECKING([D-Bus configuration directory])
        path_dbusconfdir="`$PKG_CONFIG --variable=sysconfdir dbus-1`"
        if (test -z "${path_dbusconfdir}"); then
                AC_MSG_ERROR([D-Bus configuration directory is required])
        fi
        AC_MSG_RESULT([${path_dbusconfdir}])
fi
AC_SUBST(DBUS_CONFDIR, [${path_dbusconfdir}])

AC_DEFINE_UNQUOTED(KNOTCONFIGDIR, "${knotconfigdir}",
			[Directory for the KNoT configuration files])
AC_SUBST(KNOTCONFIGDIR, "${knotconfigdir}")

AC_ARG_ENABLE(optimization, AC_HELP_STRING([--disable-optimization],
			[disable code optimization through compiler]), [
	if (test "${enableval}" = "no"); then
		CFLAGS="$CFLAGS -U_FORTIFY_SOURCE -O0"
	fi
])

AC_ARG_ENABLE(debug, AC_HELP_STRING([--enable-debug],
			[enable compiling with debugging information]), [
	if (test "${enableval}" = "yes" &&
				test "${ac_cv_prog_cc_g}" = "yes"); then
		CFLAGS="$CFLAGS -g"
	fi
])

AC_ARG_ENABLE(pie, AC_HELP_STRING([--enable-pie],
			[enable position independent executables flag]), [
	if (test "${enableval}" = "yes" &&
				test "${ac_cv_prog_cc_pie}" = "yes"); then
		CFLAGS="$CFLAGS -fPIE"
		LDFLAGS="$LDFLAGS -pie"
	fi
])

AC_CONFIG_FILES(Makefile)

AC_OUTPUT
