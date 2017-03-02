AC_INIT(armadito-mod-clamav, 0.12.8, fdechelle@teclib.com)
AM_INIT_AUTOMAKE([foreign])

# collect arguments
# debug
AC_ARG_ENABLE([debug],
	AS_HELP_STRING([--enable-debug],[enable debugging @<:@default is yes@:>@]),
	,
	enable_debug="yes")

# check for needed programs
AC_PROG_CC([gcc])
AC_PROG_LIBTOOL

# start with clean CFLAGS
CFLAGS=

# check for debug
AC_MSG_CHECKING(for debug)
AC_MSG_RESULT($enable_debug)
AM_CONDITIONAL([DEBUG], [test "$enable_debug" = "yes"])
if test "$enable_debug" = "yes"; then
   AC_DEFINE(DEBUG,1,[Define DEBUG to enable debug messages])
   CFLAGS="${CFLAGS} -g"
fi

PKG_PROG_PKG_CONFIG

# check for libarmadito
PKG_CHECK_MODULES(LIBARMADITO, libarmadito, [HAVE_LIBARMADITO=yes], [HAVE_LIBARMADITO=no])
# check for libarmadito/armadito.h in source tree
if test "$HAVE_LIBARMADITO" = "no"; then
   OLD_CPPFLAGS="$CPPFLAGS"
   CPPFLAGS=-I$srcdir/../../armadito-core/libmodule/include
   AC_CHECK_HEADER([libarmadito/armadito.h], [], [AC_MSG_ERROR([cannot find Armadito module library])], [])
   CPPFLAGS="$OLD_CPPFLAGS"
   LIBARMADITO_CFLAGS='-I$(top_srcdir)/../../armadito-core/libmodule/include'
   AC_SUBST([LIBARMADITO_CFLAGS])
fi

# check for libclamav
PKG_CHECK_MODULES(LIBCLAMAV, libclamav, [], [AC_MSG_ERROR([cannot find ClamAV library])])

# Output files
AC_CONFIG_FILES([
Makefile
src/Makefile
conf/Makefile
])
AC_OUTPUT
