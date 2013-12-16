#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.69])
AC_INIT([lkm-misc], [1.0.0], [xiaosuo@gmail.com])
AC_CONFIG_SRCDIR([src/bnotify.c])
AM_INIT_AUTOMAKE([foreign -Wall -Werror])
AC_CONFIG_HEADERS([config.h])

AC_USE_SYSTEM_EXTENSIONS
AC_SYS_LARGEFILE

# Checks for programs.
AC_PROG_CC
AC_PROG_CC_C99
AC_PROG_CC_C_O

# Checks for libraries.
AC_ARG_WITH([kbuild],
		AS_HELP_STRING([--with-kbuild=PATH], [PATH to kernel build directory [default="/lib/modules/$(uname -r)/build"]])
AS_HELP_STRING([--without-kbuild], [Build only library]),
		[kbuilddir="$withval"],
		[kbuilddir="/lib/modules/$(uname -r)/build"])
if test "$kbuilddir" = no; then
	kbuilddir="";
fi
AC_SUBST(kbuilddir)

# Checks for header files.
AC_CHECK_HEADERS([stdlib.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_CHECK_HEADER_STDBOOL
AC_TYPE_PID_T
AC_TYPE_SIZE_T
AC_TYPE_SSIZE_T

# Checks for library functions.

AC_CONFIG_FILES([Makefile
                 src/Makefile
		 include/Makefile])
AC_OUTPUT
AC_MSG_RESULT([
	$PACKAGE_NAME $VERSION
	PACKAGE_TARNAME:		${PACKAGE_TARNAME}
	prefix:				${prefix}
	exec_prefix:			${exec_prefix}
	bindir:				${bindir}
	sysconfdir:			${sysconfdir}
	libdir:				${libdir}
	datarootdir:			${datarootdir}
	docdir:				${docdir}
	kbuilddir:			${kbuilddir}

	CC:				${CC}
	CFLAGS:				${CFLAGS}
	CPPFLAGS:			${CPPFLAGS}
	LDFLAGS:			${LDFLAGS}
])
