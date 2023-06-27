AC_PREREQ([2.69])
AC_INIT([libidevicebackup], m4_esyscmd([git rev-list --count HEAD | tr -d '\n']), [elcomsoft.rd@elcomsoft.com])

AC_CANONICAL_SYSTEM
AC_CANONICAL_HOST
AM_PROG_LIBTOOL

AM_INIT_AUTOMAKE([subdir-objects])
AC_CONFIG_HEADERS([config.h])
AC_CONFIG_MACRO_DIRS([m4])


AC_DEFINE([VERSION_COMMIT_COUNT], "m4_esyscmd([git rev-list --count HEAD | tr -d '\n'])", [Git commit count])
AC_DEFINE([VERSION_COMMIT_SHA], "m4_esyscmd([git rev-parse HEAD | tr -d '\n'])", [Git commit sha])
AC_SUBST([VERSION_COMMIT_COUNT], ["m4_esyscmd([git rev-list --count HEAD | tr -d '\n'])"])
AC_SUBST([VERSION_COMMIT_SHA], ["m4_esyscmd([git rev-parse HEAD | tr -d '\n'])"])

# Checks for programs.
AC_PROG_CXX
AC_PROG_CC

# Check for operating system
AC_MSG_CHECKING([whether we need platform-specific build settings])
case $host_os in
  *mingw32*|*cygwin*)
  AC_MSG_RESULT([${host_os}])
  win32=true
  LDFLAGS+=" -no-undefined -lws2_32"
      ;;
esac


CXXFLAGS+=" -std=c++11"
CFLAGS+=" -std=c11"
# Versioning.

# Checks for libraries.
LIBGENERAL_REQUIRES_STR="libgeneral >= 70"
LIBPLIST_REQUIRES_STR="libplist-2.0 >= 2.3.0"
LIBIMOBILEDEVICE_REQUIRES_STR="libimobiledevice-1.0 >= 1.3.0"
LIBIMOBILEDEVICE_GLUE_REQUIRES_STR="libimobiledevice-glue-1.0 >= 1.0.0"

PKG_CHECK_MODULES(libgeneral, $LIBGENERAL_REQUIRES_STR)
PKG_CHECK_MODULES(libplist, $LIBPLIST_REQUIRES_STR)
PKG_CHECK_MODULES(libimobiledevice, $LIBIMOBILEDEVICE_REQUIRES_STR)
PKG_CHECK_MODULES(libimobiledevice_glue, $LIBIMOBILEDEVICE_GLUE_REQUIRES_STR)

AC_SUBST([libgeneral_requires], [$LIBGENERAL_REQUIRES_STR])
AC_SUBST([libplist_requires], [$LIBPLIST_REQUIRES_STR])
AC_SUBST([libimobiledevice_requires], [$LIBIMOBILEDEVICE_REQUIRES_STR])
AC_SUBST([libimobiledevice_glue_requires], [$LIBIMOBILEDEVICE_GLUE_REQUIRES_STR])

AC_ARG_ENABLE([debug],
            [AS_HELP_STRING([--enable-debug],
            [enable debug build(default is no)])],
            [debug_build=true],
            [debug_build=false])

if test "$debug_build" = true; then
  echo "*** Note: debug build requested ***"
  CFLAGS+=" -g -O0 -DDEBUG=1"
  CXXFLAGS+=" -g -O0 -DDEBUG=1"
fi

# Checks for header files.
AC_CHECK_HEADERS([arpa/inet.h winsock.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_CHECK_FUNCS([stpcpy])


AC_CONFIG_FILES([Makefile
                 include/Makefile
                 libidevicebackup.pc
                 libidevicebackup/Makefile])
AC_OUTPUT


echo "
Configuration for $PACKAGE-$VERSION:
-------------------------------------------

  install prefix ..........: $prefix
  debug build .............: $debug_build"
echo "  compiler ................: ${CC}

  Now type 'make' to build $PACKAGE-$VERSION,
  and then 'make install' for installation.
"
