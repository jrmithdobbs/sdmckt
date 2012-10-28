#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.68])
AC_INIT(sdmkct, 0.0.0)
AC_CONFIG_SRCDIR([doc/shamirs.original.comments.c])
AC_CONFIG_HEADERS([config.h])

AC_LANG([C])

AM_INIT_AUTOMAKE([1.11])
AM_SILENT_RULES([yes])

dnl Checks for programs.
# First we make sure we have a compiler and we prefer clang due to licensing
AC_CANONICAL_HOST
AC_PROG_CC([clang gcc cc])
AC_PROG_CC_C99

AC_ARG_VAR(DEBUG,[Turn on debug printing.])
uname_m="$(uname -m)"

# Next we setup a sane build environment independent of autotools for *BSD
if test -z "$CFLAGS" -o "$CFLAGS" = '-g -O2'; then
  CFLAGS="-g -O2"
fi
CPPFLAGS="${CPPFLAGS:-"-I/usr/local/include"}"
uname="`uname`"
case "${host}" in
    *bsd*|*darwin*)
      LDFLAGS="${LDFLAGS:-"-L/usr/local/lib"}"
      if test -z "$PKG_CONFIG_PATH"; then
        for d in \
          /usr/lib/pkgconfig \
          /usr/local/lib/pkgconfig \
          ; do
          if test -d "$d"; then
            if test -z "$PKG_CONFIG_PATH"; then
              PKG_CONFIG_PATH="$d"
            else
              PKG_CONFIG_PATH="${PKG_CONFIG_PATH}:${d}"
            fi
          fi
        done
      fi
      PKG_CONFIG_PATH="/usr/lib/pkgconfig:/usr/local/lib/pkgconfig"
    ;;
    *) ;;
esac
case "${host}" in
  *openbsd*)
    CFLAGS="${CFLAGS} -Wtrampolines"
    # system libusb is linked against pthread and linker wont auto-associate
    LDFLAGS="${LDFLAGS} -pthread"
  ;;
  *darwin*)
  if test -d '/opt/local'; then
    LDFLAGS="${LDFLAGS} -L/opt/local/lib"
    CPPFLAGS="${CPPFLAGS} -I/opt/local/include"
    PKG_CONFIG_PATH="${PKG_CONFIG_PATH}:/opt/local/lib/pkgconfig"
  fi
  if test -d '/sw'; then
    LDFLAGS="${LDFLAGS} -L/sw/lib"
    CPPFLAGS="${CPPFLAGS} -I/sw/include"
    PKG_CONFIG_PATH="${PKG_CONFIG_PATH}:/sw/lib/pkgconfig"
  fi
  ;;
  *) ;;
esac
if test "x$uname" = 'xDarwin'; then
  if test -d '/opt/local'; then
    LDFLAGS="${LDFLAGS} -L/opt/local/lib"
    CPPFLAGS="${CPPFLAGS} -I/opt/local/include"
    PKG_CONFIG_PATH="${PKG_CONFIG_PATH}:/opt/local/lib/pkgconfig"
  fi
  if test -d '/sw'; then
    LDFLAGS="${LDFLAGS} -L/sw/lib"
    CPPFLAGS="${CPPFLAGS} -I/sw/include"
    PKG_CONFIG_PATH="${PKG_CONFIG_PATH}:/sw/lib/pkgconfig"
  fi
fi
if test "$(basename "$CC")" = 'clang'; then
  CFLAGS="${CFLAGS} -Qunused-arguments"
fi
export CFLAGS CPPFLAGS LDFLAGS PKG_CONFIG_PATH

case "${host}" in
	*freebsd*)
		true
	;;
	*)
		AC_ARG_VAR(WORKING_MLOCK,[Specifies that mlock()/munlock() can be used by unprivileged user.])
	;;
esac

AC_PROG_INSTALL
AC_PROG_MAKE_SET
AC_PROG_MKDIR_P

dnl Checks for libraries.
AC_C_INLINE

dnl Checks for header files.
AC_CHECK_HEADERS([arpa/inet.h stdint.h stdlib.h string.h unistd.h fcntl.h stddef.h sys/param.h sys/time.h termios.h])

dnl Checks for typedefs, structures, and compiler characteristics.
AC_HEADER_STDBOOL
AC_TYPE_SIZE_T
AC_TYPE_SSIZE_T
AC_TYPE_UINT8_T
AC_TYPE_UINT16_T
AC_TYPE_UINT32_T
AC_TYPE_UINT64_T

dnl Checks for library functions.
AC_FUNC_ERROR_AT_LINE
AC_FUNC_MALLOC
AC_FUNC_REALLOC
AC_FUNC_MMAP

AC_CHECK_FUNCS([clock_gettime gettimeofday memmove memset munmap strcspn strdup strerror sysinfo])

dnl Check for usable OpenSSL
AC_ARG_WITH([openssl],
  AS_HELP_STRING([--with-openssl], [Specify path to openssl.]))
AS_IF([test "x$have_openssl" = "xno"],
  [AC_MSG_ERROR([Cannot disable openssl!])])
dnl default
dnl do nothing
dnl user-specified path
AS_IF([test "x$with_openssl" != "xyes" -a "x$with_openssl" != "x" ],
  [
    OPENSSL_CFLAGS="-I${with_openssl}/include"
    OPENSSL_LDFLAGS="-L${with_openssl}/lib"
  ])
OPENSSL_LIBS="-lcrypto"
dnl necessary for all cases
AC_ARG_VAR(OPENSSL_CFLAGS,[CFLAGS for openssl])
AC_ARG_VAR(OPENSSL_LDFLAGS,[LDFLAGS for openssl])
AC_ARG_VAR(OPENSSL_LIBS,[LIBS for openssl])

old_CPPFLAGS="${CPPFLAGS}"
old_LDFLAGS="${LDFLAGS}"
CPPFLAGS="${OPENSSL_CFLAGS} ${old_CPPFLAGS}"
LDFLAGS="${OPENSSL_LDFLAGS} ${old_LDFLAGS}"
export CPPFLAGS old_CPPFLAGS LDFLAGS old_LDFLAGS
dnl # openssl checks begin #
AC_CHECK_HEADER([openssl/aes.h], true, AC_MSG_ERROR([Could not find openssl.h]))
AC_CHECK_LIB([crypto], [AES_encrypt,AES_set_encrypt_key], true, AC_MSG_ERROR([Could not find usable -lcrypto]))
dnl # openssl checks end   #
LDFLAGS="${old_LDFLAGS}"
CPPFLAGS="${old_CPPFLAGS}"
export LDFLAGS CPPFLAGS
unset old_LDFLAGS old_CPPFLAGS

dnl Check for yubikey deps.

dnl setup libyubikey option
AC_ARG_WITH([libyubikey],
  AS_HELP_STRING([--with-libyubikey], [Specify path to libyubikey]))
AS_IF([test "x$with_libyubikey" = "xno"],
  [AC_MSG_ERROR([Cannot disable libyubikey!])])
dnl default
dnl do nothing
dnl user-specified path
AS_IF([test "x$with_libyubikey" != "xyes" -a "x$with_libyubikey" != "x" ],
  [
    YUBIKEY_CFLAGS="-I${with_libyubikey}/include"
    YUBIKEY_LDFLAGS="-L${with_libyubikey}/lib"
  ])
dnl necessary for all cases
YUBIKEY_LIBS="-lyubikey"
AC_ARG_VAR(YUBIKEY_CFLAGS,[CFLAGS for libyubikey])
AC_ARG_VAR(YUBIKEY_LDFLAGS,[LDFLAGS for libyubikey])
AC_ARG_VAR(YUBIKEY_LIBS,[LIBS for libyubikey])

old_CPPFLAGS="${CPPFLAGS}"
old_LDFLAGS="${LDFLAGS}"
CPPFLAGS="${YUBIKEY_CFLAGS} ${old_CPPFLAGS}"
LDFLAGS="${YUBIKEY_LDFLAGS} ${old_LDFLAGS}"
export CPPFLAGS old_CPPFLAGS LDFLAGS old_LDFLAGS
dnl # yubikey checks begin #
AC_CHECK_HEADER([yubikey.h], true, AC_MSG_ERROR([Could not find yubikey.h]))
AC_CHECK_LIB([yubikey], [yubikey_hex_encode,yubikey_hex_decode], true, AC_MSG_ERROR([Could not find -lyubikey]))
dnl # yubikey checks end   #
LDFLAGS="${old_LDFLAGS}"
CPPFLAGS="${old_CPPFLAGS}"
export LDFLAGS CPPFLAGS
unset old_LDFLAGS old_CPPFLAGS

dnl setup libykpers options
AC_ARG_WITH([libykpers],
  AS_HELP_STRING([--with-libykpers], [Specify path to ykpers. pkg-config used if not specified]))
AS_IF([test "x$with_libykpers" = "xno"],
  [AC_MSG_ERROR([Cannot disable libykpers!])])
old_PKG_CONFIG_PATH="${PKG_CONFIG_PATH}"
export PKG_CONFIG_PATH old_PKG_CONFIG_PATH
dnl default
AS_IF([test "x$with_libykpers" = "xyes" -o "x$with_libykpers" = "x" ],[true])
dnl user-specified path
AS_IF([test "x$with_libykpers" != "xyes" -a "x$with_libykpers" != "x" ],
  [
    PKG_CONFIG_PATH="${with_libykpers}/lib/pkgconfig"
    export PKG_CONFIG_PATH
  ])
PKG_CHECK_MODULES([YKPERS], [ykpers-1], true, AC_MSG_ERROR([Could not find ykpers-1!]))
YKPERS_LDFLAGS="${YKPERS_LDFLAGS:-"$(pkg-config --libs-only-L ykpers-1)"}"
YKPERS_LIBS="$(echo "${YKPERS_LIBS}" | tr ' ' '\n' | sed 's,^-L.*$,,;/^$/d;')"
export YKPERS_LDFLAGS YKPERS_LIBS
AC_ARG_VAR(YKPERS_LDFLAGS,[LDFLAGS for libykpers])

PKG_CONFIG_PATH="${old_PKG_CONFIG_PATH}"
export PKG_CONFIG_PATH
unset old_PKG_CONFIG_PATH

old_CPPFLAGS="${CPPFLAGS}"
old_LDFLAGS="${LDFLAGS}"
CPPFLAGS="${YUBIKEY_CFLAGS} ${YKPERS_CFLAGS} ${old_CPPFLAGS}"
LDFLAGS="${YUBIKEY_LDFLAGS} ${YKPERS_LDFLAGS} ${old_LDFLAGS}"
export CPPFLAGS old_CPPFLAGS LDFLAGS old_LDFLAGS
dnl # ykpers-1 checks begin #
AC_CHECK_HEADER([ykpers.h], true, AC_MSG_ERROR([Could not find ykpers-1/ykpers.h]))
AC_CHECK_LIB([ykpers-1], [yk_init,yk_open_first_key,yk_write_to_key,yk_read_response_from_key], true, AC_MSG_ERROR([Could not find usable -lykpers-1!]))
dnl # ykpers-1 checks end   #
LDFLAGS="${old_LDFLAGS}"
CPPFLAGS="${old_CPPFLAGS}"
export LDFLAGS CPPFLAGS
unset old_LDFLAGS old_CPPFLAGS

dnl Special options
AC_ARG_WITH([scryptimpl],
  AS_HELP_STRING([--with-scryptimpl=<sse,nosse,ref>],[Pick scrypt implementation. Defaults to sse on amd64. Defaults to nosse on <=i686]))
AS_IF([test "x$with_scryptimpl" = "x"],
  [
		AS_IF([test "x$uname_m" = 'xx86_64' -o "x$uname_m" = 'amd64'],
			[AC_DEFINE([SCRYPT_SSE], 1, [Use sse2 optimizations for scrypt.])],
			[AC_DEFINE([SCRYPT_NOSSE], 1, [Do not use sse2 optimization for scrypt.])])
	])
AS_IF([test "x$with_scryptimpl" = "xyes" -o "x$with_scryptimpl" = "xsse" ],
  [
    AC_DEFINE([SCRYPT_SSE], 1 [Use sse2 optimizations for scrypt.])
		AS_IF([test "x$uname_m" != 'xx86_64' -o "x$uname_m" != 'amd64'],
      [CFLAGS="${CFLAGS} -march=pentium4";LDLAGS="${LDLAGS} -march=pentium4";])
  ])
AS_IF([test "x$with_scryptimpl" = "xno" -o "x$with_scryptimpl" = "xnosse"],
	[AC_DEFINE([SCRYPT_NOSSE], 1, [Do not use sse2 optimizations for scrypt.])])
AS_IF([test "x$with_scryptimpl" = "xref"],
	[AC_DEFINE([SCRYPT_REF], 1, [Use reference implementation of scrypt. (useful for special platforms/compliers)])])

COMPILED_CFLAGS="$( 
  echo ${CFLAGS} ${YUBIKEY_CFLAGS} ${YKPERS_CFLAGS} ${OPENSSL_CFLAGS} \
  | tr ' ' '\n' | sort | uniq | tr '\n' ' '
)"
COMPILED_LDFLAGS="$( 
  echo ${LDFLAGS} ${YUBIKEY_LDFLAGS} ${YKPERS_LDFLAGS} ${OPENSSL_LDFLAGS} \
  | tr ' ' '\n' | sort | uniq | tr '\n' ' '
)"
COMPILED_LIBS="$( 
  echo ${YUBIKEY_LIBS} ${YKPERS_LIBS} ${OPENSSL_LIBS} \
  | tr ' ' '\n' | sort | uniq | tr '\n' ' '
)"
CFLAGS="$COMPILED_CFLAGS"
LDFLAGS="$COMPILED_LDFLAGS"
LIBS="$COMPILED_LIBS"
unset COMPILED_CFLAGS COMPILED_LDFLAGS COMPILED_LIBS
export CFLAGS LDFLAGS LIBS
echo =========================================================================
echo "YUBIKEY_LDFLAGS: ${YUBIKEY_LDFLAGS}"
echo "OPENSSL_LDFLAGS: ${OPENSSL_LDFLAGS}"
echo "YKPERS_LDFLAGS : ${YKPERS_LDFLAGS}"
echo "FINAL LDFLAGS  : ${LDFLAGS}"
echo "YUBIKEY_CLFAGS : ${YUBIKEY_CFLAGS}"
echo "OPENSSL_CFLAGS : ${OPENSSL_CFLAGS}"
echo "YKPERS_CFLAGS  : ${YKPERS_CFLAGS}"
echo "FINAL CFLAGS   : ${CFLAGS}"
echo "YUBIKEY_LIBS   : ${YUBIKEY_LIBS}"
echo "OPENSSL_LIBS   : ${OPENSSL_LIBS}"
echo "YKPERS_LIBS    : ${YKPERS_LIBS}"
echo "FINAL LIBS     : ${LIBS}"
echo "FINAL CPPFLAGS : ${CPPFLAGS}"
echo =========================================================================

unset uname_m

dnl Output our Makefile!
AC_OUTPUT(Makefile)
