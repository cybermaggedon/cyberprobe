#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.68])
AC_INIT([cyberprobe], [2.5.2], [cyberprobe-discussion@googlegroups.com])
AM_INIT_AUTOMAKE([-Wall -Werror subdir-objects foreign])
AC_CONFIG_SRCDIR([src/cyberprobe.C])
AC_CONFIG_HEADERS([config.h])
AC_CONFIG_MACRO_DIR([m4])
AC_CONFIG_TESTDIR([tests])

# Checks for programs.
AC_PROG_CXX
AC_PROG_CC
AM_PROG_AR

# Libtool
LT_INIT

# pkg-config
PKG_PROG_PKG_CONFIG

# systemd
AC_MSG_CHECKING([have systemd])
AC_ARG_WITH([systemdsystemunitdir],
  [AS_HELP_STRING([--with-systemdsystemunitdir=DIR],
  [Directory for systemd service files])],,
  [with_systemdsystemunitdir=auto])

AS_IF([test "x$with_systemdsystemunitdir" = "xyes" -o "x$with_systemdsystemunitdir" = "xauto"], [
  def_systemdsystemunitdir=$($PKG_CONFIG --variable=systemdsystemunitdir systemd)
  AS_IF([test "x$def_systemdsystemunitdir" = "x"],
    [AS_IF([test "x$with_systemdsystemunitdir" = "xyes"],
    [AC_MSG_ERROR([systemd support requested but pkg-config unable to query systemd package])])
  with_systemdsystemunitdir=no],
  [with_systemdsystemunitdir="$def_systemdsystemunitdir"])])

AS_IF([test "x$with_systemdsystemunitdir" != "xno"],
  [AC_SUBST([systemdsystemunitdir], [$with_systemdsystemunitdir])])
AM_CONDITIONAL([HAVE_SYSTEMD], [test "x$with_systemdsystemunitdir" != "xno"])
AC_MSG_RESULT([$with_systemdsystemunitdir])

# Python
AM_PATH_PYTHON([3.0])

# Check for Boost.
BOOST_REQUIRE
BOOST_PROGRAM_OPTIONS

# Protobuf
PKG_CHECK_MODULES([PROTOBUF], [protobuf >= 3.0.0],
    [with_protobuf=yes],
    [with_protobuf=no])

AS_IF([test "x$with_protobuf" != "xno"],
    [AC_SUBST([WITH_PROTOBUF], [$with_protobuf])
     AC_DEFINE([WITH_PROTOBUF], 1, [Set if protobuf compiler is available])])

AM_CONDITIONAL([WITH_PROTOBUF], [test "x$with_protobuf" != "xno"])

AC_SUBST([PROTOBUF_LIBS])
AC_SUBST([PROTOBUF_CFLAGS])

# ProtoBuf compiler.
# First, specify with --with-protoc=/path/of/protoc.
# Or, specify with env variable PROTOC.
# If neither of the above, find it in the path.
#AC_MSG_CHECKING([for ProtoBuf compiler protoc])
AC_ARG_WITH([protoc],
    [AS_HELP_STRING([--with-protoc=/path/of/protoc],
        [Location of the protocol buffers compiler protoc. Defaults to looking on path.])],
    [PROTOC="$withval"],
    [ AS_IF([test "x${PROTOC}" == "x"],
        [AC_PATH_PROG([PROTOC], [protoc], [no])])
    ]
)

# GRPC++ which is optional.
PKG_CHECK_MODULES([GRPC], [grpc++ >= 1.0.0 grpc >= 5.0.0],
    [with_grpc=yes],
    [with_grpc=no])

AS_IF([test "x$with_grpc" != "xno"],
    [AC_SUBST([WITH_GRPC], [$with_grpc])
     AC_DEFINE([WITH_GRPC], 1, [Set if grpc++ is available])])

AM_CONDITIONAL([WITH_GRPC], [test "x$with_grpc" != "xno"])

AC_SUBST([GRPC_CFLAGS])
AC_SUBST([GRPC_LIBS])

# Lua
AX_PROG_LUA([5.1], [], [], [AC_MSG_ERROR([Lua interpreter missing.])])
AX_LUA_HEADERS([], [AC_MSG_ERROR([Lua headers missing.])])
AX_LUA_LIBS([], [AC_MSG_ERROR([Lua library missing.])])

# Check for some Lua modules.
# AC_MSG_CHECKING([Lua socket module])
# AS_IF([echo 'if require("socket") then print("yes") end' | lua -], [],
# 	    [AC_MSG_ERROR([Lua socket module is not installed.])])

AC_CHECK_LIB([ncurses], [main], [], [AC_MSG_ERROR(Library ncurses missing.)])
AC_CHECK_LIB([pcap], [main], [], [AC_MSG_ERROR(Library pcap missing.)])
AC_SEARCH_LIBS([pcap_create], [pcap],
		    [AC_DEFINE([HAVE_PCAP_CREATE], 1,
		    [Set if pcap_create is supported (added in libpcap 1.0)])])
AC_SEARCH_LIBS([pcap_set_timeout], [pcap],
		    [AC_DEFINE([HAVE_PCAP_SET_TIMEOUT], 1,
		    [Set if pcap_set_timeout is supported])])
AC_CHECK_LIB([pthread], [main], [], [AC_MSG_ERROR(Library pthread missing.)])
AC_CHECK_LIB([readline], [main], [], [AC_MSG_ERROR(Library readline missing.)])
AC_CHECK_LIB([ssl], [main], [], [AC_MSG_ERROR(Library ssl missing.)])

AC_CHECK_LIB([dag], [main],
		    [AM_CONDITIONAL([WITH_DAG], [true])]
		    [AC_DEFINE([WITH_DAG], [1], [Set if compiling DAG support])],
		    [AM_CONDITIONAL([WITH_DAG], [false])])

# LUA specifics
AC_SEARCH_LIBS([luaL_register], [lua lua5.1],
		    [AC_DEFINE([HAVE_LUAL_REGISTER], 1,
		    [Set if luaL_register is supported (removed in 5.2)])])
AC_SEARCH_LIBS([luaL_setfuncs], [lua lua5.2],
		    [AC_DEFINE([HAVE_LUAL_SETFUNCS], 1,
		    [Set if luaL_setfuncs is supported (added in 5.2)])])
AC_SEARCH_LIBS([lua_rawlen], [lua lua5.2],
		    [AC_DEFINE([HAVE_LUA_RAWLEN], 1,
		    [Set if lua_rawlen is supported (added in 5.2)])])

# Checks for header files.
AC_CHECK_HEADERS([arpa/inet.h netdb.h netinet/in.h stdint.h stdlib.h sys/socket.h sys/time.h unistd.h openssl/ssl.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_TYPE_INT32_T
AC_TYPE_INT64_T
AC_TYPE_SIZE_T
AC_TYPE_UINT16_T
AC_TYPE_UINT32_T
AC_TYPE_UINT64_T
AC_TYPE_UINT8_T

# Checks for library functions.
AC_FUNC_ERROR_AT_LINE
AC_FUNC_MALLOC
AC_CHECK_FUNCS([gethostbyname gettimeofday socket strdup uname])

AC_CONFIG_FILES([Makefile src/Makefile include/Makefile config/Makefile
	docs/Makefile stix/Makefile www/Makefile tests/Makefile tests/atlocal
	init/Makefile subscribers/Makefile pkg.mk utils/Makefile
	indicators/Makefile
 	cyberprobe.spec])

AC_OUTPUT

