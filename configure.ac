#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.69])
AC_INIT([cyberprobe], [0.74], [cyberprobe-general@lists.sourceforge.net])
AM_INIT_AUTOMAKE([-Wall -Werror])
AC_CONFIG_SRCDIR([src/target.h])
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
AM_PATH_PYTHON

# Check for Boost.
BOOST_REQUIRE
BOOST_REGEX([mt])

# Lua
AX_PROG_LUA([5.1], [], [], [AC_MSG_ERROR([Lua interpreter missing.])])
AX_LUA_HEADERS([], [AC_MSG_ERROR([Lua headers missing.])])
AX_LUA_LIBS([], [AC_MSG_ERROR([Lua library missing.])])

# Check for some Lua modules.
AC_MSG_CHECKING([Lua json.encode module])
AS_IF([echo 'if require("json.encode") then print("yes") end' | lua -], [], 
	    [AC_MSG_ERROR([Lua json.encode module is not installed.])])
AC_MSG_CHECKING([Lua lfs (luafilesystem) module])
AS_IF([echo 'if require("lfs") then print("yes") end' | lua -], [], 
	    [AC_MSG_ERROR([Lua lfs module is not installed.])])
AC_MSG_CHECKING([Lua md5 module])
AS_IF([echo 'if require("md5") then print("yes") end' | lua -], [], 
	    [AC_MSG_ERROR([Lua md5 module is not installed.])])
AC_MSG_CHECKING([Lua mime module])
AS_IF([echo 'if require("mime") then print("yes") end' | lua -], [], 
	    [AC_MSG_ERROR([Lua mime module is not installed.])])

AC_CHECK_LIB([expat], [main], [], [AC_MSG_ERROR(Library expat missing.)])
AC_CHECK_LIB([ncurses], [main], [], [AC_MSG_ERROR(Library ncurses missing.)])
AC_CHECK_LIB([pcap], [main], [], [AC_MSG_ERROR(Library pcap missing.)])
AC_CHECK_LIB([pthread], [main], [], [AC_MSG_ERROR(Library pthread missing.)])
AC_CHECK_LIB([readline], [main], [], [AC_MSG_ERROR(Library readline missing.)])

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
AC_CHECK_HEADERS([arpa/inet.h netdb.h netinet/in.h stdint.h stdlib.h sys/socket.h sys/time.h unistd.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_CHECK_HEADER_STDBOOL
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
	init/Makefile subscribers/Makefile])

AC_OUTPUT

