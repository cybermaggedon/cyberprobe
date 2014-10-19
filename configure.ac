#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.69])
AC_INIT([cyberprobe], [0.55], [cyberprobe-general@lists.sourceforge.net])
AM_INIT_AUTOMAKE([-Wall -Werror])
AC_CONFIG_SRCDIR([src/target.h])
AC_CONFIG_HEADERS([config.h])
AC_CONFIG_MACRO_DIR([m4])
AC_CONFIG_TESTDIR([tests])

# Optimiser settings
CXXFLAGS="-O6"

# Checks for programs.
AC_PROG_CXX
AC_PROG_CC
AM_PROG_AR

# Libtool
LT_INIT

# Python
AM_PATH_PYTHON

# Checks for libraries.
# FIXME: Replace `main' with functions in libraries:

BOOST_REQUIRE
BOOST_REGEX([mt])

# Lua
AX_PROG_LUA([5.1], [], [], [AC_MSG_ERROR([Lua interpreter missing.])])
AX_LUA_HEADERS([], [AC_MSG_ERROR([Lua headers missing.])])
AX_LUA_LIBS([], [AC_MSG_ERROR([Lua library missing.])])

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
	docs/Makefile stix/Makefile www/Makefile tests/Makefile tests/atlocal])

AC_OUTPUT

