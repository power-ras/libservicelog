#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

m4_define([ppu_version], 1.1.19)

AC_PREREQ(2.69)
AC_INIT([libservicelog], ppu_version, [hegdevasant@in.ibm.com])
AC_CONFIG_SRCDIR([src/servicelog.c])
AC_CONFIG_HEADER([config/config.h])
AC_CONFIG_AUX_DIR([config])
AC_CONFIG_MACRO_DIR([m4])
AM_INIT_AUTOMAKE([-Wall subdir-objects -Werror foreign])
AM_PROG_AR

GENERIC_LIBRARY_NAME=libservicelog
GENERIC_PACKAGE_NAME=servicelog
GENERIC_MAJOR_VERSION=1
GENERIC_MINOR_VERSION=1
GENERIC_MICRO_VERSION=19
GENERIC_API_VERSION=$GENERIC_MAJOR_VERSION
AC_SUBST(GENERIC_API_VERSION)

AC_SUBST(GENERIC_LIBRARY_VERSION)
AC_SUBST(GENERIC_PACKAGE_NAME)

PACKAGE=$GENERIC_LIBRARY_NAME
AC_SUBST(GENERIC_LIBRARY_NAME)

GENERIC_VERSION=$GENERIC_MAJOR_VERSION.$GENERIC_MINOR_VERSION.$GENERIC_MICRO_VERSION
GENERIC_RELEASE=$GENERIC_MAJOR_VERSION.$GENERIC_MINOR_VERSION
AC_SUBST(GENERIC_RELEASE)
AC_SUBST(GENERIC_VERSION)

# Checks for programs.
AC_PROG_CC
AC_PROG_CXX
AC_PROG_YACC
AC_PROG_LEX
AC_PROG_INSTALL
AC_PROG_LN_S
AC_PROG_MAKE_SET
AC_PROG_LIBTOOL
AC_SUBST(LIBTOOL_DEPS)
AM_PROG_CC_C_O

# Checks for libraries.
AC_CHECK_LIB([sqlite3], [sqlite3_open], [], [
	echo "Error! libsqlite3 not found"
    exit -1])
AC_CHECK_LIB([rtasevent], [parse_rtas_event], [], [
	echo "Error! librtasevent not found"
	exit -1])
AC_CHECK_LIB([rtas], [rtas_activate_firmware], [], [
	echo "Error! librtas not found"
	exit -1])

# Checks for functions
AC_CHECK_FUNCS([dup2 localtime_r strchr strdup strstr strtoul])

# Checks for header files.
AC_HEADER_STDC
AC_CHECK_HEADERS([stdint.h stdlib.h string.h unistd.h fcntl.h libintl.h malloc.h stddef.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_TYPE_SIZE_T
AC_STRUCT_TM
AC_FUNC_ALLOCA
AC_FUNC_FORK
AC_FUNC_REALLOC
AC_TYPE_INT16_T
AC_TYPE_INT32_T
AC_TYPE_INT8_T
AC_TYPE_PID_T
AC_TYPE_UINT16_T
AC_TYPE_UINT32_T
AC_TYPE_UINT64_T
AC_TYPE_UINT8_T

# Checks for library functions.
AC_FUNC_MALLOC
AC_FUNC_MKTIME
AC_FUNC_STAT
AC_FUNC_STRFTIME
AC_CHECK_FUNCS([memset strerror strtoull uname])

AC_CONFIG_FILES([Makefile libservicelog.spec src/servicelog-1.pc])
AC_OUTPUT
