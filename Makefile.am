# Copyright (C) 2008, IBM
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU Library General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Library General Public License for more details.
#
# You should have received a copy of the GNU Library General Public
# Licence along with this program; if not, see <http://www.gnu.org/licenses/>.

ACLOCAL_AMFLAGS = -I m4

EXTRA_DIST = servicelog.db bootstrap.sh src/tests/*

#AM_CPPFLAGS	= -I.. -I./servicelog-1/
AM_CFLAGS	= -Wall -g -I.. -I./servicelog-1 -DDEST_DIR='"${exec_prefix}"'
AM_LDFLAGS	= -lsqlite3 -lrtas -lrtasevent

library_include_HEADERS = servicelog-1/servicelog.h servicelog-1/libservicelog.h
noinst_HEADERS = src/slog_internal.h

lib_LTLIBRARIES = libservicelog.la
library_includedir = $(includedir)/servicelog-1/

libservicelog_la_SOURCES = src/servicelog.c src/addl_data.c src/event.c \
			   src/repair_action.c src/notify.c src/v29_compat.c \
			   src/v29_print.c src/v29_notify_gram.y \
			   src/v29_notify_lex.l ${noinst_HEADERS} \
			   ${library_include_HEADERS}

pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = src/servicelog-1.pc

BUILT_SOURCES = src/v29_notify_gram.h
AM_YFLAGS	= -d -p v29nfy_
# -P for the code prefixes, -o because autoconf wants the standard file name
AM_LFLAGS	= -Pv29nfy_ -olex.yy.c

libservicelog_la_LDFLAGS = -module -version-info \
	@GENERIC_API_VERSION@ -release @GENERIC_RELEASE@

check_PROGRAMS = src/tests/test_libservicelog
src_tests_test_libservicelog_SOURCES = src/tests/test_libservicelog.c
src_tests_test_libservicelog_LDADD = libservicelog.la

TESTS=src/tests/run_tests

check: all

runtest: all $(check_PROGRAMS)
	cd src/tests && ./run_tests

LIBTOOL_DEPS = @LIBTOOL_DEPS@
libtool: $(LIBTOOL_DEPS)
	$(SHELL) ./config.status --recheck

install-exec-hook:
	install -D --mode=754 servicelog.db \
		${DESTDIR}/var/lib/servicelog/servicelog.db
