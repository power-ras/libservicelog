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

lib_LTLIBRARIES = libservicelog.la
library_includedir = $(includedir)/servicelog-1/
lib_h_files = ../servicelog-1/servicelog.h ../servicelog-1/libservicelog.h

noinst_HEADERS = slog_internal.h

INCLUDES	= -I.. -I../servicelog-1/

libservicelog_la_SOURCES = servicelog.c addl_data.c event.c repair_action.c \
		notify.c v29_compat.c v29_print.c v29_notify_gram.y \
		v29_notify_lex.l ${noinst_HEADERS} ${lib_h_files}

BUILT_SOURCES = v29_notify_gram.h
AM_YFLAGS = -d -p v29nfy_
# -P for the code prefixes, -o because autoconf wants the standard file name
AM_LFLAGS = -Pv29nfy_ -olex.yy.c

pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = servicelog-1.pc

libservicelog_la_LDFLAGS = -module -version-info \
	@GENERIC_API_VERSION@ -release @GENERIC_RELEASE@

AM_CFLAGS	= -Wall -g -DDEST_DIR='"${exec_prefix}"'
AM_LDFLAGS	= -lsqlite3 -lrtas -lrtasevent

LIBTOOL_DEPS = @LIBTOOL_DEPS@
libtool: $(LIBTOOL_DEPS)
	$(SHELL) ./config.status --recheck
