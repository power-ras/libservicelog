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

SUBDIRS = src

EXTRA_DIST = servicelog.db bootstrap.sh

library_includedir = ${includedir}/servicelog-1/
library_include_HEADERS = servicelog-1/servicelog.h servicelog-1/libservicelog.h

install-exec-hook:
	install -D --mode=754 servicelog.db \
		${DESTDIR}/var/lib/servicelog/servicelog.db
