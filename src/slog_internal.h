/*
 * @file slog_internal.h
 * @brief Internal header file for servicelog
 *
 * Copyright (C) 2008  IBM
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Library General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Library General Public License for more details.
 *
 * You should have received a copy of the GNU Library General Public
 * Licence along with this program; if not, see <http://www.gnu.org/licenses/>.
 */

#ifndef _SLOG_INTERNAL_H
#define _SLOG_INTERNAL_H

#include <servicelog-1/servicelog.h>

#define SERVICELOG_PATH	"/var/lib/servicelog/servicelog.db"

#define DESC_MAXLEN	2048
#define SQL_MAXLEN	(DESC_MAXLEN + 1024)

#define SL_TYPE_MAX	4
#define SL_NOTIFY_MAX	1
#define SL_METHOD_MAX	3

/* common defines for print routines */
#define PRNT_FMT_STR		"%-20s%s\n"
#define PRNT_FMT_STR_NR		"%-20s%s"
#define PRNT_FMT_CHAR		"%-20s%c\n"
#define PRNT_FMT_NUM		"%-20s%d\n"
#define PRNT_FMT_LNUM		"%-20s%ld\n"
#define PRNT_FMT_UINT		"%-20s%u\n"
#define PRNT_FMT_UINT64		"%-20s%llu\n"
#define PRNT_FMT_HEX		"%-20s%08x\n"
#define PRNT_FMT_LHEX		"%-20s%016llx\n"

struct servicelog {
	sqlite3 *db;
	uint32_t flags;
	char *location;
#define SL_MAX_ERR		256
	char error[SL_MAX_ERR];
};

#define EVENTS_JOIN "events " \
		"LEFT JOIN os ON os.event_id = events.id " \
		"LEFT JOIN rtas ON rtas.event_id = events.id " \
		"LEFT JOIN enclosure ON enclosure.event_id = events.id " \
		"LEFT JOIN bmc ON bmc.event_id = events.id "


int sl_hex_dump(FILE *str, void *data, size_t len);
int sl_printf(FILE *stream, char *fmt, ...);
size_t get_system_info(char *var, char *buf, size_t sz);
int replace_query_keywords(servicelog *slog, char *query, sqlite3_stmt **stmt,
			   char *err, size_t err_sz);

void sqlite_blob_functions();

int notify_event(servicelog *slog, uint64_t event_id);
int notify_repair(servicelog *slog, uint64_t repair_id);

int insert_addl_data_os(servicelog *, struct sl_event *);
int insert_addl_data_rtas(servicelog *, struct sl_event *);
int insert_addl_data_enclosure(servicelog *, struct sl_event *);
int insert_addl_data_bmc(servicelog *, struct sl_event *);

int retrieve_addl_data_os(void *, int, char **, char **);
int retrieve_addl_data_rtas(void *, int, char **, char **);
int retrieve_addl_data_enclosure(void *, int, char **, char **);
int retrieve_addl_data_bmc(void *, int, char **, char **);

void free_addl_data_os(struct sl_event *);
void free_addl_data_rtas(struct sl_event *);
void free_addl_data_enclosure(struct sl_event *);
void free_addl_data_bmc(struct sl_event *);

int print_addl_data_os(FILE *, struct sl_event *, int);
int print_addl_data_rtas(FILE *, struct sl_event *, int);
int print_addl_data_enclosure(FILE *, struct sl_event *, int);
int print_addl_data_bmc(FILE *, struct sl_event *, int);

#endif
