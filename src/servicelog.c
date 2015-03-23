/**
 * @file servicelog.c
 * @brief Primary APIs for access to the servicelog database
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
. *
 * You should have received a copy of the GNU Library General Public
 * Licence along with this program; if not, see <http://www.gnu.org/licenses/>.
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdarg.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <grp.h>
#include <dlfcn.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sqlite3.h>
#include "slog_internal.h"

static char *sql_create_table_events =
	"CREATE TABLE events ("
	"  'id' INTEGER NOT NULL PRIMARY KEY,"
	"  'time_logged' DATE,"
	"  'time_event' DATE,"
	"  'time_last_update' DATE,"
	"  'type' INTEGER,"
	"  'severity' INTEGER,"
        "  'platform' TEXT,"
        "  'machine_serial' TEXT,"
        "  'machine_model' TEXT,"
        "  'nodename' TEXT,"
	"  'refcode' TEXT,"
	"  'description' TEXT,"
	"  'serviceable' INTEGER,"
	"  'predictive' INTEGER,"
	"  'disposition' INTEGER,"
	"  'call_home_status' INTEGER,"
	"  'closed' INTEGER,"
	"  'repair' INTEGER,"
	"  'callouts' INTEGER,"
	"  'raw_data' BLOB"
	");";
static char *sql_trigger_insert_event =
	"CREATE TRIGGER trigger_events_insert AFTER INSERT ON events"
	" BEGIN"
	"  UPDATE events SET time_logged = DATETIME('NOW'),"
	"                    time_last_update = DATETIME('NOW')"
	"  WHERE rowid = new.rowid;"
	" END;";
static char *sql_trigger_update_event =
	"CREATE TRIGGER trigger_events_update AFTER UPDATE ON events"
	" BEGIN"
	"  UPDATE events SET time_last_update = DATETIME('NOW')"
	"  WHERE rowid = new.rowid;"
	" END;";

static char *sql_create_table_callouts =
	"CREATE TABLE callouts ("
	"  'id' INTEGER NOT NULL PRIMARY KEY,"
	"  'event_id' INTEGER,"
	"  'priority' TEXT,"
	"  'type' INTEGER,"
	"  'procedure' TEXT,"
	"  'location' TEXT,"
	"  'fru' TEXT,"
	"  'serial' TEXT,"
	"  'ccin' TEXT"
	")";

static char *sql_create_table_os =
	"CREATE TABLE os ("
	"  'event_id' INTEGER NOT NULL PRIMARY KEY,"
        "  'version' TEXT,"
	"  'subsystem' TEXT,"
        "  'driver' TEXT,"
        "  'device' TEXT"
	");";
static char *sql_create_table_rtas =
	"CREATE TABLE rtas ("
	"  'event_id' INTEGER NOT NULL PRIMARY KEY,"
	"  'action_flags' INTEGER,"
	"  'platform_id' INTEGER,"
	"  'creator_id' TEXT,"
	"  'subsystem_id' INTEGER,"
	"  'pel_severity' INTEGER,"
	"  'event_type' INTEGER,"
	"  'event_subtype' INTEGER,"
	"  'kernel_id' INTEGER,"
	"  'addl_word1' INTEGER,"
	"  'addl_word2' INTEGER,"
	"  'addl_word3' INTEGER,"
	"  'addl_word4' INTEGER,"
	"  'addl_word5' INTEGER,"
	"  'addl_word6' INTEGER,"
	"  'addl_word7' INTEGER,"
	"  'addl_word8' INTEGER"
	");";
static char *sql_create_table_enclosure =
	"CREATE TABLE enclosure ("
	"  'event_id' INTEGER NOT NULL PRIMARY KEY,"
	"  'enclosure_serial' TEXT,"
	"  'enclosure_model' TEXT"
	");";
static char *sql_create_table_bmc =
	"CREATE TABLE bmc ("
	"  'event_id' INTEGER NOT NULL PRIMARY KEY,"
	"  'sel_id' INTEGER,"
	"  'sel_type' INTEGER,"
	"  'generator' INTEGER,"
	"  'version' INTEGER,"
	"  'sensor_type' INTEGER,"
	"  'sensor_number' INTEGER,"
	"  'event_class' INTEGER,"
	"  'event_type' INTEGER,"
	"  'direction' INTEGER"
	");";

static char *sql_create_table_repair_actions =
	"CREATE TABLE repair_actions ("
	"  'id' INTEGER NOT NULL PRIMARY KEY,"
	"  'time_logged' DATE,"
	"  'time_repair' DATE,"
	"  'procedure' TEXT,"
	"  'location' TEXT,"
        "  'platform' TEXT,"
        "  'machine_serial' TEXT,"
        "  'machine_model' TEXT,"
	"  'notes' TEXT"
	");";
static char *sql_trigger_insert_repair_action =
	"CREATE TRIGGER trigger_repair_actions_insert AFTER INSERT ON "
	"repair_actions"
	" BEGIN"
	"  UPDATE repair_actions SET time_logged = DATETIME('NOW')"
	"  WHERE rowid = new.rowid;"
	" END;";

static char *sql_create_table_notifications =
	"CREATE TABLE notifications ("
	"  'id' INTEGER NOT NULL PRIMARY KEY,"
	"  'time_logged' DATE,"
	"  'time_last_update' DATE,"
	"  'notify' INTEGER,"
	"  'command' TEXT,"
	"  'method' INTEGER,"
	"  'match' TEXT"
	");";
static char *sql_trigger_insert_notification =
	"CREATE TRIGGER trigger_notifications_insert AFTER INSERT ON "
	"notifications"
	" BEGIN"
	"  UPDATE notifications SET time_logged = DATETIME('NOW'),"
	"                           time_last_update = DATETIME('NOW')"
	"  WHERE rowid = new.rowid;"
	" END;";
static char *sql_trigger_update_notification =
	"CREATE TRIGGER trigger_notifications_update AFTER UPDATE ON "
	"notifications"
	" BEGIN"
	"  UPDATE notifications SET time_last_update = DATETIME('NOW')"
	"  WHERE rowid = new.rowid;"
	" END;";

extern int errno;

static char sl_print_width = 80;
static int line_offset = 0;

/**
 * sl_hex_dump
 *
 * Dump the provided buffer in raw hex output
 */
int
sl_hex_dump(FILE *str, void *data, size_t len)
{
	char *h, *a;
	char *end = data + len;
	unsigned int offset = 0;
	int i,j;

	h = a = data;

	while (h < end) {
		/* print offset */
		fprintf(str, "0x%08x:  ", offset);
		offset += 16;

		/* print hex */
		for (i = 0; i < 4; i++) {
			for (j = 0; j < 4; j++) {
				if (h < end)
					fprintf(str, "%02x", *h++);
				else
					fprintf(str, "  ");
			}
			fprintf(str, " ");
		}

		/* print ascii */
		fprintf(str, "    [");
		for (i = 0; i < 16; i++) {
			if (a <= end) {
				if ((*a >= ' ') && (*a <= '~'))
					fprintf(str, "%c", *a);
				else
					fprintf(str, ".");
				a++;
			} else
				fprintf(str, " ");
		}
		fprintf(str, "]\n");
	}

	return len;
}

/**
 * sl_printf
 *
 * fprintf function for libservicelog to maintain word wrapping for all
 * output at sl_print_width (68) characters.
 */
int
sl_printf(FILE *stream, char *fmt, ...)
{
	va_list ap;
	int i, buf_offset = 0, offset = 0;
	int tmpbuf_len, width = 0, prnt_len;
	char buf[1024], tmpbuf[1024];
	char *newline = NULL, *brkpt = NULL;

	memset(tmpbuf, 0, sizeof(tmpbuf));
	memset(buf, 0, sizeof(buf));

	va_start(ap, fmt);
	tmpbuf_len = vsnprintf(tmpbuf, 1024, fmt, ap);
	va_end(ap);

	i = 0;
	while (i < tmpbuf_len) {
		brkpt = NULL;
		newline = NULL;

		for (i = offset, width = line_offset;
		     (width < sl_print_width) && (i < tmpbuf_len);
		     i++) {

			switch (tmpbuf[i]) {
			case ' ':
			case '-':
				width++;
				brkpt = &tmpbuf[i];
				break;
			case '\n':
				newline = &tmpbuf[i];
				width++;
				break;
			default:
				width++;
				break;
			}

			if (newline != NULL) {
				prnt_len = newline - &tmpbuf[offset] + 1;
				snprintf(buf + buf_offset, prnt_len,
					 "%s", &tmpbuf[offset]);
				buf_offset = strlen(buf);
				buf_offset += sprintf(buf + buf_offset, "\n");
				offset += prnt_len;
				line_offset = 0;
				break;
			}
		}

		if (width >= sl_print_width) {
			if (brkpt == NULL) {
				/* won't fit on one line, break across lines */
				prnt_len = width - line_offset + 1;
			} else {
				prnt_len = (brkpt - &tmpbuf[offset]) + 1;
			}

			/* print up to the last brkpt */
			snprintf(buf + buf_offset, prnt_len, "%s", &tmpbuf[offset]);
			buf_offset = strlen(buf);
			buf_offset += sprintf(buf + buf_offset, "\n");
			offset += prnt_len;
			line_offset = 0;
		}
	}

	prnt_len = sprintf(buf + buf_offset, "%s", &tmpbuf[offset]);
	line_offset += prnt_len;

	return fprintf(stream, "%s", buf);
}

/**
 * get_system_info
 * @brief Obtain the serial number or model of the current system
 *
 * @param[in]  var variable to retrieve ("serial" or "model")
 * @param[out] buf buffer in which to store the null terminated serial number
 * @param[in]  sz size of the buffer passed as buf
 * @return number of characters written to the buf
 */
size_t
get_system_info(char *var, char *buf, size_t sz)
{
	int n_read, n_junk_chars = 0;
	char filebuf[32], junk_chars[6];
	FILE *fd;

	buf[0] = '\0';

	if (!strcmp(var, "serial")) {
		snprintf(filebuf, 32, "/proc/device-tree/system-id");
		n_junk_chars = 6;
	}
	else if (!strcmp(var, "model")) {
		snprintf(filebuf, 32, "/proc/device-tree/model");
		n_junk_chars = 4;
	}
	else
		return 0;

	fd = fopen(filebuf, "r");
	if (fd == NULL)
		return 0;

	if (n_junk_chars > 0)
		fread(junk_chars, n_junk_chars, 1, fd);

	n_read = fread(buf, sz, 1, fd);
	fclose(fd);

	return n_read;
}

/**
 * replace_query_keywords
 * @brief Replace keywords in a query string with their appropriate values
 * @param[in] slog servicelog handle
 * @param[in] query the string upon which to operate
 * @param[out] stmt resulting sqlite query statement
 * @param[out] err buffer in which to write any error information
 * @param[in] err_sz the size of the buffer passed as err
 * @return 0 on success, !0 otherwise (message returned in err buffer)
 */
int
replace_query_keywords(servicelog *slog, char *query, sqlite3_stmt **stmt,
		       char *err, size_t err_sz)
{
	int num, rc, i;
	const char *name;

	if ((slog == NULL) || (query == NULL))
		return 1;

	rc = sqlite3_prepare(slog->db, query, -1, stmt, NULL);
	if (rc != SQLITE_OK) {
		snprintf(err, err_sz, "%s", sqlite3_errmsg(slog->db));
		return 2;
	}

	/* TODO: check for the "age" special query parameter */

	/* replace $ keywords with their appropriate values */
	num = sqlite3_bind_parameter_count(*stmt);

	for (i=1; i<=num; i++) {
		name = sqlite3_bind_parameter_name(*stmt, i);
		if (!strncmp(name, "$BASIC", 6))
			sqlite3_bind_int(*stmt, i, SL_TYPE_BASIC);
		else if (!strncmp(name, "$OS", 3))
			sqlite3_bind_int(*stmt, i, SL_TYPE_OS);
		else if (!strncmp(name, "$RTAS", 5))
			sqlite3_bind_int(*stmt, i, SL_TYPE_RTAS);
		else if (!strncmp(name, "$BMC", 4))
			sqlite3_bind_int(*stmt, i, SL_TYPE_BMC);
		else if (!strncmp(name, "$ENCLOSURE", 10))
			sqlite3_bind_int(*stmt, i, SL_TYPE_ENCLOSURE);
		else if (!strncmp(name, "$FATAL", 6))
			sqlite3_bind_int(*stmt, i, SL_SEV_FATAL);
		else if (!strncmp(name, "$ERROR", 6))
			sqlite3_bind_int(*stmt, i, SL_SEV_ERROR);
		else if (!strncmp(name, "$ERROR_LOCAL", 12))
			sqlite3_bind_int(*stmt, i, SL_SEV_ERROR_LOCAL);
		else if (!strncmp(name, "$WARNING", 8))
			sqlite3_bind_int(*stmt, i, SL_SEV_WARNING);
		else if (!strncmp(name, "$EVENT", 6))
			sqlite3_bind_int(*stmt, i, SL_SEV_EVENT);
		else if (!strncmp(name, "$INFO", 5))
			sqlite3_bind_int(*stmt, i, SL_SEV_INFO);
		else if (!strncmp(name, "$DEBUG", 6))
			sqlite3_bind_int(*stmt, i, SL_SEV_DEBUG);
		else {
			if (err != NULL)
				snprintf(err, err_sz, "Unrecognized value: %s",
					 name);
			return 2;
		}
	}

	return 0;
}

/**
 * format_text_to_insert
 * @brief Replace one ' (apostrophe) with two to make a legal SQL string.
 *
 * @param[in] input input string
 * @param[out] output legal SQL string
 * @param[in] size size of the output buffer
 */
void
format_text_to_insert(char *input, char *output, int size)
{
	char *end = output + size - 1; /* Leave room for trailing NULL. */

	while (*input && output < end) {
		if (*input == '\'') {
			if (output + 2 > end)
				break; /* Lack room for 2 apostrophes. */
			*output++ = '\'';
		}
		*output++ = *input++;
	}
	*output = '\0';
}

/**
 * servicelog_init
 * @brief Populate the database with tables and triggers.
 *
 * @param[in] slog servicelog handle
 * @return 0 on success, 1 bad parameter, 2 on SQL error
 */
static int
servicelog_init(servicelog *slog)
{
	int rc;
	char *err;

	if (slog == NULL)
		return 1;

	slog->error[0] = '\0';

	/*
	 * The IF NOT EXISTS feature of SQL was not introduced in sqlite
	 * until 3.3, so we will check the type of failure after each
	 * table or trigger creation to determine if the failure was
	 * due to the table/trigger already existing.
	 */

	/* Create the "events" table and its triggers */
	rc = sqlite3_exec(slog->db, sql_create_table_events, NULL, NULL, &err);
	if ((rc != SQLITE_ERROR) && (rc != SQLITE_OK))
		goto err_out;

	sqlite3_free(err);
	rc = sqlite3_exec(slog->db, sql_trigger_insert_event, NULL, NULL, &err);
	if ((rc != SQLITE_ERROR) && (rc != SQLITE_OK))
		goto err_out;

	sqlite3_free(err);
	rc = sqlite3_exec(slog->db, sql_trigger_update_event, NULL, NULL, &err);
	if ((rc != SQLITE_ERROR) && (rc != SQLITE_OK))
		goto err_out;

	sqlite3_free(err);
	/* Create the "callouts" table */
	rc = sqlite3_exec(slog->db, sql_create_table_callouts,
			  NULL, NULL, &err);
	if ((rc != SQLITE_ERROR) && (rc != SQLITE_OK))
		goto err_out;

	sqlite3_free(err);
	/* Create the additional data tables */
	rc = sqlite3_exec(slog->db, sql_create_table_os, NULL, NULL, &err);
	if ((rc != SQLITE_ERROR) && (rc != SQLITE_OK))
		goto err_out;

	sqlite3_free(err);
	rc = sqlite3_exec(slog->db, sql_create_table_rtas, NULL, NULL, &err);
	if ((rc != SQLITE_ERROR) && (rc != SQLITE_OK))
		goto err_out;

	sqlite3_free(err);
	rc = sqlite3_exec(slog->db, sql_create_table_enclosure,
			  NULL, NULL, &err);
	if ((rc != SQLITE_ERROR) && (rc != SQLITE_OK))
		goto err_out;

	sqlite3_free(err);
	rc = sqlite3_exec(slog->db, sql_create_table_bmc, NULL, NULL, &err);
	if ((rc != SQLITE_ERROR) && (rc != SQLITE_OK))
		goto err_out;

	sqlite3_free(err);
	/* Create the "repair_actions" table and its triggers */
	rc = sqlite3_exec(slog->db, sql_create_table_repair_actions,
			  NULL, NULL, &err);
	if ((rc != SQLITE_ERROR) && (rc != SQLITE_OK))
		goto err_out;

	sqlite3_free(err);
	rc = sqlite3_exec(slog->db, sql_trigger_insert_repair_action,
			  NULL, NULL, &err);
	if ((rc != SQLITE_ERROR) && (rc != SQLITE_OK))
		goto err_out;

	sqlite3_free(err);
	/* Create the "notifications" table and its triggers */
	rc = sqlite3_exec(slog->db, sql_create_table_notifications,
			  NULL, NULL, &err);
	if ((rc != SQLITE_ERROR) && (rc != SQLITE_OK))
		goto err_out;

	sqlite3_free(err);
	rc = sqlite3_exec(slog->db, sql_trigger_insert_notification,
			  NULL, NULL, &err);
	if ((rc != SQLITE_ERROR) && (rc != SQLITE_OK))
		goto err_out;
	sqlite3_free(err);

	rc = sqlite3_exec(slog->db, sql_trigger_update_notification,
			  NULL, NULL, &err);
	if ((rc != SQLITE_ERROR) && (rc != SQLITE_OK))
		goto err_out;
	sqlite3_free(err);

	return 0;

err_out:
	snprintf(slog->error, SL_MAX_ERR, "Error: %s", err);
	sqlite3_free(err);
	return 2;
}

/**
 * servicelog_open
 * @brief Open the database
 * @param[in] servicelog: struct servlog
 * @param[out] slog pointer to servicelog handle for the opened database
 * @param[in] flags see SL_FLAG_*
 * @return 0 on success, EINVAL on bad parameter, ENOENT if db does not exist
 */
int
servicelog_open(servicelog **slog, uint32_t flags)
{
	int rc;
	struct servicelog *log;

	if (slog == NULL)
		return EINVAL;

	*slog = NULL;

	log = malloc(sizeof(struct servicelog));
	if (!log)
		return ENOMEM;
	memset(log, 0, sizeof(struct servicelog));

	log->flags = flags;
	log->location = SERVICELOG_PATH;
	log->error[0] = '\0';

	rc = sqlite3_open(log->location, &(log->db));
	if (rc) {
		snprintf(log->error, SL_MAX_ERR, "%s", sqlite3_errmsg(log->db));
		servicelog_close(log);
		return ENOENT;
	}

	rc = servicelog_init(log);
	if (rc) {
		servicelog_close(log);
		return ENOENT;
	}

	*slog = log;
	return 0;
}

/**
 * servicelog_close
 * @brief Open the database
 *
 * @param[out] slog servicelog handle to be closed
 */
void
servicelog_close(servicelog *slog)
{
	if (slog == NULL)
		return;

	sqlite3_close(slog->db);
	free(slog);
}

/**
 * servicelog_truncate
 * @brief Remove all records from the log (must be opened with SL_FLAG_ADMIN)
 *
 * @param[in] slog servicelog handle
 * @param[in] notifications_too remove notify records in addition to events
 * @return 0 on success, EINVAL on bad parameter, ENOENT if db does not exist
 */
int
servicelog_truncate(servicelog *slog, int notifications_too)
{
	int rc;

	if (slog == NULL)
		return EINVAL;

	if ((slog->flags && SL_FLAG_ADMIN) == 0) {
		snprintf(slog->error, SL_MAX_ERR, "The database must be "
			 "opened with the ADMIN flag");
		return EACCES;
	}

	rc = sqlite3_exec(slog->db, "DELETE FROM events",
			  NULL, NULL, NULL);
	rc = sqlite3_exec(slog->db, "DELETE FROM callouts",
			  NULL, NULL, NULL);
	rc = sqlite3_exec(slog->db, "DELETE FROM os",
			  NULL, NULL, NULL);
	rc = sqlite3_exec(slog->db, "DELETE FROM rtas",
			  NULL, NULL, NULL);
	rc = sqlite3_exec(slog->db, "DELETE FROM enclosure",
			  NULL, NULL, NULL);
	rc = sqlite3_exec(slog->db, "DELETE FROM bmc",
			  NULL, NULL, NULL);
	rc = sqlite3_exec(slog->db, "DELETE FROM repair_actions",
			  NULL, NULL, NULL);

	if (notifications_too)
		rc = sqlite3_exec(slog->db, "DELETE FROM notifications",
				  NULL, NULL, NULL);

	return 0;
}

/**
 * servicelog_error
 * @brief Returns a string detailing the last servicelog error encountered
 *
 * @param[in] slog servicelog handle
 * @return pointer to error string
 */
char *
servicelog_error(servicelog *slog)
{
	return slog->error;
}
