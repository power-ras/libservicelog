/**
 * @file event.c
 * @brief APIs for inserting/retrieving events
 *
 * Copyright (C) 2008, 2013 IBM
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

#include <grp.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <sqlite3.h>
#include <inttypes.h>
#include <sys/types.h>
#include <sys/utsname.h>
// #define _XOPEN_SOURCE
#define __USE_XOPEN
#include <time.h>
#include "slog_internal.h"

static char *severity_text[] = { "", "DEBUG", "INFO", "EVENT", "WARNING",
				 "ERROR_LOCAL", "ERROR", "FATAL" };

static char *disp_text[] = { "Recoverable", "Unrecoverable",
			     "Unrecoverable, Bypassed" };

static char *callhome_text[] = { "None Needed", "Call Home Candidate",
				 "Called Home" };

struct addl_data {
	char *title;
	char *table;
	int (*insert)(servicelog *, struct sl_event *);
	int (*retrieve)(void *, int, char **, char **);
	void (*free)(struct sl_event *);
	int (*print)(FILE *, struct sl_event *, int);
};

/*
 * If you wish to add a new type, reserve a number for it in the SL_TYPE_*
 * defines, increment SL_TYPE_MAX, write the SQL to create the new table,
 * implement helper routines (as documented in addl_data.c), and add a new
 * addl_data struct to this array.
 */
struct addl_data addl_data_fcns[SL_TYPE_MAX + 1] = {
	{	.title = "Basic Event",
		.table = NULL,
		.insert = NULL,
		.retrieve = NULL,
		.free = NULL,
		.print = NULL,
	},
	{	.title = "Operating System Event",
		.table = "os",
		.insert = insert_addl_data_os,
		.retrieve = retrieve_addl_data_os,
		.free = free_addl_data_os,
		.print = print_addl_data_os,
	},
	{	.title = "Power Platform (RTAS) Event",
		.table = "rtas",
		.insert = insert_addl_data_rtas,
		.retrieve = retrieve_addl_data_rtas,
		.free = free_addl_data_rtas,
		.print = print_addl_data_rtas,
	},
	{	.title = "I/O Enclosure Event",
		.table = "enclosure",
		.insert = insert_addl_data_enclosure,
		.retrieve = retrieve_addl_data_enclosure,
		.free = free_addl_data_enclosure,
		.print = print_addl_data_enclosure,
	},
	{	.title = "BMC Event",
		.table = "bmc",
		.insert = insert_addl_data_bmc,
		.retrieve = retrieve_addl_data_bmc,
		.free = free_addl_data_bmc,
		.print = print_addl_data_bmc,
	},
};

static int
put_blob(sqlite3 *db, char *table, uint64_t row, char *column,
	 unsigned char *blob, int sz)
{
	int rc;
	char query[80];
	sqlite3_stmt *stmt;

	snprintf(query, 80, "UPDATE %s SET %s = ? WHERE id = ""%" PRIu64 ,
		 table, column, row);

	do {
		rc = sqlite3_prepare(db, query, 80, &stmt, 0);
		if (rc != SQLITE_OK)
			return rc;

		rc = sqlite3_bind_blob(stmt, 1, blob, sz, SQLITE_STATIC);
		if (rc != SQLITE_OK) {
			sqlite3_finalize(stmt);
			return rc;
		}

		rc = sqlite3_step(stmt);
		if (rc != SQLITE_DONE) {
			sqlite3_finalize(stmt);
			return rc;
		}

		rc = sqlite3_finalize(stmt);
	} while (rc == SQLITE_SCHEMA);

	return rc;
}

int
servicelog_event_log(servicelog *slog, struct sl_event *event,
		     uint64_t *new_id)
{
	int rc, attempts = 0, n_callouts = 0;
	uint64_t event_id = 0;
	char *err;
	char buf[SQL_MAXLEN], timebuf[32];
	char serialbuf[20] = {0,} , modelbuf[20] = {0,};
	char description[DESC_MAXLEN];
	struct tm *t;
	struct sl_callout *callout;
	struct utsname uname_buf;

	if (new_id != NULL)
		*new_id = 0;

	/* Input validation begins here */

	if (slog == NULL)
	       return 1;

	if (event == NULL) {
		snprintf(slog->error, SL_MAX_ERR,
			 "Invalid parameter(s) to servicelog_event_log()");
		return 1;
	}

	/* refcode should always be specified */
	if ((event->refcode == NULL) || (strlen(event->refcode) == 0)) {
		snprintf(slog->error, SL_MAX_ERR,
			 "The refcode field must be specified");
		return 1;
	}

	/* description should always be specified */
	if ((event->description == NULL) || (strlen(event->description) == 0)) {
		snprintf(slog->error, SL_MAX_ERR,
			 "The description field must be specified");
		return 1;
	}

	/* type should be within the range */
	if (event->type > SL_TYPE_MAX) {
		snprintf(slog->error, SL_MAX_ERR, "An invalid value appeared "
			 "in the type field (%d)", event->type);
		return 1;
	}

	/* severity should be within the range */
	if ((event->severity < SL_SEV_DEBUG) ||
	    (event->severity > SL_SEV_FATAL)) {
		snprintf(slog->error, SL_MAX_ERR, "An invalid value appeared "
			 " in the severity field (%d)", event->severity);
		return 1;
	}

	/* serviceable should be 1 or 0 */
	if ((event->serviceable != 0) && (event->serviceable != 1)) {
		snprintf(slog->error, SL_MAX_ERR, "The serviceable field must "
			 "be 0 or 1; %d was specified", event->serviceable);
		return 1;
	}

	/* predictive should be 1 or 0 */
	if ((event->predictive != 0) && (event->predictive != 1)) {
		snprintf(slog->error, SL_MAX_ERR, "The predictive field must "
			 "be 0 or 1; %d was specified", event->predictive);
		return 1;
	}

	/* check raw_data_len and raw_data */
	if ((event->raw_data_len > 0) && (event->raw_data == NULL)) {
		snprintf(slog->error, SL_MAX_ERR, "The raw_data field must "
			 "not be NULL if raw_data_len > 0");
		return 1;
	}
	if ((event->raw_data_len == 0) && (event->raw_data != NULL)) {
		snprintf(slog->error, SL_MAX_ERR, "The raw_data_len field "
			 "cannot be zero if data is specified in raw_data");
		return 1;
	}

	/* addl_data should be non-NULL unless this is a BASIC event */
	if ((event->type != SL_TYPE_BASIC) && (event->addl_data == NULL)) {
		snprintf(slog->error, SL_MAX_ERR,
			 "The addl_data field cannot be NULL");
		return 1;
	}

	/* Input data looks valid at this point */
	callout = event->callouts;
	while (callout) {
		n_callouts++;
		callout = callout->next;
	}

	if (event->time_logged == 0)
		event->time_logged = time(NULL);

	t = gmtime(&(event->time_event));
	strftime(timebuf, 32, "%Y-%m-%d %H:%M:%S", t);

	if (event->machine_serial == NULL) {
		get_system_info("serial", serialbuf, 20);
	} else {
		strncpy(serialbuf, event->machine_serial, 19);
		serialbuf[19] = '\0';
	} /* if */

	if (event->machine_model == NULL) {
		get_system_info("model", modelbuf, 20);
	} else {
		strncpy(modelbuf, event->machine_model, 19);
		modelbuf[19] = '\0';
	} /* if */

	if (!event->serviceable)
		event->closed = 1;

	rc = uname(&uname_buf);
	if (rc != 0) {
		snprintf(slog->error, SL_MAX_ERR, "Could not retrieve "
			 "system information");
		return 2;
	}

	do {
		rc = sqlite3_exec(slog->db, "BEGIN TRANSACTION",
				  NULL, NULL, &err);
		if (rc != SQLITE_OK) {
			snprintf(slog->error, SL_MAX_ERR, "SQL error (%d): %s",
				 rc, err);
			sqlite3_free(err);
			return 2;
		}

		/* update the "events" table */
		format_text_to_insert(event->description, description,
								DESC_MAXLEN);

		snprintf(buf, SQL_MAXLEN, "INSERT INTO events (time_event, type, "
			 "severity, platform, machine_serial, machine_model, "
			 "nodename, refcode, description, serviceable, "
			 "predictive, disposition, call_home_status, closed, "
			 "repair, callouts) VALUES ('%s', %d, %d, '%s', '%s', "
			 "'%s', '%s', '%s', '%s', %d, %d, %d, %d, %d, 0, %d);",
			 timebuf, event->type, event->severity,
			 uname_buf.machine, serialbuf, modelbuf,
			 uname_buf.nodename, event->refcode,
			 description, event->serviceable,
			 event->predictive, event->disposition,
			 event->call_home_status, event->closed, n_callouts);
		rc = sqlite3_exec(slog->db, buf, NULL, NULL, &err);
		if (rc != SQLITE_OK) {
			snprintf(slog->error, SL_MAX_ERR, "INSERT(1) error (%d): "
				 "%s", rc, err);
			sqlite3_free(err);
			goto rollback;
		}

		event_id = (uint64_t)sqlite3_last_insert_rowid(slog->db);
		event->id = event_id;

		/* write the raw_data blob to the "events" table */
		if (event->raw_data && (event->raw_data_len > 0)) {
			rc = put_blob(slog->db, "events", event_id, "raw_data",
				      event->raw_data, event->raw_data_len);
			if (rc != SQLITE_OK)
				goto rollback;
		}

		/* update the appropriate additional data table */
		if (addl_data_fcns[event->type].insert != NULL) {
			rc = addl_data_fcns[event->type].insert(slog, event);
			if (rc != SQLITE_OK) {
				snprintf(slog->error, SL_MAX_ERR,
					 "INSERT(2) error (%d)", rc);
				goto rollback;
			}
		}

		/* now that the addl_data in inserted, insert the callouts */
		callout = event->callouts;
		while (callout != NULL) {
			char *proc, *loc, *fru, *serial, *ccin;

			if (callout->procedure)
				proc = callout->procedure;
			else
				proc = "";

			if (callout->location)
				loc = callout->location;
			else
				loc = "";

			if (callout->fru)
				fru = callout->fru;
			else
				fru = "";

			if (callout->serial)
				serial = callout->serial;
			else
				serial = "";

			if (callout->ccin)
				ccin = callout->ccin;
			else
				ccin = "";

			snprintf(buf, SQL_MAXLEN, "INSERT INTO callouts (event_id, "
				 "priority, type, procedure, location, fru, "
				 "serial, ccin) VALUES (""%" PRIu64 ", '%c', %d, '%s', "
				 "'%s', '%s', '%s', '%s');", event_id,
				 callout->priority, callout->type, proc, loc,
				 fru, serial, ccin);
			rc = sqlite3_exec(slog->db, buf, NULL, NULL, &err);
			if (rc != SQLITE_OK) {
				snprintf(slog->error, SL_MAX_ERR,
					 "INSERT(3) error (%d): %s", rc, err);
				sqlite3_free(err);
				goto rollback;
			}
			callout = callout->next;
		}

		rc = sqlite3_exec(slog->db, "COMMIT TRANSACTION",
				  NULL, NULL, NULL);
rollback:
		if (rc != SQLITE_OK) {
			sqlite3_exec(slog->db, "ROLLBACK TRANSACTION",
				     NULL, NULL, NULL);
		}
	} while ((rc != SQLITE_OK) && (attempts++ < 10));

	if (rc != SQLITE_OK)
		return 2;

	if (new_id != NULL)
		*new_id = event_id;

	rc = notify_event(slog, event_id);
	if (rc != 0)
		return 4;

	return 0;
}

static int
build_callout(void *c, int argc, char **argv, char **column)
{
	int i;
	struct sl_callout *callout;
	struct sl_callout **callout_list = (struct sl_callout **)c;

	if (*callout_list == NULL) {
		*callout_list = calloc(1, sizeof(struct sl_callout));
		callout = *callout_list;
	} else {
		callout = *callout_list;
		while (callout->next != NULL)
			callout = callout->next;
		callout->next = calloc(1, sizeof(struct sl_callout));
		callout = callout->next;
	}

	if (!callout)
		return 1;

	for (i=0; i<argc; i++) {
		if (!strcmp(column[i], "priority"))
			callout->priority = argv[i][0];
		else if (!strcmp(column[i], "type"))
			callout->type = atoi(argv[i]);
		else if (!strcmp(column[i], "procedure")) {
			callout->procedure = strdup(argv[i]);
			if (!callout->procedure)
				goto free_mem;
		}
		else if (!strcmp(column[i], "location")) {
			callout->location = strdup(argv[i]);
			if (!callout->location)
				goto free_mem;
		}
		else if (!strcmp(column[i], "fru")) {
			callout->fru = strdup(argv[i]);
			if (!callout->fru)
				goto free_mem;
		}
		else if (!strcmp(column[i], "serial")) {
			callout->serial = strdup(argv[i]);
			if (!callout->serial)
				goto free_mem;
		}
		else if (!strcmp(column[i], "ccin")) {
			callout->ccin = strdup(argv[i]);
			if (!callout->ccin)
				goto free_mem;
		}
	}

	return 0;

free_mem:
	if (callout->procedure)
		free(callout->procedure);

	if (callout->location)
		free(callout->location);

	if (callout->fru)
		free(callout->fru);

	if (callout->serial)
		free(callout->serial);

	if (callout->ccin)
		free(callout->ccin);

	free(callout);

	return 1;
}

int
servicelog_event_get(servicelog *slog, uint64_t event_id,
		     struct sl_event **event)
{
	char query[30];

	snprintf(query, 30, "id=""%" PRIu64 , event_id);
	return servicelog_event_query(slog, query, event);
}

int
servicelog_event_query(servicelog *slog, char *query,
		       struct sl_event **event)
{
	int rc;
	char buf[512], where[512], *err, *table, errstr[80];
	struct sl_event *e = NULL;
	int (*retrieve_fcn)(void *, int, char **, char **);
	sqlite3_stmt *stmt;

	if (slog == NULL)
	       return 1;

	if ((query == NULL) || (event == NULL)) {
		snprintf(slog->error, SL_MAX_ERR, "Invalid parameter(s)");
		return 1;
	}

	*event = NULL;

	if (strlen(query) > 0)
		snprintf(where, 512, " WHERE (%s)", query);
	else
		where[0] = 0;

	snprintf(buf, 512, "SELECT * FROM %s%s", EVENTS_JOIN, where);

	rc = replace_query_keywords(slog, buf, &stmt, errstr, 80);
	if (rc != 0) {
		snprintf(slog->error, SL_MAX_ERR,
			 "Invalid keyword in query string: %s", errstr);
		return 1;
	}

	/* Run the query and build a new sl_event struct for each result row */
	do {
		int n_cols, i, sz;
		const char *name, *str;
		struct tm t;
		const void *b;

		rc = sqlite3_step(stmt);

		if (rc == SQLITE_DONE)
			continue;

		if (rc != SQLITE_ROW) {
			snprintf(slog->error, SL_MAX_ERR, "Query error (%d): "
				 "%s", rc, sqlite3_errmsg(slog->db));
			sqlite3_finalize(stmt);
			return 1;
		}

		if (*event == NULL) {
			*event = calloc(1, sizeof(struct sl_event));
			e = *event;
		} else {
			e->next = calloc(1, sizeof(struct sl_event));
			e = e->next;
		}

		if (!e)
			return 1;

		n_cols = sqlite3_column_count(stmt);
		for (i = 0; i<n_cols; i++) {
			name = sqlite3_column_name(stmt, i);

			if (!strcmp(name, "id"))
				e->id = (uint64_t)sqlite3_column_int64(stmt, i);
			else if (!strcmp(name, "time_logged")) {
				strptime((char*)sqlite3_column_text(stmt, i),
					 "%Y-%m-%d %T", &t);
				e->time_logged = mktime(&t);
			}
			else if (!strcmp(name, "time_event")) {
				strptime((char*)sqlite3_column_text(stmt, i),
					 "%Y-%m-%d %T", &t);
				e->time_event = mktime(&t);
			}
			else if (!strcmp(name, "time_last_update")) {
				strptime((char*)sqlite3_column_text(stmt, i),
					 "%Y-%m-%d %T", &t);
				e->time_last_update = mktime(&t);
			}
			else if (!strcmp(name, "type"))
				e->type = sqlite3_column_int(stmt, i);
			else if (!strcmp(name, "severity"))
				e->severity = sqlite3_column_int(stmt, i);
			else if (!strcmp(name, "platform")) {
				str = (char *)sqlite3_column_text(stmt, i);
				e->platform = strdup(str);
				if (!e->platform)
					goto free_mem;
			}
			else if (!strcmp(name, "machine_serial")) {
				str = (char *)sqlite3_column_text(stmt, i);
				e->machine_serial = strdup(str);
				if (!e->machine_serial)
					goto free_mem;
			}
			else if (!strcmp(name, "machine_model")) {
				str = (char *)sqlite3_column_text(stmt, i);
				e->machine_model = strdup(str);
				if (!e->machine_model)
					goto free_mem;
			}
			else if (!strcmp(name, "nodename")) {
				str = (char *)sqlite3_column_text(stmt, i);
				e->nodename = strdup(str);
				if (!e->nodename)
					goto free_mem;
			}
			else if (!strcmp(name, "refcode")) {
				str = (char *)sqlite3_column_text(stmt, i);
				e->refcode = strdup(str);
				if (!e->refcode)
					goto free_mem;
			}
			else if (!strcmp(name, "description")) {
				str = (char *)sqlite3_column_text(stmt, i);
				e->description = strdup(str);
				if (!e->description)
					goto free_mem;
			}
			else if (!strcmp(name, "serviceable"))
				e->serviceable = sqlite3_column_int(stmt, i);
			else if (!strcmp(name, "predictive"))
				e->predictive = sqlite3_column_int(stmt, i);
			else if (!strcmp(name, "disposition"))
				e->disposition = sqlite3_column_int(stmt, i);
			else if (!strcmp(name, "call_home_status"))
				e->call_home_status = sqlite3_column_int(stmt,
									 i);
			else if (!strcmp(name, "closed"))
				e->closed = sqlite3_column_int(stmt, i);
			else if (!strcmp(name, "repair"))
				e->repair = (uint64_t)sqlite3_column_int64(stmt,
									   i);
			else if (!strcmp(name, "raw_data")) {
				b = sqlite3_column_blob(stmt, i);
				sz = sqlite3_column_bytes(stmt, i);
				if (sz > 0) {
					e->raw_data_len = sz;
					e->raw_data = malloc(sz);
					if (!e->raw_data)
						goto free_mem;
					memcpy(e->raw_data, b, sz);
				}

				/* For whatever reason, sqlite seems to add
				 * zero'ed out copies of fields after this
				 * one, which should be the last.  So we'll
				 * just quit populating fields at this point.
				 */
				break;
			}
		}
	} while (rc != SQLITE_DONE);

	sqlite3_finalize(stmt);

	e = *event;
	while (e) {
		/* Retrieve any callouts associated with this event */
		snprintf(buf, 512, "SELECT * FROM callouts WHERE "
			 "event_id = ""%" PRIu64 , e->id);
		rc = sqlite3_exec(slog->db, buf, build_callout, &(e->callouts),
				  NULL);

		/* Retrieve any additional data associated with this event */
		if (addl_data_fcns[e->type].retrieve != NULL) {
			table = addl_data_fcns[e->type].table;
			retrieve_fcn = addl_data_fcns[e->type].retrieve;

			snprintf(buf, 512, "SELECT * FROM %s WHERE "
				 "event_id = ""%" PRIu64, table, e->id);

			rc = sqlite3_exec(slog->db, buf, retrieve_fcn, e, &err);
			if (rc != SQLITE_OK) {
				snprintf(slog->error, SL_MAX_ERR,
					 "Query error (%d): %s", rc, err);
				sqlite3_free(err);
				return 1;
			}
		}

		e = e->next;
	}

	return 0;

free_mem:
	if (e->platform)
		free(e->platform);

	if (e->machine_serial)
		free(e->machine_serial);

	if (e->machine_model)
		free(e->machine_model);

	if (e->nodename)
		free(e->nodename);

	if (e->refcode)
		free(e->refcode);

	if (e->description)
		free(e->description);

	if (e->raw_data)
		free(e->raw_data);

	free(e);

	return 1;
}

int
servicelog_event_close(servicelog *slog, uint64_t event_id)
{
	int rc;
	char buf[80], *err;

	if (slog == NULL)
		return 1;

	snprintf(buf, 80, "UPDATE events SET closed=1 WHERE id=""%" PRIu64,
		 event_id);

	rc = sqlite3_exec(slog->db, buf, NULL, NULL, &err);
	if (rc != SQLITE_OK) {
		snprintf(slog->error, SL_MAX_ERR, "UPDATE error (%d): %s",
			 rc, err);
		sqlite3_free(err);
		return 2;
	}

	return 0;
}

int
servicelog_event_repair(servicelog *slog, uint64_t event_id,
			uint64_t repair_id)
{
	int rc;
	char buf[80], *err;

	if (slog == NULL)
		return 1;

	snprintf(buf, 80, "UPDATE events SET closed=1, repair=""%" PRIu64 " WHERE "
		"id=""%" PRIu64, repair_id, event_id);

	rc = sqlite3_exec(slog->db, buf, NULL, NULL, &err);
	if (rc != SQLITE_OK) {
		snprintf(slog->error, SL_MAX_ERR, "UPDATE error (%d): %s",
			 rc, err);
		sqlite3_free(err);
		return 2;
	}

	return 0;
}

static int
delete_row(servicelog *slog, const char *table, const char *id_column,
		uint64_t id)
{
	int rc;
	char buf[80], *err;

	snprintf(buf, 80, "DELETE FROM %s WHERE %s=""%" PRIu64 , table, id_column, id);
	rc = sqlite3_exec(slog->db, buf, NULL, NULL, &err);
	if (rc != SQLITE_OK) {
		snprintf(slog->error, SL_MAX_ERR, "DELETE error (%d): %s",
								rc, err);
		sqlite3_free(err);
	}
	return rc;
}

int
servicelog_event_delete(servicelog *slog, uint64_t event_id)
{
	int rc;
	char *err;

	if (slog == NULL)
		return 1;

	rc = sqlite3_exec(slog->db, "BEGIN TRANSACTION", NULL, NULL, &err);
	if (rc != SQLITE_OK) {
		snprintf(slog->error, SL_MAX_ERR, "SQL error (%d): %s",
								rc, err);
		sqlite3_free(err);
		return 2;
	}

	rc = delete_row(slog, "events", "id", event_id);
	if (rc != SQLITE_OK)
		goto rollback;
	rc = delete_row(slog, "callouts", "event_id", event_id);
	if (rc != SQLITE_OK)
		goto rollback;
	rc = delete_row(slog, "os", "event_id", event_id);
	if (rc != SQLITE_OK)
		goto rollback;
	rc = delete_row(slog, "rtas", "event_id", event_id);
	if (rc != SQLITE_OK)
		goto rollback;
	rc = delete_row(slog, "enclosure", "event_id", event_id);
	if (rc != SQLITE_OK)
		goto rollback;
	rc = delete_row(slog, "bmc", "event_id", event_id);
	if (rc != SQLITE_OK)
		goto rollback;

	rc = sqlite3_exec(slog->db, "COMMIT TRANSACTION", NULL, NULL, &err);
	if (rc == SQLITE_OK)
		return 0;

	snprintf(slog->error, SL_MAX_ERR, "SQL error (%d): %s", rc, err);
	sqlite3_free(err);

rollback:
	sqlite3_exec(slog->db, "ROLLBACK TRANSACTION", NULL, NULL, NULL);
	return 2;
}

/**
 * servicelog_event_print
 * @brief Print an event to a specified stream
 *
 * @param[in] str the stream to which to print
 * @param[in] event the event(s) to print: NULL = no events
 * @param[in] verbosity a verbosity ranging from -1 to 2
 * @return number of characters written; -1 on invalid parameter
 */
int
servicelog_event_print(FILE *str, struct sl_event *event, int verbosity)
{
	int count = 0, i = 0, n_callouts = 0;
	char *pos;
	struct sl_callout *callout;

	if (str == NULL)
		return -1;
	while (event) {
		callout = event->callouts;
		while (callout) {
			n_callouts++;
			callout = callout->next;
		}
		callout = event->callouts;

		if (verbosity < 0) {
			struct tm time;

			/* just print param/value pairs */
			count += fprintf(str, "ServicelogID: ""%" PRIu64 "\n",
					 event->id);
			localtime_r(&(event->time_logged), &time);
			count += fprintf(str, "LogTime: %02d/%02d/%04d "
					 "%02d:%02d:%02d\n", time.tm_mon+1,
					 time.tm_mday, time.tm_year+1900,
					 time.tm_hour, time.tm_min,
					 time.tm_sec);
			localtime_r(&(event->time_event), &time);
			count += fprintf(str, "EventTime: %02d/%02d/%04d "
					 "%02d:%02d:%02d\n", time.tm_mon+1,
					 time.tm_mday, time.tm_year+1900,
					 time.tm_hour, time.tm_min,
					 time.tm_sec);
			localtime_r(&(event->time_last_update), &time);
			count += fprintf(str, "LastUpdateTime: %02d/%02d/%04d "
					 "%02d:%02d:%02d\n", time.tm_mon+1,
					 time.tm_mday, time.tm_year+1900,
					 time.tm_hour, time.tm_min,
					 time.tm_sec);
			count += fprintf(str, "EventType: %s\n",
					 addl_data_fcns[event->type].title);
			count += fprintf(str, "Severity: %d\n",
					 event->severity);
			count += fprintf(str, "Platform: %s\n",
					 event->platform);
			count += fprintf(str, "MachineSerial: %s\n",
					 event->machine_serial);
			count += fprintf(str, "MachineModel: %s\n",
					 event->machine_model);
			count += fprintf(str, "NodeName: %s\n",
					 event->nodename);
			count += fprintf(str, "RefCode: %s\n", event->refcode);

			/* replace newlines with | chars in the description */
			while ((pos = strchr(event->description, '\n')) != NULL)
				*pos = '|';
			count += fprintf(str, "Description: %s\n",
					 event->description);

			count += fprintf(str, "Serviceable: %d\n",
					 event->serviceable);
			count += fprintf(str, "Predictive: %d\n",
					 event->predictive);
			count += fprintf(str, "Disposition: %d\n",
					 event->disposition);
			count += fprintf(str, "CallHomeStatus: %d\n",
					 event->call_home_status);
			count += fprintf(str, "Closed: %d\n", event->closed);
			count += fprintf(str, "RepairID: ""%" PRIu64 "\n",
					 event->repair);
			while (callout != NULL) {
				count += fprintf(str, "Callout: %c %d %s %s %s "
						 "%s %s\n", callout->priority,
						 callout->type,
						 callout->procedure,
						 callout->location,
						 callout->fru, callout->serial,
						 callout->ccin);
				callout = callout->next;
			}
		}
		else {
			count += sl_printf(str, PRNT_FMT_UINT64,
					   "Servicelog ID:", event->id);
			count += sl_printf(str, PRNT_FMT_STR_NR,
					   "Log Timestamp:",
					   ctime(&(event->time_logged)));
			count += sl_printf(str, PRNT_FMT_STR_NR,
					   "Event Timestamp:",
					   ctime(&(event->time_event)));
			count += sl_printf(str, PRNT_FMT_STR_NR,
					   "Update Timestamp:",
					   ctime(&(event->time_last_update)));
			count += sl_printf(str, PRNT_FMT_STR, "Type:",
					   addl_data_fcns[event->type].title);
			count += sl_printf(str, "%-20s%d (%s)\n", "Severity:",
					   event->severity,
					   severity_text[event->severity]);
			count += sl_printf(str, PRNT_FMT_STR, "Platform:",
					   event->platform);
			count += sl_printf(str, "%-20s%s/%s\n", "Model/Serial:",
					   event->machine_model,
					   event->machine_serial);
			count += sl_printf(str, PRNT_FMT_STR, "Node Name:",
					   event->nodename);
			count += sl_printf(str, PRNT_FMT_STR, "Reference Code:",
					   event->refcode);

			count += sl_printf(str, PRNT_FMT_STR,
					   "Serviceable Event:",
					   ((event->serviceable) ?
						"Yes" : "No"));
			count += sl_printf(str, PRNT_FMT_STR,
					   "Predictive Event:",
					   ((event->predictive) ?
						"Yes" : "No"));
			count += sl_printf(str, "%-20s%d (%s)\n",
					   "Disposition:",
					   event->disposition,
					   disp_text[event->disposition]);
			count += sl_printf(str, "%-20s%d (%s)\n",
					   "Call Home Status:",
					   event->call_home_status,
					   callhome_text[
						event->call_home_status]);
			if (event->closed && event->repair) {
				count += sl_printf(str,
					   "%-20sRepaired by %llu\n",
					   "Status:", event->repair);
			}
			else {
				count += sl_printf(str, PRNT_FMT_STR, "Status:",
						   ((event->closed) ?
							"Closed" : "Open"));
			}
		}

		if (addl_data_fcns[event->type].print != NULL)
			count += addl_data_fcns[event->type].print(str, event,
								   verbosity);

		if (verbosity >= 0) {
			count += sl_printf(str, "\nDescription:\n%s\n\n",
					   event->description);
		}
		if (verbosity >= 1) {
			callout = event->callouts;
			i = 0;
			while (callout != NULL) {
				count += sl_printf(str, "\n<< Callout %d >>\n",
						   i + 1);
				i++;

				count += sl_printf(str, PRNT_FMT_CHAR,
						   "Priority",
						   callout->priority);
				count += sl_printf(str, PRNT_FMT_NUM, "Type",
						   callout->type);
				count += sl_printf(str, PRNT_FMT_STR,
						   "Procedure Id:",
						   callout->procedure);
				count += sl_printf(str, PRNT_FMT_STR,
						   "Location:",
						   callout->location);
				count += sl_printf(str, PRNT_FMT_STR, "FRU:",
						   callout->fru);
				count += sl_printf(str, PRNT_FMT_STR, "Serial:",
						   callout->serial);
				count += sl_printf(str, PRNT_FMT_STR, "CCIN:",
						   callout->ccin);
				count += sl_printf(str, "\n");
				callout = callout->next;
			}
		}
		event = event->next;
	}

	return count;
}

void
servicelog_event_free(struct sl_event *event)
{
	struct sl_event *t1, *t2;
	struct sl_callout *c1, *c2;

	t1 = event;
	while (t1) {
		t2 = t1->next;

		c1 = t1->callouts;
		while (c1) {
			c2 = c1->next;
			free(c1->procedure);
			free(c1->location);
			free(c1->fru);
			free(c1->serial);
			free(c1->ccin);
			free(c1);
			c1 = c2;
		}

		free(t1->platform);
		free(t1->machine_serial);
		free(t1->machine_model);
		free(t1->nodename);
		free(t1->refcode);
		free(t1->description);
		free(t1->raw_data);
		if (addl_data_fcns[t1->type].free != NULL)
			addl_data_fcns[t1->type].free(t1);
		free(t1);
		t1 = t2;
	}
}
