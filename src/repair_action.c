/**
 * @file repair_action.c
 * @brief APIs for inserting/retrieving repair actions
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

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
// #define _XOPEN_SOURCE
#define __USE_XOPEN
#include <time.h>
#include <grp.h>
#include <sys/types.h>
#include <sys/utsname.h>
#include <sqlite3.h>
#include "slog_internal.h"

static void
add_to_list(servicelog *slog, struct sl_event **events, uint64_t id)
{
	struct sl_event *event, *e;

	servicelog_event_get(slog, id, &event);

	if (*events == NULL)
		*events = event;
	else {
		e = *events;
		while (e->next)
			e = e->next;
		e->next = event;
	}
}

/*
 * All this is about matching procedure and location strings in event
 * callouts with those in a repair actions.  See the comment in
 * servicelog_repair_log() for details.
 *
 * For both repair actions and events, a null pointer or an empty string
 * ("") counts as a null string.
 */
#define RA_NO_MATCH	0x0
#define RA_NULL_MATCH	0x1	/* null strings match */
#define RA_STRING_MATCH	0x2	/* non-null strings match */
struct ra_match {
	const char *repair_str;
	int repair_str_null;
	int all_callouts_null;
	int matches;		/* bitmap of RA_*_MATCH */
};

static void
rstr_match_init(struct ra_match *ram, const char *ra_str)
{
	if (ra_str) {
		ram->repair_str = ra_str;
		ram->repair_str_null = !strcmp(ra_str, "");
	} else {
		ram->repair_str = "";
		ram->repair_str_null = 1;
	}
	ram->all_callouts_null = 1;
	ram->matches = 0x0;
}

static int
rstr_match(struct ra_match *ram, const char *event_str)
{
	int match = RA_NO_MATCH;
	if (event_str) {
		if (!strcmp(event_str, "")) {
			if (ram->repair_str_null)
				match = RA_NULL_MATCH;
		} else {
			ram->all_callouts_null = 0;
			if (!strcmp(ram->repair_str, event_str))
				match = RA_STRING_MATCH;
		}
	} else if (ram->repair_str_null)
		match = RA_NULL_MATCH;
	ram->matches |= match;
	return match;
}

static int
rstr_matched_somewhere(struct ra_match *ram)
{
	if (ram->matches & RA_STRING_MATCH)
		return 1;
	if (ram->all_callouts_null && (ram->matches & RA_NULL_MATCH))
		return 1;
	return 0;
}

int
servicelog_repair_log(servicelog *slog, struct sl_repair_action *repair,
		      uint64_t *new_id, struct sl_event **events)
{
	int rc;
	uint64_t ra_id = 0;
	char *err;
	char buf[SQL_MAXLEN], timebuf[32], serialbuf[20], modelbuf[20];
	char notes[DESC_MAXLEN];
	struct tm *t;
	struct utsname uname_buf;
	struct sl_event *event, *e;
	struct sl_callout *c;
	int testing;
	char *testing_env_var;

	if (new_id != NULL)
		*new_id = 0;

	/* Input validation begins here */

	if (slog == NULL)
		return 1;
	if (repair == NULL) {
		snprintf(slog->error, SL_MAX_ERR, "Invalid parameter(s)");
		return 1;
	}

	/*
	 * The procedure and location fields can be empty strings, but
	 * not null pointers.
	 */
	if (repair->procedure == NULL || repair->location == NULL) {
		snprintf(slog->error, SL_MAX_ERR,
			 "The procedure and location fields must be specified");
		return 1;
	}

	/* Input data looks valid at this point */

	if (repair->time_logged == 0)
		repair->time_logged = time(NULL);

	t = gmtime(&(repair->time_repair));
	strftime(timebuf, 32, "%Y-%m-%d %H:%M:%S", t);

	if (repair->machine_serial == NULL)
		get_system_info("serial", serialbuf, 20);
	else
		strncpy(serialbuf, repair->machine_serial, 20);

	if (repair->machine_model == NULL)
		get_system_info("model", modelbuf, 20);
	else
		strncpy(modelbuf, repair->machine_model, 20);

	rc = uname(&uname_buf);
	if (rc != 0) {
		snprintf(slog->error, SL_MAX_ERR, "Could not retrieve "
			 "system information");
		return 3;
	}

	notes[0] = '\0';
	if (repair->notes != NULL)
		format_text_to_insert(repair->notes, notes, DESC_MAXLEN);

	/* update the "repair_actions" table */
	snprintf(buf, SQL_MAXLEN, "INSERT INTO repair_actions (time_repair, "
		 "procedure, location, platform, machine_serial, "
		 "machine_model, notes) VALUES ('%s', '%s', '%s', '%s', '%s', "
		 "'%s', '%s');", timebuf, repair->procedure, repair->location,
		 uname_buf.machine, serialbuf, modelbuf, notes);
	rc = sqlite3_exec(slog->db, buf, NULL, NULL, &err);
	if (rc != SQLITE_OK) {
		snprintf(slog->error, SL_MAX_ERR, "INSERT error (%d): %s",
			 rc, err);
		sqlite3_free(err);
		return 2;
	}
	sqlite3_free(err);

	ra_id = (uint64_t)sqlite3_last_insert_rowid(slog->db);
	repair->id = ra_id;

	if (new_id != NULL)
		*new_id = ra_id;

	/*
	 * Obtain a list of events repaired by this repair action.  Such an
	 * event meets all of the following critera:
	 * - serviceable
	 * - not closed
	 * - machine_serial and machine_model match the repair action
	 *	(typically the case if the event and the repair action
	 *	are logged on the same system).  This test is skipped
	 *	if $SERVICELOG_TEST=yes, so testers can inject and repair
	 *	events recorded on other systems.
	 * - at least one callout matches the repair action's procedure
	 * - at least one callout matches the repair action's location
	 * A null procedure or location in the repair action is considered
	 * to match only if all the callouts' corresponding values are also
	 * null.  However, if any callout matches the repair action both
	 * on procedure and location (even if they're null), the event is
	 * considered to match.  See, e.g., PR #59982.
	 */
	testing_env_var = getenv("SERVICELOG_TEST");
	testing = (testing_env_var && !strcmp(testing_env_var, "yes"));

	servicelog_event_query(slog, "serviceable = 1 AND closed = 0", &event);
	*events = NULL;
	e = event;
	while (e) {
		if (testing || (!strcmp(e->machine_serial, serialbuf) &&
		    !strcmp(e->machine_model, modelbuf))) {
			struct ra_match procedure_matches, location_matches;
			int procedure_match, location_match;
			int callout_matched = 0;

			rstr_match_init(&procedure_matches, repair->procedure);
			rstr_match_init(&location_matches, repair->location);
			for (c = e->callouts; c; c = c->next) {
				procedure_match = rstr_match(&procedure_matches,
								c->procedure);
				location_match = rstr_match(&location_matches,
								c->location);
				if (procedure_match && location_match) {
					callout_matched = 1;
					break;
				}
			}

			/*
			 * An event with no callouts is matched by a
			 * repair_action with null location and procedure.
			 */
			if (!e->callouts && procedure_matches.repair_str_null
					&& location_matches.repair_str_null)
				callout_matched = 1;

			if (callout_matched ||
			    (rstr_matched_somewhere(&procedure_matches)
			    && rstr_matched_somewhere(&location_matches)))
				add_to_list(slog, events, e->id);
		}
		e = e->next;
	}
	servicelog_event_free(event);

	/* Mark the repaired events as such. */
	for (e = *events; e; e = e->next) {
		rc = servicelog_event_repair(slog, e->id, ra_id);
		if (rc != 0) {
			servicelog_event_free(*events);
			return rc;
		}
		e->closed = 1;
		e->repair = ra_id;
	}

	rc = notify_repair(slog, ra_id);
	if (rc != 0)
		return 4;

	return 0;

}

int
servicelog_repair_get(servicelog *slog, uint64_t repair_id,
		      struct sl_repair_action **repair)
{
	char query[30];

	snprintf(query, 30, "id=%llu", repair_id);
	return servicelog_repair_query(slog, query, repair);
}

int
servicelog_repair_query(servicelog *slog, char *query,
			struct sl_repair_action **repair)
{
	int rc;
	char buf[512], where[512], errstr[80];
	sqlite3_stmt *stmt;
	struct sl_repair_action *r = NULL;

	if ((slog == NULL) || (query == NULL) || (repair == NULL)) {
		snprintf(slog->error, SL_MAX_ERR, "Invalid parameter(s)");
		return 1;
	}

	*repair = NULL;

	if (strlen(query) > 0)
		snprintf(where, 512, " WHERE (%s)", query);
	else
		where[0] = '\0';

	snprintf(buf, 512, "SELECT * FROM repair_actions%s", where);

	rc = replace_query_keywords(slog, buf, &stmt, errstr, 80);
	if (rc != 0) {
		snprintf(slog->error, SL_MAX_ERR,
			 "Invalid keyword in query string: %s", errstr);
		return 1;
	}

	do {
		int n_cols, i;
		const char *name, *str;
		struct tm t;

		rc = sqlite3_step(stmt);

		if (rc == SQLITE_DONE)
			continue;

		if (rc != SQLITE_ROW) {
			snprintf(slog->error, SL_MAX_ERR, "Query error (%d): "
				 "%s", rc, sqlite3_errmsg(slog->db));
			sqlite3_finalize(stmt);
			return 1;
		}

		if (*repair == NULL) {
			*repair = malloc(sizeof(struct sl_repair_action));
			r = *repair;
		} else {
			r->next = malloc(sizeof(struct sl_repair_action));
			r = r->next;
		}
		if (!r)
			return 1;
		memset(r, 0, sizeof(struct sl_repair_action));

		n_cols = sqlite3_column_count(stmt);
		for (i = 0; i<n_cols; i++) {
			name = sqlite3_column_name(stmt, i);

			if (!strcmp(name, "id"))
				r->id = (uint64_t)sqlite3_column_int64(stmt, i);
			else if (!strcmp(name, "time_logged")) {
				strptime((char*)sqlite3_column_text(stmt, i),
					 "%Y-%m-%d %T", &t);
				r->time_logged = mktime(&t);
			}
			else if (!strcmp(name, "time_repair")) {
				strptime((char*)sqlite3_column_text(stmt, i),
					 "%Y-%m-%d %T", &t);
				r->time_repair = mktime(&t);
			}
			else if (!strcmp(name, "procedure")) {
				str = (char *)sqlite3_column_text(stmt, i);
				r->procedure = strdup(str);
				if (!r->procedure)
					goto free_mem;
			}
			else if (!strcmp(name, "location")) {
				str = (char *)sqlite3_column_text(stmt, i);
				r->location = strdup(str);
				if (!r->location)
					goto free_mem;
			}
			else if (!strcmp(name, "platform")) {
				str = (char *)sqlite3_column_text(stmt, i);
				r->platform = strdup(str);
				if (!r->platform)
					goto free_mem;
			}
			else if (!strcmp(name, "machine_serial")) {
				str = (char *)sqlite3_column_text(stmt, i);
				r->machine_serial = strdup(str);
				if (!r->machine_serial)
					goto free_mem;
			}
			else if (!strcmp(name, "machine_model")) {
				str = (char *)sqlite3_column_text(stmt, i);
				r->machine_model = strdup(str);
				if (!r->machine_model)
					goto free_mem;
			}
			else if (!strcmp(name, "notes")) {
				str = (char *)sqlite3_column_text(stmt, i);
				r->notes = strdup(str);
				if (!r->notes)
					goto free_mem;
			}
		} /* for */
	} while (rc != SQLITE_DONE);

	sqlite3_finalize(stmt);

	return 0;

free_mem:
	if (r->procedure)
		free(r->procedure);

	if (r->location)
		free(r->location);

	if (r->platform)
		free(r->platform);

	if (r->machine_serial)
		free(r->machine_serial);

	if (r->machine_model)
		free(r->machine_model);

	if (r->notes)
		free(r->notes);

	free(r);

	return 1;
}

int
servicelog_repair_delete(servicelog *slog, uint64_t repair_id)
{
	int rc;
	char buf[80], *err;

	if (slog == NULL)
		return 1;

	snprintf(buf, 80, "DELETE FROM repair_actions WHERE id=%llu",
		 repair_id);

	rc = sqlite3_exec(slog->db, buf, NULL, NULL, &err);
	if (rc != SQLITE_OK) {
		snprintf(slog->error, SL_MAX_ERR, "DELETE error (%d): %s",
			 rc, err);
		sqlite3_free(err);
		return 2;
	}
	sqlite3_free(err);

	return 0;
}

/**
 * servicelog_repair_print
 * @brief Print a repair action to a specified stream
 *
 * @param[in] str the stream to which to print
 * @param[in] repair the repair action(s) to print
 * @param[in] verbosity a verbosity ranging from -1 to 2
 * @return number of characters written; -1 on invalid parameter
 */
int
servicelog_repair_print(FILE *str, struct sl_repair_action *repair,
			int verbosity)
{
	int count = 0;

	if ((str == NULL) || (repair == NULL))
		return -1;

	while (repair) {
		if (verbosity < 0) {
			struct tm time;

			count += fprintf(str, "ServicelogID: %llu\n",
					 repair->id);
			localtime_r(&(repair->time_logged), &time);
			count += fprintf(str, "LogTime: %02d/%02d/%04d "
					 "%02d:%02d:%02d\n", time.tm_mon+1,
					 time.tm_mday, time.tm_year+1900,
					 time.tm_hour, time.tm_min,
					 time.tm_sec);
			count += fprintf(str, "Procedure: %s",
					 repair->procedure);
			count += fprintf(str, "Location: %s", repair->location);
			count += fprintf(str, "Platform: %s", repair->platform);
			count += fprintf(str, "MachineSerial: %s\n",
					 repair->machine_serial);
			count += fprintf(str, "MachineModel: %s\n",
					 repair->machine_model);
			count += fprintf(str, "Notes: %s", repair->notes);
		}
		else {
			count += sl_printf(str, PRNT_FMT_UINT64,
					   "Servicelog ID:", repair->id);
			count += sl_printf(str, PRNT_FMT_STR_NR,
					   "Log Timestamp:",
					   ctime(&(repair->time_logged)));
			count += sl_printf(str, PRNT_FMT_STR, "Procedure:",
					   repair->procedure);
			count += sl_printf(str, PRNT_FMT_STR, "Location:",
					   repair->location);
			count += sl_printf(str, PRNT_FMT_STR, "Platform:",
					   repair->platform);
			count += sl_printf(str, "%-20s%s/%s\n",
					   "Model/Serial:",
					   repair->machine_model,
					   repair->machine_serial);
			count += sl_printf(str, PRNT_FMT_STR, "Notes:",
					   repair->notes);
		}
		repair = repair->next;
	}

	return count;
}

void
servicelog_repair_free(struct sl_repair_action *repairs)
{
	struct sl_repair_action *t1, *t2;

	t1 = repairs;
	while (t1) {
		t2 = t1->next;
		free(t1->procedure);
		free(t1->location);
		free(t1->platform);
		free(t1->machine_serial);
		free(t1->machine_model);
		free(t1->notes);
		free(t1);
		t1 = t2;
	}
}
