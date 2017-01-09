/**
 * @file notify.c
 * @brief APIs for servicelog notification tools
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

#include <grp.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <inttypes.h>
#include <sys/types.h>
#include <sys/utsname.h>
#define __USE_XOPEN	// for strptime
#include <time.h>
#include <sqlite3.h>
#include "slog_internal.h"

static char *notify_text[] = { "EVENT", "REPAIR" };

static char *method_text[] = {
			"Log Number via Command Line",
			"Log Number via stdin",
			"Pretty Text via stdin",
			"Parameter/Value Pairs via stdin"
			};

/*
 * Validate that the match string is a valid SQL WHERE clause for an event
 * or a repair_action, as selected by notify->notify.  Returns 0 for valid,
 * -1 for invalid.
 */
static int
validate_notify_match(servicelog *slog, struct sl_notify *notify)
{
	int rc;
	char buf[1024], errstr[80];
	sqlite3_stmt *stmt;
	const char *table;

	if (!notify->match) {
		snprintf(slog->error, SL_MAX_ERR,
			"No match string was specified");
		return -1;
	}

	/*
	 * Empty match strings can come from v0.2.9-type uses of
	 * servicelog_notify.
	 */
	if (strlen(notify->match) == 0)
		return 0;

	if (notify->notify == SL_NOTIFY_REPAIRS)
		table = "repair_actions";
	else
		table = EVENTS_JOIN;

	snprintf(buf, 1024, "SELECT * FROM %s WHERE (%s)", table,
		 notify->match);
	rc = replace_query_keywords(slog, buf, &stmt, errstr, 80);
	sqlite3_finalize(stmt);
	if (rc != 0) {
		snprintf(slog->error, SL_MAX_ERR, "An invalid match string "
			 "was specified: %s", errstr);
		return -1;
	}
	return 0;
}

/**
 * servicelog_notify_log
 * @brief Public API for registering a new notification tool
 *
 * @param[in] slog the servicelog into which to add the tool
 * @param[in] notify details of the notification tool
 * @param[out] new_id the ID of the newly inserted record
 * @return 0 on success, 1 on invalid parameter, 2 on SQL error
 */
int
servicelog_notify_log(servicelog *slog, struct sl_notify *notify,
		      uint64_t *new_id)
{
	const char *out;
	int rc;
	sqlite3_stmt *pstmt = NULL;

	/* Input validation begins here */
	if (slog == NULL)
		return SQLITE_ERROR;
	if (notify == NULL) {
		snprintf(slog->error, SL_MAX_ERR,
			 "Invalid parameter(s) to servicelog_notify_add()");
		return 1;
	}

	/* command should always be specified */
	if ((notify->command == NULL) || (strlen(notify->command) == 0)) {
		snprintf(slog->error, SL_MAX_ERR,
			 "The command field must be specified");
		return SQLITE_ERROR;
	}

	/* notify should be within the range */
	if ((notify->notify > SL_NOTIFY_MAX) || (notify->notify < 0)) {
		snprintf(slog->error, SL_MAX_ERR, "An invalid value appeared "
			 "in the notify field (%d)", notify->notify);
		return SQLITE_ERROR;
	}

	/* method should be within the range */
	if ((notify->method > SL_METHOD_MAX) || (notify->method < 0)) {
		snprintf(slog->error, SL_MAX_ERR, "An invalid value appeared "
			 "in the method field (%d)", notify->method);
		return SQLITE_ERROR;
	}

	/* validate that the match string is a valid SQL WHERE clause */
	if (validate_notify_match(slog, notify) != 0)
		return SQLITE_ERROR;

	/* Input data looks valid at this point */

	rc = sqlite3_prepare(slog->db, "INSERT INTO notifications (notify,"
			     " command, method, match) VALUES (?, ?, ?, ?);",
			     -1, &pstmt, &out);
	if (rc != SQLITE_OK) {
		snprintf(slog->error, SL_MAX_ERR,
			 "%s", sqlite3_errmsg(slog->db));
		return SQLITE_INTERNAL;
	}

	rc = sqlite3_bind_int(pstmt, 1,	notify->notify);
	rc = rc ? rc : sqlite3_bind_text(pstmt, 2, notify->command,
		notify->command ? strlen(notify->command):0, SQLITE_STATIC);
	rc = rc ? rc : sqlite3_bind_int(pstmt, 3, notify->method);
	rc = rc ? rc : sqlite3_bind_text(pstmt, 4, notify->match,
			notify->match ? strlen(notify->match):0, SQLITE_STATIC);
	if (rc != SQLITE_OK)
		goto sqlt_fail;

	rc = sqlite3_step(pstmt);
	if (rc != SQLITE_ROW && rc != SQLITE_DONE)
		goto sqlt_fail;

	rc = sqlite3_finalize(pstmt);
	*new_id = (uint64_t)sqlite3_last_insert_rowid(slog->db);
	notify->id = *new_id;
	return rc;

sqlt_fail:
	snprintf(slog->error, SL_MAX_ERR, "%s", sqlite3_errmsg(slog->db));
	rc = sqlite3_finalize(pstmt);

	return SQLITE_INTERNAL;
}

int
servicelog_notify_get(servicelog *slog, uint64_t notify_id,
		      struct sl_notify **notify)
{
	char query[30];

	snprintf(query, 30, "id=""%" PRIu64 " ", notify_id);
	return servicelog_notify_query(slog, query, notify);
}

int
servicelog_notify_query(servicelog *slog, char *query,
			struct sl_notify **notify)
{
	int rc;
	char buf[512], where[512], errstr[80];
	struct sl_notify *n = NULL;
	sqlite3_stmt *stmt;

	if (slog == NULL)
		return 1;
	if ((query == NULL) || (notify == NULL)) {
		snprintf(slog->error, SL_MAX_ERR, "Invalid parameter(s)");
		return 1;
	}

	*notify = NULL;

	if (strlen(query) > 0)
		snprintf(where, 512, " WHERE (%s)", query);
	else
		where[0] = '\0';

	snprintf(buf, 512, "SELECT * FROM notifications%s", where);

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

		if (*notify == NULL) {
			*notify = calloc(1, sizeof(struct sl_notify));
			n = *notify;
		} else {
			n->next = calloc(1, sizeof(struct sl_notify));
			n = n->next;
		}

		if (!n)
			goto free_mem;

		n_cols = sqlite3_column_count(stmt);
		for (i = 0; i<n_cols; i++) {
			name = sqlite3_column_name(stmt, i);

			if (!strcmp(name, "id"))
				n->id = (uint64_t)sqlite3_column_int64(stmt, i);
			else if (!strcmp(name, "time_logged")) {
				strptime((char*)sqlite3_column_text(stmt, i),
					 "%Y-%m-%d %T", &t);
				n->time_logged = mktime(&t);
			}
			else if (!strcmp(name, "time_last_update")) {
				strptime((char*)sqlite3_column_text(stmt, i),
					 "%Y-%m-%d %T", &t);
				n->time_last_update = mktime(&t);
			}
			else if (!strcmp(name, "notify"))
				n->notify = sqlite3_column_int(stmt, i);
			else if (!strcmp(name, "command")) {
				str = (char *)sqlite3_column_text(stmt, i);
				if (!str)
					goto free_mem;
				n->command = strdup(str);
				if (!n->command)
					goto free_mem;
			}
			else if (!strcmp(name, "method"))
				n->method = sqlite3_column_int(stmt, i);
			else if (!strcmp(name, "match")) {
				str = (char *)sqlite3_column_text(stmt, i);
				if (!str)
					goto free_mem;
				n->match = strdup(str);
				if (!n->match)
					goto free_mem;
			}
		} /* for */
	} while (rc != SQLITE_DONE);

	sqlite3_finalize(stmt);

	return 0;
free_mem:
	servicelog_notify_free(*notify);

	return 1;
}

int
servicelog_notify_update(servicelog *slog, uint64_t notify_id,
			 struct sl_notify *notify)
{
	int rc;
	const char *out;
	sqlite3_stmt *pstmt = NULL;

	/* Input validation begins here */

	if (slog == NULL)
		return 1;
	if (notify == NULL) {
		snprintf(slog->error, SL_MAX_ERR,
			 "Invalid parameter(s) to servicelog_notify_add()");
		return SQLITE_ERROR;
	}

	/* command should always be specified */
	if ((notify->command == NULL) || (strlen(notify->command) == 0)) {
		snprintf(slog->error, SL_MAX_ERR,
			 "The command field must be specified");
		return SQLITE_ERROR;
	}

	/* notify should be within the range */
	if ((notify->notify > SL_NOTIFY_MAX) || (notify->notify < 0)) {
		snprintf(slog->error, SL_MAX_ERR, "An invalid value appeared "
			 "in the notify field (%d)", notify->notify);
		return SQLITE_ERROR;
	}

	/* method should be within the range */
	if ((notify->method > SL_METHOD_MAX) || (notify->method < 0)) {
		snprintf(slog->error, SL_MAX_ERR, "An invalid value appeared "
			 "in the method field (%d)", notify->method);
		return SQLITE_ERROR;
	}

	/* validate that the match string is a valid SQL WHERE clause */
	if (validate_notify_match(slog, notify) != 0)
		return SQLITE_ERROR;

	/* Input data looks valid at this point */

	rc = sqlite3_prepare(slog->db, "UPDATE notifications SET notify=?, "
			     "command=?, method=?, match=?) WHERE id=?",
			     -1, &pstmt, &out);
	if (rc != SQLITE_OK) {
		snprintf(slog->error, SL_MAX_ERR,
			 "%s", sqlite3_errmsg(slog->db));
		return SQLITE_INTERNAL;
	}

	rc = sqlite3_bind_int(pstmt, 1, notify->notify);
	rc = rc ? rc : sqlite3_bind_text(pstmt, 2, notify->command,
		notify->command ? strlen(notify->command):0, SQLITE_STATIC);
	rc = rc ? rc : sqlite3_bind_int(pstmt, 3, notify->method);
	rc = rc ? rc : sqlite3_bind_text(pstmt, 4, notify->match,
			notify->match ? strlen(notify->match):0, SQLITE_STATIC);
	rc = rc ? rc : sqlite3_bind_int64(pstmt, 5, notify_id);
	if (rc != SQLITE_OK)
		goto sqlt_fail;

	rc = sqlite3_step(pstmt);
	if (rc != SQLITE_ROW && rc != SQLITE_DONE)
		goto sqlt_fail;

	rc = sqlite3_finalize(pstmt);
	notify->id = notify_id;
	return rc;

sqlt_fail:
	snprintf(slog->error, SL_MAX_ERR, "%s", sqlite3_errmsg(slog->db));
	rc = sqlite3_finalize(pstmt);

	return SQLITE_INTERNAL;
}

int
servicelog_notify_delete(servicelog *slog, uint64_t notify_id)
{
	const char *out;
	int rc;
	sqlite3_stmt *pstmt = NULL;

	if (slog == NULL)
		return SQLITE_ERROR;

	rc = sqlite3_prepare(slog->db, "DELETE FROM notifications WHERE id=?",
			     -1, &pstmt, &out);
	if (rc != SQLITE_OK) {
		snprintf(slog->error, SL_MAX_ERR,
			 "%s", sqlite3_errmsg(slog->db));
		return SQLITE_INTERNAL;
	}

	rc = sqlite3_bind_int64(pstmt, 1, notify_id);
	if (rc != SQLITE_OK)
		goto sqlt_fail;

	rc = sqlite3_step(pstmt);
	if (rc != SQLITE_ROW && rc != SQLITE_DONE)
		goto sqlt_fail;

	rc = sqlite3_finalize(pstmt);
	return rc;

sqlt_fail:
	snprintf(slog->error, SL_MAX_ERR, "%s", sqlite3_errmsg(slog->db));
	rc = sqlite3_finalize(pstmt);

	return SQLITE_INTERNAL;
}

/**
 * servicelog_notify_print
 * @brief Print details of a registered notification tool to a specified stream
 *
 * @param[in] str the stream to which to print
 * @param[in] notify the notification(s) to print
 * @param[in] verbosity a verbosity ranging from -1 to 2
 * @return number of characters written; -1 on invalid parameter
 */
int
servicelog_notify_print(FILE *str, struct sl_notify *notify, int verbosity)
{
	int count = 0;

	if ((str == NULL) || (notify == NULL))
		return -1;

	while (notify) {
		if (verbosity < 0) {
			struct tm time;

			count += fprintf(str, "ServicelogID: ""%" PRIu64 "\n",
					 notify->id);
			localtime_r(&(notify->time_logged), &time);
			count += fprintf(str, "LogTime: %02d/%02d/%04d "
					 "%02d:%02d:%02d\n", time.tm_mon+1,
					 time.tm_mday, time.tm_year+1900,
					 time.tm_hour, time.tm_min,
					 time.tm_sec);
			localtime_r(&(notify->time_last_update), &time);
			count += fprintf(str, "LastUpdateTime: %02d/%02d/%04d "
					 "%02d:%02d:%02d\n", time.tm_mon+1,
					 time.tm_mday, time.tm_year+1900,
					 time.tm_hour, time.tm_min,
					 time.tm_sec);
			count += fprintf(str, "Notify: %d", notify->notify);
			count += fprintf(str, "Command: %s", notify->command);
			count += fprintf(str, "Method: %d", notify->method);
			count += fprintf(str, "Match: %s", notify->match);
		}
		else {
			count += sl_printf(str, PRNT_FMT_UINT64,
					   "Servicelog ID:", notify->id);
			count += sl_printf(str, PRNT_FMT_STR_NR,
					   "Log Timestamp:",
					   ctime(&(notify->time_logged)));
			count += sl_printf(str, PRNT_FMT_STR_NR,
					   "Update Timestamp:",
					   ctime(&(notify->time_last_update)));
			count += sl_printf(str, "%-20s%d (%s)\n",
					   "Notify:", notify->notify,
					   notify_text[notify->notify]);
			count += sl_printf(str, PRNT_FMT_STR, "Command:",
					   notify->command);
			count += sl_printf(str, "%-20s%d (%s)\n",
					   "Method:", notify->method,
					   method_text[notify->method]);
			count += sl_printf(str, PRNT_FMT_STR, "Match:",
					   notify->match);
			count += printf("\n");
		}
		notify = notify->next;
	}

	return count;
}

void
servicelog_notify_free(struct sl_notify *notifies)
{
	struct sl_notify *t1, *t2;

	t1 = notifies;
	while (t1) {
		t2 = t1->next;
		free(t1->command);
		free(t1->match);
		free(t1);
		t1 = t2;
	}
}

/**
 * run_notification_tool
 * @brief Run a notification tool for a given group of records
 *
 * @param[in] notify notification tool to be run
 * @param[in] type one of SL_NOTIFY_*
 * @param[in] records the list of records (usually one) to which notify applies
 * @param return 0 on success, 1 on invalid param
 */
static int
run_notification_tool(struct sl_notify *notify, int type, void *records)
{
	char cmd[DESC_MAXLEN + 10], *argv[30], buf[128], *pos;
	struct sl_event *event = NULL;
	struct sl_repair_action *repair = NULL;
	void *record = records;
	uint64_t id = 0;
	int pipe_fd[2], pid, i, rc = 0;
	ssize_t __attribute__((unused)) rc1;
	FILE *stream;

	if (notify == NULL)
		return 1;

	if (type == SL_NOTIFY_EVENTS)
		event = (struct sl_event *)records;
	else if (type == SL_NOTIFY_REPAIRS)
		repair = (struct sl_repair_action *)records;
	else
		return 1;

	while (record) {
		if (type == SL_NOTIFY_EVENTS)
			id = event->id;
		else if (type == SL_NOTIFY_REPAIRS)
			id = repair->id;

		if (notify->method == SL_METHOD_NUM_VIA_CMD_LINE)
			snprintf(cmd, DESC_MAXLEN + 10, "%s ""%" PRIu64,
						 notify->command, id);
		else {
			/* need pipes to pass in stdin */
			snprintf(cmd, DESC_MAXLEN + 10, "%s", notify->command);

			if (pipe(pipe_fd) < 0)
				continue;
		}

		pid = fork();
		if (pid == -1) {	/* fork failed */
			if (notify->method != SL_METHOD_NUM_VIA_CMD_LINE) {
				close(pipe_fd[0]);
				close(pipe_fd[1]);
			}
			continue;
		} else if (pid == 0) {	/* child; set up pipes, exec command */
			if (notify->method != SL_METHOD_NUM_VIA_CMD_LINE) {
				close(pipe_fd[1]);
				rc = dup2(pipe_fd[0], fileno(stdin));
				if (rc == -1) {
					close(pipe_fd[0]);
					return -1;
				}
			}

			/* build up args for execv */
			for (i = 0; i < 30; i++)
				argv[i] = NULL;

			argv[0] = "";
			pos = strchr(cmd, ' ');
			if (pos) {
				*pos++ = '\0';
				for (i = 1; i < 30; i++) {
					if (!pos || !(*pos))
						break;
					while (*pos == ' ')
						pos++;

					switch (*pos) {
					case '\"':
						argv[i] = pos + 1;
						pos = strchr(argv[i] + 1, '\"');
						if (pos)
							*pos++ = '\0';
						break;
					case '\'':
						argv[i] = pos + 1;
						pos = strchr(argv[i] + 1, '\'');
						if (pos)
							*pos++ = '\0';
						break;
					case '\0':
						break;
					default:
						argv[i] = pos;
						pos = strchr(argv[i], ' ');
						if (pos)
							*pos++ = '\0';
						break;
					}
				}
			}

			execv(cmd, argv);

			exit(-1);
		}

		if (notify->method == SL_METHOD_NUM_VIA_STDIN) {
			close(pipe_fd[0]);
			snprintf(buf, 128, "%" PRIu64, id);
			rc1 = write(pipe_fd[1], buf, strlen(buf));
			close(pipe_fd[1]);
		}
		else if (notify->method == SL_METHOD_PRETTY_VIA_STDIN) {
			close(pipe_fd[0]);
			stream = fdopen(pipe_fd[1], "w");
			if (stream) {
				if (type == SL_NOTIFY_EVENTS)
					servicelog_event_print(stream, event, 2);
				else if (type == SL_NOTIFY_REPAIRS)
					servicelog_repair_print(stream, repair, 2);

				fclose(stream);
			}
			close(pipe_fd[1]);
		}
		else if (notify->method == SL_METHOD_SIMPLE_VIA_STDIN) {
			close(pipe_fd[0]);
			stream = fdopen(pipe_fd[1], "w");
			if (!stream) {
				if (type == SL_NOTIFY_EVENTS)
					servicelog_event_print(stream, event, -1);
				else if (type == SL_NOTIFY_REPAIRS)
					servicelog_repair_print(stream,repair, -1);

				fclose(stream);
			}
			close(pipe_fd[1]);
		}

		if (type == SL_NOTIFY_EVENTS) {
			event = event->next;
			record = (void *)event;
		}
		else if (type == SL_NOTIFY_REPAIRS) {
			repair = repair->next;
			record = (void *)repair;
		}
	}

	return 0;
}

/**
 * @struct check_notify_data
 *
 * Used by the notify_event and notify_repair routines to pass necessary
 * data to the callback function that is called for every row of the results
 * of the SQL query.
 */
struct check_notify_data {
	servicelog *slog;
	uint64_t id;
	int notify;
};

/**
 * check_notify
 * @brief Callback to check if a notify tool should be invoked for a new record
 *
 * @param[in] d a pointer to a check_notify_data structure
 * @param[in] argc number of columns in the current row of the query result
 * @param[in] argv value of each column in the current row of the query result
 * @param[in] column column name for each column in the current row
 */
static int
check_notify(void *d, int argc, char **argv, char **column)
{
	int i, rc = 1;
	char query[1024];
	struct tm t;
	struct check_notify_data *data = (struct check_notify_data *)d;
	struct sl_notify notify;
	struct sl_event *events;
	struct sl_repair_action *repairs;

	memset(&notify, 0, sizeof(struct sl_notify));

	for (i=0; i<argc; i++) {

		if ((!argv[i]) || (!column[i]))
			goto free_mem;

		if (!strcmp(column[i], "id"))
			notify.id = strtoull(argv[i], NULL, 10);
		else if (!strcmp(column[i], "time_logged")) {
			strptime(argv[i], "%Y-%m-%d %T", &t);
			notify.time_logged = mktime(&t);
		}
		else if (!strcmp(column[i], "time_last_update")) {
			strptime(argv[i], "%Y-%m-%d %T", &t);
			notify.time_last_update = mktime(&t);
		}
		else if (!strcmp(column[i], "notify"))
			notify.notify = atoi(argv[i]);
		else if (!strcmp(column[i], "command")) {
			notify.command = strdup(argv[i]);
			if (!notify.command)
				goto free_mem;
		}
		else if (!strcmp(column[i], "method"))
			notify.method = atoi(argv[i]);
		else if (!strcmp(column[i], "match")) {
			notify.match = strdup(argv[i]);
			if (!notify.match)
				goto free_mem;
		}
	}

	if (!notify.match || strlen(notify.match) == 0)
		snprintf(query, 1024, "id=""%" PRIu64, data->id);
	else
		snprintf(query, 1024, "(%s) AND id=""%" PRIu64, notify.match,
								data->id);

	if (data->notify == SL_NOTIFY_EVENTS) {
		rc = servicelog_event_query(data->slog, query, &events);

		if ((rc == 0) && (events != NULL))
			run_notification_tool(&notify, SL_NOTIFY_EVENTS,
					      events);

		servicelog_event_free(events);
		goto free_mem;
	}
	else if (data->notify == SL_NOTIFY_REPAIRS) {
		rc = servicelog_repair_query(data->slog, query, &repairs);

		if ((rc == 0) && (repairs != NULL))
			run_notification_tool(&notify, SL_NOTIFY_REPAIRS,
					      repairs);

		servicelog_repair_free(repairs);
		goto free_mem;
	}

	/* Return successful */
	rc = 0;

free_mem:
	if (notify.command)
		free(notify.command);

	if (notify.match)
		free(notify.match);

	return rc;
}

/**
 * notify_event
 * @brief Run any notification tools for a new event
 *
 * Called by servicelog_event_log, after a new event has been logged.
 *
 * @param[in] slog servicelog structure
 * @param[in] event_id the ID of the new event record
 @ @return 0 on success; sqlite3 error code on failure
 */
int
notify_event(servicelog *slog, uint64_t event_id)
{
	int rc;
	char query[80];
	struct check_notify_data data;

	data.slog = slog;
	data.id = event_id;
	data.notify = SL_NOTIFY_EVENTS;

	snprintf(query, 80, "SELECT * FROM notifications WHERE notify = %d",
		 SL_NOTIFY_EVENTS);
	rc = sqlite3_exec(slog->db, query, check_notify, &data, NULL);
	if (rc != SQLITE_OK)
		return rc;

	return 0;
}

/**
 * notify_repair
 * @brief Run any notification tools for a new repair action
 *
 * Called by servicelog_log_repair_action after a new repair action has been
 * logged.
 *
 * @param[in] slog servicelog structure
 * @param[in] repair_id the ID of the new repair action record
 @ @return 0 on success; sqlite3 error code on failure
 */
int
notify_repair(servicelog *slog, uint64_t repair_id)
{
	int rc;
	char query[80];
	struct check_notify_data data;

	data.slog = slog;
	data.id = repair_id;
	data.notify = SL_NOTIFY_REPAIRS;

	snprintf(query, 80, "SELECT * FROM notifications WHERE notify = %d",
		 SL_NOTIFY_REPAIRS);
	rc = sqlite3_exec(slog->db, query, check_notify, &data, NULL);
	if (rc != SQLITE_OK)
		return rc;

	return 0;
}
