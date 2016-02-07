/**
 * @file addl_data.c
 * @brief Helper routines for addl_data tables in the servicelog database
 *
 * Copyright (C) 2008, IBM
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
#include <string.h>
#include <stdint.h>
#include <sqlite3.h>
#include <inttypes.h>
#include <sys/utsname.h>
#include "slog_internal.h"

/*
 * Each time a new table to contain additional data for a new type of event
 * is added, three new routines need to be created:
 *
 *   insert_addl_data_<type>, for inserting a new event
 *   retrieve_addl_data_<type>, for retrieving an existing event
 *   free_addl_data_<type>, for freeing an event
 *   print_addl_data_<type>, for printing an event
 *
 * Pointers to these routines should be added to the addl_data_fcns array
 * in servicelog.c.  This will cause these routines to be invoked when
 * an event of the new type is inserted or retrieved.
 */


/**
 * insert_addl_data_os
 * @brief Helper function for inserting into the os table
 *
 * @param[in] slog the servicelog to receive the event
 * @param[in] event the event to be inserted
 */
int
insert_addl_data_os(servicelog *slog, struct sl_event *event)
{
	int rc;
	char *version;
	const char *out;
	struct sl_data_os *os;
	struct utsname uname_buf;
	sqlite3_stmt *pstmt = NULL;

	os = (struct sl_data_os *)event->addl_data;

	if (os->version == NULL) {
		rc = uname(&uname_buf);
		version = uname_buf.version;
	}
	else
		version = os->version;

	rc = sqlite3_prepare(slog->db, "INSERT OR REPLACE INTO os (event_id,"
		" version, subsystem, driver, device) VALUES (?, ?, ?, ?, ?);",
		 -1, &pstmt, &out);
	if (rc != SQLITE_OK)
		return rc;

	rc = sqlite3_bind_int64(pstmt, 1, event->id);
	rc = rc ? rc : sqlite3_bind_text(pstmt, 2, version,
					 strlen(version), SQLITE_STATIC);
	rc = rc ? rc : sqlite3_bind_text(pstmt, 3, os->subsystem,
					 strlen(os->subsystem), SQLITE_STATIC);
	rc = rc ? rc : sqlite3_bind_text(pstmt, 4, os->driver,
					 strlen(os->driver), SQLITE_STATIC);
	rc = rc ? rc : sqlite3_bind_text(pstmt, 5, os->device,
					 strlen(os->device), SQLITE_STATIC);

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

	return rc;
}

/**
 * insert_addl_data_rtas
 * @brief Helper function for inserting into the rtas table
 *
 * @param[in] slog the servicelog to receive the event
 * @param[in] event the event to be inserted
 */
int
insert_addl_data_rtas(servicelog *slog, struct sl_event *event)
{
	const char *out;
	int rc;
	struct sl_data_rtas *rtas;
	sqlite3_stmt *pstmt = NULL;

	rtas = (struct sl_data_rtas *)event->addl_data;

	rc = sqlite3_prepare(slog->db, "INSERT OR REPLACE INTO rtas ("
		"event_id, action_flags, platform_id, creator_id,"
		" subsystem_id, pel_severity, event_type, event_subtype,"
		" kernel_id, addl_word1, addl_word2, addl_word3, addl_word4,"
		" addl_word5, addl_word6, addl_word7, addl_word8) VALUES (?,"
		" ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);",
		-1, &pstmt, &out);
	if (rc != SQLITE_OK)
		return rc;

	rc = sqlite3_bind_int64(pstmt, 1, event->id);
	rc = rc ? rc : sqlite3_bind_int(pstmt, 2, rtas->action_flags);
	rc = rc ? rc : sqlite3_bind_int(pstmt, 3, rtas->platform_id);
	rc = rc ? rc : sqlite3_bind_text(pstmt, 4, &(rtas->creator_id),
					 1, SQLITE_STATIC);
	rc = rc ? rc : sqlite3_bind_int(pstmt, 5, rtas->subsystem_id);
	rc = rc ? rc : sqlite3_bind_int(pstmt, 6, rtas->pel_severity);
	rc = rc ? rc : sqlite3_bind_int(pstmt, 7, rtas->event_type);
	rc = rc ? rc : sqlite3_bind_int(pstmt, 8, rtas->event_subtype);
	rc = rc ? rc : sqlite3_bind_int(pstmt, 9, rtas->kernel_id);
	rc = rc ? rc : sqlite3_bind_int(pstmt, 10, rtas->addl_words[0]);
	rc = rc ? rc : sqlite3_bind_int(pstmt, 11, rtas->addl_words[1]);
	rc = rc ? rc : sqlite3_bind_int(pstmt, 12, rtas->addl_words[2]);
	rc = rc ? rc : sqlite3_bind_int(pstmt, 13, rtas->addl_words[3]);
	rc = rc ? rc : sqlite3_bind_int(pstmt, 14, rtas->addl_words[4]);
	rc = rc ? rc : sqlite3_bind_int(pstmt, 15, rtas->addl_words[5]);
	rc = rc ? rc : sqlite3_bind_int(pstmt, 16, rtas->addl_words[6]);
	rc = rc ? rc : sqlite3_bind_int(pstmt, 17, rtas->addl_words[7]);

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

	return rc;
}

/**
 * insert_addl_data_enclosure
 * @brief Helper function for inserting into the enclosure table
 *
 * @param[in] slog the servicelog to receive the event
 * @param[in] event the event to be inserted
 */
int
insert_addl_data_enclosure(servicelog *slog, struct sl_event *event)
{
	const char *out;
	int rc;
	sqlite3_stmt *pstmt = NULL;
	struct sl_data_enclosure *encl;

	encl = (struct sl_data_enclosure *)event->addl_data;

	rc = sqlite3_prepare(slog->db, "INSERT OR REPLACE INTO enclosure"
		" (event_id, enclosure_model, enclosure_serial) VALUES (?,"
		" ?, ?);", -1, &pstmt, &out);
	if (rc != SQLITE_OK) {
		snprintf(slog->error, SL_MAX_ERR, "%s",
				sqlite3_errmsg(slog->db));
		return rc;
	}

	rc = sqlite3_bind_int64(pstmt, 1, event->id);
	rc = rc ? rc : sqlite3_bind_text(pstmt, 2, encl->enclosure_model,
					 strlen(encl->enclosure_model), SQLITE_STATIC);
	rc = rc ? rc : sqlite3_bind_text(pstmt, 3, encl->enclosure_serial,
					 strlen(encl->enclosure_serial), SQLITE_STATIC);

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

	return rc;
}

/**
 * insert_addl_data_bmc
 * @brief Helper function for inserting into the bmc table
 *
 * @param[in] slog the servicelog to receive the event
 * @param[in] event the event to be inserted
 */
int
insert_addl_data_bmc(servicelog *slog, struct sl_event *event)
{
	const char *out;
	int rc;
	struct sl_data_bmc *bmc;
	sqlite3_stmt *pstmt = NULL;

	bmc = (struct sl_data_bmc *)event->addl_data;

	rc = sqlite3_prepare(slog->db, "INSERT OR REPLACE INTO bmc (event_id,"
		" sel_id, sel_type, generator, version, sensor_type,"
		" sensor_number, event_class, event_type, direction) VALUES"
		" (?, ?, ?, ?, ?, ?, ?, ?, ?, ?);", -1, &pstmt, &out);
	if (rc != SQLITE_OK) {
		snprintf(slog->error, SL_MAX_ERR,
			 "%s", sqlite3_errmsg(slog->db));
		return rc;
	}

	rc = sqlite3_bind_int64(pstmt, 1, event->id);
	rc = rc ? rc : sqlite3_bind_int(pstmt, 2, bmc->sel_id);
	rc = rc ? rc : sqlite3_bind_int(pstmt, 3, bmc->sel_type);
	rc = rc ? rc : sqlite3_bind_int(pstmt, 4, bmc->generator);
	rc = rc ? rc : sqlite3_bind_int(pstmt, 5, bmc->version);
	rc = rc ? rc : sqlite3_bind_int(pstmt, 6, bmc->sensor_type);
	rc = rc ? rc : sqlite3_bind_int(pstmt, 7, bmc->sensor_number);
	rc = rc ? rc : sqlite3_bind_int(pstmt, 8, bmc->event_class);
	rc = rc ? rc : sqlite3_bind_int(pstmt, 9, bmc->event_type);
	rc = rc ? rc : sqlite3_bind_int(pstmt, 10, bmc->direction);

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
 * retrieve_addl_data_os
 * @brief Helper function for retrieving from the os table
 *
 * @param[in] e the event to be retrieved
 * @param[in] argc the number of columns in the table
 * @param[in] argv the values stored in the various columns for this row
 * @param[in] column the titles of the columns
 */
int
retrieve_addl_data_os(void *e, int argc, char **argv, char **column)
{
	int i;
	struct sl_event *event = (struct sl_event *)e;
	struct sl_data_os *os;

	event->addl_data = calloc(1, sizeof(struct sl_data_os));
	if (!event->addl_data)
		return 1;

	os = (struct sl_data_os *)event->addl_data;

	for (i=0; i<argc; i++) {
		if (!strcmp(column[i], "version")) {
			os->version = strdup(argv[i]);
			if (!os->version)
				goto free_mem;
		}
		else if (!strcmp(column[i], "subsystem")) {
			os->subsystem = strdup(argv[i]);;
			if (!os->subsystem)
				goto free_mem;
		}
		else if (!strcmp(column[i], "driver")) {
			os->driver = strdup(argv[i]);
			if (!os->driver)
				goto free_mem;
		}
		else if (!strcmp(column[i], "device")) {
			os->device = strdup(argv[i]);
			if (!os->device)
				goto free_mem;
		}
	}

	return 0;

free_mem:
	if (os->version)
		free(os->version);

	if (os->subsystem)
		free(os->subsystem);

	if (os->driver)
		free(os->driver);

	if (os->device)
		free(os->device);

	if (event->addl_data)
		free(event->addl_data);

	return 1;
}

/**
 * retrieve_addl_data_rtas
 * @brief Helper function for retrieving from the rtas table
 *
 * @param[in] e the event to be retrieved
 * @param[in] argc the number of columns in the table
 * @param[in] argv the values stored in the various columns for this row
 * @param[in] column the titles of the columns
 */
int
retrieve_addl_data_rtas(void *e, int argc, char **argv, char **column)
{
	int i;
	struct sl_event *event = (struct sl_event *)e;
	struct sl_data_rtas *rtas;

	event->addl_data = calloc(1, sizeof(struct sl_data_rtas));
	if (!event->addl_data)
		return 1;

	rtas = (struct sl_data_rtas *)event->addl_data;

	for (i=0; i<argc; i++) {
		if (!strcmp(column[i], "action_flags")) {
			rtas->action_flags = atoi(argv[i]);
		}
		else if (!strcmp(column[i], "platform_id")) {
			rtas->platform_id = atoi(argv[i]);
		}
		else if (!strcmp(column[i], "creator_id")) {
			rtas->creator_id = argv[i][0];
		}
		else if (!strcmp(column[i], "subsystem_id")) {
			rtas->subsystem_id = atoi(argv[i]);
		}
		else if (!strcmp(column[i], "pel_severity")) {
			rtas->pel_severity = atoi(argv[i]);
		}
		else if (!strcmp(column[i], "event_type")) {
			rtas->event_type = atoi(argv[i]);
		}
		else if (!strcmp(column[i], "event_subtype")) {
			rtas->event_subtype = atoi(argv[i]);
		}
		else if (!strcmp(column[i], "kernel_id")) {
			rtas->kernel_id = atoi(argv[i]);
		}
		else if (!strcmp(column[i], "addl_word1")) {
			rtas->addl_words[0] = atoi(argv[i]);
		}
		else if (!strcmp(column[i], "addl_word2")) {
			rtas->addl_words[1] = atoi(argv[i]);
		}
		else if (!strcmp(column[i], "addl_word3")) {
			rtas->addl_words[2] = atoi(argv[i]);
		}
		else if (!strcmp(column[i], "addl_word4")) {
			rtas->addl_words[3] = atoi(argv[i]);
		}
		else if (!strcmp(column[i], "addl_word5")) {
			rtas->addl_words[4] = atoi(argv[i]);
		}
		else if (!strcmp(column[i], "addl_word6")) {
			rtas->addl_words[5] = atoi(argv[i]);
		}
		else if (!strcmp(column[i], "addl_word7")) {
			rtas->addl_words[6] = atoi(argv[i]);
		}
		else if (!strcmp(column[i], "addl_word8")) {
			rtas->addl_words[7] = atoi(argv[i]);
		}
	}

	return 0;
}

/**
 * retrieve_addl_data_enclosure
 * @brief Helper function for retrieving from the enclosure table
 *
 * @param[in] e the event to be retrieved
 * @param[in] argc the number of columns in the table
 * @param[in] argv the values stored in the various columns for this row
 * @param[in] column the titles of the columns
 */
int
retrieve_addl_data_enclosure(void *e, int argc, char **argv, char **column)
{
	int i;
	struct sl_event *event = (struct sl_event *)e;
	struct sl_data_enclosure *encl;

	event->addl_data = calloc(1, sizeof(struct sl_data_enclosure));
	if (!event->addl_data)
		return 1;

	encl = (struct sl_data_enclosure *)event->addl_data;

	for (i=0; i<argc; i++) {
		if (!strcmp(column[i], "enclosure_serial")) {
			encl->enclosure_serial = strdup(argv[i]);
			if (!encl->enclosure_serial)
				goto free_mem;
		}
		else if (!strcmp(column[i], "enclosure_model")) {
			encl->enclosure_model = strdup(argv[i]);
			if (!encl->enclosure_model)
				goto free_mem;
		}
	} /* for */

	return 0;

free_mem:
	if (encl->enclosure_serial)
		free(encl->enclosure_serial);

	if (encl->enclosure_model)
		free(encl->enclosure_model);

	if (event->addl_data)
		free(event->addl_data);

	return 1;
}

/**
 * retrieve_addl_data_bmc
 * @brief Helper function for retrieving from the bmc table
 *
 * @param[in] e the event to be retrieved
 * @param[in] argc the number of columns in the table
 * @param[in] argv the values stored in the various columns for this row
 * @param[in] column the titles of the columns
 */
int
retrieve_addl_data_bmc(void *e, int argc, char **argv, char **column)
{
	int i;
	struct sl_event *event = (struct sl_event *)e;
	struct sl_data_bmc *bmc;

	event->addl_data = calloc(1, sizeof(struct sl_data_bmc));
	if (!event->addl_data)
		return 1;

	bmc = (struct sl_data_bmc *)event->addl_data;

	for (i=0; i<argc; i++) {
		if (!strcmp(column[i], "sel_id")) {
			bmc->sel_id = atoi(argv[i]);
		}
		else if (!strcmp(column[i], "sel_type")) {
			bmc->sel_type = atoi(argv[i]);
		}
		else if (!strcmp(column[i], "generator")) {
			bmc->generator = atoi(argv[i]);
		}
		else if (!strcmp(column[i], "version")) {
			bmc->version = atoi(argv[i]);
		}
		else if (!strcmp(column[i], "sensor_type")) {
			bmc->sensor_type = atoi(argv[i]);
		}
		else if (!strcmp(column[i], "sensor_number")) {
			bmc->sensor_number = atoi(argv[i]);
		}
		else if (!strcmp(column[i], "event_class")) {
			bmc->event_class = atoi(argv[i]);
		}
		else if (!strcmp(column[i], "event_type")) {
			bmc->event_type = atoi(argv[i]);
		}
		else if (!strcmp(column[i], "direction")) {
			bmc->direction = atoi(argv[i]);
		}
	}

	return 0;
}

/**
 * free_addl_data_os
 * @brief Helper function for freeing an event that was retrieved
 *
 * @param[in] event the event containing an additional data section to be freed
 */
void free_addl_data_os(struct sl_event *event)
{
	struct sl_data_os *os = (struct sl_data_os *)event->addl_data;

	if (os) {
		free(os->version);
		free(os->subsystem);
		free(os->driver);
		free(os->device);
		free(os);
	}

	return;
}

/**
 * free_addl_data_rtas
 * @brief Helper function for freeing an event that was retrieved
 *
 * @param[in] event the event containing an additional data section to be freed
 */
void free_addl_data_rtas(struct sl_event *event)
{
	struct sl_data_rtas *rtas = (struct sl_data_rtas *)event->addl_data;

	if (rtas)
		free(rtas);

	return;
}

/**
 * free_addl_data_enclosure
 * @brief Helper function for freeing an event that was retrieved
 *
 * @param[in] event the event containing an additional data section to be freed
 */
void free_addl_data_enclosure(struct sl_event *event)
{
	struct sl_data_enclosure *encl =
			(struct sl_data_enclosure *)event->addl_data;

	if (encl) {
		free(encl->enclosure_serial);
		free(encl->enclosure_model);
		free(encl);
	}

	return;
}

/**
 * free_addl_data_bmc
 * @brief Helper function for freeing an event that was retrieved
 *
 * @param[in] event the event containing an additional data section to be freed
 */
void free_addl_data_bmc(struct sl_event *event)
{
	struct sl_data_bmc *bmc = (struct sl_data_bmc *)event->addl_data;

	if (bmc)
		free(bmc);

	return;
}

/**
 * print_addl_data_os
 * @brief Helper function for printing an OS event
 *
 * @param[in] str the stream to which to print
 * @param[in] event the event to be printed
 * @param[in] verbosity how much data should be printed
 * @return the number of characters printed to the stream
 */
int
print_addl_data_os(FILE *str, struct sl_event *event, int verbosity)
{
	struct sl_data_os *os = (struct sl_data_os *)(event->addl_data);
	int count = 0;

	if (verbosity < 0) {
		count += fprintf(str, "KernelVersion: %s\n", os->version);
		count += fprintf(str, "Subsystem: %s\n", os->subsystem);
		count += fprintf(str, "Driver: %s\n", os->driver);
		count += fprintf(str, "Device: %s\n", os->device);
	}
	else {
		count += sl_printf(str, PRNT_FMT_STR, "Kernel Version:",
				   os->version);
		count += sl_printf(str, PRNT_FMT_STR, "Subsystem:",
				   os->subsystem);
		count += sl_printf(str, PRNT_FMT_STR, "Driver:", os->driver);
		count += sl_printf(str, PRNT_FMT_STR, "Device:", os->device);
	}

	return count;
}

/**
 * print_addl_data_rtas
 * @brief Helper function for printing an RTAS event
 *
 * @param[in] str the stream to which to print
 * @param[in] event the event to be printed
 * @param[in] verbosity how much data should be printed
 * @return the number of characters printed to the stream
 */
int
print_addl_data_rtas(FILE *str, struct sl_event *event, int verbosity)
{
	struct sl_data_rtas *rtas = (struct sl_data_rtas *)(event->addl_data);
	int count = 0;
	char *detail;

	if (verbosity < 0) {
		count += fprintf(str, "KernelID: %d\n", rtas->kernel_id);
		count += fprintf(str, "AddlWord0: 0x%08x\n",
				 rtas->addl_words[0]);
		count += fprintf(str, "AddlWord1: 0x%08x\n",
				 rtas->addl_words[1]);
		count += fprintf(str, "AddlWord2: 0x%08x\n",
				 rtas->addl_words[2]);
		count += fprintf(str, "AddlWord3: 0x%08x\n",
				 rtas->addl_words[3]);
		count += fprintf(str, "AddlWord4: 0x%08x\n",
				 rtas->addl_words[4]);
		count += fprintf(str, "AddlWord5: 0x%08x\n",
				 rtas->addl_words[5]);
		count += fprintf(str, "AddlWord6: 0x%08x\n",
				 rtas->addl_words[6]);
		count += fprintf(str, "AddlWord7: 0x%08x\n",
				 rtas->addl_words[7]);
		count += fprintf(str, "ActionFlags: 0x%04x\n",
				 rtas->action_flags);
		count += fprintf(str, "EventType: %d\n",
				 rtas->event_type);

		if ((uint8_t)(*event->raw_data) >= 6) {
			count += fprintf(str, "PlatformID: 0x%x\n",
					 rtas->platform_id);
			count += fprintf(str, "CreatorID: %c\n",
					 rtas->creator_id);
			count += fprintf(str, "SubsystemID: 0x%02x\n",
					 rtas->subsystem_id);
			count += fprintf(str, "EventSubtype: 0x%02x\n",
					 rtas->event_subtype);
			count += fprintf(str, "RTASSeverity: 0x%02x\n",
					 rtas->pel_severity);
		}

		return count;
	}

	count += sl_printf(str, "%-20s%04x\n", "Action Flags:",
			   rtas->action_flags);

	/* Print detailed event type */
	switch(rtas->event_type) {
		case 64:
			detail = " - EPOW (Environmental/Power Warning)";
			break;
		case 224:
			detail = " - Platform Event";
			break;
		case 225:
			detail = " - I/O Events";
			break;
		case 226:
			detail = " - Platform Information Event";
			break;
		case 227:
			detail = " - Resource Deallocation Event";
			break;
		case 228:
			detail = " - Dump Notification Event";
			break;
		default:
			detail = "";
	}
	count += sl_printf(str, "%-20s%d%s\n", "Event Type:",
			   rtas->event_type, detail);

	count += sl_printf(str, PRNT_FMT_NUM, "Kernel ID:", rtas->kernel_id);

	if (event->raw_data && (uint8_t)(*event->raw_data) < 6)
		goto skip_v6;

	count += sl_printf(str, PRNT_FMT_HEX, "Platform ID:",
			   rtas->platform_id);

	/* Print detailed creator ID */
	switch (rtas->creator_id) {
		case 'E':
			detail = " - Service Processor";
			break;
		case 'H':
			detail = " - Hypervisor";
			break;
		case 'W':
			detail = " - Power Control";
			break;
		case 'L':
			detail = " - Partition Firmware";
			break;
		default:
			detail = "";
	}
	count += sl_printf(str, "%-20s%c%s\n", "Creator ID:",
			   rtas->creator_id, detail);

	/* Print detailed subsystem ID */
	detail = "";
	if ((rtas->subsystem_id >= 0x10) && (rtas->subsystem_id <= 0x1F))
		detail = " - Processor subsystem including internal cache";
	else if ((rtas->subsystem_id >= 0x20) && (rtas->subsystem_id <= 0x2F))
		detail = " - Memory subsystem including external cache";
	else if ((rtas->subsystem_id >= 0x30) && (rtas->subsystem_id <= 0x3F))
		detail = " - I/O subsystem (hub, bridge, bus)";
	else if ((rtas->subsystem_id >= 0x40) && (rtas->subsystem_id <= 0x4F))
		detail = " - I/O adapter, device and peripheral";
	else if ((rtas->subsystem_id >= 0x50) && (rtas->subsystem_id <= 0x5F))
		detail = " - CEC hardware";
	else if ((rtas->subsystem_id >= 0x60) && (rtas->subsystem_id <= 0x6F))
		detail = " - Power/Cooling subsystem";
	else if ((rtas->subsystem_id >= 0x70) && (rtas->subsystem_id <= 0x79))
		detail = " - Other subsystem";
	else if ((rtas->subsystem_id >= 0x7A) && (rtas->subsystem_id <= 0x7F))
		detail = " - Surveillance error";
	else if ((rtas->subsystem_id >= 0x80) && (rtas->subsystem_id <= 0x8F))
		detail = " - Platform firmware";
	else if ((rtas->subsystem_id >= 0x90) && (rtas->subsystem_id <= 0x9F))
		detail = " - Software";
	else if ((rtas->subsystem_id >= 0xA0) && (rtas->subsystem_id <= 0xAF))
		detail = " - External environment";
	count += sl_printf(str, "%-20s%02x%s\n", "Subsystem ID:",
			   rtas->subsystem_id, detail);

	/* Print detailed RTAS severity */
	switch(rtas->pel_severity) {
		case 0x00:
			detail = " - Informational or non-error event";
			break;
		case 0x10:
			detail = " - Recovered error, general";
			break;
		case 0x14:
			detail = " - Recovered Error, spare capacity utilized";
			break;
		case 0x15:
			detail = " - Recovered Error, loss of entitled "
				"capacity";
			break;
		case 0x20:
			detail = " - Predictive Error, general";
			break;
		case 0x21:
			detail = " - Predictive Error, degraded performance";
			break;
		case 0x22:
			detail = " - Predictive Error, fault may be corrected "
				"after platform reboot";
			break;
		case 0x23:
			detail = " - Predictive Error, fault may be corrected "
				"after boot, degraded performance";
			break;
		case 0x24:
			detail = " - Predictive Error, loss of redundancy";
			break;
		case 0x40:
			detail = " - Unrecoverable Error, general";
			break;
		case 0x41:
			detail = " - Unrecoverable Error, bypassed with "
				"degraded performance";
			break;
		case 0x44:
			detail = " - Unrecoverable Error, bypassed with loss "
				"of redundancy";
			break;
		case 0x45:
			detail = " - Unrecoverable Error, bypassed with loss "
				"of redundancy and performance";
			break;
		case 0x48:
			detail = " - Unrecoverable Error, bypassed with loss "
				"of function";
			break;
		case 0x60:
			detail = " - Error on diagnostic test, general";
			break;
		case 0x61:
			detail = " - Error on diagnostic test, resource may "
				"produce incorrect results";
			break;
		default:
			detail = "";
	}
	count += sl_printf(str, "%-20s%02x%s\n", "RTAS Severity:",
			   rtas->pel_severity, detail);

	/* Print detailed event subtype */
	switch(rtas->event_subtype) {
		case 0x00:
			detail = " - Not applicable";
			break;
		case 0x01:
			detail = " - Miscellaneous, Information Only";
			break;
		case 0x08:
			detail = " - Dump Notification";
			break;
		case 0x10:
			detail = " - Previously reported error has been "
				"corrected by the system";
			break;
		case 0x20:
			detail = " - System resources manually deconfigured "
				"by user";
			break;
		case 0x21:
			detail = " - System resources deconfigured by system "
				"due to prior error event";
			break;
		case 0x22:
			detail = " - Resource deallocation event notification";
			break;
		case 0x30:
			detail = " - Customer environmental problem has "
				"returned to normal";
			break;
		case 0x40:
			detail = " - Concurrent Maintenance Event";
			break;
		case 0x60:
			detail = " - Capacity Upgrade Event";
			break;
		case 0x70:
			detail = " - Resource Sparing Event";
			break;
		case 0x80:
			detail = " - Dynamic Reconfiguration Event";
			break;
		case 0xD0:
			detail = " - Normal system/platform shutdown or "
				"powered off";
			break;
		case 0xE0:
			detail = " - Platform powered off by user without "
				"normal shutdown (abnormal power-off)";
			break;
		default:
			detail = "";
	}
	count += sl_printf(str, "%-20s%02x%s\n", "Event Subtype:",
			   rtas->event_subtype, detail);

skip_v6:
	count += sl_printf(str, "\nExtended Reference Codes:\n");
	count += sl_printf(str, "2: %08x  3: %08x  4: %08x  5: %08x\n",
			   rtas->addl_words[0], rtas->addl_words[1],
			   rtas->addl_words[2], rtas->addl_words[3]);
	count += sl_printf(str, "6: %08x  7: %08x  8: %08x  9: %08x\n",
			   rtas->addl_words[4], rtas->addl_words[5],
			   rtas->addl_words[6], rtas->addl_words[7]);

	return count;
}

/**
 * print_addl_data_enclosure
 * @brief Helper function for printing an enclosure event
 *
 * @param[in] str the stream to which to print
 * @param[in] event the event to be printed
 * @param[in] verbosity how much data should be printed
 * @return the number of characters printed to the stream
 */
int
print_addl_data_enclosure(FILE *str, struct sl_event *event, int verbosity)
{
	struct sl_data_enclosure *encl =
			(struct sl_data_enclosure *)(event->addl_data);
	int count = 0;

	if (verbosity < 0) {
		count += fprintf(str, "EnclosureSerial: %s\n",
				 encl->enclosure_serial);
		count += fprintf(str, "EnclosureModel: %s\n",
				 encl->enclosure_model);
	}
	else {
		count += sl_printf(str, PRNT_FMT_STR, "Enclosure Serial:",
				   encl->enclosure_serial);
		count += sl_printf(str, PRNT_FMT_STR, "Enclosure Model:",
				   encl->enclosure_model);
	}

	return count;
}

/**
 * print_addl_data_bmc
 * @brief Helper function for printing a BMC event
 *
 * @param[in] str the stream to which to print
 * @param[in] event the event to be printed
 * @param[in] verbosity how much data should be printed
 * @return the number of characters printed to the stream
 */
int
print_addl_data_bmc(FILE *str, struct sl_event *event, int verbosity)
{
	struct sl_data_bmc *bmc = (struct sl_data_bmc *)(event->addl_data);
	int count = 0;
	char *detail;

	if (verbosity < 0) {
		count += fprintf(str, "SELID: %u\n", bmc->sel_id);
		count += fprintf(str, "SELType: %u\n", bmc->sel_type);
		count += fprintf(str, "Generator: 0x%x\n", bmc->generator);
		count += fprintf(str, "Version: %u\n", bmc->version);
		count += fprintf(str, "SensorType: %u\n", bmc->sensor_type);
		count += fprintf(str, "SensorNumber: %u\n", bmc->sensor_number);
		count += fprintf(str, "EventClass: %u\n", bmc->event_class);
		count += fprintf(str, "EventType: %u\n", bmc->event_type);
		count += fprintf(str, "Direction: %d\n", bmc->direction);
	}
	else {
		count += sl_printf(str, PRNT_FMT_UINT, "SEL ID:", bmc->sel_id);

		if (bmc->sel_type == 2)
			detail = " - System Event Record";
		else if ((bmc->sel_type >= 0xC0) && (bmc->sel_type <= 0xDF))
			detail = " - OEM Timestamped";
		else if ((bmc->sel_type >= 0xE0) && (bmc->sel_type <= 0xFF))
			detail = " - OEM Non-Timestamped";
		else
			detail = " - Unknown";
		count += sl_printf(str, "%-20s%02x%s\n", "SEL Type:",
				   bmc->sel_type, detail);

		count += sl_printf(str, "%-02s%02x\n", "Generator ID:",
				   bmc->generator);
		count += sl_printf(str, "%-02s%02x\n", "Format Version:",
				   bmc->version);

		count += sl_printf(str, PRNT_FMT_HEX, "Sensor Type:",
				   bmc->sensor_type);
		count += sl_printf(str, PRNT_FMT_HEX, "Sensor Number:",
				   bmc->sensor_number);

		count += sl_printf(str, PRNT_FMT_HEX, "Event Class:",
				   bmc->event_class);
		count += sl_printf(str, PRNT_FMT_HEX, "Event Type:",
				   bmc->event_type);

		count += sl_printf(str, PRNT_FMT_STR, "Direction:",
				   (bmc->direction ? "Deassert" : "Assert"));
	}

	return count;
}
