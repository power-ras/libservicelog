/**
 * @brief libservicelog test suite
 *
 * Copyright (C) 2017 IBM
 *
 * Author : Ankit Kumar <kumar.ankit008@in.ibm.com>
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
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>

#include "servicelog.h"

/* Event type passed as argument */
#define SERVICELOG_EVENT_BASIC		1
#define SERVICELOG_EVENT_OS		2
#define SERVICELOG_EVENT_RTAS		3
#define SERVICELOG_EVENT_ENCL		4
#define SERVICELOG_EVENT_BMC		5
#define SERVICELOG_EVENT_DUMP		6
#define SERVICELOG_EVENT_TRUNCATE	7


/* Truncate all events */
static int truncate_all_events(void)
{
	uint32_t rc;
	servicelog *slog;
	struct sl_event *event, *events;
	struct sl_repair_action *repair, *repairs;

	rc = servicelog_open(&slog, SL_FLAG_ADMIN);
	if (rc != 0) {
		fprintf(stderr, "Could not open servicelog database.\n%s\n",
			servicelog_error(slog));
		return -1;
	}

	rc = servicelog_event_query(slog, "", &events);
	if (rc != 0) {
		fprintf(stderr, "%s\n", servicelog_error(slog));
		servicelog_close(slog);
		return -2;
	}

	for (event = events; event; event = event->next) {
		rc = servicelog_event_delete(slog, event->id);
		if (rc) {
			fprintf(stderr, "Failed to delete events from "
				"database.\n%s\n", servicelog_error(slog));
			servicelog_event_free(events);
			servicelog_close(slog);
			return -3;
		}
	}
	servicelog_event_free(events);

	servicelog_repair_query(slog, "", &repairs);
	if (rc) {
		fprintf(stderr, "Failed to read events from database.\n%s\n",
			servicelog_error(slog));
		servicelog_close(slog);
		return -4;
	}

	for (repair = repairs; repair; repair = repair->next) {
		rc = servicelog_repair_delete(slog, repair->id);
		if (rc) {
			fprintf(stderr, "Failed to delete repair events "
				"from database.\n%s\n", servicelog_error(slog));
			servicelog_repair_free(repairs);
			servicelog_close(slog);
			return -5;
		}
	}
	servicelog_repair_free(repairs);

	servicelog_close(slog);
	return 0;
}

/* Common event logging code */
static int svc_event_log(struct sl_event *event, int event_type,
			 int serviceable_flag, int predictive_flag,
			 int callhome_flag, int status)
{
        unsigned char raw_data[] = "event_log_field";
        char refcode[] = "Bug Repro";
        char description[] = "Some Error Return";
        uint32_t rc;
        uint64_t log_id = 0;
	servicelog *slog;

        rc = servicelog_open(&slog, SL_FLAG_ADMIN);
        if ( rc != 0 ) {
		fprintf(stderr, "Could not open servicelog database.\n%s\n",
			servicelog_error(slog));
                return -1;
        }

        event->time_event = 0;
        event->type = event_type;
        event->severity = 2;
        event->machine_serial = (char *)"machine-serial";
        event->machine_model = (char *)"machine-model";
        event->refcode = refcode;
        event->description = description;
        event->serviceable = serviceable_flag;
        event->predictive = predictive_flag;
        event->disposition = SL_DISP_RECOVERABLE;
        event->call_home_status = callhome_flag;
        event->closed = status;

        event->raw_data_len = 41;
        event->raw_data = raw_data;

        event->callouts = NULL;
        event->next = NULL;

        rc = servicelog_event_log(slog, event, &log_id);
        if (rc != 0) {
		fprintf(stderr, "The servicelog said : %s\n",
			servicelog_error(slog));
                servicelog_close(slog);
                return -2;
        }

        rc = servicelog_event_close(slog, log_id);
        if (rc != 0) {
		fprintf(stderr, "The servicelog said : %s\n",
			servicelog_error(slog));
                servicelog_close(slog);
                return -3;
        }

        servicelog_close(slog);
        return 0;
}

/* Log basic event */
static int log_basic_event(void)
{
	struct sl_event event;

	memset(&event, 0, sizeof(struct sl_event));

	return svc_event_log(&event, SL_TYPE_BASIC, 0, 0, 0, 0);
}

/* Log RTAS event */
static int log_rtas_event(void)
{
	struct sl_event event;
	struct sl_data_rtas rtas_data;

	memset(&event, 0, sizeof(struct sl_event));

	rtas_data.action_flags = 43008;
	rtas_data.platform_id = 2181039597;
	rtas_data.creator_id = 'H';
	rtas_data.subsystem_id = 130;
	rtas_data.pel_severity = 64;
	rtas_data.event_type= 224;
	rtas_data.event_subtype = 0;
	rtas_data.kernel_id = 1000;
	rtas_data.addl_words[0] = 265293824;
	rtas_data.addl_words[1] = 0 ;
	rtas_data.addl_words[2] = 0;
	rtas_data.addl_words[3] = 0;
	rtas_data.addl_words[4] = 0;
	rtas_data.addl_words[5] = 0;
	rtas_data.addl_words[6] = 0;
	rtas_data.addl_words[7] = 0;

	event.addl_data = &rtas_data;

	return svc_event_log(&event, SL_TYPE_RTAS, 1, 1, 1, 1);
}

/* Log OS event */
static int log_os_event(void)
{
	struct sl_event event;
	struct sl_data_os os_data;

	memset(&event, 0, sizeof(struct sl_event));

	os_data.version = (char *) "testx-2.5.6-guess";
	os_data.subsystem = (char *) "testx-linux-guess";
	os_data.driver = (char *) "testx-kernerl-driver-guess";
	os_data.device = (char *) "testx-scsidev-guess";

	event.addl_data = &os_data;

	return svc_event_log(&event, SL_TYPE_OS, 0, 0, 0, 0);
}

/* Log enclosure event */
static int log_enclosure_event(void)
{
	struct sl_event event;
	struct sl_data_enclosure enclosure_data;

	memset(&event, 0, sizeof(struct sl_event));

	enclosure_data.enclosure_model =
				(char *) "testx-enclosure-model-check-1.0";
	enclosure_data.enclosure_serial =
				(char *) "testx-enclosure-serial-check-1.0";

	event.addl_data = &enclosure_data;

	return svc_event_log(&event, SL_TYPE_ENCLOSURE, 0, 0, 0, 0);
}

/* Log BMC event */
static int log_bmc_event(void)
{
	struct sl_event event;
	struct sl_data_bmc bmc_data;

	memset(&event, 0, sizeof(struct sl_event));

	bmc_data.sel_id = 1234543;
	bmc_data.sel_type = 1234544;
	bmc_data.generator = 12345;
	bmc_data.version = 223;
	bmc_data.sensor_type = 222;
	bmc_data.sensor_number = 221;
	bmc_data.event_class = 220;
	bmc_data.event_type = 224;
	bmc_data.direction = 125;

	event.addl_data = &bmc_data;

	return svc_event_log(&event, SL_TYPE_BMC, 0, 0, 0, 0);
}

/* Retrieve logged event */
static int retrieve_logged_event(void)
{
	int rc;
	struct sl_event *event;
	servicelog *slog;

	rc = servicelog_open(&slog, 0);
	if (rc) {
		fprintf(stderr, "Could not open servicelog database.\n%s\n",
			servicelog_error(slog));
		return -1;
	}

	rc = servicelog_event_query(slog, "", &event);
	if (rc != 0) {
		fprintf(stderr, "%s\n", servicelog_error(slog));
		servicelog_close(slog);
		return -2;
	}

	rc = servicelog_event_print(stdout, event, 1);
	if (rc < 0) {
		fprintf(stderr, "%s\n", servicelog_error(slog));
		servicelog_event_free(event);
		servicelog_close(slog);
		return -3;
	}

	servicelog_event_free(event);
	servicelog_close(slog);
	return 0;
}

static void usage(char *progname)
{
	printf("usage: %s <event type>\n", progname);
	printf("Event type : 1 - Log basic event\n");
	printf("           : 2 - Log OS event\n");
	printf("           : 3 - Log RTAS event\n");
	printf("           : 4 - Log enclosure event\n");
	printf("           : 5 - Log BMC event\n");
	printf("           : 6 - Read all events from servicelog db\n");
	printf("           : 7 - Delete all events from servicelog db\n");
}

int main(int argc, char *argv[])
{
	int option;

	if (argc != 2) {
		usage(argv[0]);
		return -1;
	}

	option = atoi(argv[1]);

	switch(option) {
	case SERVICELOG_EVENT_BASIC:
		if (log_basic_event()) {
			fprintf(stderr, "log_basic_event failed\n");
			return 0;
		}
		break;
	case SERVICELOG_EVENT_OS:
		if (log_os_event()) {
			fprintf(stderr, "log_os_event failed\n");
			return 0;
		}
		break;
	case SERVICELOG_EVENT_RTAS:
		if (log_rtas_event()) {
			fprintf(stderr, "log_rtas_event failed\n");
			return 0;
		}
		break;
	case SERVICELOG_EVENT_ENCL:
		if (log_enclosure_event()) {
			fprintf(stderr, "log_enclosure_event failed\n");
			return 0;
		}
		break;
	case SERVICELOG_EVENT_BMC:
		if (log_bmc_event()) {
			fprintf(stderr, "log_bmc_event failed\n");
			return 0;
		}
		break;
	case SERVICELOG_EVENT_DUMP:
		if (retrieve_logged_event()) {
			fprintf(stderr, "retrieve_logged_event failed\n");
			return 0;
		}
		break;
	case SERVICELOG_EVENT_TRUNCATE:
		if (truncate_all_events()) {
			fprintf(stderr, "truncate_all_events failed\n");
			return 0;
		}
		break;
	default:
		fprintf(stderr, "Invalid option\n\n");
		usage(argv[0]);
		return -1;
	}

	return 0;
}
