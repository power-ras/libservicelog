/**
 * @file v29_compat.c
 * The servicelog compatibility layer: functions available in
 * servicelog 0.2.9 that were unavailable -- or implemented differently
 * -- in 1.0.
 *
 * Copyright (C) 2005, 2009 IBM Corporation
 *
 * Authors of servicelog v0.2.9:
 * @author Nathan Fontenot <nfont@austin.ibm.com>
 * @author Michael Strosaker <strosake@us.ibm.com>
 *
 * Compatibility layer:
 * @author Jim Keniston <jkenisto@us.ibm.com>
 * @author Brad Peters <bpeters@us.ibm.com>
 */

#include <string.h>
#include <malloc.h>
#include <errno.h>
#include <time.h>
#include <inttypes.h>
#include "slog_internal.h"
#define EXCLUDE_SERVICELOG_COMPAT_DECLS
#include "../servicelog-1/libservicelog.h"

/*
 * Error returns:
 * -1 for internal errors
 * errno codes (e.g., EINVAL) for others
 */


/* ----------------------------------------- */
/* TODO: Implement these stub functions */
int
v29_servicelog_log_event(struct v29_servicelog *slog, void *event,
							uint32_t *reckey)
{
	return ENOSYS;
}

/* like strncpy, but guarantees a terminating null */
static void
strNcpy(char *dest, const char *src, size_t n)
{
	strncpy(dest, src, n);
	dest[n-1] = '\0';
}

static void
cond_strcpy(char *dest, const char *src, size_t n)
{
	if (src)
		strNcpy(dest, src, n);
	else
		dest[0] = '\0';
}

int
convert_key_to_v29(servicelog *log, uint64_t key64, uint32_t *key32,
							const char *key_type)
{
	*key32 = (uint32_t) key64;
	if (*key32 != key64) {
		snprintf(log->error, SL_MAX_ERR,
			"v1+ %s ID ""%"PRIu64 "truncated to 32 bits", key_type, key64);
		return EDOM;
	}
	return 0;
}

/*
 * Encode time_t in sqlite3 DB format: YYYY-MM-DD HH:MM:SS
 * That's 20 bytes, including the trailing null.
 */
static char *
encode_db_date(char *buf, size_t bufsz, time_t date)
{
	struct tm tm;
	(void) strftime(buf, bufsz, "%Y-%m-%d %H:%M:%S", gmtime_r(&date, &tm));
	return buf;
}

static void
free_v29_event_list(struct sl_header *ev29)
{
	struct sl_header *next;
	while (ev29) {
		next = ev29->next;
		free(ev29);
		ev29 = next;
	}
}

int
v29_servicelog_open(struct v29_servicelog *slog, const char *log_path,
							int create)
{
	struct servicelog *log;
	int ret;

	if (!slog)
		return EINVAL;
	ret = servicelog_open(&log, SL_FLAG_ADMIN);
	slog->v1_servicelog = log;
	return ret;
}

void
v29_servicelog_close(struct v29_servicelog *slog)
{
	if (slog && slog->v1_servicelog)
		servicelog_close((struct servicelog*) slog->v1_servicelog);
}

char *
v29_servicelog_error(struct v29_servicelog *slog)
{
	if (slog)
		return servicelog_error((servicelog*)slog->v1_servicelog);
	return NULL;
}

int
v29_servicelog_sync(struct v29_servicelog *slog)
{
	return 0;
}

/**
 * copy_event_to_v29_header
 * @brief Copy values from a v1 event to a v0.2.9 event header
 * Caller must fill *v29 with zeroes first.
 */
static void
copy_event_to_v29_header(servicelog *log, struct sl_event *event,
						struct sl_header *v29)
{
	v29->next = NULL;
	(void) convert_key_to_v29(log, event->id, &v29->db_key, "event");
	/* event_type set by caller */
	/* version set by caller */
	/* event_length set by caller */
	v29->time_event = event->time_event;
	v29->time_log = event->time_logged;
	v29->severity = event->severity;
	v29->repair_action = 0;
	v29->serviceable_event = event->serviceable;

	/* Should this be event->closed? */
	v29->event_repaired = (event->repair != 0);
}

/**
 * @brief Convert the list of callouts from v1 event to v0.2.9 event
 * @param next where to put the first callout
 * @param event the v1 event
 * @return address following end of last callout stored
 */
static char *
convert_callouts(servicelog *log, char *next, struct sl_event *event)
{
	struct sl_callout *callout;

	for (callout = event->callouts; callout; callout = callout->next) {
		struct sl_ppc64_callout *callout29;
		callout29 = (struct sl_ppc64_callout*) next;
		next += sizeof(*callout29);
		if (callout->next)
			callout29->next = (struct sl_ppc64_callout*) next;
		else
			callout29->next = NULL;
		callout29->priority = callout->priority;
		callout29->type = callout->type;
		(void) convert_key_to_v29(log, event->repair,
					&callout29->repair_key, "repair");
		cond_strcpy(callout29->procedure_id, callout->procedure, 32);
		cond_strcpy(callout29->location, callout->location, 128);
		cond_strcpy(callout29->fru, callout->fru, 32);
		cond_strcpy(callout29->serial, callout->serial, 32);
		cond_strcpy(callout29->ccin, callout->ccin, 32);
	}
	return next;
}

/**
 * convert_os_to_v29
 * @brief Convert a v1 event of type SL_TYPE_OS to v0.2.9.
 *
 * @param log v1 servicelog struct
 * @param ev v1 event header
 * @param data29 receives the pointer to the v0.2.9 event we create
 * @param sz receives the size of the malloc-ed block containing the
 * entire v0.2.9 event
 * @return 0 for success
 */
static int
convert_os_to_v29(servicelog *log, struct sl_event *ev, void **data29,
							size_t *sz)
{
	struct sl_os os29, *ev29;
	struct sl_data_os *os1;
	int message_sz = 0, procedure_sz = 0;
	char *next;
	size_t ev29_sz;

	memset(&os29, 0, sizeof(os29));
	copy_event_to_v29_header(log, ev, &os29.head);
	os29.head.event_type = SL_TYPE_OS;
	os29.head.version = SL_OS_VERSION;

	(void) convert_key_to_v29(log, ev->repair, &os29.repair_key, "repair");

	os1 = (struct sl_data_os*) ev->addl_data;
	if (!os1) {
		snprintf(log->error, SL_MAX_ERR,
			"internal error: SL_TYPE_OS event lacks os struct");
		return -1;
	}
	cond_strcpy(os29.subsystem, os1->subsystem, 32);
	cond_strcpy(os29.refcode, ev->refcode, 9);

	if (ev->description)
		message_sz = strlen(ev->description) + 1;

	if (ev->callouts && ev->callouts->procedure)
		procedure_sz = strlen(ev->callouts->procedure) + 1;

	ev29_sz = sizeof(os29) + message_sz + procedure_sz;
	ev29 = malloc(ev29_sz);
	if (!ev29) {
		snprintf(log->error, SL_MAX_ERR, "out of memory in %s",
							__FUNCTION__);
		return ENOMEM;
	}

	os29.head.event_length = (uint32_t) ev29_sz;
	memcpy(ev29, &os29, sizeof(os29));
	next = (char*) ev29;
	next += sizeof(os29);

	if (message_sz) {
		strcpy(next, ev->description);
		ev29->message = next;
		next += message_sz;
	}
	if (procedure_sz) {
		strcpy(next, ev->callouts->procedure);
		ev29->repair_procedure = next;
	}

	*data29 = ev29;
	*sz = ev29_sz;
	return 0;
}

/**
 * convert_rtas_to_v29
 * @brief Convert a v1 SL_TYPE_RTAS event to a v0.2.9 SL_TYPE_PPC64_RTAS event
 *
 * @param log v1 servicelog struct
 * @param ev v1 event header
 * @param data29 receives the pointer to the v0.2.9 event we create
 * @param sz receives the size of the malloc-ed block containing the
 * entire v0.2.9 event, including callouts and variable-length strings.
 * @return 0 for success
 */
static int
convert_rtas_to_v29(servicelog *log, struct sl_event *ev, void **data29,
							size_t *sz)
{
	struct sl_ppc64_rtas rtas29, *ev29;
	struct sl_data_rtas *rtas1;
	int description_sz = 0;
	int nr_callouts;
	struct sl_callout *callout;
	char *next;
	size_t ev29_sz;

	memset(&rtas29, 0, sizeof(rtas29));
	copy_event_to_v29_header(log, ev, &rtas29.head);
	rtas29.head.event_type = SL_TYPE_PPC64_RTAS;
	rtas29.head.version = SL_PPC64_RTAS_VERSION;

	rtas1 = (struct sl_data_rtas*) ev->addl_data;
	if (!rtas1) {
		snprintf(log->error, SL_MAX_ERR,
			"internal error: SL_TYPE_RTAS event lacks rtas struct");
		return -1;
	}
	rtas29.action_flags = rtas1->action_flags;
	rtas29.rtas_event_type = rtas1->event_type;
	rtas29.kernel_id = rtas1->kernel_id;
	cond_strcpy(rtas29.refcode, ev->refcode, 9);
	memcpy(rtas29.addl_words, rtas1->addl_words, 8*sizeof(uint32_t));
	cond_strcpy(rtas29.machine_type, ev->machine_model, 9);
	if (ev->description)
		description_sz = strlen(ev->description) + 1;
	rtas29.rtas_event_len = ev->raw_data_len;
	rtas29.platform_id = rtas1->platform_id;
	rtas29.creator_id = rtas1->creator_id;
	rtas29.subsystem_id = rtas1->subsystem_id;
	rtas29.rtas_severity = rtas1->pel_severity;
	rtas29.event_subtype = rtas1->event_subtype;

	nr_callouts = 0;
	for (callout = ev->callouts; callout; callout = callout->next)
		nr_callouts++;

	ev29_sz = sizeof(rtas29) + description_sz +
		nr_callouts*sizeof(struct sl_ppc64_callout) +
		ev->raw_data_len;
	ev29 = malloc(ev29_sz);
	if (!ev29) {
		snprintf(log->error, SL_MAX_ERR, "out of memory in %s",
							__FUNCTION__);
		return ENOMEM;
	}

	rtas29.head.event_length = (uint32_t) ev29_sz;
	memcpy(ev29, &rtas29, sizeof(rtas29));
	next = (char*) ev29;
	next += sizeof(rtas29);

	if (description_sz) {
		strcpy(next, ev->description);
		ev29->description = next;
		next += description_sz;
	}

	if (nr_callouts) {
		ev29->callouts = (struct sl_ppc64_callout*) next;
		next = convert_callouts(log, next, ev);
	}

	if (ev->raw_data_len != 0) {
		memcpy(next, ev->raw_data, ev->raw_data_len);
		ev29->rtas_event = next;
		next += ev->raw_data_len;
	}

	*data29 = ev29;
	*sz = ev29_sz;
	return 0;
}

/**
 * convert_encl_to_v29
 * @brief Convert a v1 SL_TYPE_ENCL event to a v0.2.9 SL_TYPE_PPC64_ENCL event
 *
 * @param log v1 servicelog struct
 * @param ev v1 event header
 * @param data29 receives the pointer to the v0.2.9 event we create
 * @param sz receives the size of the malloc-ed block containing the
 * entire v0.2.9 event, including callouts and variable-length strings.
 * @return 0 for success
 */
static int
convert_encl_to_v29(servicelog *log, struct sl_event *ev, void **data29,
							size_t *sz)
{
	struct sl_ppc64_encl encl29, *ev29;
	struct sl_data_enclosure *encl1;
	int description_sz = 0;
	int nr_callouts;
	struct sl_callout *callout;
	char *next;
	size_t ev29_sz;

	memset(&encl29, 0, sizeof(encl29));
	copy_event_to_v29_header(log, ev, &encl29.head);
	encl29.head.event_type = SL_TYPE_PPC64_ENCL;
	encl29.head.version = SL_PPC64_ENCL_VERSION;

	encl1 = (struct sl_data_enclosure *) ev->addl_data;
	if (!encl1) {
		snprintf(log->error, SL_MAX_ERR,
			"internal error: SL_TYPE_ENCL event lacks encl struct");
		return -1;
	}

	cond_strcpy(encl29.refcode, ev->refcode, 9);
	if (ev->description)
		description_sz = strlen(ev->description) + 1;
	cond_strcpy(encl29.machine_type, encl1->enclosure_model, 9);
	cond_strcpy(encl29.machine_serial_no, encl1->enclosure_serial, 13);
	encl29.event_len = ev->raw_data_len;

	nr_callouts = 0;
	for (callout = ev->callouts; callout; callout = callout->next)
		nr_callouts++;

	ev29_sz = sizeof(encl29) + description_sz +
		nr_callouts*sizeof(struct sl_ppc64_callout) +
		ev->raw_data_len;
	ev29 = malloc(ev29_sz);
	if (!ev29) {
		snprintf(log->error, SL_MAX_ERR, "out of memory in %s",
							__FUNCTION__);
		return ENOMEM;
	}

	encl29.head.event_length = (uint32_t) ev29_sz;
	memcpy(ev29, &encl29, sizeof(encl29));
	next = (char*) ev29;
	next += sizeof(encl29);

	if (description_sz) {
		strncpy(next, ev->description, (ev29_sz - sizeof(encl29) - 1));
		ev29->description = next;
		next += description_sz;
	}

	if (nr_callouts) {
		ev29->callouts = (struct sl_ppc64_callout*) next;
		next = convert_callouts(log, next, ev);
	}

	if (ev->raw_data_len != 0) {
		memcpy(next, ev->raw_data, ev->raw_data_len);
		ev29->event = next;
		next += ev->raw_data_len;
	}

	*data29 = ev29;
	*sz = ev29_sz;
	return 0;
}

/**
 * convert_v1_event_to_v29
 * @brief Convert v1+ event to v0.2.9 format
 *
 * @param log v1+ structure containing the database parameters
 * @param ev1 v1+ event
 * @param ev29 a pointer to receive the event data
 * @param sz a pointer to receive the size of the retrieved data
 * @return 0 on success, use db_strerror for other values
 */
int
convert_v1_event_to_v29(servicelog *log, struct sl_event *ev1, void **ev29,
								size_t *sz)
{
	switch (ev1->type) {
	case SL_TYPE_OS:
		return convert_os_to_v29(log, ev1, ev29, sz);
	case SL_TYPE_RTAS:
		return convert_rtas_to_v29(log, ev1, ev29, sz);
	case SL_TYPE_ENCLOSURE:
		return convert_encl_to_v29(log, ev1, ev29, sz);
	case SL_TYPE_BASIC:
	default:
		snprintf(log->error, SL_MAX_ERR,
			"v1+ event type %d cannot be represented in v0.2.9",
			ev1->type);
		return ENOSYS;
	}
}

uint32_t
convert_type_to_v29(uint32_t v1_type)
{
	switch (v1_type) {
	// TODO: Map SL_TYPE_BASIC to SL_TYPE_APP?
	case SL_TYPE_OS:	return SL_TYPE_OS;
	case SL_TYPE_RTAS:	return SL_TYPE_PPC64_RTAS;
	case SL_TYPE_ENCLOSURE:	return SL_TYPE_PPC64_ENCL;
	default:		return 0;
	}
}

uint32_t
convert_type_to_v1(uint32_t v29_type)
{
	switch (v29_type) {
	// TODO: Map SL_TYPE_APP to SL_TYPE_BASIC?
	case SL_TYPE_OS:		return SL_TYPE_OS;
	case SL_TYPE_PPC64_RTAS:	return SL_TYPE_RTAS;
	case SL_TYPE_PPC64_ENCL:	return SL_TYPE_ENCLOSURE;
	default:			return 0;
	}
}

/* Get the list of events repaired by the sl_repair_action with repair_id. */
static int
find_repaired_events(servicelog *log, uint64_t repair_id,
						struct sl_event **events)
{
	char query[40] = {0,};

	snprintf(query, 39, "repair=""%" PRIu64, repair_id);
	return servicelog_event_query(log, query, events);
}

/**
 * convert_v1_repair_to_v29
 * @brief Convert a v1 repair action to a v0.2.9 repair event
 *
 * @param log v1 servicelog struct
 * @param rpr1 v1 repair action
 * @param data29 receives the pointer to the v0.2.9 event we create
 * @param sz receives the size of the malloc-ed block containing the entire
 * v0.2.9 event, including variable-length strings, and repairs array.
 * @return 0 for success
 */
static int
convert_v1_repair_to_v29(servicelog *log, struct sl_repair_action *rpr1,
						void **data29, size_t *sz)
{
	struct sl_repair rpr29, *ev29;
	int location_sz = 0, procedure_sz = 0;
	char *next;
	size_t ev29_sz;
	struct sl_event *re, *repaired_events = NULL;
	int str_size;

	if (find_repaired_events(log, rpr1->id, &repaired_events) != 0)
		repaired_events = NULL;

	memset(&rpr29, 0, sizeof(rpr29));
	(void) convert_key_to_v29(log, rpr1->id, &rpr29.head.db_key, "repair");
	/*
	 * Unlike in 0.2.9, v1+ repair "events" don't have an associated
	 * "real event" type.  So just pick the type of the first repaired
	 * event.
	 */
	if (repaired_events)
		rpr29.head.event_type = convert_type_to_v29(repaired_events->type);
	else
		rpr29.head.event_type = 0;
	rpr29.head.version = SL_REPAIR_VERSION;
	rpr29.head.time_event = rpr1->time_repair;
	rpr29.head.time_log = rpr1->time_logged;
	rpr29.head.severity = SL_SEV_INFO;	// per log_repair_action.c
	rpr29.head.repair_action = 1;
	rpr29.head.serviceable_event = 0;
	rpr29.head.event_repaired = 0;

	if (rpr1->location)
		location_sz = strlen(rpr1->location) + 1;
	if (rpr1->procedure)
		procedure_sz = strlen(rpr1->procedure) + 1;

	rpr29.num_repairs = 0;
	for (re = repaired_events; re; re = re->next)
		rpr29.num_repairs++;

	ev29_sz = sizeof(rpr29) + location_sz + procedure_sz +
		rpr29.num_repairs*sizeof(uint32_t);
	ev29 = malloc(ev29_sz);
	if (!ev29) {
		snprintf(log->error, SL_MAX_ERR, "out of memory in %s",
							__FUNCTION__);
		servicelog_event_free(repaired_events);
		return ENOMEM;
	}

	rpr29.head.event_length = (uint32_t) ev29_sz;
	memcpy(ev29, &rpr29, sizeof(rpr29));
	next = (char*) ev29;
	next += sizeof(rpr29);

	str_size = (ev29_sz - sizeof(rpr29) - 1);
	if (location_sz) {
		strncpy(next, rpr1->location, str_size);
		ev29->location = next;
		next += location_sz;
		str_size -= (strlen(location_sz) + 1);
	}
	if (procedure_sz) {
		strncpy(next, rpr1->procedure, str_size);
		ev29->procedure = next;
		next += procedure_sz;
	}
	if (rpr29.num_repairs > 0) {
		ev29->repairs = (uint32_t*) next;
		for (re = repaired_events; re; re = re->next) {
			(void) convert_key_to_v29(log, re->id, (uint32_t*) next,
								"event");
			next += sizeof(uint32_t);
		}
	}

	*data29 = ev29;
	*sz = ev29_sz;
	servicelog_event_free(repaired_events);
	return 0;
}

/**
 * servicelog_get_event
 * @brief Retrieve an event from the servicelog database by unique ID
 *
 * @param slog v0.2.9 structure containing the database parameters
 * @param id the unique key of the event to retrieve
 * @param event a pointer to receive the event data
 * @param sz a pointer to receive the size of the retrieved data
 * @return 0 on success (see below)
 * If the query was valid but no matching event is found, we return ENOENT
 * (v0.2.9 returns a DB error) and don't set *event.
 *
 * In v1+, a regular event and a repair action (which counts as an event
 * in v0.2.9) can have the same ID.  If we find both, return a 2-event
 * list with the regular event first and then the repair event, and *sz
 * is set to the size of the regular event.
 */
int
v29_servicelog_get_event(struct v29_servicelog *slog, uint32_t id, void **event,
								size_t *sz)
{
	servicelog *log;
	struct sl_event *ev1;
	struct sl_repair_action *repair1;
	size_t event_sz, repair_sz;
	struct sl_header *ev29 = NULL, *repair29 = NULL;
	void *data29;
	int rce, rcr;

	if (!slog)
		return EINVAL;
	log = (servicelog*) slog->v1_servicelog;

	if (!event || !sz) {
		snprintf(log->error, SL_MAX_ERR,
			"null event or size pointer passed to %s",
			__FUNCTION__);
		return EINVAL;
	}

	rce = servicelog_event_get(log, id, &ev1);
	if (rce == 0 && ev1 != NULL) {
		data29 = NULL;
		rce = convert_v1_event_to_v29(log, ev1, &data29, &event_sz);
		servicelog_event_free(ev1);
		if (data29 != NULL && rce == 0)
			ev29 = (struct sl_header*) data29;
	}
	rcr = servicelog_repair_get(log, id, &repair1);
	if (rcr == 0 && repair1 != NULL) {
		data29 = NULL;
		rcr = convert_v1_repair_to_v29(log, repair1, &data29,
								&repair_sz);
		servicelog_repair_free(repair1);
		if (data29 != NULL && rcr == 0)
			repair29 = (struct sl_header*) data29;
	}
	if (ev29) {
		ev29->next = repair29;
		*sz = event_sz;
		*event = ev29;
		return 0;
	} else if (repair29) {
		*sz = repair_sz;
		*event = repair29;
		return 0;
	}

	/* No events matched, so check for error codes. */
	if (rce)
		return rce;
	if (rcr)
		return rcr;
	return ENOENT;
}

// not in v1
int
v29_servicelog_delete_event(struct v29_servicelog *slog, uint32_t event_id)
{
	if (!slog)
		return EINVAL;
	return servicelog_event_delete((struct servicelog *) slog->v1_servicelog, event_id);
}

// not in v1
int
v29_servicelog_update_event(struct v29_servicelog *slog, void *event)
{
	/* bpeters: It is not possible to update an event under the 1.0+ API. */
	return ENOSYS;
}

/**
 * v29_types_to_v1_match
 * @brief encode bitmap of v0.2.9 event types to match as v1+ SQL match string
 * @param next where to store the match string
 * @param bitmap v0.2.9 events to match
 * @return address of null that terminates match string: same as initial
 * value of match if no types specified
 */
char *
v29_types_to_v1_match(char *next, uint64_t bitmap)
{
	char *start = next;
	int t;
	int ntypes = 0;

	// Leave room for the '(', if needed.
	*next++ = ' ';
	for (t = SL_TYPE_OS; t <= SL_TYPE_PPC64_ENCL; t++) {
		if (bitmap & (1 << t)) {
			if (++ntypes > 1)
				next += snprintf(next, 5, " OR ");
			next += snprintf(next, 10, "type == %d",
						convert_type_to_v1(t));
		}
	}
	if (ntypes > 1) {
		*start = '(';
		*next++ = ')';
	} else if (ntypes == 0) {
		next = start;
		*start = '\0';
	}
	return next;
}

/**
 * convert_v29_query_to_v1
 * @brief: Convert v29 query struct to a sqlite WHERE clause
 * @param [in]: v29_query - the sl_query struct passed in from consumer
 * @param [out]: v1_where allocated mem pointing to new query string will be returned here.
 * 					Caller responsible for calling free()
 */
int
convert_v29_query_to_v1(struct sl_query *v29_query, char **v1_where)
{
	char tmp[1024];
	char *next = tmp, *end = (tmp + sizeof(tmp) - 1);
	char *and_connector = " AND ";
	char *connector = "";

	*next = '\0';
	if (v29_query->num_types > 0) {
		int i;
		uint64_t type_bitmap = 0;
		for (i = 0; i < v29_query->num_types; i++)
			type_bitmap |= (1 << v29_query->event_types[i]);
		next = v29_types_to_v1_match(next, type_bitmap);
		connector = and_connector;
	}

	// printf("Assembled type WHERE clause: %s\n", tmp);

	// Create time boundaries
	if (v29_query->start_time) {
		char d[32];
		next += snprintf(next, (end - next), "%stime_event >= '%s'",
				connector,
				encode_db_date(d, 32, v29_query->start_time));
		connector = and_connector;
	}

	if (v29_query->end_time) {
		char d[32];
		next += snprintf(next, (end - next), "%stime_event <= '%s'",
			connector,
			encode_db_date(d, 32, v29_query->end_time));
		connector = and_connector;
	}

	if (v29_query->is_serviceable == SL_QUERY_YES) {
		next += snprintf(next, (end - next), "%sserviceable = 1",
			connector);
		connector = and_connector;
	} else if (v29_query->is_serviceable == SL_QUERY_NO) {
		next += snprintf(next, (end - next), "%sserviceable = 0",
			connector);
		connector = and_connector;
	}

	if (v29_query->is_repaired == SL_QUERY_YES) {
		next += snprintf(next, (end - next), "%srepair != 0", connector);
		connector = and_connector;
	} else if (v29_query->is_repaired == SL_QUERY_NO) {
		next += snprintf(next, (end - next), "%srepair = 0", connector);
		connector = and_connector;
	}

	if (v29_query->severity > 1) {
		next += snprintf(next, (end - next), "%sseverity >= %d",
			connector, v29_query->severity);
		connector = and_connector;
	}

	*v1_where = strdup(tmp);
	// printf("Final query statement: %s\n", *v1_where);

	return 0;
}

/*
 * Set *events to the list of all regular (non-repair-action) v0.2.9 events
 * that match v29_query.
 */
static int
query_regular_events(servicelog *log, struct sl_query *v29_query,
					struct sl_header **events)
{
	char *v1_query = NULL;
	struct sl_header *v29_events, *v29, **v29_next;
	struct sl_event *v1_events, *v1;
	int rc;
	size_t sizResp;

	convert_v29_query_to_v1(v29_query, &v1_query);

	// Do Query call, build v29 response to caller
	rc = servicelog_event_query(log, v1_query, &v1_events);
	free(v1_query);
	if (rc)
		return rc;

	v29_events = NULL;
	v29_next = &v29_events; // where to store the next v29 ptr
	for (v1 = v1_events; v1; v1 = v1->next) {
		void *ve = NULL;	// Avoid compiler warning
		rc = convert_v1_event_to_v29(log, v1, &ve, &sizResp);
		v29 = (struct sl_header*) ve;
		if (rc) {
			free_v29_event_list(v29_events);
			servicelog_event_free(v1_events);
			// printf("Query failed.\n");
			return rc;
		}
		*v29_next = v29;
		v29_next = &v29->next;
	}
	servicelog_event_free(v1_events);
	*events = v29_events;
	return 0;
}

/*
 * Set *repair_events to the list v0.2.9 event equivalents of all the
 * v1 repair actions that sort of match v29_query.
 */
static int
query_repair_events(servicelog *log, struct sl_query *v29_query,
					struct sl_header **repair_events)
{
	int result;
	char v1_match[1024];
	char *next = v1_match, *end = (next + sizeof(v1_match) - 1);
	char *connector = "";
	struct sl_repair_action *v1, *v1_repairs;
	struct sl_header *v29, *v29_repairs, **v29_next;

	*repair_events = NULL;

	/*
	 * A repair_action can't be serviceable or repaired.  A repair_action
	 * has no severity per se, but allow anything up to SL_SEV_INFO.
	 */
	if (v29_query->is_serviceable == SL_QUERY_YES
				|| v29_query->is_repaired == SL_QUERY_YES
				|| v29_query->severity > SL_SEV_INFO)
		return 0;

	/* Find all the repair_actions in the specified time range. */
	*next = '\0';
	if (v29_query->start_time) {
		char d[32];
		next += snprintf(next, (end - next), "%stime_repair >= '%s'",
			connector,
			encode_db_date(d, 32, v29_query->start_time));
		connector = " AND ";
	}
	if (v29_query->end_time) {
		char d[32];
		next += snprintf(next, (end - next), "%stime_repair <= '%s'",
			connector,
			encode_db_date(d, 32, v29_query->end_time));
	}

	v1_repairs = NULL;
	result = servicelog_repair_query(log, v1_match, &v1_repairs);
	if (result != 0) {
		servicelog_repair_free(v1_repairs);
		/* servicelog_repair_query() set log->error. */
		return result;
	}
	if (!v1_repairs)
		return 0;

	/*
	 * Convert each v1+ repair_action to a v0.2.9 repair event.  The
	 * type of each is deduced from the repaired event(s), if any.
	 * Use that to further filter the list.
	 */
	v29_repairs = NULL;
	v29_next = &v29_repairs; // where to store the next v29 ptr we keep
	for (v1 = v1_repairs; v1; v1 = v1->next) {
		int keep = 1;
		size_t sz = 0;
		void *ve = NULL;	// avoid compiler warning

		result = convert_v1_repair_to_v29(log, v1, &ve, &sz);
		if (result != 0) {
			free_v29_event_list(v29_repairs);
			servicelog_repair_free(v1_repairs);
			return result;
		}
		v29 = (struct sl_header*) ve;
		if (v29_query->num_types > 0) {
			int i;
			keep = 0;
			for (i = 0; i < v29_query->num_types; i++) {
				if (v29_query->event_types[i]
							== v29->event_type) {
					keep = 1;
					break;
				}
			}
		}
		if (keep) {
			*v29_next = v29;
			v29_next = &v29->next;
		} else
			free(v29);
	}
	servicelog_repair_free(v1_repairs);
	*repair_events = v29_repairs;
	return 0;
}

/**
 * v29_servicelog_query
 * @brief: Front end by which a v29 query can be be used to query the v1 db
 * @param [in and out]: v29_query - params of query, result returned in ->result
 *
 * In v0.2.9, repair actions count as events, so we have to return any that
 * match.  Use servicelog_event_query() to get matching regular v1+ events,
 * and servicelog_repair_query() to get matching v1+ repair actions, and
 * concatenate the lists.
 *
 * For a valid query with or without any matches, we return 0, like v0.2.9.
 */
int
v29_servicelog_query(struct v29_servicelog *slog, struct sl_query *v29_query)
{
	servicelog *log;
	struct sl_header *repair_events = NULL;
	struct sl_header *regular_events = NULL;
	int result;

	if (!slog)
		return EINVAL;
	log = (servicelog*) slog->v1_servicelog;
	if (!v29_query) {
		snprintf(log->error, SL_MAX_ERR, "null query passed to %s",
							__FUNCTION__);
		return EINVAL;
	}

	switch (v29_query->is_repair_action) {
	case SL_QUERY_YES:
		result = query_repair_events(log, v29_query, &repair_events);
		break;
	case SL_QUERY_NO:
		result = query_regular_events(log, v29_query, &regular_events);
		break;
	case SL_QUERY_ALL:
		result = query_regular_events(log, v29_query, &regular_events);
		if (result != 0)
			return result;
		result = query_repair_events(log, v29_query, &repair_events);
		break;
	default:
		snprintf(log->error, SL_MAX_ERR,
			"unrecognized is_repair_action value: %d",
			v29_query->is_repair_action);
		return EINVAL;
	}

	if (result != 0) {
		if (regular_events)
			free_v29_event_list(regular_events);
		if (repair_events)
			free_v29_event_list(repair_events);
		return result;
	}

	if (regular_events) {
		if (repair_events) {
			/* Append repair_events to regular_events. */
			struct sl_header *v29;
			for (v29 = regular_events; v29->next; v29 = v29->next)
				;
			v29->next = repair_events;
		}
		v29_query->result = regular_events;
	} else
		v29_query->result = repair_events;
	return 0;
}

/**
 * v29_servicelog_query_close
 * @brief: Free all allocated memory
 */
int
v29_servicelog_query_close(struct v29_servicelog *slog, struct sl_query *v29_query)
{
	if (slog || !v29_query)
		return EINVAL;
	free_v29_event_list(v29_query->result);
	return 0;
}

/* Notification Registration */

int v29_servicelog_notify_free_list(struct v29_sl_notify *notify)
{
	struct v29_sl_notify *next;

	while (notify) {
		next = notify->next;
		free(notify);
		notify = next;
	}

	return 0;
}

extern int v29nfy_parse();
extern void v29nfy_gram_init(const char *v1_match, struct v29_sl_notify *nfy,
                                                        int *semantic_errs);
extern void v29nfy_gram_fini();

/**
 * _convert_v1_sl_notify_to_v29
 * @brief Convert a v1+ sl_notify to a v0.2.9 sl_notify
 * @param slog v0.2.9 (!) struct servicelog
 * @param v29 pointer to block containing v0.2.9 struct sl_notify.  CALLER
 *	must ensure that this block can hold the v0.2.9 sl_notify PLUS
 *	v1->command appended to it
 * @param size the size of the v29_sl_notify struct + the command string + 1.
 */
int
_convert_v1_sl_notify_to_v29(struct v29_servicelog *slog, struct v29_sl_notify *v29, struct sl_notify *v1, uint32_t size)
{
	struct servicelog *log;
	char *cmd;
	int parse_result, semantic_errors = 0;
	int result;

	if (!slog)
		return EINVAL;
	log = (servicelog*) slog->v1_servicelog;

	v29->next = NULL;
	result = convert_key_to_v29(log, v1->id, &v29->key, "notification");
	if (result)
		return result;
	/*
	 * Parse v1->match to fill in the event_types, serviceable_event,
	 * and severity fields.
	 *
	 * v29nfy_gram_init() initializes the 3 fields to match everything,
	 * so that's what you get if there's no match string.  (Can that
	 * happen?)
	 */
	 v29nfy_gram_init(v1->match, v29, &semantic_errors);
	 if (v1->match) {
		parse_result = v29nfy_parse();
		v29nfy_gram_fini();
		if (parse_result != 0 || semantic_errors != 0) {
			snprintf(log->error, SL_MAX_ERR, "can't translate "
				"match string '%s' for v1+ sl_notify ""%" PRIu64 "to "
				"v0.2.9 sl_notify", v1->match, v1->id);
			return ENOTSUP;
		}
	 }

	v29->version = SL_NOTIFY_VERSION;
	v29->created = v1->time_logged;

// Brad says: ALL is what Director uses for repair action and serviceable_event
	if (v1->notify == SL_NOTIFY_EVENTS)
		v29->repair_action = SL_QUERY_NO;
	else if (v1->notify == SL_NOTIFY_REPAIRS)
		v29->repair_action = SL_QUERY_YES;
	else	/* Hmm.  It should be one or the other in v1+. */
		v29->repair_action = SL_QUERY_ALL;

	v29->method = v1->method;	// These happen to match.
	v29->command_length = size - sizeof(struct v29_sl_notify);
	cmd = ((char *) v29) + sizeof(struct v29_sl_notify);
	strncpy(cmd, v1->command, v29->command_length);

	return 0;
}

/**
 * v29_servicelog_notify_query
 * @brief: Queries db for notifications
 * @param [in] command: If set, searches for notification tools calling specified command line
 * @param [out] notify_list: Linked list of discovered DB entries
 * @param [out] num_matches: Number of hits in linked list
 */
int v29_servicelog_notify_query(struct v29_servicelog *slog, char *command,
        struct v29_sl_notify **notify_list, int *num_matches)
{
	servicelog *log;
	int rc, size = 0;
	int num = 0;
	struct sl_notify *notifications, *v1;
	struct v29_sl_notify *v29 = NULL, **v29_next;

	if (!slog)
		return EINVAL;
	log = (servicelog*) slog->v1_servicelog;

	/* Validate the query structure */
	if (!command || !notify_list || !num_matches) {
		snprintf(log->error, SL_MAX_ERR,
			"null parameter(s) passed to %s", __FUNCTION__);
		return EINVAL;
	}

	//Grab all entries in notifications table, then search for matches on command
	/* TODO, maybe : Change this to a query looking for command substring and bitmasking the actual types looked for */
	rc = servicelog_notify_query(log, "", &notifications);
	if (rc != 0) {
		// printf("Error Sev: %d.   Access to DB failed.\n", rc);
		return rc;
	}

	*notify_list = NULL;
	v29_next = notify_list;	// pointer to next v0.2.9 object goes here
	for (v1 = notifications; v1; v1 = v1->next) {
		if (strstr(v1->command, command) != NULL) {
			num++;
			// Calc total mem needed to store v29_sl_notify struct + data on end (command and such)
			size = sizeof(struct v29_sl_notify)
						+ strlen(v1->command) + 1;
			v29 = malloc(size);
			if (!v29) {
				snprintf(log->error, SL_MAX_ERR,
					"out of memory in %s", __FUNCTION__);
				rc = ENOMEM;
				goto abort;
			}
			rc = _convert_v1_sl_notify_to_v29(slog, v29, v1, size);
			if (rc != 0)
				goto abort;
			*v29_next = v29;
			v29_next = &v29->next;
		}
	}

	*num_matches = num;
	servicelog_notify_free(notifications);
	return 0;

abort:
	if (v29)
		free(v29);
	v29_servicelog_notify_free_list(*notify_list);
	*notify_list = NULL;
	servicelog_notify_free(notifications);
	return rc;
}

int v29_servicelog_notify_get(struct v29_servicelog *slog, uint32_t id,
        struct v29_sl_notify **notify_list)
{
	servicelog *log;
	int rc = 0;
	uint32_t size;
	struct sl_notify *v1 = NULL;
	struct v29_sl_notify *v29;

	if (!slog)
		return EINVAL;
	log = (servicelog*) slog->v1_servicelog;

	if (!id || !notify_list) {
		snprintf(log->error, SL_MAX_ERR, "null notification ID "
			"and/or null sl_notify pointer passed to %s",
			__FUNCTION__);
		return EINVAL;
	}

	rc = servicelog_notify_get(log, id, &v1);
	if (rc)
		return rc;

	size = sizeof(struct v29_sl_notify) + strlen(v1->command) + 1;
	v29 = malloc(size);
	if (!v29) {
		snprintf(log->error, SL_MAX_ERR, "out of memory in %s",
							__FUNCTION__);
		servicelog_notify_free(v1);
		return ENOMEM;
	}
	rc = _convert_v1_sl_notify_to_v29(slog, v29, v1, size);

	servicelog_notify_free(v1);
	if (rc) {
		v29_servicelog_notify_free_list(v29);
		v29 = NULL;
	}
	*notify_list = v29;
	return rc;
}

/**
 * _convert_v29_sl_notify_to_v1
 * @brief Convert a v0.2.9 sl_notify to a v1+ sl_notify
 * @param slog v1+ struct servicelog
 * @param v29 pointer to v0.2.9 struct sl_notify
 * @param v1 pointer to v1+ sl_notify object to be populated
 *
 * returns with v1->command pointing at v29's command, and v1->match
 * strdup-ed
 */
void
_convert_v29_sl_notify_to_v1(servicelog *log, struct v29_sl_notify *v29,
						struct sl_notify *v1)
{
	char v1_match[1024];
	char *next = v1_match, *end  = (next + sizeof(v1_match) - 1);
	char *connector = "";
	char *and_connector = " AND ";

	v1->next = NULL;
	v1->time_logged = v29->created;

	/*
	 * v0.2.9 incompatibility: There's no v1 SL_NOTIFY_* value for
	 * v29->repair_action = SL_QUERY_ANY.  For that case, we could
	 * generate two v1 notifications, one for SL_NOTIFY_REPAIRS and
	 * one for SL_NOTIFY_EVENTS.  Instead the servicelog_notify
	 * command does that for us.
	 */
	v1->notify = (v29->repair_action == SL_QUERY_YES ?
				SL_NOTIFY_REPAIRS : SL_NOTIFY_EVENTS);
	v1->command = ((char*)v29) + sizeof(*v29);
	/* v1 and v0.2.9 have different names, but same meaning. */
	v1->method = v29->method;

	connector = "";
	v1_match[0] = '\0';
	next = v29_types_to_v1_match(v1_match, v29->event_types);
	if (next > v1_match)
		connector = and_connector;
	if (v29->severity > 1) {
		next += snprintf(next, (end - next), "%sseverity >= %d",
			connector, v29->severity);
		connector = and_connector;
	}
	switch (v29->serviceable_event) {
	case SL_QUERY_YES:
		snprintf(next, (end - next), "%sserviceable == 1", connector);
		break;
	case SL_QUERY_NO:
		snprintf(next, (end - next), "%sserviceable == 0", connector);
		break;
	}
	v1->match = strdup(v1_match);
}

/**
 * v29_servicelog_notify_add
 * @brief Add a new notification tool
 *
 * @param slog v0.2.9 structure containing the database parameters
 * @param notify pointer to the v0.2.9 notification tool data
 * @param reckey contains the key of the new record, if the return value is 0
 * @return 0 on success
 */
int
v29_servicelog_notify_add(struct v29_servicelog *slog,
			struct v29_sl_notify *notify, uint32_t *reckey)
{
	servicelog *log;
	struct sl_notify v1_notify;
	uint64_t v1_id;
	int result;

	if (!slog)
		return EINVAL;
	log = (servicelog*) slog->v1_servicelog;

	if (!notify || !reckey || !notify->command_length) {
		snprintf(log->error, SL_MAX_ERR,
			"null notify or ID or command passed to %s",
			__FUNCTION__);
		return EINVAL;
	}

	_convert_v29_sl_notify_to_v1(log, notify, &v1_notify);

	result = servicelog_notify_log(log, &v1_notify, &v1_id);
	free(v1_notify.match);
	if (result == 0)
		result = convert_key_to_v29(log, v1_id, reckey, "notification");
	return result;
}

int
v29_servicelog_notify_update(struct v29_servicelog *slog, uint32_t id,
        struct v29_sl_notify *notify)
{
	servicelog *log;
	int rc = 0;
	struct sl_notify v1_notify;

	if (!slog)
		return EINVAL;
	log = (servicelog*) slog->v1_servicelog;

	if (!id || !notify || !notify->command_length) {
		snprintf(log->error, SL_MAX_ERR,
			"null notify or ID or command passed to %s",
			__FUNCTION__);
		return EINVAL;
	}

	_convert_v29_sl_notify_to_v1(log, notify, &v1_notify);

	rc = servicelog_notify_update(log, id, &v1_notify);
	free(v1_notify.match);
	return rc;
}

int v29_servicelog_notify_remove(struct v29_servicelog *slog, uint32_t id)
{
	int rc;

	if (!slog)
		return EINVAL;
	rc = servicelog_notify_delete((servicelog*)slog->v1_servicelog, id);
	return rc;
}

/* v29 Print functions defined in v29_print.c */

/* A catch-all function that allows us to add fixes as needed */
void *v29_utility(int code, ...)
{
	return NULL;
}
