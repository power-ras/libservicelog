/**
 * @file libservicelog.h
 * Header file for servicelog compatibility layer.  This header is
 * intended for use by programs that use the servicelog 0.2.9
 * (legacy) API, and also by the code that implements the compatibility
 * layer.
 *
 * Where there is a conflict between a 0.2.9 object (or function) and a
 * 1.0 object of the same name, the 0.2.9 object is renamed by adding a
 * "0.29_" prefix.  In order to have visibility of both versions of a
 * particular object, the code that implements the compatibility layer
 * defines the macro EXCLUDE_SERVICELOG_COMPAT_DECLS.
 *
 * Copyright (C) 2005, 2009 IBM Corporation
 *
 * Original authors:
 * @author Nathan Fontenot <nfont@austin.ibm.com>
 * @author Michael Strosaker <strosake@us.ibm.com>
 *
 * Adapted for compatibility layer:
 * @author Jim Keniston <jkenisto@us.ibm.com>
 * @author Brad Peters <bpeters@us.ibm.com>
 */

#ifndef _LIBSERVICELOG_H
#define _LIBSERVICELOG_H

#include <time.h>
#include <stdint.h>
#include <sys/types.h>
/*
 * Dropped from compatibility layer due to complete rework of database
 * layout in v1.0: SERVICELOG_PATH, SERVICELOG_DB_NAME, NOTIFY_DB_NAME
 */

/**
 * @struct sl_header
 *
 * Structure to define the type of event data being stored in the database.
 * This structure must appear as the first thing in all event structures
 * defined for use with the servicelog database.
 */
struct sl_header {
	struct sl_header *next;
	uint32_t	db_key;		/**< db entry key */
	uint32_t	event_type;	/**< event type */
	uint32_t	version;	/**< version of the event_type */
	uint32_t	event_length;	/**< total event length */
	time_t		time_event;	/**< timestamp of event occurence */
	time_t		time_log;	/**< timestamp of event logging */
	uint32_t	severity;	/**< int field of event severity */

	uint32_t	repair_action:1;
	uint32_t	serviceable_event:1;
	uint32_t	event_repaired:1;
	uint32_t	/* reserved */ :29;
};

/* defines for sl_header.event_type */
#ifndef SL_TYPE_OS
#define SL_TYPE_OS		1
#endif
#define SL_TYPE_APP		2
#define SL_TYPE_PPC64_RTAS	3
#define SL_TYPE_PPC64_ENCL	4
#define SL_MAX_EVENT_TYPE	5	/* this should be the highest event
					 * type number + 1.
					 */

#ifndef SL_SEV_FATAL
/* defines for sl_header.severity */
#define SL_SEV_FATAL		7
#define SL_SEV_ERROR		6
#define SL_SEV_ERROR_LOCAL	5
#define SL_SEV_WARNING		4
#define SL_SEV_EVENT		3
#define SL_SEV_INFO		2
#define SL_SEV_DEBUG		1
#endif

/**
 * @struct sl_query
 *
 * Structure to contain all the elements used in querying the database
 */
struct sl_query {
	int		num_types;
	uint32_t	*event_types;
	uint32_t	severity;
	uint32_t	is_serviceable;
	uint32_t	is_repair_action;
	uint32_t	is_repaired;
	time_t		start_time;
	time_t		end_time;
	struct sl_header *result;
};

/**
 * sl_repair
 *
 * Repair Action
 */
#define SL_REPAIR_VERSION	1

struct sl_repair {
	struct sl_header head;
	char		*location;
	char		*procedure;
	int		num_repairs;
	uint32_t	*repairs;
};

/**
 * sl_os
 *
 * OS Generic.
 * Note: If there is a message string for this event it should be appended
 * after this struct itself as a NULL terminated string.  The message_length
 * field should the include the length of the string (including the NULL).
 */
#define SL_OS_VERSION		1

struct sl_os {
	struct sl_header head;
	char		refcode[9];
	char		subsystem[32];
	char		*message;
	char		*repair_procedure;
	uint32_t	repair_key;
};

/**
 * sl_app
 *
 * Application generic.
 * Note: If there is a message string for this event it should be appended
 * after this struct itself as a NULL terminated string.  The message_length
 * field should the include the length of the string (including the NULL).
 */
#define SL_APP_VERSION		1

struct sl_app {
	struct sl_header head;
	char		refcode[9];
	char		*command;
	char		*message;
	char		*repair_procedure;
	pid_t		pid;
	uint32_t	repair_key;
};

/**
 * sl_ppc64_callout
 *
 * Structure to contain data that may appear as part of ppc64_* events
 */
struct sl_ppc64_callout {
	struct sl_ppc64_callout *next;
	char		priority;
	uint32_t	type;
	uint32_t	repair_key;
	char		procedure_id[32];
	char		location[128];
	char		fru[32];
	char		serial[32];
	char		ccin[32];
};

/**
 * sl_ppc64_rtas
 *
 * PPC64 RTAS Event
 * This event has several items that may appear after the end of the
 * structure itself.  If there are any fru callouts they should appear
 * first, followed by the actual raw RTAS event itself.
 */
#define SL_PPC64_RTAS_VERSION	2

struct sl_ppc64_rtas {
	struct sl_header head;

	uint16_t	action_flags;
#define PPC64_RTAS_FLAGS_CALL_HOME_REQD		0x1000
#define PPC64_RTAS_FLAGS_REPORT_EXTERNALLY	0x2000
#define PPC64_RTAS_FLAGS_SERVICE_ACTION		0x8000

	uint16_t	rtas_event_type;
	uint32_t	kernel_id;

	char		refcode[9];
	uint32_t	addl_words[8];

	char		machine_type[9];
	char		machine_serial_no[13];

	char		*description;
	struct sl_ppc64_callout *callouts;
	uint32_t	rtas_event_len;
	char		*rtas_event;

	/* The following fields are new to version 2 of the struct */
	uint32_t	platform_id;
	char		creator_id;
#define PPC64_RTAS_CREATOR_ID_SERV_PROC		'E'
#define PPC64_RTAS_CREATOR_ID_HYPERVISOR	'H'
#define PPC64_RTAS_CREATOR_ID_POWER_CTRL	'W'
#define PPC64_RTAS_CREATOR_ID_LPAR_FW		'L'

	uint8_t		subsystem_id;
	uint8_t		rtas_severity;
	uint8_t		event_subtype;
};


/**
 * sl_ppc64_encl
 *
 * PPC64 Enclosure event
 * This is meant to cover all events generated from an enclosure on a PPC64
 * machine.
 */
#define SL_PPC64_ENCL_VERSION	1

struct sl_ppc64_encl {
	struct sl_header head;
	char		refcode[9];
	char		*description;
	struct sl_ppc64_callout *callouts;
	char		machine_type[9];
	char		machine_serial_no[13];
	uint32_t	event_len;
	char		*event;
};

/*
 * sl_notify
 *
 * Used in the notify database to indicate when an application wants to be
 * notified of the occurrence.  The actual command (and its associated
 * command-line args) should appear as a NULL-terminated string immediately
 * after this struct.  The command_length field should be the length of this
 * string (including the NULL).
 *
 * This is the "legacy" version.  See servicelog.h for the v1.1 version.
 */
#define SL_NOTIFY_VERSION	1

struct v29_sl_notify {
	struct v29_sl_notify *next;
	uint32_t	key;		/**< key for this record */
	uint32_t	version;	/**< version of this structure */
	time_t		created;	/**< timestamp of record creation */
	uint64_t	event_types;	/**< bitmask of event types */
	uint32_t	severity;	/**< minimum event severity */
	uint32_t	repair_action;	/**< notify of repair actions? */
	uint32_t	serviceable_event; /**< notify of serv events only? */
	uint32_t	method;		/**< notification method */
#define SL_NOTIFY_NUM_VIA_STDIN		0
#define SL_NOTIFY_NUM_VIA_CMD_LINE	1
#define SL_NOTIFY_TEXT_VIA_STDIN	2
#define SL_NOTIFY_PAIRS_VIA_STDIN	3

	uint32_t	command_length;	/**< length of the command */
};

/*
 * Stubbed out the definition of struct servicelog, which was very much
 * wedded to the old DB format.  The 0.2.9 version of libservicelog.h
 * says:
 *
 * "...  Users shouldn't access to any of the fields in this
 * struct to use the database but instead go through the provided interfaces."
 *
 * Users need only pass around a pointer to the servicelog struct.
 */
struct v29_servicelog {
	void *v1_servicelog;
};

#define SL_CREATE	1

#ifndef EXCLUDE_SERVICELOG_COMPAT_DECLS

#define SL_QUERY_ALL    0
#define SL_QUERY_YES    1
#define SL_QUERY_NO     2

#define SERVICELOG_PATH "/var/lib/servicelog/servicelog.db"

/*------------------------- v29 to v1 API Function/struct redefs ---------------------*/
/*
 * Make the v29_* structs and functions available using the expected names.
 */

/*  ----------------------------------------------------------
 * v29 front-end to v1.1 actual implementation call
 *                     Structs:
 *  ----------------------------------------------------------
 */
#define sl_notify v29_sl_notify
#define servicelog v29_servicelog


/* ----------------------------------------------------------
 * v29 front-end to v1.1 actual implementation call
 *                    Functions:
 * ----------------------------------------------------------
 */
#define servicelog_open v29_servicelog_open
#define servicelog_close v29_servicelog_close
#define servicelog_error v29_servicelog_error
#define servicelog_sync v29_servicelog_sync /* TODO */
#define servicelog_log_event v29_servicelog_log_event /* TODO */
#define servicelog_get_event v29_servicelog_get_event
#define servicelog_delete_event v29_servicelog_delete_event /* TODO */
#define servicelog_update_event v29_servicelog_update_event /* TODO */
#define servicelog_query v29_servicelog_query
#define servicelog_query_close v29_servicelog_query_close

#define servicelog_notify_query v29_servicelog_notify_query
#define servicelog_notify_get v29_servicelog_notify_get
#define servicelog_notify_add v29_servicelog_notify_add
#define servicelog_notify_update v29_servicelog_notify_update
#define servicelog_notify_remove v29_servicelog_notify_remove
#define servicelog_notify_free_list v29_servicelog_notify_free_list
#define servicelog_print_header v29_servicelog_print_header
#define servicelog_print_event v29_servicelog_print_event
#define servicelog_print_notification_tool v29_servicelog_print_notification_tool


/* --------- v29 API Function Headers --------------*/
int servicelog_open(struct servicelog *, const char *, int);
void servicelog_close(struct servicelog *);
char *servicelog_error(struct servicelog *);
int servicelog_sync(struct servicelog *);
int servicelog_log_event(struct servicelog *, void *, uint32_t *);
int servicelog_get_event(struct servicelog *, uint32_t, void **, size_t *);
int servicelog_delete_event(struct servicelog *, uint32_t);
int servicelog_update_event(struct servicelog *, void *);

/* Servicelog Queries */
int servicelog_query(struct servicelog *, struct sl_query *);
int servicelog_query_close(struct servicelog *, struct sl_query *);
/* Notification Registration */
int servicelog_notify_query(struct servicelog *, char *, struct sl_notify **,
	int *);
int servicelog_notify_get(struct servicelog *, uint32_t, struct sl_notify **);
int servicelog_notify_add(struct servicelog *, struct sl_notify *, uint32_t *);
int servicelog_notify_update(struct servicelog *, uint32_t, struct sl_notify *);
int servicelog_notify_remove(struct servicelog *, uint32_t);	// not in v1
int servicelog_notify_free_list(struct sl_notify *);	// not in v1
/* Print Routines */
int servicelog_print_header(FILE *, struct sl_header *, int);	// not in v1
int servicelog_print_event(FILE *, void *, int);	// not in v1
int servicelog_print_notification_tool(FILE *, struct sl_notify *); // not in v1

#endif /* EXCLUDE_SERVICELOG_COMPAT_DECLS */

#endif /* _LIBSERVICELOG_H */
