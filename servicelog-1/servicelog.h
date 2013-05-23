/*
 * @file servicelog.h
 * @brief Header file for servicelog
 *
 * Copyright (C) 2005, 2008, IBM
 * See 'COPYING' for License of this code.
 */

#ifndef _SERVICELOG_H
#define _SERVICELOG_H

#include <stdint.h>
#include <stdio.h>
#include <time.h>
#include <sqlite3.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * The system's servicelog database is represented by an instance of this
 * opaque structure.
 */
typedef struct servicelog servicelog;

/**
 * @struct sl_event
 *
 * Structure to represent the base information concerning an event that
 * is stored in the servicelog database.
 */
struct sl_event {
	struct sl_event *next;		/* only used if in a linked list */
	uint64_t	id;		/* unique identifier */
	time_t		time_logged;
	time_t		time_event;
	time_t		time_last_update;
	uint32_t	type;		/* one of SL_TYPE_* */
	uint8_t		severity;	/* one of SL_SEV_* */
	char		*platform;	/* ppc64, etc */
	char		*machine_serial;
	char		*machine_model;
	char		*nodename;
	char		*refcode;
	char		*description;
	int		serviceable;	/* 1 or 0 */
	int		predictive;	/* 1 or 0 */
	int		disposition;	/* one of SL_DISP_* */
	int		call_home_status;	/* one of SL_CALLHOME_*,
						   only valid if serviceable */
	int		closed;		/* 1 or 0, only valid if serviceable */
	uint64_t	repair;		/* id of repairing repair_action */
	struct sl_callout *callouts;
	uint32_t	raw_data_len;
	unsigned char	*raw_data;
	void		*addl_data;	/* pointer to an sl_data_* struct */
};

/* defines for sl_event.type */
#define SL_TYPE_BASIC		0
#define SL_TYPE_OS		1
#define SL_TYPE_RTAS		2
#define SL_TYPE_ENCLOSURE	3
#define SL_TYPE_BMC		4

/* defines for sl_event.severity */
#define SL_SEV_FATAL		7
#define SL_SEV_ERROR		6
#define SL_SEV_ERROR_LOCAL	5
#define SL_SEV_WARNING		4
#define SL_SEV_EVENT		3
#define SL_SEV_INFO		2
#define SL_SEV_DEBUG		1

/* defines for sl_event.disposition */
#define SL_DISP_RECOVERABLE	0
#define SL_DISP_UNRECOVERABLE	1
#define SL_DISP_BYPASSED	2 /* unrecoverable, bypassed with degraded
				     performance */

/* defines for sl_event.call_home_status */
#define SL_CALLHOME_NONE	0
#define SL_CALLHOME_CANDIDATE	1
#define SL_CALLHOME_CALLED	2

/* Taken from the v0.29 API for use in backwards compatibility */
#define SL_QUERY_ALL    0
#define SL_QUERY_YES    1
#define SL_QUERY_NO     2

/**
 * @struct sl_callout
 *
 * Structure representing a callout, or a suggested repair procedure.
 */
struct sl_callout {
	struct sl_callout *next;	/* only used if in a linked list */
	char		priority;
	uint32_t	type;
	char		*procedure;
	char		*location;
	char		*fru;
	char		*serial;
	char		*ccin;
};

/**
 * @struct sl_data_os
 *
 * Structure to store additional data for an OS event.
 */
struct sl_data_os {
	char		*version;	/* kernel version */
	char		*subsystem;
	char		*driver;
	char		*device;
};

/**
 * @struct sl_data_rtas
 *
 * Structure to store additional data for an RTAS (ppc64 platform) event.
 */
struct sl_data_rtas {
	uint16_t	action_flags;
	uint32_t	platform_id;
	char		creator_id;
	uint8_t		subsystem_id;
	uint8_t		pel_severity;
	uint16_t	event_type;
	uint8_t		event_subtype;
	uint32_t	kernel_id;
	uint32_t	addl_words[8];
};

/* flags for sl_data_rtas.action_flags */
#define RTAS_FLAGS_CALL_HOME_REQD	0x1000
#define RTAS_FLAGS_REPORT_EXTERNALLY	0x2000
#define RTAS_FLAGS_SERVICE_ACTION	0x8000

/* defines for sl_data_rtas.creator_id */
#define RTAS_CREATOR_ID_SERV_PROC	'E'
#define RTAS_CREATOR_ID_HYPERVISOR	'H'
#define RTAS_CREATOR_ID_POWER_CTRL	'W'
#define RTAS_CREATOR_ID_LPAR_FW		'L'

/**
 * @struct sl_data_enclosure
 *
 * Structure to store additional data for an external I/O enclosure.
 */
struct sl_data_enclosure {
	char		*enclosure_serial;
	char		*enclosure_model;
};

/**
 * @struct sl_data_bmc
 *
 * Structure to store additional data for an event from a BMC service processor
 */
struct sl_data_bmc {
	uint32_t	sel_id;
	uint32_t	sel_type;
	uint16_t	generator;
	uint8_t		version;
	uint8_t		sensor_type;
	uint8_t		sensor_number;
	uint8_t		event_class;
	uint8_t		event_type;
	int		direction;
};

#define BMC_DIRECTION_ASSERT	0
#define BMC_DIRECTION_DEASSERT	1

/**
 * @struct sl_repair_action
 *
 * Structure to represent information concerning a repair action that
 * is stored in the servicelog database.
 */
struct sl_repair_action {
	struct sl_repair_action *next;	/* only used if in a linked list */
	uint64_t	id;		/* unique identifier */
	time_t		time_logged;
	time_t		time_repair;
	char		*procedure;	/* repair procedure followed */
	char		*location;	/* location code of repaired device */
	char		*platform;	/* ppc64, etc */
	char		*machine_serial;
	char		*machine_model;
	char		*notes;
};

#define SL_NOTIFY_EVENTS	0
#define SL_NOTIFY_REPAIRS	1

#define SL_METHOD_NUM_VIA_CMD_LINE	0
#define SL_METHOD_NUM_VIA_STDIN		1
#define SL_METHOD_PRETTY_VIA_STDIN	2
#define SL_METHOD_SIMPLE_VIA_STDIN	3

/**
 * @struct sl_notify
 *
 * Structure to represent information concerning a notification tool that
 * is stored in the servicelog database.
 */
struct sl_notify {
	struct sl_notify *next;		/* only used if in a linked list */
	uint64_t	id;		/* unique identifier */
	time_t		time_logged;
	time_t		time_last_update;
	int		notify;		/* one of SL_NOTIFY_* defines */
	char		*command;	/* command to be invoked */
	int		method;		/* one of SL_METHOD_* defines */
	char		*match;		/* query string to match events */
};


#define SL_FLAG_READONLY	0x00000001
#define SL_FLAG_ADMIN		0x80000000

int servicelog_open(servicelog **slog, uint32_t flags);
void servicelog_close(servicelog *slog);
int servicelog_truncate(servicelog *slog, int notifications_too);
char *servicelog_error(servicelog *slog);

/* These calls are used to log and retrieve event records */
int servicelog_event_log(servicelog *slog, struct sl_event *event, uint64_t *new_id);
int servicelog_event_get(servicelog *slog, uint64_t event_id, struct sl_event **event);
int servicelog_event_query(servicelog *slog, char *query, struct sl_event **event);
int servicelog_event_close(servicelog *slog, uint64_t event_id);
int servicelog_event_repair(servicelog *slog, uint64_t event_id, uint64_t repair_id);
int servicelog_event_delete(servicelog *slog, uint64_t event_id);
int servicelog_event_print(FILE *str, struct sl_event *event, int verbosity);
void servicelog_event_free(struct sl_event *events);

/* These calls are used to log and retrieve repair action records */
int servicelog_repair_log(servicelog *slog,
			  struct sl_repair_action *repair, uint64_t *new_id,
			  struct sl_event **events);
int servicelog_repair_get(servicelog *slog, uint64_t repair_id,
			  struct sl_repair_action **repair);
int servicelog_repair_query(servicelog *slog, char *query,
			    struct sl_repair_action **repairs);
int servicelog_repair_delete(servicelog *slog, uint64_t repair_id);
int servicelog_repair_print(FILE *str, struct sl_repair_action *repair,
			    int verbosity);
void servicelog_repair_free(struct sl_repair_action *repairs);

/* These calls are used to register and retrieve notification tool records */
int servicelog_notify_log(servicelog *slog, struct sl_notify *notify,
			  uint64_t *new_id);
int servicelog_notify_get(servicelog *slog, uint64_t notify_id,
			  struct sl_notify **notify);
int servicelog_notify_query(servicelog *slog, char *query,
			    struct sl_notify **notify);
int servicelog_notify_update(servicelog *slog, uint64_t notify_id,
			     struct sl_notify *notify);
int servicelog_notify_delete(servicelog *slog, uint64_t notify_id);
int servicelog_notify_print(FILE *str, struct sl_notify *notify, int verbosity);
void servicelog_notify_free(struct sl_notify *notifies);

#ifdef __cplusplus
}  /* end 'extern "C"' block */
#endif
#endif
