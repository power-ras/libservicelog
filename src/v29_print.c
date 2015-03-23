/**
 * @file servicelog_print.c
 * @brief Routines for manipulating the system service log
 *
 * Copyright (C) 2005, 2013 IBM Corporation
 *
 * Authors of servicelog v0.2.9:
 * @author Michael Strosaker <strosake@us.ibm.com>
 * @author Nathan Fontenot <nfont@austin.ibm.com>
 *
 * Compatibility layer:
 * @author Jim Keniston <jkenisto@us.ibm.com>
 * @author Brad Peters <bpeters@us.ibm.com>
 */

#define EXCLUDE_SERVICELOG_COMPAT_DECLS

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ipc.h>
#include <sys/sem.h>
#include <stdarg.h>
#include <librtasevent.h>
#include "libservicelog.h"
#include "servicelog.h"


/* common defines for print routines */
#define PRNT_FMT_STR		"%-20s%s\n"
#define PRNT_FMT_STR_NR		"%-20s%s"
#define PRNT_FMT_CHAR		"%-20s%c\n"
#define PRNT_FMT_NUM		"%-20s%d\n"
#define PRNT_FMT_LNUM		"%-20s%ld\n"
#define PRNT_FMT_HEX		"%-20s%08x\n"
#define PRNT_FMT_LHEX		"%-20s%016llx\n"

static char *severity_text[] = { "", "DEBUG", "INFO", "EVENT", "WARNING",
				 "ERROR_LOCAL", "ERROR", "FATAL" };

static char sl_print_width = 80;
static int line_offset = 0;

/**
 * sl_hex_dump
 *
 * Dump the provided buffer in raw hex output
 */
static int
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
static int
sl_printf(FILE *stream, char *fmt, ...)
{
    va_list     ap;
    char        buf[1024];
    char        tmpbuf[1024];
    int         i, len;
    int         buf_offset = 0, offset = 0;
    int         tmpbuf_len;
    int         width = 0;
    int         prnt_len;
    char        *newline = NULL;
    char        *brkpt = NULL;

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

            switch(tmpbuf[i]) {
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
                snprintf(buf + buf_offset, prnt_len, "%s", &tmpbuf[offset]);
                buf_offset = strlen(buf);
                buf_offset += sprintf(buf + buf_offset, "\n");
                offset += prnt_len;
                line_offset = 0;
                break;
            }
        }

        if (width >= sl_print_width) {

            if (brkpt == NULL) {
               /* this won't fit on one line, break it across lines */
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

    len = fprintf(stream, "%s", buf);

    return len;
}

int
_v29_get_event_type_title(struct sl_header *hdr, char **title)
{
	if (hdr->event_type == SL_TYPE_OS) {
		*title = "OS Event";
	}
	else if (hdr->event_type == SL_TYPE_PPC64_RTAS) {
		*title = "PPC64 Platform Event";
	}
	else if (hdr->event_type == SL_TYPE_PPC64_ENCL) {
		*title = "PPC64 Platform Enclosure Event";
	}
	else if (hdr->event_type == SL_TYPE_APP) {
		*title = "Application Event";
	}
	else {
		*title = "Unknown Event Type";
		return EINVAL;
	}

	return 0;
}

/**
 * sl_print_hdr
 *
 * Generic routine to print the header common to all events.
 */
int
v29_servicelog_print_header(FILE *str, struct sl_header *hdr, int verbosity)
{
	int count = 0;
	char *title;

	if (verbosity < 0) {
		struct tm time;

		/* just print param/value pairs */
		count += fprintf(str, "ServicelogID: %d\n", hdr->db_key);
		count += fprintf(str, "EventType: ");
		if ((hdr->event_type < 0) ||
		    (hdr->event_type >= SL_MAX_EVENT_TYPE)) {
			count += fprintf(str, "\n");
		}
		else {
			_v29_get_event_type_title(hdr, &title);
			count += fprintf(str, "%s\n", title);
		}
		count += fprintf(str, "Version: %d\n", hdr->version);
		count += fprintf(str, "RepairAction: %d\n", hdr->repair_action);
		count += fprintf(str, "Serviceable: %d\n",
				 hdr->serviceable_event);
		count += fprintf(str, "Repaired: %d\n", hdr->event_repaired);
		localtime_r(&(hdr->time_event), &time);
		count += fprintf(str, "EventTime: %02d/%02d/%04d %02d:%02d:%02d"
				 "\n", time.tm_mon+1, time.tm_mday,
				 time.tm_year+1900, time.tm_hour,
				 time.tm_min, time.tm_sec);
		localtime_r(&(hdr->time_log), &time);
		count += fprintf(str, "LogTime: %02d/%02d/%04d %02d:%02d:%02d"
				 "\n", time.tm_mon+1, time.tm_mday,
				 time.tm_year+1900, time.tm_hour,
				 time.tm_min, time.tm_sec);
		count += fprintf(str, "Severity: %d\n", hdr->severity);
		return count;
	}

	if ((hdr->event_type < 0) || (hdr->event_type >= SL_MAX_EVENT_TYPE)) {
		count += sl_printf(str, "Unknown Event:\n");
	} else {
		if (hdr->repair_action) {
			_v29_get_event_type_title(hdr, &title);
			count += sl_printf(str, "Repair Action: (for %s)\n", title);
		} else {
			_v29_get_event_type_title(hdr, &title);
			count += sl_printf(str, "%s:\n", title);
		}
	}

	count += sl_printf(str, PRNT_FMT_NUM, "Servicelog ID:", hdr->db_key);
	count += sl_printf(str, PRNT_FMT_STR_NR, "Event Timestamp:",
			   ctime(&(hdr->time_event)));
	count += sl_printf(str, PRNT_FMT_STR_NR, "Log Timestamp:",
			   ctime(&(hdr->time_log)));
	count += sl_printf(str, "%-20s%d (%s)\n", "Severity:",
			   hdr->severity, severity_text[hdr->severity]);
	count += sl_printf(str, PRNT_FMT_NUM, "Version:", hdr->version);

	count += sl_printf(str, PRNT_FMT_STR, "Serviceable Event:",
			   ((hdr->serviceable_event) ? "Yes" : "No"));
	count += sl_printf(str, PRNT_FMT_STR, "Event Repaired:",
			   ((hdr->event_repaired) ? "Yes" : "No"));

	return count;
}

/**
 * sl_print_app_event
 * @breif Print the contents of an Application event
 */
static int
sl_print_app_event(FILE *str, void *event, int verbosity)
{
	struct sl_app *app = (struct sl_app *)event;
	int count = 0;

	count += v29_servicelog_print_header(str, &app->head, verbosity);

	if (verbosity < 0) {
		count += fprintf(str, "RepairEventKey: ");
		if (app->repair_key)
			fprintf(str, "%d\n", app->repair_key);
		else
			fprintf(str, "\n");
		count += fprintf(str, "Refcode: %s\n", app->refcode);
		count += fprintf(str, "Pid: %d\n", app->pid);
		count += fprintf(str, "Command: %s\n", app->command);
		count += fprintf(str, "Message: %s\n", app->message);
		count += fprintf(str, "RepairProcedure: %s\n",
				 app->repair_procedure);
		return count;
	}

	if (strlen(app->refcode) > 0)
		count += sl_printf(str, PRNT_FMT_STR, "Refcode:", app->refcode);

	count += sl_printf(str, PRNT_FMT_NUM, "Pid:", app->pid);

	if (app->repair_key > 0)
		count += sl_printf(str, PRNT_FMT_NUM, "Repair Event Key:",
				   app->repair_key);

	if (app->command != NULL)
		count += sl_printf(str, PRNT_FMT_STR, "Command:", app->command);
	if (app->message != NULL)
		count += sl_printf(str, PRNT_FMT_STR, "Message:", app->message);
	if (app->repair_procedure)
		count += sl_printf(str, PRNT_FMT_STR, "Repair Procedure:",
				   app->repair_procedure);

	return count;
}

/**
 * sl_print_os_event
 * @brief print the contents of an OS event
 */
static int
sl_print_os_event(FILE *str, void *event, int verbosity)
{
	struct sl_os *os = (struct sl_os *)event;
	int count = 0;

	count += v29_servicelog_print_header(str, &os->head, verbosity);

	if (verbosity < 0) {
		count += fprintf(str, "RepairEventKey: ");
		if (os->repair_key)
			fprintf(str, "%d\n", os->repair_key);
		else
			fprintf(str, "\n");
		count += fprintf(str, "Refcode: %s\n", os->refcode);
		count += fprintf(str, "Subsystem: %s\n", os->subsystem);
		count += fprintf(str, "Message: %s\n", os->message);
		count += fprintf(str, "RepairProcedure: %s\n",
				 os->repair_procedure);
		return count;
	}

	if (strlen(os->refcode) > 0)
		count += sl_printf(str, PRNT_FMT_STR, "Refcode:", os->refcode);

	if (strlen(os->subsystem) > 0)
		count += sl_printf(str, PRNT_FMT_STR, "Subsystem:",
				   os->subsystem);

	if (os->repair_key > 0)
		count += sl_printf(str, PRNT_FMT_NUM, "Repair Entry Key:",
				   os->repair_key);

	if (os->message)
		count += sl_printf(str, PRNT_FMT_STR, "Message:", os->message);

	if (os->repair_procedure)
		count += sl_printf(str, PRNT_FMT_STR, "Repair Procedure:",
				   os->repair_procedure);

	return count;
}

/**
 * sl_print_ppc64_event
 *
 * Print the contents of a PPC64 event
 */
static int
sl_print_ppc64_rtas_event(FILE *str, void *event, int verbosity)
{
	struct sl_ppc64_rtas *ppc64 = (struct sl_ppc64_rtas *)event;
	struct sl_ppc64_callout *callout;
	int i = 0, count = 0;
	char *detail, *pos;

	count += v29_servicelog_print_header(str, &ppc64->head, verbosity);

	if (verbosity < 0) {
		count += fprintf(str, "Refcode: %s\n", ppc64->refcode);
		count += fprintf(str, "AddlWord0: 0x%08x\n",
				 ppc64->addl_words[0]);
		count += fprintf(str, "AddlWord1: 0x%08x\n",
				 ppc64->addl_words[1]);
		count += fprintf(str, "AddlWord2: 0x%08x\n",
				 ppc64->addl_words[2]);
		count += fprintf(str, "AddlWord3: 0x%08x\n",
				 ppc64->addl_words[3]);
		count += fprintf(str, "AddlWord4: 0x%08x\n",
				 ppc64->addl_words[4]);
		count += fprintf(str, "AddlWord5: 0x%08x\n",
				 ppc64->addl_words[5]);
		count += fprintf(str, "AddlWord6: 0x%08x\n",
				 ppc64->addl_words[6]);
		count += fprintf(str, "AddlWord7: 0x%08x\n",
				 ppc64->addl_words[7]);
		count += fprintf(str, "ActionFlags: 0x%04x\n",
				 ppc64->action_flags);
		count += fprintf(str, "EventType: %d\n",
				 ppc64->rtas_event_type);
		count += fprintf(str, "KernelID: %d\n", ppc64->kernel_id);

		if ((uint8_t)(*ppc64->rtas_event) >= 6) {
			count += fprintf(str, "PlatformID: 0x%x\n",
					 ppc64->platform_id);
			count += fprintf(str, "CreatorID: %c\n",
					 ppc64->creator_id);
			count += fprintf(str, "SubsystemID: 0x%02x\n",
					 ppc64->subsystem_id);
			count += fprintf(str, "EventSubtype: 0x%02x\n",
					 ppc64->event_subtype);
			count += fprintf(str, "RTASSeverity: 0x%02x\n",
					 ppc64->rtas_severity);
		}

		count += fprintf(str, "MachineType: %s\n", ppc64->machine_type);
		count += fprintf(str, "MachineSerial: %s\n",
				 ppc64->machine_serial_no);

		/* replace newlines with | characters in the description */
		while ((pos = strchr(ppc64->description, '\n')) != NULL)
			*pos = '|';
		count += fprintf(str, "Description: %s\n", ppc64->description);

		callout = ppc64->callouts;
		while (callout != NULL) {
			count += fprintf(str, "Callout: %c %d %s %s %s %s %s %d"
					 "\n", callout->priority, callout->type,
					 callout->procedure_id,
					 callout->location, callout->fru,
					 callout->serial, callout->ccin,
					 callout->repair_key);
			callout = callout->next;
		}
		return count;
	}

	count += sl_printf(str, PRNT_FMT_STR, "Reference Code:",
			   ppc64->refcode);

	count += sl_printf(str, "%-20s%04x\n", "Action Flags:",
			   ppc64->action_flags);

	/* Print detailed event type */
	switch(ppc64->rtas_event_type) {
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
			   ppc64->rtas_event_type, detail);

	count += sl_printf(str, PRNT_FMT_NUM, "Kernel ID:", ppc64->kernel_id);

	/* bpeters: TODO: We're assuming that if this field is NULL, then we have a v6 event.
	 * This seems to work, but what happens if in fact it is <v6?
	 */
	if ((ppc64->rtas_event) != NULL) {
		if ((uint8_t)(*ppc64->rtas_event) < 6)
			goto skip_v6;
	}

	count += sl_printf(str, PRNT_FMT_HEX, "Platform ID:",
			   ppc64->platform_id);

	/* Print detailed creator ID */
	switch (ppc64->creator_id) {
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
			   ppc64->creator_id, detail);

	/* Print detailed subsystem ID */
	detail = "";
	if ((ppc64->subsystem_id >= 0x10) && (ppc64->subsystem_id <= 0x1F))
		detail = " - Processor subsystem including internal cache";
	else if ((ppc64->subsystem_id >= 0x20) && (ppc64->subsystem_id <= 0x2F))
		detail = " - Memory subsystem including external cache";
	else if ((ppc64->subsystem_id >= 0x30) && (ppc64->subsystem_id <= 0x3F))
		detail = " - I/O subsystem (hub, bridge, bus)";
	else if ((ppc64->subsystem_id >= 0x40) && (ppc64->subsystem_id <= 0x4F))
		detail = " - I/O adapter, device and peripheral";
	else if ((ppc64->subsystem_id >= 0x50) && (ppc64->subsystem_id <= 0x5F))
		detail = " - CEC hardware";
	else if ((ppc64->subsystem_id >= 0x60) && (ppc64->subsystem_id <= 0x6F))
		detail = " - Power/Cooling subsystem";
	else if ((ppc64->subsystem_id >= 0x70) && (ppc64->subsystem_id <= 0x79))
		detail = " - Other subsystem";
	else if ((ppc64->subsystem_id >= 0x7A) && (ppc64->subsystem_id <= 0x7F))
		detail = " - Surveillance error";
	else if ((ppc64->subsystem_id >= 0x80) && (ppc64->subsystem_id <= 0x8F))
		detail = " - Platform firmware";
	else if ((ppc64->subsystem_id >= 0x90) && (ppc64->subsystem_id <= 0x9F))
		detail = " - Software";
	else if ((ppc64->subsystem_id >= 0xA0) && (ppc64->subsystem_id <= 0xAF))
		detail = " - External environment";
	count += sl_printf(str, "%-20s%02x%s\n", "Subsystem ID:",
			   ppc64->subsystem_id, detail);

	/* Print detailed RTAS severity */
	switch(ppc64->rtas_severity) {
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
			   ppc64->rtas_severity, detail);

	/* Print detailed event subtype */
	switch(ppc64->event_subtype) {
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
		default:
			detail = "";
	}
	count += sl_printf(str, "%-20s%02x%s\n", "Event Subtype:",
			   ppc64->event_subtype, detail);

	count += sl_printf(str, PRNT_FMT_STR, "Machine Type/Model:",
			   ppc64->machine_type);
	count += sl_printf(str, PRNT_FMT_STR, "Machine Serial:",
			   ppc64->machine_serial_no);

skip_v6:
	if (verbosity == 0) {
		count += sl_printf(str, PRNT_FMT_STR, "Callouts:",
				   (ppc64->callouts == NULL ? "No" : "Yes"));
		return count;
	}

	count += sl_printf(str, "\nExtended Reference Codes:\n");
	count += sl_printf(str, "2: %08x  3: %08x  4: %08x  5: %08x\n",
			   ppc64->addl_words[0], ppc64->addl_words[1],
			   ppc64->addl_words[2], ppc64->addl_words[3]);
	count += sl_printf(str, "6: %08x  7: %08x  8: %08x  9: %08x\n",
			   ppc64->addl_words[4], ppc64->addl_words[5],
			   ppc64->addl_words[6], ppc64->addl_words[7]);

	/* print the description */
	count += sl_printf(str, "\nDescription:\n%s\n", ppc64->description);

	callout = ppc64->callouts;

	/* print the FRU callouts */
	while (callout != NULL) {
		count += sl_printf(str, "\n<< Callout %d >>\n", i + 1);
		i++;

		if (callout->priority != '\0') {
			/* newer style callout */
			count += sl_printf(str, PRNT_FMT_CHAR, "Priority",
					   callout->priority);
			count += sl_printf(str, PRNT_FMT_NUM, "Type",
					   callout->type);
			count += sl_printf(str, PRNT_FMT_NUM,
					   "Repair Event Key:",
					   callout->repair_key);
			count += sl_printf(str, PRNT_FMT_STR, "Procedure Id:",
					   callout->procedure_id);

			count += sl_printf(str, PRNT_FMT_STR, "Location:",
					   callout->location);
			count += sl_printf(str, PRNT_FMT_STR, "FRU:",
					   callout->fru);
			count += sl_printf(str, PRNT_FMT_STR, "Serial:",
					   callout->serial);
			count += sl_printf(str, PRNT_FMT_STR, "CCIN:",
					   callout->ccin);
		} else {
			/* older style callout */
			count += sl_printf(str, PRNT_FMT_STR, "Location:",
					   callout->location);
			count += sl_printf(str, PRNT_FMT_STR, "FRU:",
					   callout->fru);
			count += sl_printf(str, PRNT_FMT_STR, "Ref-Code:",
					   callout->procedure_id);
		}

		callout = callout->next;
	}

	if (ppc64->rtas_event) {
		struct rtas_event *re;

		re = parse_rtas_event(ppc64->rtas_event, ppc64->rtas_event_len);
		if (re == NULL) {
			count += sl_printf(str, "\n<< Raw Event Dump Begin "
					   "(%d bytes) >>\n",
					   ppc64->rtas_event_len);
			count += sl_hex_dump(str, ppc64->rtas_event,
					     ppc64->rtas_event_len);
			count += sl_printf(str, "<< Raw Event Dump End >>\n");
		} else {
			sl_printf(str, "\n");
			rtas_set_print_width(sl_print_width);
			if (verbosity >= 2)
				count += rtas_print_event(str, re, verbosity);
			else
				count += rtas_print_raw_event(str, re);

			cleanup_rtas_event(re);
		}
	}

	return count;
}

/**
 * sl_print_repair_action
 *
 * print the contents of a repair action event
 */
static int
sl_print_repair_action(FILE *str, void *event, int verbosity)
{
	struct sl_repair *repair = (struct sl_repair *)event;
	int count = 0, i;

	count += v29_servicelog_print_header(str, &repair->head, verbosity);

	if (verbosity < 0) {
		count += fprintf(str, "Location: %s\n", repair->location);
		count += fprintf(str, "Procedure: %s\n", repair->procedure);
		count += fprintf(str, "Repairs: ");
		for (i = 0; i< repair->num_repairs; i++)
			count += fprintf(str, "%d ", repair->repairs[i]);
		count += fprintf(str, "\n");
		return count;
	}

	if (repair->location != NULL)
		count += sl_printf(str, PRNT_FMT_STR, "Location:",
				   repair->location);
	if (repair->procedure != NULL)
		count += sl_printf(str, PRNT_FMT_STR, "Procedure:",
				repair->procedure);

	if (repair->num_repairs) {
		sl_printf(str, "Repair for event key(s):\n");

		for (i = 0; i < repair->num_repairs; i++)
			sl_printf(str, "    %d\n", repair->repairs[i]);
	}

	return count;
}

/**
 * servicelog_print_event
 * @brief Print an event from the servicelog database by unique ID
 *
 * Output will be limited to 68 columns.
 *
 * @param str file stream for printing
 * @param event the event data stored in the service log
 * @param verbosity verboseness of output; -1 to print param/value pairs
 * @return number of bytes printed
 */
int
v29_servicelog_print_event(FILE *str, void *event, int verbosity)
{
	struct sl_header *hdr;
	int count = 0;

	if (event == NULL)
		return count;

	hdr = (struct sl_header *)event;

	if (hdr->repair_action) {
		count += sl_print_repair_action(str, (struct sl_repair *)event,
						verbosity);
	} else {
		switch (hdr->event_type) {
		    case SL_TYPE_OS:
			sl_print_os_event(str, event, verbosity);
			break;

		    case SL_TYPE_APP:
			sl_print_app_event(str, event, verbosity);
			break;

		    case SL_TYPE_PPC64_RTAS:
			sl_print_ppc64_rtas_event(str, event, verbosity);
			break;

		    default:
		    {
			/* unknown event type; do a hex dump */
			char *start = event + sizeof(*hdr);
			size_t len = hdr->event_length - sizeof(*hdr);

			count += v29_servicelog_print_header(str, hdr,
								verbosity);
			count += sl_hex_dump(str, start, len);
			break;
		    }
		}
	}

	return count;
}

/**
 * servicelog_print_notification_tool
 * @brief Display the information from an sl_notify structure
 *
 * @param notify the structure to print
 */
int
v29_servicelog_print_notification_tool(FILE *str, struct v29_sl_notify *notify)
{
	int count = 0;

	count += sl_printf(str, PRNT_FMT_NUM, "Servicelog ID:", notify->key);
	count += fprintf(str, "%-20s%s\n", "Command:", (char *)notify +
		           sizeof(struct sl_notify));
	count += sl_printf(str, PRNT_FMT_NUM, "Command Length:",
			   notify->command_length);
	count += sl_printf(str, PRNT_FMT_STR_NR, "Created:",
			   ctime(&(notify->created)));

	count += sl_printf(str, PRNT_FMT_LHEX, "Event Types:",
			   notify->event_types);

	count += sl_printf(str, "%-20s", "Event Types:");
	if (notify->event_types & (1 << SL_TYPE_OS))
		count += sl_printf(str, "OS ");
	if (notify->event_types & (1 << SL_TYPE_APP))
		count += sl_printf(str, "APP ");
	if (notify->event_types & (1 << SL_TYPE_PPC64_RTAS))
		count += sl_printf(str, "PPC64_RTAS ");
	if (notify->event_types & (1 << SL_TYPE_PPC64_ENCL))
		count += sl_printf(str, "PPC64_ENCL ");
	count += sl_printf(str, "\n");

	count += sl_printf(str, "%-20s%d (%s)\n", "Min Severity:",
			   notify->severity, severity_text[notify->severity]);

	if (notify->repair_action == SL_QUERY_YES)
		count += sl_printf(str, PRNT_FMT_STR, "Repair Action:",
				   "Notified of Repair Actions Only "
				   "(No Events)");
	else if (notify->repair_action == SL_QUERY_NO)
		count += sl_printf(str, PRNT_FMT_STR, "Repair Action:",
				   "No Notification of Repair Actions "
				   "(Events Only)");
	else if (notify->repair_action == SL_QUERY_ALL)
		count += sl_printf(str, PRNT_FMT_STR, "Repair Action:",
				   "Notified of Both Events and "
				   "Repair Actions");
	else
		count += sl_printf(str, PRNT_FMT_STR, "Repair Action:",
				   "UNKNOWN");

	if (notify->serviceable_event == SL_QUERY_YES)
		count += sl_printf(str, PRNT_FMT_STR, "Serviceable Event:",
				   "Notified of Serviceable Events Only");
	else if (notify->serviceable_event == SL_QUERY_NO)
		count += sl_printf(str, PRNT_FMT_STR, "Serviceable Event:",
				   "Notified of Non-Serviceable Events "
				   "Only");
	else if (notify->serviceable_event == SL_QUERY_ALL)
		count += sl_printf(str, PRNT_FMT_STR, "Serviceable Event:",
				   "Notified of Both Serviceable and "
				   "Non-Serviceable Events");
	else
		count += sl_printf(str, PRNT_FMT_STR, "Serviceable Event:",
				   "UNKNOWN");

	if (notify->method == SL_NOTIFY_NUM_VIA_STDIN)
		count += sl_printf(str, PRNT_FMT_STR, "Notification:",
				   "Servicelog event ID via stdin");
	else if (notify->method == SL_NOTIFY_NUM_VIA_CMD_LINE)
		count += sl_printf(str, PRNT_FMT_STR, "Notification:",
				   "Servicelog event ID via command-line "
				   "argument");
	else if (notify->method == SL_NOTIFY_TEXT_VIA_STDIN)
		count += sl_printf(str, PRNT_FMT_STR, "Notification:",
				   "Event text via stdin");
	else if (notify->method == SL_NOTIFY_PAIRS_VIA_STDIN)
		count += sl_printf(str, PRNT_FMT_STR, "Notification:",
				   "Parameter/value pairs via stdin");
	else
		count += sl_printf(str, PRNT_FMT_STR, "Notification:",
				   "UNKNOWN");

	return count;
}
