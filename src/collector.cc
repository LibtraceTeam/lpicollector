/*
 * This file is part of lpicollector
 *
 * Copyright (c) 2013 The University of Waikato, Hamilton, New Zealand.
 * Author: Meenakshee Mungro
 *	   Shane Alcock
 *
 * All rights reserved.
 *
 * This code has been developed by the University of Waikato WAND
 * research group. For further information please see http://www.wand.net.nz/
 *
 * lpicollector is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * lpicollector is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with lpicollector. If not, see <http://www.gnu.org/licenses/>.
 */

#define __STDC_FORMAT_MACROS

#include <stdio.h>
#include <assert.h>
#include <getopt.h>
#include <signal.h>
#include <stdlib.h>
#include <inttypes.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/time.h>
#include <errno.h>
#include <sys/types.h>
#include <netdb.h>
#include <pthread.h>

#include <libtrace.h>
#include <libwandevent.h>
#include <libflowmanager.h>
#include <libprotoident.h>
#include <libfifo.h>
#include <libpacketdump.h>

#include "live_common.h"
#include "lpicp_export.h"
#include "lpicp.h"
#include "server.h"



enum {
        DIR_METHOD_TRACE,
        DIR_METHOD_MAC,
        DIR_METHOD_PORT
};

int dir_method = DIR_METHOD_TRACE;

char *local_mac = NULL;
uint8_t mac_bytes[6];

libtrace_t *trace = NULL;
libtrace_packet_t *packet = NULL;

uint32_t report_freq = 300;
char* local_id = (char*) "unnamed";

/* Struct that stores the time at which the reporting period started */
struct timeval start_reporting_period;

static volatile int done = 0;

/* Bool that stores whether the user has set exporting expired flow records in the
 * options */
bool export_expired = false;
/* Bool that stores whether the user has set exporting ongoing flow records in the
 * options */
bool export_ongoing = false;

/* Used to specify at which time  interval to export expired flows  */
int expired_interval = 0;
/* Default amount of time after a which a flow is classified as "ongoing" and 
 * needs to be exported */
int ongoing_max_runtime = 600;
/* Default amount of time after which to export ongoing flows */
int iterate_ongoing_flows = 300;

double last_observed_ts = 0.0;

/* Structure which contains all the current values for all the statistics the 
 * collector needs to track. */
LiveCounters counts;

pthread_t thread1;

/* Function prototypes */
void collect_packets(wand_event_handler_t *ev_hdl, libtrace_t *trace, 
		libtrace_packet_t *packet );
void find_ongoing_flows_cb(wand_event_handler_t *ev_hdl, void *data);

static void usage(char *prog) {
	printf("Usage details for %s\n\n", prog);
	printf("%s [-f <filter>] [-l <local mac>] [-i <local_ID>] [-r <freq>] [-c <clients>] [-s <fifosize>] [-p <port>] [-e <expired_itvl>] [-o <ongoing_limit>] [-v <ongoing_itvl>]   [-h] [-T] [-P] [-R] [-U] [-E] [-O]\n\n", prog);
        printf("Options:\n");
	printf("  -f <filter>   Ignore flows that do not match the given BPF filter\n");
	printf("  -l <mac>      Determine direction based on <mac> representing the 'inside' \n                portion of the network\n");
	printf("  -i <local_id>	Id number to use for this monitor (defaults to $HOSTNAME)\n");
	printf("  -r <freq>	Report statistics every <freq> seconds\n");
	printf("  -c <clients>	Max number of clients that can connect to the server\n");
	printf("  -s <fifosize> Size of the FIFO (defaults to 100MB if not set\n");
	printf("  -p <port>	Port on which the server will listen for new connections. Defaults to 3678\n");
	printf("  -e <exp_itvl> Interval at which to check for expired flows \n");
	printf("  -o <on_limit> Number of seconds after which a running flow is classified as ongoing \n");
	printf("  -v <on_itvl>  Interval at which to check for ongoing flows \n");
	printf("  -h		Print usage\n");
	printf("  -T            Use trace direction tags to determine direction\n");
        printf("  -P            Use port number to determine direction\n");
        printf("  -R            Ignore flows involving private RFC 1918 address space\n");
        printf("  -U		Enable keeping LPI statistics for every individual\n		local IP address observed in the data source\n");
	printf("  -E		Enable exporting expired flow statistics \n");
	printf("  -O		Enable exporting ongoing flow statistics \n");
	exit(0);
}	
			

/* Function which prints the stats to the console every n seconds, where n is a 
 * value provided in the command line arguments 
 */
void output_stats(wand_event_handler_t *ev_hdl, void *data)
{
	struct timeval tv = *(struct timeval *)data;	

	gettimeofday(&start_reporting_period, NULL);	
	start_reporting_period.tv_sec = start_reporting_period.tv_sec - 
			(start_reporting_period.tv_sec % report_freq);
	start_reporting_period.tv_usec = 0;
	wand_add_timer(ev_hdl, report_freq, 0, &start_reporting_period,  
			output_stats);
	
	lpicp_export_counters(&counts, start_reporting_period, local_id, report_freq);	
	
	reset_counters(&counts, false);
}

/* Expires all flows that libflowmanager believes have been idle for too
 * long. The exp_flag variable tells libflowmanager whether it should force
 * expiry of all flows (e.g. if you have reached the end of the program and
 * want the stats for all the still-active flows). Otherwise, only flows
 * that have been idle for longer than their expiry timeout will be expired.
 */
int expire_live_flows(double ts, bool exp_flag) {
	Flow *expired;

	/* Loop until libflowmanager has no more expired flows available */
	while ((expired = lfm_expire_next_flow(ts, exp_flag)) != NULL) {               
		
		/* TODO: push flow info to exporter 
		 * function that takes in a flow 
		 * 
		 * reg lpicp header, subheader(# flows, etc), struct with flow 
		 * stuff */
		 		
		LiveFlow *live = (LiveFlow *)expired->extension;	
		
		if (expired_interval != 0 || export_expired) {
			if (lpicp_export_flow(local_id, expired, live, LPICP_EXPIRED) == -1) 
				return -1;			
		}
					
		destroy_live_flow(live, &counts);
		
		/* VERY IMPORTANT: delete the Flow structure itself, even
		 * though we did not directly allocate the memory ourselves 
		 */
		lfm_release_flow(expired);
	}
}

bool new_user_check(libtrace_packet_t *packet) {
	/* We want to avoid creating new "users" for packets that are clearly
	 * random Internet trash */
	
	/* This function isn't very smart -- just trying to avoid the worst
	 * cases for now */
	libtrace_tcp_t *tcp = trace_get_tcp(packet);
	//libtrace_icmp_t *icmp = trace_get_icmp(packet);

	if (tcp && tcp->rst)
		return false;
	//if (icmp && (icmp->type == 3 || icmp->type == 11 || icmp->type == 5))
	//	return false;
	return true;
}

/* Function which processes a packet after it is read from the trace.
 * It expires any old flows that are due to expire, takes the current packet 
 * and matches it to the flow it belongs to, checks if it is a new flow and acts
 * accordingly, updates the state properly by checking if it is a TCP flow, and
 * updates the expiry time for the current flow. 
 */
int process_packet(libtrace_packet_t *packet)
{
	uint8_t dir = 255;
	Flow *f;
	LiveFlow *live = NULL;
	bool is_new = false;
    
	/* Defines a tcp header structure */
	libtrace_tcp_t *tcp = NULL;
	void *l3;
	double ts;

	uint16_t l3_type = 0;

	l3 = trace_get_layer3(packet, &l3_type, NULL);
	/* if the packet is not an IPv4 or IPv6 packet */
	if (l3_type != TRACE_ETHERTYPE_IP && l3_type != TRACE_ETHERTYPE_IPV6) 
		return 0;
	if (l3 == NULL) 
		return 0;
    
	/* Expire all suitably idle flows */
	ts = trace_get_seconds(packet);
	last_observed_ts = ts;
	
	if (expire_live_flows(ts, false) == -1) {
		
	}
	
	/* Determine packet direction */	
	if (dir_method == DIR_METHOD_TRACE) {
		dir = trace_get_direction(packet);
	}
	if (dir_method == DIR_METHOD_MAC) {
		dir = mac_get_direction(packet, mac_bytes);
	}
	if (dir_method == DIR_METHOD_PORT) {
		dir = port_get_direction(packet);
	}
    
	if (dir != 0 && dir != 1)
		return 0;
			
	/* Match the packet to a Flow - this will create a new flow if
	 * there is no matching flow already in the Flow map and set the
	 * is_new flag to true */
	f = lfm_match_packet_to_flow(packet, dir, &is_new);

	/* Libflowmanager did not like something about that packet - best to
	 * just ignore it and carry on */
	if (f == NULL) {
		return 0;
	}
	    
	tcp = trace_get_tcp(packet);
	
	/* If the returned flow is new, allocate and initialise any custom data 
	 * that needs to be tracked for the flow */
	if (is_new) {	
		init_live_flow(&counts, f, dir, ts, new_user_check(packet));
		live = (LiveFlow *)f->extension;
	} 
	else {
		live = (LiveFlow *)f->extension;
	}

	/*
	uint32_t local;
	bool ok = false;
	local = f->id.get_local_ip();
	if (l3_type == TRACE_ETHERTYPE_IPV6)
		ok = true; 
	
	if ((local & 0x000000ff) == (0x0000000a))
		ok = true;
	if ((local & 0x0000ffff) == (0x00008672))
		ok = true;
	if ((local & 0x000000ff) == (0x000000e0))
		ok = true;
	if ((local & 0x0000ffff) == (0x0000fea9))
		ok = true;
	
	if ((local == 0xffffffff))
		ok = true;
	
	if (!ok) {
		printf("%u\n", local);
		trace_dump_packet(packet);
		assert(0);
	}
	*/
	
	/* Call method which updates the statistics stored in the LiveFlow 
         * structure, based on the provided packet */
	update_liveflow_stats(live, packet, &counts, dir);
	
	/* Pass the packet into libprotolive so that it can extract any
	 * info it needs from this packet */
	lpi_update_data(packet, &live->lpi, dir);	
	
	if (update_protocol_counters( live, &counts, 
				trace_get_wire_length(packet),
				trace_get_payload_length(packet), dir) == -1) {		
		fprintf(stderr, "Error while extracting information from packet!" );
	}
		
	/* Update TCP state for TCP flows. The TCP state determines how long
	 * the flow can be idle before being expired by libflowmanager. For
	 * instance, flows for which we have only seen a SYN will expire much
	 * quicker than a TCP connection that has completed the handshake */	
	if (tcp) {
		lfm_check_tcp_flags(f, tcp, dir, ts);
	}

	/* Tell libflowmanager to update the expiry time for this flow */
	lfm_update_flow_expiry_timeout(f, ts);	
	
	return 1;
}

/* File descriptor callback method which is executed when a fd is added */
void source_read_event( wand_event_handler_t *ev_hdl, int fd, void *data, 
			enum wand_eventtype_t event_type)
{
	wand_del_fd(ev_hdl, fd);

	/* Not very nice if this fails but it really REALLY shouldn't fail */
	assert(event_type == EV_READ);
	collect_packets(ev_hdl,trace, packet);
}

int check_ongoing_flow(Flow *flow, void *data)
{
	/* get the LiveFlow structure out of the flow */
	LiveFlow *live = (LiveFlow *)flow->extension;	
	
	double* current_time = (double *)data;
	
	/* If the flow has been running for more than the specified number of 
	 * seconds(600 by default) */	 	 
	if ((*current_time - live->start_ts) > ongoing_max_runtime) {
		/* call method to add it to a buffer for exporting ongoing flows */
		if (lpicp_export_flow(local_id, flow, live, LPICP_ONGOING) == -1)
			/* An error has occured */
			return -1;
	
	}	
	
	/* No errors have occured and the ongoing flow has been exported 
	 * successfully */
	return 1;
}

static inline void setup_ongoing_flows_timer(wand_event_handler_t *ev_hdl)
{

	wand_add_timer(ev_hdl, iterate_ongoing_flows, 0, NULL,
			find_ongoing_flows_cb);

}

void find_ongoing_flows_cb(wand_event_handler_t *ev_hdl, void *data)
{
	
	if (last_observed_ts != 0) 
		int ret = lfm_foreach_flow(check_ongoing_flow, 
						(void *)&last_observed_ts);	
	
	lpicp_export_ongoing_flows(local_id);

	/* Setup the timer to iterate over all flows every N seconds so 
	 * as to find the flows that are ongoing */
	setup_ongoing_flows_timer(ev_hdl);		
}

/* Callback function for packet_timer which is executed when the timer fires */
void sleep_timer_event(wand_event_handler_t *ev_hdl, void *data)
{
	collect_packets(ev_hdl, trace, packet);
}

/* Function which handles a SIGINT by deleting the signal and halting execution
 * of the program
 */
static void cleanup_signal(wand_event_handler_t *ev_hdl, int signum, 
		void *data) 
{	
	wand_del_signal(signum);
		
	fprintf(stdout, "%s\n", "Terminating program...");
	done = 1;
	ev_hdl->running = false;
	
	/* cancel thread with pthread_cancel and thread id*/
	pthread_cancel(thread1);
}

/* Function which processes a libtrace event and executes the appropriate code 
 * for each event type
 */
int process_event(wand_event_handler_t *ev_hdl, libtrace_eventobj_t event, 
		libtrace_packet_t *packet)
{
	switch(event.type)
	{
		/* wait on a file descriptor(comes up when working with a live 
		 * source) */
		case TRACE_EVENT_IOWAIT:
			wand_add_fd(ev_hdl, event.fd, EV_READ, NULL, 
					source_read_event);
			
			/* Stop the current poll loop */
			return 0;
		
		/* this event type comes up with static trace files */
		case TRACE_EVENT_SLEEP:
			/* Next packet will be available in N seconds, sleep 
			 * until then */
			int micros;
			micros = (int)((event.seconds - 
					(int)event.seconds) * 1000000.0);
			wand_add_timer(ev_hdl, (int)event.seconds, micros,
					NULL, sleep_timer_event);
			
			return 0;
			
		case TRACE_EVENT_PACKET:
			/* A packet is available - pass it on to the meter */
			if (event.size == -1)
			{
				/* Error occured */
				/* We don't need wdcap's fancy error handling - 
				 * just drop the trace */
				ev_hdl->running = false;
				return 0;
			}

			/* No error, so call function which processes packets */
			if (process_packet(packet) == -1) {
				ev_hdl->running = false;
				return 0;
			}

			/* check for more packets */
			return 1;
			
		case TRACE_EVENT_TERMINATE:
			/* The input trace has terminated */
			ev_hdl->running = false;
			return 0;
		
		default:
			fprintf(stderr, "Unknown libtrace event type: %d\n", 
						event.type);
			return 0;	
	}	
}

/* Function which polls the trace for the next packet if available */
void collect_packets(wand_event_handler_t *ev_hdl, libtrace_t *trace, 
		libtrace_packet_t *packet )
{
	struct libtrace_eventobj_t event;
	int poll_again = 1;

	do
	{
		if (done)
			return;
			
		/* Process the next libtrace event from an input trace and 
		 * return a libtrace_event struct containing the event type and 
		 * details of the event */
		event = trace_event(trace, packet);

		/* process_event returns 1(allows resuming packet checking) or
		 *  0(stops polling) */
		poll_again = process_event(ev_hdl, event, packet);		
	}
	
	while (poll_again);	
}

int main(int argc, char *argv[])
{	
	int rc;	
	time_t first_report;
			
	int opt, i;
	libtrace_filter_t *filter = NULL;
	char *filterstring = NULL;
	
	wand_event_handler_t *ev_hdl = NULL;
	bool opt_false = false;
	bool ignore_rfc1918 = false;
	bool track_users = false;	
	
	int port_num = 3678;
	
	/* Size of the FIFO, which defaults to 10MB unless set in the options */
	uint64_t fifo_size = 104857600;
	
	/* The default number of clients that can be connected to the server at a time. 
	* Can be set when starting the server */
	int max_clients = 20; 
	
	/* Initialise libwandevent */
	if (wand_event_init() == -1) {
		fprintf(stderr, "Error initialising libwandevent\n");
		return -1;
	}
	
	/* create an event handler */
	ev_hdl = wand_create_event_handler();
		
	if (ev_hdl == NULL) {
		fprintf(stderr, "Error creating event handler\n");
		return -1;
	}
		
	/* event handler has been correctly created, so add a signal event for SIGINT */
	wand_add_signal(SIGINT, NULL, cleanup_signal);	
	
	if (argc < 2) {
		usage(argv[0]);
		return 1;
	}

	while ((opt = getopt(argc, argv, "f:l:i:r:c:s:p:e:o:v:hTPRUEO")) != EOF) {
		switch (opt) {
			/* Ignore flows that do not match the given BPF filter */
			case 'f':
				filterstring = optarg;
				break;
			/* Determine direction based on <mac> representing the 
			 * 'inside' portion of the network */
			case 'l':
				local_mac = optarg;
				dir_method = DIR_METHOD_MAC;
				break;
			/* Store string that will identify this particular 
			 * measurement process, e.g. source of the packets */
			case 'i':
				local_id = optarg;
				break;
			/* Store the number of seconds that have passed since 
			 * the counters were last reset */
			case 'r':
				report_freq = atoi(optarg);
				break;
			/* The maximum number of clients that can connect to the 
			 * server. 
			 * Defaults to 20 if the option is not set */
			case 'c':
				max_clients = atoi(optarg);				
				break;
			/* Print usage */
			case 'h':
				usage(argv[0]);
				break;	
			/* The size of the FIFO, which defaults to 100MB if 
			 * not set */
			case 's':
				fifo_size = strtoul(optarg, NULL, 10);
				break;
			/* The port on which the server should listen.
			 * Defaults to 3678 */
			case 'p':
				port_num = atoi(optarg);				
				break;
			case 'e':
				expired_interval = atoi(optarg);
				break;	
			case 'o':
				ongoing_max_runtime = atoi(optarg);
				break;
			case 'v':
				iterate_ongoing_flows = atoi(optarg);
				break;	
			/* Use trace direction tags to determine direction */
			case 'T':
				dir_method = DIR_METHOD_TRACE;
				break;
			/* Use port number to determine direction */
			case 'P':
				dir_method = DIR_METHOD_PORT;
				break;
			/* Ignore any flows where an RFC1918 private IP address 
			 * is involved */ 
			case 'R':
				ignore_rfc1918 = true;
				break;
			/* Flag to enable keeping LPI statistics for every 
			 * individual local IP address observed in the data 
			 * source */
			case 'U':
				track_users = true;
				break;
			/* Flag which enables exporting expired flows to clients */
			case 'E':
				export_expired = true;
				break;
			case 'O':
				export_ongoing = true;
				break;
			default:
				usage(argv[0]);
		}
	}
	
	struct sockaddr_in addr;
	int sock, sa_len = sizeof(struct sockaddr_in);
	int sockopt = 1;

	sock = socket(PF_INET, SOCK_STREAM, 0);
	if (sock == -1) {
		perror ("socket");
		return -1;
	}

	if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &sockopt, sizeof(sockopt)) == -1) {
		perror("setsockopt (SO_REUSEADDR)");
		return -1;
	}
	
	addr.sin_family = AF_INET;
	memset(addr.sin_zero, 0, sizeof(addr.sin_zero));
	addr.sin_port = htons(port_num);
	
	/* Bind to all local IPv4 addresses */
	addr.sin_addr.s_addr = INADDR_ANY;
	
	/* Bind the socket to the port */
	if (bind(sock, (struct sockaddr *)&addr, sa_len) == -1) {
		perror("bind");
		return -1;
	}
	
	/* Start listening for inbound connections */
	if (listen(sock, 10) == -1) {
		perror("listen");
		return -1;
	}
	
	/* Add listening fd to libwandevent */
	wand_add_fd(ev_hdl, sock, EV_READ, NULL, accept_connections);
	
	// if -l <mac> was specified in the command line args
	if (local_mac != NULL) {

		if (convert_mac_string(local_mac, mac_bytes) < 0) {
			fprintf(stderr, "Invalid MAC: %s\n", local_mac);
			return 1;
		}
	}
    
	/* This tells libflowmanager to ignore any flows where an RFC1918 
	 * private IP address is involved */
	if (lfm_set_config_option(LFM_CONFIG_IGNORE_RFC1918, 
						&ignore_rfc1918) == 0)
		return -1;

	/* This tells libflowmanager not to replicate the TCP timewait behaviour 
	 * where closed TCP connections are retained in the Flow map for an 
	 * extra 2 minutes */
	if (lfm_set_config_option(LFM_CONFIG_TCP_TIMEWAIT, &opt_false) == 0)
		return -1;

	/* This tells libflowmanager not to utilise the fast expiry rules for 
	 * short-lived UDP connections - these rules are experimental behaviour 
	 * not in line with recommended "best" practice */
	if (lfm_set_config_option(LFM_CONFIG_SHORT_UDP, &opt_false) == 0)
		return -1;

	if (optind + 1 > argc) {
		usage(argv[0]);
		return 1;
	}
	
	if (lpi_init_library() == -1)
		return -1;
		
	init_server(max_clients, ev_hdl, fifo_size);
	
	/* Check if the option for exporting expired flows has been set, but not
	 * the exporting interval.
	 * In that case, set the seconds to the default of 180 */
	if (export_expired && (expired_interval == 0)) {
		expired_interval = 180;
	}
	
	/* Call method which sets up the required buffers and adds the appropriate 
	 * headers */
	lpicp_export_init(local_id, ev_hdl, expired_interval, export_ongoing);
		
	init_live_counters(&counts, track_users);

	rc = pthread_create( &thread1, NULL, messaging_thread, NULL);
	if (rc != 0)
		return -1;
			
	/* Nothing has gone wrong yet, so create packet */
	packet = trace_create_packet();

	if (filterstring) {
		filter = trace_create_filter(filterstring);
	}

	gettimeofday(&start_reporting_period, NULL);
	
	/* Round down to align with a suitable boundary, e.g. if we're
	 * reporting every five minutes, we want our period to start on
	 * a five minute boundary -- 3:05:00 vs 3:06:43
	 */
	first_report = report_freq - (start_reporting_period.tv_sec % report_freq);
	start_reporting_period.tv_sec = start_reporting_period.tv_sec - 
			(start_reporting_period.tv_sec % report_freq);
	start_reporting_period.tv_usec = 0;

	wand_add_timer(ev_hdl, first_report, 0, &start_reporting_period, 
			output_stats);
	
	/* every N seconds, use lfm_foreach_flow to iterate over the flow map
	   and export any flows that have been around for more than X seconds */
	if (export_ongoing) {
		/* Setup the timer to iterate over all flows every N seconds so 
		 * as to find the flows that are ongoing */
		setup_ongoing_flows_timer(ev_hdl);	
	}
		
	for (i = optind; i < argc; i++) {
		/* Create an input trace from a URI provided in arguments and 
		 * return a pointer to a libtrace_t */
		trace = trace_create(argv[i]);

		if (trace_is_err(trace)) {
			/* outputs the error message for an input trace to 
			 * stderr and clear the error status. */
			trace_perror(trace,"Opening trace file");
			return 1;
		}

		if (filter && trace_config(trace, TRACE_OPTION_FILTER, 
								filter) == -1) {
			trace_perror(trace, "trace_config(filter)");
			return 1;
		}

		// Start an input trace and returns 0 on success, -1 on failure
		if (trace_start(trace)) {
			trace_perror(trace,"Starting trace");
			trace_destroy(trace);
			return 1;
		}

		/* as long as this is true, libwandevent will keep running */
		ev_hdl->running = true;
		
		collect_packets(ev_hdl, trace, packet);
		
		/* Once we hit a wait event, fire up the event handler. We
		 * won't fall out of this function call until we reach the
		 * end of the trace or something goes awry with reading
		 * the trace */
		wand_event_run(ev_hdl);

		/* if there's an error after the event handler has started */
		if (trace_is_err(trace)) {
			trace_perror(trace,"Reading packets");
			trace_destroy(trace);
			return 1;
		}
		
		if (done)
			break;
		
		/* Close an input trace, freeing up any resources it may have 
		 * been using */
		trace_destroy(trace);
	}

	/* cleaning up resources and final exporting of flows */
	if (filter)
		trace_destroy_filter(filter);

	trace_destroy_packet(packet);
	expire_live_flows(0, true);
	
	/* Just freeing up memory to help with memory-leak testing */
	reset_counters(&counts, true);
	
	wand_destroy_event_handler(ev_hdl);
	lpi_free_library();
	close(sock);
	
	//pthread_exit(NULL);
	
	return 0;
}
