/*
 * This file is part of lpicollector
 *
 * Copyright (c) 2013 The University of Waikato, Hamilton, New Zealand.
 * Author: Meenakshee Mungro
 *         Shane Alcock
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


#ifndef LIVE_COMMON_H_
#define LIVE_COMMON_H_

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

#include <libprotoident.h>
#include <libwandevent.h>
#include <libflowmanager.h>

using namespace std;

typedef struct ip_collector {
	uint64_t currently_active_flows[LPI_PROTO_LAST];
	uint64_t total_observed_period[LPI_PROTO_LAST];
} IPCollector;

struct ltstr {
	bool operator()(const char *s1, const char *s2) const {
		return strcmp(s1, s2) < 0;
	}
};

typedef map<const char*, IPCollector *, ltstr> IPMap;

/* This structure contains all the current values for all the statistics we
 * want our collector to be able to track on a per-user basis. There is an 
 * entry in each array for each supported LPI protocol */
typedef struct user_counts {
	
	/* Incoming packets */
        uint64_t in_pkt_count[LPI_PROTO_LAST];
	/* Outgoing packets */
        uint64_t out_pkt_count[LPI_PROTO_LAST];
	/* Incoming bytes (based on wire length) */
        uint64_t in_byte_count[LPI_PROTO_LAST];
	/* Outgoing bytes (based on wire length) */
        uint64_t out_byte_count[LPI_PROTO_LAST];
	/* New flows originating from outside the local network */
        uint64_t in_flow_count[LPI_PROTO_LAST];
	/* New flows originating from inside the local network */
        uint64_t out_flow_count[LPI_PROTO_LAST];

	/* Currently active flows that originated from outside */
        uint64_t in_current_flows[LPI_PROTO_LAST];
	/* Currently active flows that originated from inside */
        uint64_t out_current_flows[LPI_PROTO_LAST];
	/* Peak values for in_current_flows since the last report */
        uint64_t in_peak_flows[LPI_PROTO_LAST];
	/* Peak values for out_current_flows since the last report */
        uint64_t out_peak_flows[LPI_PROTO_LAST];
	
	/* Number of remote IPs that are talking to us */
	uint64_t remote_ips[LPI_PROTO_LAST];
} UserCounters;

typedef map <char *, UserCounters *, ltstr> UserMap;

typedef struct counters {

	/* The number of times that the counters have been reset, which
	 * should correspond with the number of times we have reported
	 * statistics (hence the name 'reports' rather than 'resets')
	 */
	uint32_t reports;
	uint32_t user_count;
		
	UserCounters all;
	UserMap users;
       
       	/* These aren't useful to track on a per user basis */ 
	IPMap active_local;
	IPMap observed_local;

	uint64_t all_local_ips[LPI_PROTO_LAST];
	uint64_t active_local_ips[LPI_PROTO_LAST];

	bool user_tracking;

} LiveCounters;

/* Structure containing all the data we want to store for each flow */
typedef struct live {
	/* The direction of the first packet for the flow */
        uint8_t init_dir;
        
	/* The local IP, stored as a string */
        char local_ip[INET6_ADDRSTRLEN];
	/* The remote IP, stored as a string */
        char ext_ip[INET6_ADDRSTRLEN]; 

	/** Statistics about this flow
	 * NOTE: byte and packet counts are not for the flow as a whole, but
	 * instead refer to what has been seen during the current reporting
	 * period, i.e. since the last time reset_counters() was called.
	 */
	/* Incoming packets observed for the flow */
        uint64_t in_pkts;
	/* Outgoing packets observed for the flow */
        uint64_t out_pkts;
	/* Incoming bytes (wire length) observed for the flow */
        uint64_t in_wbytes;
	/* Incoming bytes (payload length) observed for the flow */
        uint64_t in_pbytes;
	/* Outgoing bytes (wire length) observed for the flow */
        uint64_t out_wbytes;
	/* Outgoing bytes (payload length) observed for the flow */
        uint64_t out_pbytes;
        
	/* Timestamp when this flow was first observed */
	double start_ts;
	double last_ts;

	/* The reporting period when this flow was first observed */
        uint32_t start_period;
	/* The reporting period when this flow was last observed */
        uint32_t count_period;

	/* LPI data structure - needed for classification */
        lpi_data_t lpi;
	/* The protocol that this flow matches */
        lpi_module_t *proto;

	bool activated_ip;
} LiveFlow;


/* Allocates and initialises a new LiveFlow structure and attaches it to the
 * provided Flow structure. 
 * 
 * When you're done with the flow, make sure to call destroy_live_flow!
 */
void init_live_flow(LiveCounters *cnt, Flow *f, uint8_t dir, double ts, 
		bool validuser);

/* Initialises a LiveCounters structure. Does not allocate memory - you should
 * pass in a pointer to an existing instance of LiveCounters.
 *
 * This will reset ALL the counter values and the report count to zero.
 */
void init_live_counters(LiveCounters *cnt, bool track_users);

/* Resets the counters - if not doing cumulative stats, this should be called
 * after outputting the counters. 
 *
 * If wipe_all is true, then the currently active flow counts will be set to
 * zero (probably not what you want).
 * If wipe_all is false, the currently active flow counts will be retained and
 * the peak active flow counts will be set to the currently active flow count.
 *
 * Calling this function will also increment the reports value in the 
 * LiveCounters structure.
 */
void reset_counters(LiveCounters *cnt, bool wipe_all);

/* Dumps the values of all the counters to standard output
 * ts should be set to the timestamp when the counters were last reset
 * local_id is a string that will identify this particular measurement process,
 * 	e.g. the source of the packets
 * report_freq is the number of seconds that have passed since the counters
 * 	were last reset (this will be included in the output so users can do
 *	rate calculations).
 *
 * Counters are not reset after dumping - you need to call reset_counters()
 * to do that.
 */
void dump_counters_stdout(LiveCounters *cnt, double ts, char *local_id, 
                uint32_t report_freq);

/* Updates the counters based on the most recent packet for a given flow.
 * If the classification for the flow has changed, the counters for the old
 * protocol are decreased appropriately and the flow stats are reattributed
 * to the new protocol.
 *
 * Workflow is important with this function - it should be called AFTER calling
 * both update_liveflow_stats() AND lpi_update_data(). See lpi_live.cc for a
 * working example.
 *
 * wlen is the wire length for the most recent packet.
 * plen is the payload length for the most recent packet.
 * dir is the direction of the most recent packet.
 *
 * Returns -1 if an error occurs, 0 if successful.
 */
int update_protocol_counters(LiveFlow *live, LiveCounters *cnt, uint32_t wlen, 
		uint32_t plen, uint8_t dir);

/* Cleans up a LiveFlow structure that had been created using init_live_flow().
 * Also decrements the appropriate current flow counter, so you can call this
 * when a flow expires and ensure the counter is correct. */
void destroy_live_flow(LiveFlow *live, LiveCounters *cnt);

/* Updates the statistics stored in the LiveFlow structure, based on the
 * provided packet. 
 *
 * First, it checks if the counters have been reset since the last time the 
 * flow was updated. If so, the stats are reset to zero (the stats only refer
 * to the current reporting period).
 *
 * After that, the byte and packet counts are incremented accordingly.
 */
void update_liveflow_stats(LiveFlow *live, libtrace_packet_t *packet,
                LiveCounters *cnt, uint8_t dir);
                

int convert_mac_string(char *string, uint8_t *bytes);
int mac_get_direction(libtrace_packet_t *packet, uint8_t *mac_bytes);
int port_get_direction(libtrace_packet_t *packet);


#endif
