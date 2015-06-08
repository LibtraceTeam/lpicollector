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


#define __STDC_FORMAT_MACROS

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>
#include <assert.h>

#include <libfifo.h>
#include <libwandevent.h>


#include "lpicp.h"
#include "live_common.h" 
#include "server.h"

/* Struct that stores details about a protocol - the name, name length and 
 * whether it is disabled */
typedef struct proto_name {
	const char *name;
	size_t len;
	bool disabled;
} ProtoName;

ProtoName lpi_names[LPI_PROTO_LAST];
bool names_set = false;

wand_event_handler_t *event_hdl = NULL;
struct wand_timer_t *output_expired_timer;

char *monitor_id;

int expire_interval = 0;

/* Buffer used to store the statistics to be exported to the clients */
Lpi_collect_buffer_t stats_buffer;
/* Buffer used to store the protocol names to be sent to each client when they 
 * connect to the server */
Lpi_collect_buffer_t proto_buffer;
/* Buffer used to store information about expired flow records */
Lpi_collect_buffer_t expired_buffer;
/* Buffer used to store information about ongoing flow records */
Lpi_collect_buffer_t ongoing_buffer;
/* Pointer to a buffer which needs to be written to/read from */
Lpi_collect_buffer_t *buffer_to_use;

/* Function prototype */
static void lpicp_setup_expired_buffer(char *local_id);

/* This may seem counter-intuitive at first (why keep our own copy of these
 * strings?) but it turns out that calling lpi_print is not exactly a free
 * operation - it is a map lookup after all. The name string for a protocol
 * is not going to change, so let's just grab it once when we start and 
 * remember it.
 * 
 * *buffer is a pointer to the buffer to which the protocol details will be 
 * 	added.
 * *proto_subhdr is a pointer to the protocol subheader that has been added to
 * 	the buffer before the execution of this function.
 */
static void init_lpi_names(Lpi_collect_buffer_t *buffer, lpicp_proto_subheader_t *proto_subhdr) 
{
	/* counter used to keep track of active protocols, since stats for inactive
	 * protocols are not exported */
	int counter = 0;
	
	for (uint32_t i = 0; i < LPI_PROTO_LAST; i++) {
		/* Getting the protocol data for each protocol in Libprotoident's 
		 * list */
		lpi_names[i].name = lpi_print((lpi_protocol_t)i);
		lpi_names[i].len = strlen(lpi_names[i].name);
		lpi_names[i].disabled = lpi_is_protocol_inactive((lpi_protocol_t)i);
		
		/* If the protocol is not disabled, add to protocol list */
		if (!lpi_names[i].disabled) {
			counter++;
			
			/* Casting the buffer struct as a lpicp_proto_record_t */
			lpicp_proto_record_t *proto_rec = (lpicp_proto_record_t *)
					&(buffer->buf[buffer->buf_used]);
	
			/* Initialising the structure variables to the correct 
			 * values */	
			proto_rec->proto_len = ntohs(lpi_names[i].len);
			proto_rec->proto_id = ntohl(i);
		
			/* Incrementing the value of buf_used with the size of 
			 * lpicp_proto_record_t */
			buffer->buf_used +=sizeof(lpicp_proto_record_t);
		
			/* Writing the name of the protocol in the buffer at 
			 * index buf_used */
			memcpy(&buffer->buf[buffer->buf_used], 
						lpi_names[i].name, lpi_names[i].len);
			/* Increment buf_used with the length of the protocol 
			 * name */
			buffer->buf_used += lpi_names[i].len;		
		}				
	}
	
	/* Set the count of the number of active protocols sent in the list */
	proto_subhdr->proto_count = ntohl(counter);
	
	/* Set the length field in the header */
	lpicp_header_t *tmp_hdr = (lpicp_header_t *)buffer->buf; 
	tmp_hdr->total_len = ntohs(buffer->buf_used);	
	
	names_set = true;
	set_proto_buffer(buffer);
}



/* Creates a header for the custom buffer which will contain flow records.
 * This header contains the information that is common for all flows.
 * 
 * local_id is a string that will identify this particular measurement process,
 *      e.g. the source of the packets.
 * rec_type is the record type that is being sent
 * 	e.g LPICP_STATS, LPICP_PROTOCOLS, etc.
 * *buffer is a pointer to the buffer which needs to be updated with the header.
 */
static void lpicp_create_header (char *local_id, enum lpicp_record rec_type, 
						Lpi_collect_buffer_t *buffer )
{ 
	lpicp_header_t *tmp_hdr;
	char tmp[101];
	size_t local_len = strlen(local_id);

	/* Casting the buffer struct as a Lpicp_header_t and filling in the 
	 * available values*/
	tmp_hdr = (lpicp_header_t *)&(buffer->buf[buffer->buf_used]);
	tmp_hdr->version = 1;
	tmp_hdr->record_type = rec_type;
	
	/* Restricting local_id to 100 characters */
	if (local_len > 100) {
		strncpy(tmp, local_id, 100);
		local_id = tmp;		
		local_len = 100;
	}
	
	tmp_hdr->name_len = ntohs((uint16_t) local_len);
	tmp_hdr->reserved = 0;
	
	/* Incrementing buf_used with the size of the struct Lpicp_header_t */ 
	buffer->buf_used = sizeof(tmp_hdr);

	/* Copy the local_id into the buffer and increment buffer.buf_used */
	memcpy(&buffer->buf[buffer->buf_used], local_id, local_len);
	buffer->buf_used += local_len;	
}

/* Method which adds the subheader for a protocol record.
 * The subheader only contains a count of the supported(active) protocols. 
 * 
 * *buffer is a pointer to the buffer which needs to be updated with the header
 * 
 * Returns a pointer to the lpicp_proto_subheader_t which needs to be updated
 * 	after calling the init_lpi_names function.
 * */
static lpicp_proto_subheader_t* lpicp_add_proto_subheader(Lpi_collect_buffer_t *buffer)
{
	/* Casting the buffer struct as a lpicp_proto_subheader_t */
	lpicp_proto_subheader_t *proto_subhdr = 
		(lpicp_proto_subheader_t *)&(buffer->buf[buffer->buf_used]);
	
	/* Incrementing the value of buf_used with the size of lpicp_proto_subheader_t */
	buffer->buf_used +=sizeof(lpicp_proto_subheader_t);
	
	return proto_subhdr;
}

/* Function which calls the appropriate functions to add the protocol data to the 
 * buffer.
 * 
 * local_id is a string that will identify this particular measurement process,
 *      e.g. the source of the packets.
 */
static void lpicp_setup_protocol_records(char *local_id)
{
	/* Add the header first to the buffer */
	lpicp_create_header(local_id, LPICP_PROTOCOLS, &proto_buffer);
	
	/* Call method to add the subheader which contains the active protocol 
	 * count */
	lpicp_proto_subheader_t *proto_subhdr = lpicp_add_proto_subheader(&proto_buffer);
	
	if (names_set == false) {
		init_lpi_names(&proto_buffer, proto_subhdr);
	}	
}



/* Adds the subheader for a statistics record to the buffer after the header 
 * and local_id have been added.
 * 
 * tv is the timestamp when the counters were last reset.
 * report_len  is the number of seconds that have passed since the counters
 *      were last reset (this will be included in the output so users can do
 *      rate calculations).
 * dir is the direction of the most recent packet.
 * metric is the identifier for the type of measurement that will be included
 *	in this record, e.g. packets, bytes, active_ips
 * user_id is the string identifying the user that the statistics will be 
 * 	reported for (should be "all" for stats that encompass all users).
 */
static void lpicp_add_stat_header (struct timeval tv, uint32_t report_len, 
		uint8_t dir, uint8_t metric, const char *user_id)
{
	char tmp[256];
	size_t user_len = strlen(user_id);
	
	/* Restricting user_id to 255 characters */
	if (user_len > 255) {
		strncpy(tmp, user_id, 255);
		tmp[255] = '\0';
		user_id = tmp;		
		user_len = 255;
	}	
	/* Casting the buffer struct as a Lpicp_stat_header_t and filling in 
	 * the available values */
	lpicp_stat_header_t *tmp_stat_hdr = 
			(lpicp_stat_header_t *)&(stats_buffer.buf[stats_buffer.buf_used]);
	
	tmp_stat_hdr->secs = ntohl(tv.tv_sec);
	tmp_stat_hdr->usecs = ntohl(tv.tv_usec);
	tmp_stat_hdr->freq = ntohl(report_len);
	tmp_stat_hdr->dir = dir; 
	tmp_stat_hdr->metric = metric;
	tmp_stat_hdr->num_records = 0;
	tmp_stat_hdr->user_len = ntohs((uint16_t)user_len);
	tmp_stat_hdr->reserved = 0;
		
	/* Incrementing buf_used with the size of the struct 
	 * Lpicp_stat_header_t */
	stats_buffer.buf_used += sizeof(lpicp_stat_header_t);

	memcpy(&stats_buffer.buf[stats_buffer.buf_used], user_id, user_len);
	stats_buffer.buf_used += user_len;	
}

/* Appends the protocol details(protocol name length, name and value) from the 
 * array in the arguments to the buffer which is to be exported.
 * 
 * index is the index of the protocol which is used to retrieve the protocol 
 *	length, name and value from the array.
 * array is the array of counters that needs to be exported, e.g. 
 *	in_pkt_count[].
 * 
 * Returns 0 if the entry for a protocol would overflow the buffer, or else 1.
 */
static int lpicp_push_proto_values(int index, uint64_t* array)
{

	/* Check that the total size of the bytes to be added for a particular 
	 * protocol(protocol id, value) won't exceed the total number of bytes 
	 * in buffer.buf */
	if ((sizeof(index) + sizeof(uint64_t) ) > 
			(sizeof(stats_buffer.buf) - stats_buffer.buf_used)) {					
		return 0;
	} else {
		/* Adding the protocol ID */
		uint32_t id = (uint32_t)index;
		
		uint32_t *proto_id = (uint32_t *)&(stats_buffer.buf[stats_buffer.buf_used]);
		*proto_id = ntohl(id);
		stats_buffer.buf_used += sizeof(uint32_t);	
				
		/* Adding the value */
		uint64_t *value = (uint64_t *)&(stats_buffer.buf[stats_buffer.buf_used]);
		*value = hton64(array[index]);
		stats_buffer.buf_used += sizeof(uint64_t);
		
		return 1;		
	}	
}

static int lpicp_export_push(char *local_id) 
{
	lpicp_header_t *hdr;

	stats_buffer.buf_used = 0;
	stats_buffer.buf_exported = 0;

	hdr = (lpicp_header_t *)stats_buffer.buf;
	lpicp_create_header(local_id, LPICP_PUSH, &stats_buffer);

	hdr->total_len = ntohs(stats_buffer.buf_used);
	
	/* Method which will write the buffer to the FIFO */
	if (push_buffer_fifo(&stats_buffer) == -1) {
			return -1;
	}
	return 0;
}


/* Exports a single counter over the network by adding data(protocol length, 
 * name, and value) to the buffer for each of the protocols supported by 
 * Libprotoident.
 * 
 * array is the array of counters that needs to be exported, e.g. 
 * 	in_pkt_count[].
 * tv is the timestamp when the counters were last reset.
 * dir is the direction of the most recent packet.
 * metric is the identifier for the metric that this counter belongs to
 * local_id is a string that will identify this particular measurement process,
 *      e.g. the source of the packets
 * user_id is a string identifying the individual user that this counter 
 *	represents ("all" should be used for counters that cover the entire
 * 	user base)
 * report_len  is the number of seconds that have passed since the counters
 *      were last reset (this will be included in the output so users can do
 *      rate calculations). 
 */
static int lpicp_export_single_counter (uint64_t* array, struct timeval tv, 
		uint8_t dir, uint8_t metric, char* local_id, 
		const char *user_id, uint32_t report_len)
{
	uint32_t current_proto_id = 0;
	lpicp_header_t *tmp_hdr;
	lpicp_stat_header_t *tmp_stat_hdr;
	
	while (current_proto_id != LPI_PROTO_LAST ) {
		int num_rec = 0;
		
		/* Resetting the buffer */
		stats_buffer.buf_used = 0;	
		stats_buffer.buf_exported = 0;

		tmp_hdr = (lpicp_header_t *)stats_buffer.buf; 
		/* Resetting the number of records exported in this packet */
		/* Set the number of exported records */
		
		/* Adding the header, local_id and subheader to the buffer */
		lpicp_create_header(local_id, LPICP_STATS, &stats_buffer);
		lpicp_add_stat_header(tv, report_len, dir, metric, user_id);
		
		for (current_proto_id; current_proto_id < LPI_PROTO_LAST; 
				current_proto_id++) {		
			
			int ret;
			
			if (lpi_names[current_proto_id].disabled) {
				continue;
			}	
			
			if (array[current_proto_id] == 0)
				continue;
					
			ret = lpicp_push_proto_values(current_proto_id, array);		
						
			if (ret == 0) 
				break;	
			else
				num_rec++;
		}
		
		/* Set the total length of the packet */
		tmp_hdr->total_len = ntohs(stats_buffer.buf_used);
		
		/* Set the number of records exported in this flow */
		tmp_stat_hdr = (lpicp_stat_header_t *)
				(stats_buffer.buf + sizeof(tmp_hdr) + strlen(local_id));
		tmp_stat_hdr->num_records = ntohs(num_rec);		
	
		/* Method which will write the buffer to the FIFO */
		if (push_buffer_fifo(&stats_buffer) == -1) {
			return -1;
		}
	}	
	return lpicp_export_push(local_id);
}

static void lpicp_export_user_counter(UserCounters *cnt, struct timeval tv,
		char *local_id, const char *user_id, uint32_t report_len) {
	/* Exporting incoming packet counts */
	lpicp_export_single_counter( cnt->in_pkt_count, tv, 1, LPICP_METRIC_PKTS, 
				local_id, user_id, report_len);	
				
	/* Outgoing packets */
	lpicp_export_single_counter( cnt->out_pkt_count, tv, 0, 
				LPICP_METRIC_PKTS, local_id, user_id, 
				report_len);	
				
	/* Incoming bytes (based on wire length) */
	lpicp_export_single_counter( cnt->in_byte_count, tv, 1, 
				LPICP_METRIC_BYTES, local_id, user_id, 
				report_len);	
          
	/* Outgoing bytes (based on wire length) */
	lpicp_export_single_counter( cnt->out_byte_count, tv, 0, 
				LPICP_METRIC_BYTES, local_id, user_id,
				report_len);
	
	/* New flows originating from outside the local network */
        lpicp_export_single_counter( cnt->in_flow_count, tv, 1, 
				LPICP_METRIC_NEW_FLOWS, local_id, user_id,
				report_len);
                
	/* New flows originating from inside the local network */
	lpicp_export_single_counter( cnt->out_flow_count, tv, 0, 
				LPICP_METRIC_NEW_FLOWS, local_id, user_id,
				report_len);
				
	/* Peak values for in_current_flows since the last report */
	lpicp_export_single_counter( cnt->in_peak_flows, tv, 1, 
				LPICP_METRIC_PEAK_FLOWS, local_id, user_id,
				report_len);
        
	/* Peak values for out_current_flows since the last report */
	lpicp_export_single_counter( cnt->out_peak_flows, tv, 0, 
				LPICP_METRIC_PEAK_FLOWS, local_id, user_id,
				report_len);	

}

static void lpicp_add_flow_subheader(Lpi_collect_buffer_t *buffer)
{
	/* Casting the buffer struct as a lpicp_expired_subheader_t */
	lpicp_flow_subheader_t *flow_subhdr = 
		(lpicp_flow_subheader_t *)&(buffer->buf[buffer->buf_used]);
		
	flow_subhdr->num_flows = 0;
	buffer->subheader = flow_subhdr;
	
	/* Incrementing the value of buf_used with the size of lpicp_proto_subheader_t */
	buffer->buf_used += sizeof(lpicp_flow_subheader_t);	
}

static void lpicp_export_expired_buffer_cb(wand_event_handler_t *ev_hdl,
		void *data)
{
	lpicp_header_t *hdr = (lpicp_header_t *)expired_buffer.buf;
	hdr->total_len = ntohs(expired_buffer.buf_used);
	
	/* Export buffer to FIFO */
	push_buffer_fifo(&expired_buffer);
	
	lpicp_setup_expired_buffer(monitor_id);	
}

static void lpicp_setup_expired_buffer(char *local_id)
{
	/* Reset buffer */
	expired_buffer.buf_used = 0;	
			
	/* Add the header to the buffer */
	lpicp_create_header(local_id, LPICP_EXPIRED, &expired_buffer);
	
	/* Add the subheader to the buffer */
	lpicp_add_flow_subheader(&expired_buffer);	
	
	/* Once the buffer has been reset and the appropriate headers added, 
	 * start a timer which will fire every 5mins and export the expired flow 
	 * records to connected clients */
	output_expired_timer = wand_add_timer(event_hdl, expire_interval, 0,
			NULL, lpicp_export_expired_buffer_cb);
}

/* */
static void lpicp_setup_ongoing_buffer(char *local_id)
{
	/* Reset buffer */
	ongoing_buffer.buf_used = 0;	
			
	/* Add the header to the buffer */
	lpicp_create_header(local_id, LPICP_ONGOING, &ongoing_buffer);
	
	/* Add the subheader to the buffer */
	lpicp_add_flow_subheader(&ongoing_buffer);	
}


void lpicp_export_init(char* local_id, wand_event_handler_t *hdl, int exp_interval,
				bool export_ongoing)
{
	monitor_id = local_id;
	
	event_hdl = hdl;
	
	lpicp_setup_protocol_records(local_id);	
	
	if (exp_interval != 0) {
		expire_interval = exp_interval;
		lpicp_setup_expired_buffer(local_id);
	}
	
	if (export_ongoing) {
		lpicp_setup_ongoing_buffer(local_id);
	}
}

static int lpicp_finalize_buffer(char *local_id, enum lpicp_record rec_type,
						Lpi_collect_buffer_t *buffer_to_use)
{
	/* Set the total length field */
	lpicp_header_t *hdr = (lpicp_header_t *)buffer_to_use->buf;
	hdr->total_len = ntohs(buffer_to_use->buf_used);
				
	/* Push flow buffer to the FIFO  */
	if (push_buffer_fifo(buffer_to_use) == -1) {
		return -1;
	}
			
	/* Reset the appropriate buffers */
	if (rec_type == LPICP_ONGOING) {
		/* Reset the ongoing buffer and add the header 
		 * and subheader*/	
		lpicp_setup_ongoing_buffer(local_id);	
	}
	else {
		/* Delete existing timer */
		wand_del_timer(event_hdl, output_expired_timer);
				
		/* Reset the expired buffer and add the header 
		 * and subheader*/	
		lpicp_setup_expired_buffer(local_id);		
	}
	
	return 0;	
}

int lpicp_export_flow(char *local_id, Flow *flow, LiveFlow *live, enum lpicp_record rec_type)
{
	if (rec_type == LPICP_ONGOING) {
		buffer_to_use = &ongoing_buffer;
	}
	else {
		buffer_to_use = &expired_buffer;		
	}
	
	/* Flow is using an IPv4 address */
	if (flow->id.get_ip_version() == 4) {
		/* Check if the buffer has enough space to add the new record */
		if ((sizeof(lpicp_flow_record_v4_t) + buffer_to_use->buf_used)
			> sizeof(buffer_to_use->buf)) {
				
			lpicp_finalize_buffer(local_id, rec_type, buffer_to_use);				
		}
		
		/* Add flow records to buffer.
		/* Cast the buffer to a lpicp_flow_record_v4_t struct and
		* initialise the values */
		lpicp_flow_record_v4_t *flow_v4 = (lpicp_flow_record_v4_t*)
					&(buffer_to_use->buf[buffer_to_use->buf_used]);
		flow_v4->version = 4;
		flow_v4->transport_protocol = flow->id.get_protocol();
		flow_v4->reserved = 0;
		flow_v4->ip_server = flow->id.get_server_ip();
		flow_v4->ip_client = flow->id.get_client_ip();		
		flow_v4->port_server = ntohs(flow->id.get_server_port());
		flow_v4->port_client = ntohs(flow->id.get_client_port());
		
		/* Calculating the start and end seconds and microseconds */
		uint32_t start_s = (uint32_t)live->start_ts;
		flow_v4->start_secs = ntohl(start_s);
		flow_v4->start_usecs = ntohl((uint32_t)
					(((live->start_ts - start_s) 
							* 1000000)));
		uint32_t end_s = (uint32_t)live->last_ts;					
		flow_v4->end_secs = ntohl(end_s);
		flow_v4->end_usecs = ntohl((uint32_t)
					(((live->last_ts - end_s) 
							* 1000000)));
		
		/* Size of first payload-bearing packet in each direction */	
		flow_v4->lpi_payload_len[0] = ntohl(live->lpi.payload_len[0]);	
		flow_v4->lpi_payload_len[1] = ntohl(live->lpi.payload_len[1]);	
				
		flow_v4->payload_bytes[0] = byteswap64(live->out_pbytes);
		flow_v4->payload_bytes[1] = byteswap64(live->in_pbytes);
		flow_v4->first4b_payload[0] = live->lpi.payload[0];
		flow_v4->first4b_payload[1]= live->lpi.payload[1];		
		
		/* Getting the protocol ID from the LiveFlow */ 
		lpi_module_t *mod = lpi_guess_protocol(&live->lpi);		
		flow_v4->protocol_id = ntohl(mod->protocol);
			
		/* Update the buf_used field of the buffer */
		buffer_to_use->buf_used += sizeof(lpicp_flow_record_v4_t);				
	}
	/* Flow is using an IPv6 address */
	else {
		/* Check if the buffer has enough space to add the new record */
		if ((sizeof(lpicp_flow_record_v6_t) + buffer_to_use->buf_used)
			> sizeof(buffer_to_use->buf)) {
				
			lpicp_finalize_buffer(local_id, rec_type, buffer_to_use);			
		}
		
		/* Add flow records to buffer.
		/* Cast the buffer to a lpicp_flow_record_v6_t struct and
		* initialise the values */
		lpicp_flow_record_v6_t *flow_v6 = (lpicp_flow_record_v6_t*)
					&(buffer_to_use->buf[buffer_to_use->buf_used]);
					
		flow_v6->version = 6;
		flow_v6->transport_protocol = flow->id.get_protocol();
		flow_v6->reserved = 0;
		
		uint8_t* ip_server_array = flow->id.get_server_ip6();
		memcpy(&flow_v6->ip_server, ip_server_array, sizeof(flow_v6->ip_server));
		
		uint8_t* ip_client_array = flow->id.get_client_ip6();
		memcpy(&flow_v6->ip_client, ip_client_array, sizeof(flow_v6->ip_client));
						
		flow_v6->port_server = flow->id.get_server_port();
		flow_v6->port_client = flow->id.get_client_port();
		
		/* Calculating the start and end seconds and microseconds */
		uint32_t start_s = (uint32_t)live->start_ts;
		flow_v6->start_secs = ntohl(start_s);
		flow_v6->start_usecs = ntohl((uint32_t)
					(((live->start_ts - start_s) 
							* 1000000)));
		uint32_t end_s = (uint32_t)live->last_ts;					
		flow_v6->end_secs = ntohl(end_s);
		flow_v6->end_usecs = ntohl((uint32_t)
					(((live->last_ts - end_s) 
							* 1000000)));
							
		/* Size of first payload-bearing packet in each direction */	
		flow_v6->lpi_payload_len[0] = ntohl(live->lpi.payload_len[0]);	
		flow_v6->lpi_payload_len[1] = ntohl(live->lpi.payload_len[1]);	
							
		flow_v6->payload_bytes[0] = live->out_pbytes;
		flow_v6->payload_bytes[1] = live->in_pbytes;
		flow_v6->first4b_payload[0] = live->lpi.payload[0];
		flow_v6->first4b_payload[1]= live->lpi.payload[1];
		
		/* Getting the protocol ID from the LiveFlow */ 
		lpi_module_t *mod = lpi_guess_protocol(&live->lpi);		
		flow_v6->protocol_id = ntohl(mod->protocol);
		
		/* Update the buf_used field of the buffer */
		buffer_to_use->buf_used += sizeof(lpicp_flow_record_v6_t);
	}
	
	/* Increment the subheader->num_expired_flows since a v4/v6 flow
	 * record was added to the buffer */
	lpicp_flow_subheader_t *flow_subhdr = 
		(lpicp_flow_subheader_t *)(buffer_to_use->subheader);
	uint32_t count_flows = ntohl(flow_subhdr->num_flows);
	count_flows++;
	flow_subhdr->num_flows = htonl(count_flows);
	
	return 0;
}



int lpicp_export_ongoing_flows(char *local_id)
{
	lpicp_finalize_buffer(local_id, LPICP_ONGOING, &ongoing_buffer);
}

void lpicp_export_counters(LiveCounters *count, struct timeval tv, char *local_id, 
							uint32_t report_len) 
{
	if (!names_set) {
		fprintf(stderr, "lpi_export counters called without lpi_export_init being called!\n");
		return;
	}
	
	UserMap::iterator it;

	lpicp_export_user_counter(&count->all, tv, local_id, "all", 
					report_len);

	for (it = count->users.begin(); it != count->users.end(); it++)	{
		lpicp_export_user_counter(it->second, tv, local_id, 
						it->first, report_len);
	}

	lpicp_export_single_counter( count->all_local_ips, tv, 1, 
				LPICP_METRIC_OBSERVED_IPS, local_id, "all",
				report_len);
	lpicp_export_single_counter( count->active_local_ips, tv, 1,
				LPICP_METRIC_ACTIVE_IPS, local_id, "all",
				report_len);

}




