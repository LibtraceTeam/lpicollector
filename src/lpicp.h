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

#ifndef LPICP_H
#define LPICP_H

#include <sys/param.h>
#include <stdint.h>
#include <arpa/inet.h>

enum lpicp_record {
        LPICP_STATS,
        LPICP_ONGOING,
        LPICP_EXPIRED,
	LPICP_PUSH,
	LPICP_PROTOCOLS
};

enum lpicp_metric {
	LPICP_METRIC_PKTS,
	LPICP_METRIC_BYTES,	
	LPICP_METRIC_NEW_FLOWS,
	LPICP_METRIC_CURR_FLOWS,
	LPICP_METRIC_PEAK_FLOWS,
	LPICP_METRIC_ACTIVE_IPS,
	LPICP_METRIC_OBSERVED_IPS
};

/* Structure which defines a custom header used at the start of a packet which 
 * contains flow records that are to be exported over a network.
 * It contains the information that is common for all the flows. */
typedef struct __attribute__((packed)) lpicp_header {
	
	uint8_t version;
	uint8_t record_type;
	uint16_t total_len;
	uint16_t name_len;
	uint16_t reserved;

} lpicp_header_t ;

/* Structure which defines a stat header used for LPICP_STATS records */
typedef struct __attribute__((packed)) lpicp_stat_header {
	uint32_t secs;
	uint32_t usecs;
	uint32_t freq;
	uint8_t dir;
	uint8_t metric;
	uint16_t num_records;	
	uint16_t user_len;
	uint16_t reserved;	
} lpicp_stat_header_t;

/* Structure which defines the subheader for a LPICP_PROTOCOLS record */
typedef struct __attribute__((packed)) lpicp_proto_subheader {
	uint32_t proto_count;
} lpicp_proto_subheader_t;

/* Structure which defines the header for a protocol record used in 
 * LPICP_PROTOCOLS records */
typedef struct __attribute__((packed)) lpicp_proto_record {
	uint32_t proto_id;
	uint16_t proto_len;		
} lpicp_proto_record_t;

typedef struct __attribute__((packed)) lpicp_flow_subheader {
	uint32_t num_flows;
} lpicp_flow_subheader_t;

/* Structure used for exporting expired flow records that use IPv4 addresses */
typedef struct __attribute__((packed)) lpicp_flow_record_v4 {
	uint8_t version;//a0
	uint8_t transport_protocol;//a1
	uint16_t reserved;//a2
	uint32_t ip_server;
	uint32_t ip_client;	
	uint16_t port_server;//b0
	uint16_t port_client;//b1
	uint32_t start_secs;//b2
	uint32_t start_usecs;//b3
	uint32_t end_secs;//b4
	uint32_t end_usecs;//b5
	uint32_t lpi_payload_len[2];//b6,7
	uint64_t payload_bytes[2];//b8,9
	uint32_t first4b_payload[2];//b10,b11
	uint32_t protocol_id;//b12
} lpicp_flow_record_v4_t;

/* Structure used for exporting expired flow records that use IPv6 addresses */
typedef struct __attribute__((packed)) lpicp_flow_record_v6 {
	uint8_t version;//a0
	uint8_t transport_protocol;//a1
	uint16_t reserved;//a2
	struct in6_addr ip_client;
	struct in6_addr ip_server;
	uint16_t port_server;//b0
	uint16_t port_client;//b1
	uint32_t start_secs;//b2
	uint32_t start_usecs;//b3
	uint32_t end_secs;//b4
	uint32_t end_usecs;//b5
	uint32_t lpi_payload_len[2];//b6,7
	uint64_t payload_bytes[2];//b8,9
	uint32_t first4b_payload[2];//b10,b11
	uint32_t protocol_id;//b12
} lpicp_flow_record_v6_t;

#define byteswap32(num)	\
	(((num & 0x000000FFU) << 24) | ((num & 0x0000FF00U) << 8) | \
	((num & 0x00FF0000U) >> 8) | ((num&0xFF000000U)>>24))

#define byteswap64(num) \
	(byteswap32(num >> 32) | \
	((uint64_t)byteswap32(num) << 32))

#ifndef __BYTE_ORDER
#warning "Byte order is not defined"
#endif

#if __BYTE_ORDER == __LITTLE_ENDIAN
#	define ntoh64(x)	byteswap64(x)
#else	
#	define ntoh64(x)	(x)
#endif
#define hton64(x)	ntoh64(x)

#endif
