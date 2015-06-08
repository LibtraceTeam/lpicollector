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

#ifndef LPICP_EXPORT_H
#define LPICP_EXPORT_H

#include "lpicp.h"
#include "live_common.h"

/*
 * Exports all counters defined in the struct LiveCounters.
 * 
 * cnt is the struct which contains all the arrays with the protocol values.
 * tv is the timestamp when the counters were last reset.
 * local_id is a string that will identify this particular measurement process,
 * 	e.g. the source of the packets
 * report_len  is the number of seconds that have passed since the counters
 * 	were last reset (this will be included in the output so users can do
 *	rate calculations). 
 */
int lpicp_export_counters(LiveCounters *cnt, struct timeval tv, 
		char *local_id, uint32_t report_len);

/*
 * Function which initialises the exporting section of the server.
 * It is called once in the collector and creates a list of protocols and their IDs,
 * which is later on sent to each client upon connecting to the server.
 * 
 * local_id is a string that will identify this particular measurement process,
 * 	e.g. the source of the packets
 */
void lpicp_export_init(char* local_id, wand_event_handler_t *hdl, int exp_interval,
				bool export_ongoing);

int lpicp_export_flow(char *local_id, Flow *expired, LiveFlow *live, enum lpicp_record rec_type);

int lpicp_export_ongoing_flows(char *local_id);


#endif
