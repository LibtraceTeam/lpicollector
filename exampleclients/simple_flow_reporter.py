#!/usr/bin/env python

# This script is included with lpicollector to act as a demonstration of
# how to write a simple client that can read and parse the records produced
# by the lpicollector.
#
# This script will print the records to standard output.

import sys
import string
import getopt
import argparse
import struct

import common as lpicol
# This script will parse LPICP_ONGOING and LPICP_EXPIRED records emitted by
# the lpicollector and dump their contents to standard output in a human
# readable format.
known_protos = {}

if __name__ == "__main__":
        parser = argparse.ArgumentParser()

        parser.add_argument('server', nargs='?', default='localhost',
                        help='lpi_collector server to connect to')
        parser.add_argument('port', nargs='?', default=3678,
                        help='the port number to connect to')

        args = parser.parse_args()

        if args.server == None:
                sys.stderr.write("Please specify a server to connect to via the --server option\n")
                sys.exit(1)

	s = lpicol.connect_server(args.server, int(args.port))
	if s == -1:
		sys.exit(1)

        while 1:

		type, records = lpicol.read_lpicp(s)
		# Ignore stats records and push messages
                if type in [0,3]:
			continue
		# LPICP_PROTOCOLS
		if type == 4:
                        known_protos.update(records)
                        continue
                # Error, exit
		if type == -1:
			break

                for n in records['records']:

                        if n['protocol_id'] not in known_protos:
                                protoname="LPI Protocol %s" % n['protocol_id']
                        else:
                                protoname = known_protos[n['protocol_id']]
                        try:
                                print "%s,%s,%s,%s,%u,%u,%u,%u,%u,%u,%u,%u,%lu,%lu,%08x,%08x" % (records['id'], protoname, n['ip_server'], n['ip_client'],\
                                   n['port_server'], n['port_client'],\
                                   n['start_secs'], n['start_usecs'],\
                                   n['end_secs'], n['end_usecs'],\
                                   n['lpi_payload_len'][0],\
                                   n['lpi_payload_len'][1],\
                                   n['payload_bytes'][0],\
                                   n['payload_bytes'][1],\
                                   n['first4b_payload'][0],\
                                   n['first4b_payload'][1])
                        except:
                                print n
                                raise

          #      break
	
        s.close()

