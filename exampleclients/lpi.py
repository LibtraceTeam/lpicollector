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
# This script will parse LPICP_STATS records emitted by the lpicollector and
# dump their contents to standard output in a human readable format.
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

		type, stats = lpicol.read_lpicp(s)
		# Ignore flow records and push messages
                if type in [1,2,3]:
			continue
		# LPICP_PROTOCOLS
		if type == 4:
                        known_protos.update(stats)
                        continue
                # Error, exit
		if type == -1:
			break
                # Empty or malformed stats record, exit
		if type == 0 and stats == {}:
			#continue
			break
		
                for n in stats["results"]:

                        if n[0] not in known_protos:
                                protoname="LPI Protocol %s" % n[0]
                        else:
                                protoname = known_protos[n[0]]

			print "%s,%s,%s,%u,%s_%s,%s,%s" % (stats["id"],
				stats["user"],
				stats["ts"], stats["freq"], stats["dir"],
				stats["metric"], protoname, n[1])

          #      break
	
        s.close()

