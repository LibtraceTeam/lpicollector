#!/usr/bin/env python

import sys
import struct

from socket import *


lpicp_header_fmt = "!BBHHH"
lpicp_stats_fmt = "!LLLBBHHH"
lpicp_cnt_fmt = "!Q"
lpicp_stats_rec_fmt = "!LQ"
lpicp_proto_subhdr_fmt = "!L"
lpicp_proto_rec_fmt = "!LH"
lpicp_exp_subhdr_fmt = "!L"
lpicp_exp_rec_a_fmt = "!BBH"
lpicp_exp_rec_b_fmt = "!HHLLLLLLQQLLL"

lpicp_dirnames = ["out", "in"]
lpicp_metnames = ["pkts", "bytes", "new_flows", "curr_flows", "peak_flows", "active_ips", "observed_ips"]

LPICP_STATS = 0
LPICP_ONGOING = 1
LPICP_EXPIRED = 2
LPICP_PUSH = 3
LPICP_PROTOCOLS = 4


def connect_server(host, port):
    try:
        s = socket(AF_INET, SOCK_STREAM)
    except error as msg:
        sys.stderr.write("Failed to create socket: %s\n" % (msg[1]))
        return -1

    try:
        s.connect((host, port))
    except error as msg:
        sys.stderr.write("Failed to connect to %s on port %u: %s\n" %
                         (host, port, msg[1]))
        return -1

    return s


def parse_proto_record(msg_buf, name_len):
    buf_read = len(msg_buf)
    buf_parsed = name_len
    # getting the number of records from the subheader
    low = buf_parsed
    upp = buf_parsed + struct.calcsize(lpicp_proto_subhdr_fmt)
    proto_subhdr = struct.unpack(lpicp_proto_subhdr_fmt, bytes(msg_buf[low:upp]))
    buf_parsed += struct.calcsize(lpicp_proto_subhdr_fmt)
    num_records = proto_subhdr[0]
    proto_record = {}

    for i in range(0, num_records):
        low = buf_parsed
        upp = buf_parsed + struct.calcsize(lpicp_proto_rec_fmt)
        proto_rec = struct.unpack(lpicp_proto_rec_fmt, bytes(msg_buf[low:upp]))
        buf_parsed += struct.calcsize(lpicp_proto_rec_fmt)
        id = proto_rec[0]
        string_len = proto_rec[1]
        proto_name = msg_buf[buf_parsed:buf_parsed + string_len]
        proto_record[id] = proto_name
        buf_parsed += string_len

    return proto_record


def parse_flow_record(msg_buf, name_len):
    expired_records = {'records': []}
    buf_read = len(msg_buf)
    buf_parsed = name_len

    expired_records["id"] = msg_buf[0:name_len]
    low = buf_parsed
    upp = buf_parsed + struct.calcsize(lpicp_exp_subhdr_fmt)
    exp_subhdr = struct.unpack(lpicp_exp_subhdr_fmt, bytes(msg_buf[low:upp]))
    buf_parsed += struct.calcsize(lpicp_exp_subhdr_fmt)
    num_records = exp_subhdr[0]

    for i in range(0, num_records):
        # get the 3 fields before the IP addresses
        low = buf_parsed
        upp = buf_parsed + struct.calcsize(lpicp_exp_rec_a_fmt)
        exp_rec = struct.unpack(lpicp_exp_rec_a_fmt, bytes(msg_buf[low:upp]))
        buf_parsed += struct.calcsize(lpicp_exp_rec_a_fmt)

        r = {"version": exp_rec[0], "transport_protocol": exp_rec[1], "reserved": exp_rec[2]}

        # get the IP address for the server
        if exp_rec[0] == 4:
            r["ip_server"] = inet_ntop(AF_INET, (msg_buf[buf_parsed:buf_parsed + 4]))
            buf_parsed += 4
        else:
            r["ip_server"] = inet_ntop(AF_INET6, (msg_buf[buf_parsed:buf_parsed + 16]))
            buf_parsed += 16

        # get the IP address for the client
        if exp_rec[0] == 4:
            r["ip_client"] = inet_ntop(AF_INET, (msg_buf[buf_parsed:buf_parsed + 4]))
            buf_parsed += 4
        else:
            r["ip_client"] = inet_ntop(AF_INET6, (msg_buf[buf_parsed:buf_parsed + 16]))
            buf_parsed += 16

        # get the rest of the data after the IP addresses
        low = buf_parsed
        upp = buf_parsed + struct.calcsize(lpicp_exp_rec_b_fmt)
        exp_rec = struct.unpack(lpicp_exp_rec_b_fmt, bytes(msg_buf[low:upp]))
        buf_parsed += struct.calcsize(lpicp_exp_rec_b_fmt)
        r["port_server"] = exp_rec[0]
        r["port_client"] = exp_rec[1]
        r["start_secs"] = exp_rec[2]
        r["start_usecs"] = exp_rec[3]
        r["end_secs"] = exp_rec[4]
        r["end_usecs"] = exp_rec[5]
        r["lpi_payload_len"] = (exp_rec[6], exp_rec[7])
        r["payload_bytes"] = (exp_rec[8], exp_rec[9])
        r["first4b_payload"] = (exp_rec[10], exp_rec[11])
        r["protocol_id"] = exp_rec[12]
        expired_records['records'].append(r)
        assert (buf_parsed <= buf_read)
    return expired_records


def parse_stat_record(msg_buf, name_len):
    stat_record = {}
    buf_read = len(msg_buf)
    buf_parsed = name_len

    low = buf_parsed
    upp = buf_parsed + struct.calcsize(lpicp_stats_fmt)
    stats_hdr = struct.unpack(lpicp_stats_fmt, bytes(msg_buf[low:upp]))
    buf_parsed += struct.calcsize(lpicp_stats_fmt)

    user_len = int(stats_hdr[6])
    stat_record["user"] = msg_buf[buf_parsed:buf_parsed + user_len]
    buf_parsed += user_len
    stat_record["id"] = msg_buf[0:name_len]
    stat_record["ts"] = stats_hdr[0]
    stat_record["freq"] = int(stats_hdr[2])
    stat_record["dir"] = lpicp_dirnames[int(stats_hdr[3])]
    stat_record["metric"] = lpicp_metnames[int(stats_hdr[4])]
    stat_record["results"] = []

    for i in range(0, int(stats_hdr[5])):
        # getting the protocol ID
        low = buf_parsed
        upp = buf_parsed + struct.calcsize(lpicp_stats_rec_fmt)
        proto_rec = struct.unpack(lpicp_stats_rec_fmt, bytes(msg_buf[low:upp]))
        buf_parsed += struct.calcsize(lpicp_stats_rec_fmt)
        stat_record["results"].append((proto_rec[0], proto_rec[1]))
        assert (buf_parsed <= buf_read)
    return stat_record


def receive_msg(s, to_read):
    received = 0
    msg_buf = b""
    while received != to_read:
        try:
            foo = s.recv(to_read - received)
        except error as msg:
            sys.stderr.write("Error receiving body: %s\n" % (msg[1]))
            return b""
        msg_buf += foo
        received = len(msg_buf)

    return msg_buf


def receive_hdr(s):
    try:
        msg_buf = s.recv(struct.calcsize(lpicp_header_fmt))
    except error as msg:
        sys.stderr.write("Error receiving header: %s\n" % (msg[1]))
        return {}

    if not msg_buf:
        return {}

    lpicp_hdr = struct.unpack(lpicp_header_fmt, msg_buf)
    return lpicp_hdr


def read_lpicp(s):
    stats = {}

    lpicp_hdr = receive_hdr(s)
    if lpicp_hdr == {}:
        return -1, {}
    if int(lpicp_hdr[0]) != 1:
        return -1, {}

    to_read = int(lpicp_hdr[2]) - struct.calcsize(lpicp_header_fmt)
    msg_buf = receive_msg(s, to_read)

    if not msg_buf:
        return -1, {}

    name_len = int(lpicp_hdr[3])

    # LPICP_STATS
    if int(lpicp_hdr[1]) == LPICP_STATS:
        stats = parse_stat_record(msg_buf, name_len)
    # LPICP_ONGOING
    if int(lpicp_hdr[1]) == LPICP_ONGOING:
        stats = parse_flow_record(msg_buf, name_len)
    # LPICP_EXPIRED
    if int(lpicp_hdr[1]) == LPICP_EXPIRED:
        stats = parse_flow_record(msg_buf, name_len)
    # LPICP_PROTOCOLS
    if int(lpicp_hdr[1]) == LPICP_PROTOCOLS:
        stats = parse_proto_record(msg_buf, name_len)

    return int(lpicp_hdr[1]), stats
