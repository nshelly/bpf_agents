#!/usr/bin/python
# @lint-avoid-python-3-compatibility-imports
#
# tcpaccept Trace TCP accept()s.
#           For Linux, uses BCC, eBPF. Embedded C.
#
# USAGE: tcpaccept [-h] [-t] [-p PID]
#
# This uses dynamic tracing of the kernel inet_csk_accept() socket function
# (from tcp_prot.accept), and will need to be modified to match kernel changes.
#
# Copyright (c) 2015 Brendan Gregg.
# Licensed under the Apache License, Version 2.0 (the "License")
#
# 13-Oct-2015   Brendan Gregg   Created this.
# 14-Feb-2016      "      "     Switch to bpf_perf_output.

from __future__ import print_function

import argparse
import ctypes as ct
from socket import inet_ntop, AF_INET, AF_INET6
from struct import pack

from bcc import BPF

from kafka_source import BpfProducer

examples = """examples:
    ./tcpaccept           # trace all TCP accept()s
    ./tcpaccept -t        # include timestamps
    ./tcpaccept -p 181    # only trace PID 181
"""
parser = argparse.ArgumentParser(
    description="Trace TCP accepts",
    formatter_class=argparse.RawDescriptionHelpFormatter,
    epilog=examples)
parser.add_argument("--local_only",
                    action="store_true", default=False,
                    help="don't send to server")
parser.add_argument("-d", "--debug", action="store_true",
                    help="Debug mode")
parser.add_argument("-s", "--kafka-server",
                    help="Kafka bootstrap server and port")
parser.add_argument("-t", "--timestamp", action="store_true",
    help="include timestamp on output")
parser.add_argument("-p", "--pid",
    help="trace this PID only")
args = parser.parse_args()

with open("tcpaccept_source.cc", "r") as f:
    bpf_text = f.read()

# code substitutions
if args.pid:
    bpf_text = bpf_text.replace('FILTER',
        'if (pid != %s) { return 0; }' % args.pid)
else:
    bpf_text = bpf_text.replace('FILTER', '')
if args.debug:
    print(bpf_text)

# event data
TASK_COMM_LEN = 16      # linux/sched.h

class Data_ipv4(ct.Structure):
    _fields_ = [
        ("ts_us", ct.c_ulonglong),
        ("pid", ct.c_ulonglong),
        ("saddr", ct.c_ulonglong),
        ("daddr", ct.c_ulonglong),
        ("ip", ct.c_ulonglong),
        ("lport", ct.c_ulonglong),
        ("task", ct.c_char * TASK_COMM_LEN)
    ]

class Data_ipv6(ct.Structure):
    _fields_ = [
        ("ts_us", ct.c_ulonglong),
        ("pid", ct.c_ulonglong),
        ("saddr", (ct.c_ulonglong * 2)),
        ("daddr", (ct.c_ulonglong * 2)),
        ("ip", ct.c_ulonglong),
        ("lport", ct.c_ulonglong),
        ("task", ct.c_char * TASK_COMM_LEN)
    ]

PRODUCER = BpfProducer(bootstrap_servers=[args.kafka_server],
                       local_only=args.local_only)

# process event
def print_ipv4_event(cpu, data, size):
    event = ct.cast(data, ct.POINTER(Data_ipv4)).contents
    global start_ts
    if args.timestamp:
        if start_ts == 0:
            start_ts = event.ts_us
        print("%-9.3f" % ((float(event.ts_us) - start_ts) / 1000000), end="")

    PRODUCER.send("tcpaccept-ipv4", event, 4)
    print("%-6d %-12.12s %-2d %-16s %-16s %-4d" % (event.pid,
        event.task.decode(), event.ip,
        inet_ntop(AF_INET, pack("I", event.daddr)),
        inet_ntop(AF_INET, pack("I", event.saddr)), event.lport))

def print_ipv6_event(cpu, data, size):
    event = ct.cast(data, ct.POINTER(Data_ipv6)).contents
    global start_ts
    if args.timestamp:
        if start_ts == 0:
            start_ts = event.ts_us
        print("%-9.3f" % ((float(event.ts_us) - start_ts) / 1000000), end="")
    PRODUCER.send("tcpaccept-ipv6", event, 6)
    print("%-6d %-12.12s %-2d %-16s %-16s %-4d" % (event.pid,
        event.task.decode(), event.ip, inet_ntop(AF_INET6, event.daddr),
        inet_ntop(AF_INET6, event.saddr), event.lport))


# initialize BPF
b = BPF(text=bpf_text)

# header
if args.timestamp:
    print("%-9s" % ("TIME(s)"), end="")
print("%-6s %-12s %-2s %-16s %-16s %-4s" % ("PID", "COMM", "IP", "RADDR",
    "LADDR", "LPORT"))

start_ts = 0

# read events
b["ipv4_events"].open_perf_buffer(print_ipv4_event)
b["ipv6_events"].open_perf_buffer(print_ipv6_event)
while 1:
    b.kprobe_poll()
