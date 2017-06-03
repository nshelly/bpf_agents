#!/usr/bin/python
#
# @lint-avoid-python-3-compatibility-imports
#
# tcpconnect    Trace TCP connect()s.
#               For Linux, uses BCC, eBPF. Embedded C.
#
# USAGE: tcpconnect [-h] [-t] [-p PID] [-P PORT [PORT ...]]
#
# All connection attempts are traced, even if they ultimately fail.
#
# This uses dynamic tracing of kernel functions, and will need to be updated
# to match kernel changes.
#
# Copyright (c) 2015 Brendan Gregg.
# Licensed under the Apache License, Version 2.0 (the "License")
#
# 25-Sep-2015   Brendan Gregg   Created this.
# 14-Feb-2016      "      "     Switch to bpf_perf_output.
from __future__ import print_function

import re
from bcc import BPF

import sys
print("\n".join(sys.path))
import argparse
from socket import inet_ntop, ntohs, AF_INET, AF_INET6
from struct import pack
import ctypes as ct

# arguments
from kafka_source import BpfProducer

examples = """examples:
    ./tcpconnect           # trace all TCP connect()s
    ./tcpconnect -t        # include timestamps
    ./tcpconnect -p 181    # only trace PID 181
    ./tcpconnect -P 80     # only trace port 80
    ./tcpconnect -P 80,81  # only trace port 80 and 81
"""
parser = argparse.ArgumentParser(
    description="Trace TCP connects",
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
parser.add_argument("-P", "--port",
                    help="comma-separated list of destination ports to trace.")
args = parser.parse_args()

with open("tcpconnect_source.cc", "r") as f:
    bpf_text = f.read()

# code substitutions
if args.pid:
    print("substituting for pid: %d"  % args.pid)
    bpf_text = re.sub(r'//\s+FILTER_PID',
            'if (pid != %s) { return 0; }' % args.pid, bpf_text)
if args.port:
    print("substituting for ports: %s"  % args.port)
    dports = [int(dport) for dport in args.port.split(',')]
    dports_if = ' && '.join(['dport != %d' % ntohs(dport) for dport in dports])
    bpf_text = re.sub(r'//\s+FILTER_PORT',
                      'if (%s) { currsock.delete(&pid); return 0; }' % dports_if,
                      bpf_text)

# bpf_text = bpf_text.replace('FILTER_PID', '')
# bpf_text = bpf_text.replace('FILTER_PORT', '')

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
        ("sport", ct.c_ulonglong),
        ("dport", ct.c_ulonglong),
        ("task", ct.c_char * TASK_COMM_LEN)
    ]

class Data_ipv6(ct.Structure):
    _fields_ = [
        ("ts_us", ct.c_ulonglong),
        ("pid", ct.c_ulonglong),
        ("saddr", (ct.c_ulonglong * 2)),
        ("daddr", (ct.c_ulonglong * 2)),
        ("ip", ct.c_ulonglong),
        ("dport", ct.c_ulonglong),
        ("task", ct.c_char * TASK_COMM_LEN)
    ]


PRODUCER = BpfProducer(
    bootstrap_servers=[args.kafka_server], local_only=args.local_only)

# process event
def print_ipv4_event(cpu, data, size):
    event = ct.cast(data, ct.POINTER(Data_ipv4)).contents
    global start_ts
    if args.timestamp:
        if start_ts == 0:
            start_ts = event.ts_us
        print("%-9.3f" % ((float(event.ts_us) - start_ts) / 1000000), end="")

    PRODUCER.send("tcpconnect-ipv4", event, 4)
    print("%-6d %-12.12s %-2d %-16s %-4d %-16s %-4d" % \
          (event.pid, event.task.decode(), event.ip,
           inet_ntop(AF_INET, pack("I", event.saddr)), event.sport,
           inet_ntop(AF_INET, pack("I", event.daddr)), event.dport))


def print_ipv6_event(cpu, data, size):
    # TODO: Add source port
    event = ct.cast(data, ct.POINTER(Data_ipv6)).contents
    global start_ts
    if args.timestamp:
        if start_ts == 0:
            start_ts = event.ts_us
        print("%-9.3f" % ((float(event.ts_us) - start_ts) / 1000000), end="")

    PRODUCER.send("tcpconnect-ipv6", event, 6)
    print("%-6d %-12.12s %-2d %-16s %-16s %-4d" %
          (event.pid, event.task.decode(), event.ip,
           inet_ntop(AF_INET6, event.saddr),
           inet_ntop(AF_INET6, event.daddr), event.dport))

# initialize BPF
b = BPF(text=bpf_text)
b.attach_kprobe(event="tcp_v4_connect", fn_name="trace_connect_entry")
b.attach_kprobe(event="tcp_v6_connect", fn_name="trace_connect_entry")
b.attach_kretprobe(event="tcp_v4_connect", fn_name="trace_connect_v4_return")
b.attach_kretprobe(event="tcp_v6_connect", fn_name="trace_connect_v6_return")

# header
if args.timestamp:
    print("%-9s" % ("TIME(s)"), end="")
print("%-6s %-12s %-2s %-16s %-4s %-16s %-4s" % ("PID", "COMM", "IP",
                                                 "SADDR", "SPORT",
                                                 "DADDR", "DPORT"))

start_ts = 0

# read events
b["ipv4_events"].open_perf_buffer(print_ipv4_event)
b["ipv6_events"].open_perf_buffer(print_ipv6_event)
while 1:
    b.kprobe_poll()