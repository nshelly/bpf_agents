#!/usr/bin/python
#
# @lint-avoid-python-3-compatibility-imports
#
# sys_network    Trace all networking syscalls
#               For Linux, uses BCC, eBPF. Embedded C.
#
# USAGE: tcpconnect [-h] [-t] [-p PID] [-P PORT [PORT ...]]
#
# All network-related syscalls are traced.
#
#
from __future__ import print_function

import re
import sys

from bcc import BPF
from struct import pack

print("\n".join(sys.path))
import argparse
from socket import ntohs, inet_ntop, AF_INET
import ctypes as ct

# arguments
# from kafka_source import BpfProducer

socketfd_to_tuple = {}

examples = """examples:
    ./sys_stream           # trace all TCP connect()s
    ./sys_stream -t        # include timestamps
    ./sys_stream -p 181    # only trace PID 181
    ./sys_stream -P 80     # only trace port 80
    ./sys_stream.py -d -t --nocomm sudo,sshd -o wget_`date +%m-%d-%H:%M.%S`.out
"""
parser = argparse.ArgumentParser(
    description="Trace TCP connects",
    formatter_class=argparse.RawDescriptionHelpFormatter,
    epilog=examples)
parser.add_argument("-d", "--debug", action="store_true",
                    help="Debug mode")
parser.add_argument("-o", "--output",
                    default=None,
                    help="Output to file")
parser.add_argument("--trace", action="store_true",
                    help="Print trace readlines")
parser.add_argument("-s", "--kafka-server",
                    help="Kafka bootstrap server and port")
parser.add_argument("-t", "--timestamp", action="store_true",
                    help="include timestamp on output")
parser.add_argument("-p", "--pid",
                    help="trace this PID only")
parser.add_argument("--nopid",
                    help="don't trace this PID")
parser.add_argument("--nocomm",
                    help="don't trace this COMM")
parser.add_argument("-P", "--port",
                    help="comma-separated list of destination ports to trace.")
args = parser.parse_args()

with open("sys_stream.cc", "r") as f:
    bpf_text = f.read()
    bpf_text = re.sub(r'bpf_\((ntohl|ntohs)\)',
                      '\1', bpf_text)
    bpf_text = re.sub(r'//\s+Begin.*//\s+End[^\n]*$', "",
                      bpf_text,
                      flags=re.MULTILINE | re.DOTALL)
    bpf_text = "#include <bcc/proto.h>\n" + bpf_text

# code substitutions
if args.pid:
    print("substituting for pid: %s"  % args.pid)
    bpf_text = re.sub(r'//\s+FILTER PID',
            'u64 pid = send_data->pid;\n'
            'if (pid != %s) { return 0; }' % args.pid, bpf_text)
if args.nopid:
    print("filtering out pid: %s"  % args.nopid)
    bpf_text = re.sub(r'//\s+FILTER OUT PID',
            'u64 pid = send_data->pid;\n'
            'if (pid == %s) { return 0; }' % args.nopid, bpf_text)
if args.nocomm:
    compare_strs = []
    for comm in args.nocomm.split(','):
        print("filtering out comm: %s"  % comm)
        compare_str = []
        for i, c in enumerate(comm):
            compare_str.append("task[{i}] == '{c}'".format(
                i=i, c=comm[i]))
        compare_strs.append('(' + " && ".join(compare_str) + ')')

    bpf_text = re.sub(r'//\s+FILTER OUT COMM',
                      '    char *task = send_data->task;\n'
                      '    if ({compare_strs}) {{ return 0; }}'.format(
                          compare_strs=" || \n\t\t".join(compare_strs)), bpf_text)
if args.port:
    print("substituting for ports: %s"  % args.port)
    dports = [int(dport) for dport in args.port.split(',')]
    dports_if = ' && '.join(['dport != %d' % ntohs(dport) for dport in dports])
    bpf_text = re.sub(r'//\s+FILTER_PORT',
                      '    u64 dport = send_data->dport;\n'
                      '    if (%s) { currsock.delete(&pid); return 0; }' % dports_if,
                      bpf_text)

output = open(args.output, "w+") if args.output else None

def inet_ntoa(addr):
    dq = ''
    for i in range(0, 4):
        dq = dq + str(addr & 0xff)
        if (i != 3):
            dq = dq + '.'
        addr = addr >> 8
    return dq


bpf_text = bpf_text.replace("._delete", ".delete")

if args.debug:
    print(bpf_text)

# event data
TASK_COMM_LEN = 16      # linux/sched.h

class Data_send(ct.Structure):
    _fields_ = [
        ("ts_us", ct.c_ulonglong),
        ("pid", ct.c_longlong),
        ("tgid", ct.c_longlong),
        ("ppid", ct.c_longlong),
        ("sockfd", ct.c_ulonglong),
        ("len", ct.c_ulonglong),
        ("flags", ct.c_ulonglong),
        ("saddr", ct.c_ulonglong),
        ("sport", ct.c_ulonglong),
        ("daddr", ct.c_ulonglong),
        ("dport", ct.c_ulonglong),
        ("parent_task", ct.c_char * TASK_COMM_LEN),
        ("task", ct.c_char * TASK_COMM_LEN)
    ]

# PRODUCER = BpfProducer(
#     bootstrap_servers=[args.kafka_server], local_only=args.local_only)


def print_event(func_name, data, is_return=False):
    event = ct.cast(data, ct.POINTER(Data_send)).contents
    global start_ts
    if args.timestamp:
        if start_ts == 0:
            start_ts = event.ts_us
        print("%-9.4f" % ((float(event.ts_us) - start_ts) / 1000000), end="",
              file=output)

    notes = ""
    if "bind" in func_name:
        sport = event.sport
        saddr = inet_ntop(AF_INET, pack("I", event.saddr))
        notes = "{saddr}:{sport}".format(saddr=saddr, sport=sport)

    elif "connect" in func_name or func_name == "inet_csk_accept":
        sport = event.sport
        saddr = inet_ntop(AF_INET, pack("I", event.saddr)) if event.saddr else None
        dport = event.dport
        daddr = inet_ntop(AF_INET, pack("I", event.daddr)) if event.daddr else None
        notes = "{saddr}{sport} -> {daddr}:{dport}".format(
            saddr=(saddr + ":") if saddr else "", sport=sport or "",
            daddr=daddr, dport=dport)

    if "send" in func_name or "write" in func_name:
        notes = "Sending {} bytes".format(event.len)

    if "read" in func_name or "recv" in func_name:
        if is_return:
            notes = "{} bytes received".format(event.len)
        else:
            notes = "Receiving <= {} bytes...".format(event.len)

    elif func_name == "socket" and not is_return:
        family = "AF_INET" if event.len == 2 else "unknown"
        notes = "family:{family}, flags:{flags:04x}".format(family=family, flags=event.flags)

    has_sockfd = "socket" != func_name or is_return
    # PRODUCER.send("tcpconnect-ipv4", event, 4)
    print("%-20s %-6d %-12.12s %-6s %-12.12s %-6s %s" % \
          (func_name + ("_RETURN" if is_return else ""),
           event.pid, event.task.decode(),
           event.ppid, event.parent_task.decode(),
           event.sockfd if has_sockfd else "",
           notes),
          end="\n",
          file=output)


# initialize BPF
b = BPF(text=bpf_text)

# header
if args.timestamp:
    print("%-9s" % ("TIME(s)"), end="", file=output)
# print("%-10s %-8s %-12.12s %-16s %-4s %-6s %-6s %-6s %-6s %-6s" % \
#       ("FUNC", "PID", "COMM", "DADDR", "DFAM", "DPORT",
#         "ADDR_LEN", "SOCKFD", "LEN", "FLAGS"))

print("%-20s %-8s %-8s %-12.12s %-12.12s %-6s %-6s %-6s" % \
      ("FUNC", "PID", "COMM", "PPID", "PCOMM", "SOCKFD", "LEN", "Notes"),
      end="\n",
      file=output)

start_ts = 0

syscalls = [
    ("connect", False),
    ("bind", False),
    ("accept", True),
    ("send", False),
    ("sendmsg", False),
    ("sendmmsg", False),
    ("recvmsg", False),
    ("sendto", False),
    ("recv", False),
    ("recvfrom", True),
    ("write", False),
    ("read", True),
    ("close", False),
    ("socket", True),
    ("shutdown", False)
]

for syscall, do_return in syscalls:
    # print("Attaching: {syscall}, tracing_return? {do_return}".format(syscall=syscall, do_return=do_return))
    syscall_fn = "sys_{}".format(syscall)
    b.attach_kprobe(event=syscall_fn,
                    fn_name="trace_{}_entry".format(syscall))
    b[syscall + "_events"].open_perf_buffer(
        lambda cpu, data, size, event_name=syscall: print_event(event_name, data, is_return=False),
        page_cnt=2 << 5)
    if do_return:
        b.attach_kretprobe(event=syscall_fn,
                           fn_name="trace_{}_return".format(syscall))
        b[syscall + "_return_events"].open_perf_buffer(
            lambda cpu, data, size, event_name=syscall: print_event(event_name, data, is_return=True),
            page_cnt=2 << 5)

b.attach_kprobe(event="tcp_v4_connect", fn_name="trace_connect_v4_entry")
b["tcp_v4_connect_return_events"].open_perf_buffer(
    lambda cpu, data, size, event_name="tcp_v4_connect": print_event(event_name, data, is_return=True))
b.attach_kretprobe(event="tcp_v4_connect", fn_name="trace_connect_v4_return")


b.attach_kretprobe(event="inet_csk_accept", fn_name="trace_inet_csk_accept_return")
b["inet_csk_accept_return_events"].open_perf_buffer(
    lambda cpu, data, size, event_name="inet_csk_accept": print_event(event_name, data, is_return=True))


while 1:
    if args.trace:
        print(b.trace_readline())
    else:
        b.kprobe_poll()
