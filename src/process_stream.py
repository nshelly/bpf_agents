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
import json
import re
import sys

import datetime
from pprint import pprint
from time import sleep

import argparse

import os

RING_BUFFER_PAGE_CNT = 2 << 7
DEFAULT_FILE_NAME = "stream_log_{}.json".format(datetime.datetime.now().strftime("%m-%d_%H:%M:%S"))

# arguments
# from kafka_source import BpfProducer

socketfd_to_tuple = {}

parser = argparse.ArgumentParser(
    description="Process network data",
    formatter_class=argparse.RawDescriptionHelpFormatter)
parser.add_argument("-v", "--verbose", action="store_true",
                    help="Verbose mode")
parser.add_argument("-i", "--input",
                    help="Input of file")
args = parser.parse_args()

import fnmatch

data = {}
for i in os.listdir("."):
    if fnmatch.fnmatch(i, "*.json"):
        print i
        with open(i) as data_file:
            data[i] = json.load(data_file)
            pprint(data[i])


