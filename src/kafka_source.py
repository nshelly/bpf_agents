#!/usr/bin/python
import json
from socket import inet_ntop, AF_INET, AF_INET6
from struct import pack

from kafka import KafkaProducer

class BpfProducer:

    def __init__(self, bootstrap_servers, local_only=False):
        self.local_only = local_only
        if not local_only:
            self.producer = KafkaProducer(
            bootstrap_servers=bootstrap_servers,
            value_serializer=lambda m: json.dumps(m).encode('ascii'))
        else:
            self.producer = None

    def send(self, topic, event, ip_version):
        data = {
            "pid": event.pid,
            "ts_us": float(event.ts_us),
            "comm": event.task.decode(),
            "ipver": event.ipver,
            "saddr": inet_ntop(AF_INET if ip_version == 4 else AF_INET6,
                               pack("I", event.saddr)),
            "daddr": inet_ntop(AF_INET if ip_version == 4 else AF_INET6,
                               pack("I", event.daddr)),
        }
        if hasattr(event, "dport"):
            data.update({
                "dport": event.dport
            })
        else:
            data.update({
                "lport": event.lport
            })


        # produce json messages
        if not self.local_only:
            self.producer.send(topic, data)
            print("sending: ", json.dumps(data, indent=2))



# using java to automatically

# poisson arrivals of connect, with 1 to 10 ms delay for an accept
# generate a million events
# table
# map first recv to first send
# map last recv for each send