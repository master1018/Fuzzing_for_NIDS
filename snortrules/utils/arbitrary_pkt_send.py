#!/usr/bin/env python
# -*- coding: UTF-8 -*-

from scapy.all import *
from scapy.layers.http import *
# explore(scapy.layers.http)
# HTTPRequest().show()


class ArbitraryPacket(object):
    def __init__(self, pkt_payload, dst, port, count=1, protocol=None):
        self.payload = pkt_payload
        self.send_count = count
        self.protocol = protocol
        self.dst = dst
        self.port = port
        if self.protocol == "HTTP":
            self.data_type = HTTP
        else:
            self.data_type = Raw

    def show_packet(self):
        pass

    def send(self):
        for index in range(self.send_count):
            print("sending packet count: ", index)
            s = TCP_client.tcplink(self.data_type, self.dst, self.port)
            s.send(self.payload)
            # s.recv()
            s.close()


load_layer("http")
data=b'aloha'
req = HTTP()/HTTPRequest(
    Method=b'POST',
    Accept_Encoding=b'gzip, deflate',
    Cache_Control=b'no-cache',
    Connection=b'keep-alive',
    Host=b'211.69.198.54',
    Pragma=b'no-cache'
)/data
req.show()
AP = ArbitraryPacket(req, "211.69.198.54", 8080, count=20, protocol=HTTP)
AP.send()
