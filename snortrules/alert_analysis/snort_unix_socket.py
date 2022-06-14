#! /usr/bin/env python
import os
import socket
import struct
import time
from threading import Thread
from threading import Lock
from alert_analysis.alert_inference import *

def get_localtime_from_timestamp(timestamp):
    s = time.strftime("[%Y-%m-%d %H:%M:%S", time.localtime(timestamp))
    s += ",%03d]" % (timestamp * 1000 % 1000)
    return s

class SnortAlert(object):
    alert_msg_length = 256
    pkt_length = 65535
    fmt = "%ds9I%ds9I" % (alert_msg_length, pkt_length)
    fmt_size = struct.calcsize(fmt)

    def __init__(self, alert_bytes):
        self.alert_bytes = alert_bytes
        # Alertpkt struct defined in snort3/src/loggers/alert_unixsock.cc
        (self.msg, self.ts_sec, self.ts_usec, self.caplen, self.pktlen, self.dlthdr, self.nethdr, self.transhdr,
         self.data, self.valid, self.pkt, self.gid, self.sid, self.rev, self.class_id, self.priority, self.event_id,
         self.event_ref, self.ref_time_sec, self.ref_time_usec) = struct.unpack(SnortAlert.fmt, self.alert_bytes)

    def _get_timestamp(self):
        timestamp = float(self.ts_sec + self.ts_usec / 1000000)
        return timestamp

    def _get_msg(self):
        return self.msg.strip(b'\x00').decode()

    def _get_rule_info(self):
        return ":".join([str(self.gid), str(self.sid), str(self.rev)])

    def _get_pkt(self):
        return byte_str_to_char_str(self.pkt)

    def get_alert_dict(self):
        keys = ["msg", "timestamp", "rule", "pkt", "matched_case_no"]
        values = [self._get_msg(), self._get_timestamp(), self._get_rule_info(), self._get_pkt(), 0]
        return dict(zip(keys, values))


class SnortUnixSocket(Thread):
    alerts_list = []
    all_alerts_list = []
    list_operate_lock = Lock()

    def __init__(self, sock_path="/var/log/snort", sock_file_name="snort_alert"):
        super(SnortUnixSocket, self).__init__()
        self.UNSOCKFILE = os.path.join(sock_path, sock_file_name)
        self.alert_msg_length = 256
        self.pkt_length = 65535
        self.alert_buffer = []

    def run(self):
        print("Start listening to Snort unix domain socket...")
        unix_sock = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
        # unix_sock.setblocking(False)

        try:
            os.remove(self.UNSOCKFILE)
        except OSError:
            pass

        unix_sock.bind(self.UNSOCKFILE)
        # unix_sock.settimeout(1)
        while True:
            try:
                data_in = unix_sock.recv(SnortAlert.fmt_size)
            except socket.error:
                data_in = None

            if data_in:
                alert = SnortAlert(data_in).get_alert_dict()
                t = time.time()
                s = time.strftime("[%Y-%m-%d %H:%M:%S", time.localtime(t))
                s += ",%03d]" % (t * 1000 % 1000)
                print("MSG received time:", s)
                print("Alert generated time:", alert['timestamp'])


                # output to the file
                f = open("/root/github/internet_product_safe_test/result_analysis/test_log", "a+")
                get_msg = "MSG received time:" + s + "; " + "Alert generated time: %.4f" % alert['timestamp'] + '\n'
                f.write(get_msg)
                f.close()
                
                SnortUnixSocket.all_alerts_list.append(alert)
                self.alert_buffer.append(alert)

                if SnortUnixSocket.list_operate_lock.acquire(blocking=False):
                    for alert in self.alert_buffer:
                        SnortUnixSocket.alerts_list.append(alert)
                    self.alert_buffer.clear()
                    SnortUnixSocket.list_operate_lock.release()
            

            


# backup code
"""
while True:
# (data_in, addr) = unsock.recvfrom(4096)
# (msg, ts_sec, ts_usec, caplen, pktlen, dlthdr, netthdr, transhdr, data, val, pkt) = struct.unpack(fmt, data_in[:fmt_size])
# print(msg)
# print(struct.unpack(">|", pkt[netthdr+12:netthdr+16]))
print(data)
data = unsock.recvfrom(1024)
"""
