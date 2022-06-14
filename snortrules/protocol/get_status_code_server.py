#! /usr/bin/env python
# -*- coding: UTF-8 -*-

'''Class that reflect packet from specific port'''
from scapy.all import *
import socket


class GetStatusCodeServer(Thread):

    """
    监听66666,获得@@100,200,300@@的形式的数据后，通知OOP_server按照给定的形式返回状态码并调整状态机
    """

    def __init__(self,host='localhost',port=60000,bufsiz=4096):
        super(GetStatusCodeServer,self).__init__()
        self.host=host
        self.port=port
        self.bufsiz=bufsiz
        self.addr=(host,port)
        print('GetStatusCodeServer init')

    def get_remaindernum_and_statecode(self):#返回还有几个code和当前code值
        if self.index < self.total_num:
            current_code = self.code_list[self.index]
            r_num = self.total_num - self.index
            self.index = self.index + 1
            return r_num, current_code
        else:
            return 0,0

    def run(self):
        statuscode_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        statuscode_sock.bind(self.addr)
        statuscode_sock.listen(5)

        while True:
            print('\n\nGetStatusCodeServer Waiting for status code')
            statuscode_pres_sock, addr = statuscode_sock.accept()
            print('Connect from:', addr)
            total_data = []
            while True:
                data_str = statuscode_pres_sock.recv(self.bufsiz)
                if not data_str: break
                data = byte_str_to_char_str(data_str)
                total_data.append(data)
            total_data = ''.join(total_data)
            packet_data = total_data
            # packet_data=statuscode_pres_sock.recv(BUFSIZ)
            print('Receive!', packet_data)
            # handle data and extract the target_port,@@100,200,300@@
            if packet_data[:2] != '@@' or packet_data[-2:] != '@@':
                print('The @@format@@ is wrong')
                continue
            packet_data = packet_data[2:-2]
            self.code_list = packet_data.split(',')
            self.total_num = len(self.code_list)
            self.index = 0
            print('totalnum: '+str(self.total_num)+' status_code: '+str(self.code_list))
            print('Done!')
            statuscode_pres_sock.close()

        statuscode_sock.close()


def byte_str_to_char_str(data_str):
        char_str = ""
        for byte_c in data_str:
            char_str += chr(byte_c)
        return char_str

