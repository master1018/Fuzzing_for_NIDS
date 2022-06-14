#! /usr/bin/env python
# -*- coding: UTF-8 -*-

'''Class that reflect packet from specific port'''
from scapy.all import *
import socket
from protocol.tunable_responder import TunableResponder


class PacketReflectModuleServer(Thread):

    """
    open port 55555
    [Step.1] first,act as server. wait for Boofuzz to connect and receive data from Boofuzz
    data from Boofuzz is in this form:"port:21#（real_data）……" this class extract port:21# and remove it from data
    [Step.2]then act as client,make connection with 55556（packet_reflect_module_side_cilent） and tell it the port to connect （Num A） e.g. 21
    [Step.3]next act as server, bind Num A （e.g. 21） and wait 55556（packet_reflect_module_side_cilent） to connect, once the connection is made,send the real_data in step 1.
    loop to Step.1
    """

    def __init__(self,host='localhost',port=55555,bufsiz=4096):
        super(PacketReflectModuleServer,self).__init__()
        self.host=host
        self.port=port
        self.bufsiz=bufsiz
        self.addr=(host,port)
        self.trs = TunableResponder()#TunableResponderServer OOP_Server
        self.trs.start()

    def run(self):
        reflect_module_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        reflect_module_sock.bind(self.addr)
        reflect_module_sock.listen(5)

        while True:
            print('\n\nReflectServer Waiting for packet to reflect')
            reflect_pres_sock, addr = reflect_module_sock.accept()
            print('Connect from:', addr)
            total_data = []
            while True:
                data_str = reflect_pres_sock.recv(self.bufsiz)
                if not data_str: break
                data = self.byte_str_to_char_str(data_str)
                total_data.append(data)
            total_data = ''.join(total_data)
            packet_data = total_data
            # packet_data=reflect_pres_sock.recv(BUFSIZ)
            print('Receive!', packet_data)

            # handle data and extract the target_port
            port_right = packet_data.find('#')
            port_left = packet_data.find(':')
            source_port = packet_data[port_left + 1:port_right]
            data = packet_data[port_right + 1:]
            # data=packet_data
            # source_port=21
            # tell_packet_port=bytes([source_port])
            tell_packet_port = source_port.encode()
            source_port_int = int(source_port)
            #判断源port是否是OOPServer绑定的端口，如果是则通知OOPServer解绑
            if source_port_int == self.trs.port:#通知解绑
                self.trs.unbind()

            # make connection with 55556 and send port information
            print('Ready to tell port number', source_port)
            tell_port_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            tell_port_socket.connect(('localhost', 55556))
            tell_port_socket.send(tell_packet_port)  # tell target_port
            tell_port_socket.close()
            print('Tell port number complete!')
            # bind source_port and wait for 55556 to connection
            reflect_data_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            try:
                reflect_data_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            except:
                print('reflect_data_socket.setsockopt failed')
            reflect_data_socket.bind(('localhost', source_port_int))
            reflect_data_socket.listen(1)
            while True:
                print('Waiting for 55556 to connect')
                send_data_sock, addr = reflect_data_socket.accept()
                print('Connect from:', addr)
                send_data_sock.sendall(data.encode())
                print('send data complete,data:',data.encode())
                send_data_sock.close()
                break
            reflect_data_socket.close()
            print('Done!')
            reflect_pres_sock.close()
            if source_port_int == self.trs.port:#通知OOPServer重新绑定
                self.trs.bind()

        reflect_module_sock.close()


    def byte_str_to_char_str(self,data_str):
        char_str = ""
        for byte_c in data_str:
            char_str += chr(byte_c)
        return char_str

p=PacketReflectModuleServer()
p.start()

