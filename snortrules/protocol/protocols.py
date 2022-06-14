from treelib import *
import os
import json

#-*- encoding:utf-8 -*-
from imp import reload
import sys   #reload()之前必须要引入模块
reload(sys)


protocol_definition_path = "/root/github/internet_product_safe_test/snortrules/protocol"

"""生成每个协议的状态树
"""
class Protocol(object):
    def __init__(self, proto_name):
        self.protocol_name = proto_name
        self.proto_definition = self._get_protocol_definition()
        self.states = self.proto_definition['stateDiagram']['state']
        self.protocol_tree = self._parse_state_tree()

    def _parse_state_tree(self):
        protocol_definition = self._get_protocol_definition()
        transitions = protocol_definition['stateDiagram']['transition']

        protocol_tree = Tree()
        protocol_tree.create_node("NONE", "ROOT")

        parent_state_dict = {"start": "ROOT"}
        for state, transition in transitions.items():
            for item in transition:
                for action in item['action']:
                    if protocol_tree.contains(action):
                        continue
                    data = {"response": item["response"]}
                    identifier = ".".join([state, action])
                    parent = ".".join([state, action])
                    protocol_tree.create_node(action, identifier, parent_state_dict[state], data)
                    data["nid"] = parent
                    if item['to'] != state and item['to'] not in parent_state_dict:
                        parent_state_dict[item['to']] = parent

        return protocol_tree

    def _get_protocol_definition(self):
        if self.protocol_name == 'ftp':
            with open(os.path.join(protocol_definition_path, "FTP-PACKET/ftpDefine.json")) as f:
                ftp_definition = json.loads(f.read())
                return ftp_definition
        elif self.protocol_name == 'http':
            with open(os.path.join(protocol_definition_path, "FTP-PACKET/httpDefineNew413.json")) as f:
                http_definition = json.loads(f.read())
                return http_definition
        elif self.protocol_name == 'ip':
            return
        else:
            return None

    def get_command_path(self, command):
        nodes = self.protocol_tree.all_nodes()
        command_path = []
        command_nid_path = []
        for n in nodes:
            if n.tag == command:
                command_nid_path = self.protocol_tree.rsearch(n.identifier)
        if command_nid_path:
            for nid in command_nid_path:
                command_path.append(self.protocol_tree.get_node(nid).tag)
        return command_path

"""
Test codes
"""
def main():
    f = open('./protocol_tree.txt', 'w')
    protocol = Protocol("ftp")
    print(protocol.protocol_tree)
    print(protocol.states)
    for node in protocol.get_command_path("PORT"):
        print(node)
if __name__ == '__main__':
    main()
