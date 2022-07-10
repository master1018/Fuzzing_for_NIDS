"""
很重要的文件
"""
path = "E:\\Github\\Fuzzing_for_NIDS\\src\\snortrules"
import sys
sys.path.append(path)
import os
import time
import json
from rule_parse.snort_rules import SnortRule, SnortRuleAttr, RuleFile
from boofuzz import *
import exrex
from alert_analysis.alert_inference import hex_str_to_char_str
from alert_analysis.alert_inference import byte_str_to_char_str
from protocol.protocols import Protocol
from protocol.test import alert_check_post_case_callback

#print("开始生成数据了捏")

data_format = [("name", None), ("data", None), ("type", ""), ("length", 0), ("fuzzable", False)]


def get_a_data_entry():
    data = {}
    for item in data_format:
        data[item[0]] = item[1]
    return data


class FuzzCodeGenerator(object):
    def __init__(self, fuzz_primitives, protocol, target):
        self.fuzz_primitives = fuzz_primitives
        self.protocol = protocol
        self.session = None
        self.target = target
        self.nodes = []

    def get_session_definition(self):
        if self.session:
            return self.session
        else:
            return None

    def get_target_definition(self):
        if self.target:
            return self.target
        else:
            return None

    def get_nodes_definition(self):
        if self.nodes:
            return self.nodes
        else:
            return None

    def get_single_node_definition(self, name):
        for node in self.nodes:
            if node.name == name:
                return node
        return None

    """
    先获取协议树
    """
    def generate_codes(self):
        self.session = Session(
            target=Target(connection=TCPSocketConnection(self.target[0], port=self.target[1])),
            ignore_connection_issues_when_sending_fuzz_data=True,
            post_test_case_callbacks=[alert_check_post_case_callback]
        )

        fill_protocol_default_requests(self.protocol, self.session)

        for request in self.fuzz_primitives.requests:
            if not request['name'].startswith('Default'):
                s_initialize(request['name'])
            else:
                continue
            if 'data' in request:
                for data_entry in request['data']:
                    if data_entry['type'] == 'string':
                        s_string(data_entry['data'], name=data_entry['name'], fuzzable=data_entry['fuzzable'], encoding='utf-8')
                    elif data_entry['type'] == 'delimiter':
                        s_delim(data_entry['data'], fuzzable=data_entry['fuzzable'], name=data_entry['name'])
                    elif data_entry['type'] == 'CRLF':
                        s_static(data_entry['data'], name=data_entry['name'])
            self.nodes.append(s_get(request['name']))

        for relation in self.fuzz_primitives.request_relationship:
            if isinstance(relation, str):
                if relation[0] == 'NONE':
                    self.session.connect(s_get(relation[1]))
            elif relation[0] == 'Default-NONE':
                self.session.connect(s_get(relation[1]))
            else:
                self.session.connect(s_get(relation[0]), s_get(relation[1]))

        return self.session

    def _node_generation(self):
        pass


class FuzzPrimitive(object):
    def __init__(self):
        self.requests = []
        self.request_relationship = []

    def add_request(self, name):
        if self.has_request(name) is None:
            request = {'name': name}
            self.requests.append(request)
            return True
        else:
            print("Request already exists.")
            return False

    def add_data_to_request(self, req_name, data):
        req_index = self.has_request(req_name)
        if req_index is None:
            print("Request not found:", req_name, ". Data add failed.")
            return False
        else:
            self.requests[req_index]['data'] = data
        return True

    def add_request_relationship(self, req1, req2):
        req1_index = self.has_request(req1)
        if req1_index is None:
            print("Request not found:", req1)
            return False
        req2_index = self.has_request(req2)
        if req2_index is None:
            print("Request not found:", req2)
            return False
        if tuple([req1, req2]) in self.request_relationship:
            print("Request sequence already defined.")
            return False
        else:
            self.request_relationship.append(tuple([req1, req2]))

    def has_request(self, name):
        for index, request in enumerate(self.requests):
            if request['name'] == name:
                return index
        return None

    def has_request_relation(self, req1, req2):
        for index, relation in enumerate(self.request_relationship):
            if relation[0] == req1 and relation[1] == req2:
                return index
        return None


def generate_data_from_rule(rule: SnortRule, protocol):
    options = SnortRuleAttr(rule)
    contents = options.get_opt_content()
    msg_format = Protocol(protocol).proto_definition["request"]
    isdataat = options.get_opt_isdataat()
    data_list = []

    # Fill rule's contents into specific fields defined in message format
    for key, value in msg_format.items():
        if value['type'] == 'delimiter' and key != 'newline':
            data = get_a_data_entry()
            data['name'] = key
            data['type'] = 'delimiter'
            data['data'] = value['value'][0]
            data['fuzzable'] = True
            data_list.append(data)
            continue
        elif value['type'] == 'string':
            data = get_a_data_entry()
            data['name'] = key
            data['type'] = value['type']
            data['fuzzable'] = True
            if contents:
                for content in contents[:]:
                    # some content match strings contain hex strings. Switch them into chars.
                    content_match = content['match'].split('|')
                    if len(content_match) >= 3:
                        index = 1
                        content['match'] = ''
                        while index < len(content_match):
                            content['match'] += content_match[index - 1] + hex_str_to_char_str(content_match[index])
                            index += 2
                            content['match'] += content_match[index - 1]

                    if content['match'].strip() in value['value']:
                        data['data'] = content['match']
                        contents.remove(content)
                        data_list.append(data)
                        break
                    if not data['data']:
                        data['data'] = contents[0]['match']
                        contents.remove(contents[0])
                        data_list.append(data)
            else:
                if value['value']:
                    data['data'] = value['value'][0]
                else:
                    data['data'] = "fuzz"
                data_list.append(data)
        elif key == 'newline':
            break
    """
    # add pcre string into data list
    pcre = options.get_opt_pcre()
    if pcre:
        pcre_str = exrex.getone(pcre['pattern'])
        data = get_a_data_entry()
        data['name'] = 'pcre'
        data["data"] = pcre_str
        data["type"] = "string"
        data_list.append(data)

    data = get_a_data_entry()
    data['data'] = '\r\n'
    data['name'] = 'newline'
    data['type'] = 'CRLF'
    data_list.append(data)

    return data_list
    """

def generate_data_from_definition(data_type, name, data, length, primitive_type):
    return


def fill_protocol_default_requests(protocol, session):
    if protocol == "ftp":
        s_initialize('Default-USER')
        s_static('USER anon\r\n')

        s_initialize('Default-PASS')
        s_static('PASS anon\r\n')

        s_initialize('Default-PORT')
        s_static('PORT 127,0,0,1,4,1\r\n')

        s_initialize('Default-PASV')
        s_static('PASV\r\n')

        s_initialize('Default-REST')
        s_static('REST 9999\r\n')

        s_initialize('Default-RNFR')
        s_static('RNFT test\r\n')

        s_initialize('Default-QUIT')
        s_static('QUIT\r\n')

        session.connect(s_get('Default-USER'))
        session.connect(s_get("Default-USER"), s_get("Default-PASS"))
        session.connect(s_get("Default-PASS"), s_get("Default-PORT"))
        session.connect(s_get("Default-PASS"), s_get("Default-PASV"))
        session.connect(s_get("Default-PASS"), s_get("Default-REST"))
        session.connect(s_get("Default-PASS"), s_get("Default-RNFR"))

    elif protocol == "http":
        pass
    else:
        pass


"""
Test codes
"""
if __name__ == '__main__':
    d = get_a_data_entry()
    a = Protocol('ftp').proto_definition['request']
    print(a, "\n\n")
    rule_file_path = "/root/github/internet_product_safe_test/snortrules/protocol/oneRule.rules"
    rule_list = RuleFile(rule_file_path).get_rule_set()
    for rule in rule_list:
        print(generate_data_from_rule(rule, 'ftp'))
