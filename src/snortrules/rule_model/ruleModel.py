"""
This file contains classes and methods for modeling the relationships
between rules in Network Intrusion Detection Systems.
"""

from enum import Enum
from treelib import Node, Tree
from snort_rules import *


class ProtoL3(Enum):
    IP = 1


class ProtoL4(Enum):
    TCP = 1
    UDP = 2
    ICMP = 3


class ProtoL5(Enum):
    http = 1
    ftp = 2
    imap = 3
    pop3 = 4
    ssl = 5
    dns = 6
    smtp = 7
    netbios = 8
    ntp = 9
    ldp = 10
    mysql = 11
    sip = 12
    dce = 13  # DCE/RPC
    smb = 14
    rdp = 15


class RuleInfo(object):
    """
    The rule information of a single rule, including the protocol and attack,
    as well as the primitives to be used in fuzzing.
    """
    def __init__(self, snortrule):
        self.snortrule = snortrule
        self.ruleAttr = SnortRuleAttr(self.snortrule)

    def protocol_info(self):
        proto_tmp = self.__get_header_protocol()
        # -------- protocol L3 -----------
        if proto_tmp == 'ip':
            l3_protocol = {'flag': ProtoL3.IP}
            if self.ruleAttr.get_opt_ip_proto():
                l3_protocol['ip_proto'] = self.ruleAttr.get_opt_ip_proto()
        else:
            l3_protocol = {}
        # -------- protocol L4 -----------
        l4_protocol = {}
        if proto_tmp == 'tcp':
            l4_protocol['flag'] = ProtoL4.TCP
            l4_protocol['flow'] = self.ruleAttr.get_opt_flow()
        elif proto_tmp == 'udp':
            l4_protocol['flag'] = ProtoL4.UDP
            l4_protocol['flow'] = self.ruleAttr.get_opt_flow()
        elif proto_tmp == 'icmp':
            l4_protocol['flag'] = ProtoL4.ICMP
            l4_protocol['icmp'] = self.ruleAttr.get_opt_icmp()
        # -------- protocol L5 -----------
        service = self.ruleAttr.get_opt_service()
        if service:
            l5_protocol = {'flag': []}
            for proto in service:
                l5_protocol['flag'].append(proto)
        else:
            l5_protocol = {}
        return l3_protocol, l4_protocol, l5_protocol

    def attack_info(self):
        attack = {'classtype': self.ruleAttr.get_opt_classtype(), 'flowbits': self.ruleAttr.get_opt_flowbits()}
        return attack

    def fuzz_primitives(self):
        primitives = []
        if 'content' in self.snortrule.opt_keyword_list:
            primitives.append("string")
        if 'pcre' in self.snortrule.opt_keyword_list:
            primitives.append("pcre")
        if ('tos' or 'ttl' or 'fragbits') in self.snortrule.opt_keyword_list:
            primitives.append("int")
        return primitives

    def __get_header_protocol(self):
        return self.snortrule.get_proto()


class RuleNode(object):
    """
    A rule node can be one rule or a certain part of a rule denoting the protocol mentioned in the rule.
    """
    def __init__(self, rule, protocol=None):
        self.rule = rule
        self.data = []
        self.protocol = protocol
        self.link = []

    def add_rule_data(self, data):
        if data:
            self.data.append(data)
            return True
        else:
            print("Invalid input:", data, ".\n")
            return False

    def set_link(self, link, index):
        if isinstance(link, RuleNodeLink):
            self.link.append({'link': link, 'index': index})
        else:
            print("Link must be RuleNodeLink type.\n")

    def get_link(self):
        if self.link:
            return self.link
        else:
            return None


class RuleNodeLink(object):
    """
    Rule node link denotes the correlation between nodes in terms of
    protocols.
    """
    def __init__(self, node1, node2):
        if isinstance(node1, RuleNode):
            self.node1 = node1
        else:
            print("Node1 must be a RuleNode!\n")
            self.node1 = None
        if isinstance(node2, RuleNode):
            self.node2 = node2
        else:
            print("Node2 must be a RuleNode!\n")
            self.node2 = None

    def get_node(self, index):
        if index == 1:
            return self.node1
        elif index == 2:
            return self.node2
        else:
            print("Wrong node index! Can only be 1 or 2!\n")
            return None


class RuleModel(object):
    def __init__(self, rule):
        self.node_lst_l3 = []
        self.node_lst_l4 = []
        self.node_lst_l5 = []
        self.node_lst = []
        self.protocol_lst = []
        self.rule = rule
        self.attack, self.flowbits = self.parse_attack()
        self.parse_protocol()

    def parse_protocol(self):
        l3, l4, l5 = RuleInfo(self.rule).protocol_info()
        # start parsing L3 protocol
        if l3 != {}:
            node = RuleNode(self.rule, protocol=l3['flag'])
            node.add_rule_data(l3['ip_proto'])
            self.node_lst_l3.append(node)
        # start parsing L4 protocol
        if l4 != {}:
            node = RuleNode(self.rule, protocol=l4['flag'])
            if l4['flag'] == ProtoL4.ICMP:
                node.add_rule_data(l4['icmp'])
            else:
                node.add_rule_data(l4['flow'])
            self.node_lst_l4.append(node)
        # start parsing L5 protocol
        if l5 != {}:
            node = RuleNode(self.rule, protocol=l5['flag'])
            self.node_lst_l5.append(node)
        # ----------------------------------------------------------
        # Add links between nodes
        if self.node_lst_l3:
            if self.node_lst_l4:
                for node3 in self.node_lst_l3:
                    for node4 in self.node_lst_l4:
                        link = RuleNodeLink(node3, node4)
                        node3.set_link(link, 1)
                        node4.set_link(link, 2)
        if self.node_lst_l4:
            if self.node_lst_l5:
                for node4 in self.node_lst_l4:
                    for node5 in self.node_lst_l5:
                        link = RuleNodeLink(node4, node5)
                        node4.set_link(link, 1)
                        node5.set_link(link, 2)
        self.node_lst = self.node_lst_l3 + self.node_lst_l4 + self.node_lst_l5

    def parse_attack(self):
        ruleinfo = RuleInfo(self.rule)
        attack = ruleinfo.attack_info()['classtype']
        flowbits = ruleinfo.attack_info()['flowbits']
        return attack, flowbits


class RuleGroup(object):
    """
    A rule node group contains rules that have something in common.
    """
    def __init__(self, attack=None):
        self.__rule_number = 0
        self.__by_attack = attack
        self.rule_list = []

    def add_rule(self, rule, attack=None):
        if isinstance(rule, RuleModel):
            if rule not in self.rule_list:
                self.rule_list.append(rule)
            else:
                print("Rule already exists!\n")
                return False
        else:
            print("Wrong rule instance type!\n")
            return False
        self.__rule_number += 1
        return True

    @property
    def by_attack(self):
        return self.__by_attack

    @property
    def rule_number(self):
        return self.__rule_number


class RuleSetModel(object):
    """
    Takes a ruleset as input and then build up the model for such ruleset.
    """
    def __init__(self, ruleset):
        self.ruleset = ruleset
        self.tree_root_lst = []
        self.rule_node_group_lst = []
        self.protocol_dict = {}
        self.attack_dict = {}
        self.__parse_ruleset()

    def __parse_ruleset(self):
        self.__parse_rule()

    def visualization(self):
        return

    def add_node(self):
        return

    def add_link(self, node1, node2, is_directed=False):
        return

    def get_model_structure(self):
        return

    def __parse_rule(self):
        for rule in self.ruleset:
            node_lst = []
            # --------------------------------------------------
            # Start parsing protocol information
            l3, l4, l5 = RuleInfo(rule).protocol_info()
            # start parsing L3 protocol
            if l3 != {}:
                node = RuleNode(rule)
                node_lst.append(node)
            # start parsing L4 protocol
            if l4 != {}:
                node = RuleNode(rule)
                node_lst.append(node)
            # start parsing L5 protocol
            if l5 != {}:
                node = RuleNode(rule)
                node_lst.append(node)
            # ---------------------------------------------------
            # Start parsing attack information
            attack = RuleInfo(rule).attack_info()
        print("Parse ruleset in PROTOCOL succeed!\n")
        return

    def __get_rule_node_groups(self, protocol=None, attack=None):
        rng_lst = []
        rng: RuleGroup
        for rng in self.rule_node_group_lst:
            if rng.by_attack == attack:
                rng_lst.append(rng)
        return rng_lst
