path = "/root/github/internet_product_safe_test/snortrules"

import sys

sys.path.append(path)
from rule_parse.snort_rules import *
from rule_model.rule_model import RuleInfo
from protocol.protocols import Protocol
import Levenshtein
import json
import os

rule_selection_method = [
    'signature',
    'rule_state',
    'protocol',
    'sequence'
]


def get_rule_protocol(rule):
    rule_info = RuleInfo(rule)
    return rule_info.protocol_info()


def get_rule_protocol_state(rule):
    protocols = get_rule_protocol(rule)
    l5_proto = protocols[2]
    contents = SnortRuleAttr(rule).get_opt_content()
    for content in contents:
        for proto in l5_proto['flag']:
            p = Protocol(proto)
            s_result = p.get_command_path(content['match'].strip())
            state_order = []
            try:
                for node in s_result:
                    state_order.append(node)
            except:
                pass
            state_order.reverse()
            return state_order
    return None


class RuleSelector(object):
    def __init__(self, rule_file: RuleFile, protocol, method):
        self.rule_list = rule_file.get_rule_set()
        self.protocol = protocol
        if method in rule_selection_method:
            self.method = method
        else:
            print("Unsupported rule selection method:", method, ". Using default sequence.")
            self.method = 'sequence'
        self.selected_rules = None

    def select_rules_by_method(self):
        if self.method == 'sequence':
            return self._select_by_sequence()
        elif self.method == 'signature':
            return self._select_by_signature()
        elif self.method == 'protocol':
            return self._select_by_protocol()
        elif self.method == 'rule_state':
            return self._select_by_rule_state()
        else:
            return None

    def _select_by_signature(self):
        pass

    def _select_by_rule_state(self):
        pass

    def _select_by_protocol(self):
        pass

    def _select_by_sequence(self):
        # self.selected_rules = []
        # for rule in self.rule_list:
        #     self.selected_rules.append(rule)
        self.group_by_protocol_state()
        return True

    def _calc_levenshtein_distance(self, r1, r2):
        pass

    def _calc_option_distance(self, r1, r2):
        pass

    def _calc_signature_relationship(self, sig1, sig2):
        pass

    def _get_rule_state(self, rule):
        pass

    def _group_by_signature(self):
        pass

    def _group_by_sequence(self):
        pass

    def group_by_protocol_state(self):
        self.selected_rules = {"NONE": []}
        for rule in self.rule_list:
            rule_proto_state = get_rule_protocol_state(rule)
            if rule_proto_state:
                if len(rule_proto_state[:-1]) == 1:
                    if rule_proto_state[0] == 'NONE':
                        self.selected_rules['NONE'].append(rule)
                else:
                    if tuple(rule_proto_state[:-1]) not in self.selected_rules:
                        self.selected_rules[tuple(rule_proto_state[:-1])] = []
                        self.selected_rules[tuple(rule_proto_state[:-1])].append(rule)
                    else:
                        self.selected_rules[tuple(rule_proto_state[:-1])].append(rule)
            else:
                self.selected_rules["NONE"].append(rule)
        return True

    def _group_by_rule_state(self):
        pass


"""
Test codes
"""
# protocol_definition_path = "/root/github/internet_product_safe_test/snortrules/protocol"
# rule_file_path = "/root/github/internet_product_safe_test/snortrules/protocol/oneRule.rules"
# rf = RuleFile(rule_file_path)
#
# rule_str = "alert tcp $EXTERNAL_NET any -> $HOME_NET 21 ( msg:\"PROTOCOL-FTP SITE CHMOD overflow attempt\"; " \
#            "flow:to_server,established; content:\"SITE\",nocase; content:\"CHMOD\",distance 0,nocase; isdataat:200,relative; " \
#            "pcre:\"/^SITE\s+CHMOD\s[^\n]{200}/smi\"; metadata:ruleset community; service:ftp; " \
#            "reference:bugtraq,10181; reference:bugtraq,9483; reference:bugtraq,9675; reference:cve,1999-0838; " \
#            "reference:nessus,12037; classtype:attempted-admin; sid:2340; rev:15; )"
# r = SnortRule(rule_str)
#
# rule_selector = RuleSelector(rf, 'ftp', 'sequence')
# rule_selector.group_by_protocol_state()
# print(rule_selector.selected_rules)
