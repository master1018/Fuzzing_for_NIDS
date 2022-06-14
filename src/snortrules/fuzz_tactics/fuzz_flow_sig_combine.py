#!/usr/bin/env python
import random
path = "/root/github/internet_product_safe_test/snortrules"

import sys

sys.path.append(path)
from rule_parse.snort_rules import *
from fuzz_exec.rule_selection import RuleInfo
from fuzz_tactics.fuzz_flow_base import FuzzStrategyFlowBase
from alert_analysis.alert_inference import hex_str_to_char_str


class Signature(object):
    def __init__(self, rule_id, index=0, pattern_str="", sticky_buffer=None, start_pos=0, sig_type=None):
        self.index = index
        self.pattern_str = pattern_str
        self.sticky_buffer = sticky_buffer
        # Chosen starting position of the signature in the sticky buffer
        self.start_pos = start_pos
        # positioning range of the signature in the sticky buffer
        self.range = None
        self.sig_type = sig_type
        self.rule_id = rule_id

    @property
    def length(self):
        # automatically count the length if the pattern string is given
        if not self.pattern_str:
            print("Pattern string not specified. Cannot get length.")
            return 0
        else:
            return len(self.get_transformed_pattern())

    def set_sig(self, match_string):
        # Check if match string contains illegal characters.
        illegal_characters = (';', '\\', '"')
        if self.sig_type == "content":
            for c in match_string:
                if c in illegal_characters:
                    print("The match string contains illegal character:", c)
                    return False
            self.pattern_str = match_string
            return True
        else:
            self.pattern_str = match_string
            return True

    def set_start_pos(self, s_pos):
        if s_pos < 0:
            print("Invalid starting position index.")
        else:
            self.start_pos = s_pos

    def get_transformed_pattern(self):
        if self.sig_type != "content":
            return self.pattern_str
        if self.pattern_str.find('|') == -1:
            return self.pattern_str
        else:
            trans_pattern_str = ""
            e_pointer = 0
            while True:
                s_pointer = self.pattern_str.find('|', e_pointer)
                if s_pointer != -1:
                    trans_pattern_str += self.pattern_str[e_pointer:s_pointer]
                    e_pointer = self.pattern_str.find('|', s_pointer + 1)
                    trans_pattern_str += hex_str_to_char_str(self.pattern_str[s_pointer + 1:e_pointer])
                    e_pointer += 1
                else:
                    trans_pattern_str += self.pattern_str[e_pointer:]
                    break
            return trans_pattern_str

    def construct_from_content(self, content):
        self.sig_type = "content"
        if not self.set_sig(content['match']):
            return False
        if content['sticky'] != '':
            self.sticky_buffer = content['sticky']
        # -1 means no limit
        if content['depth'] or content['offset'] or content['distance'] or content['within']:
            self.range = {}
            if content['depth'] or content['offset']:
                if content['depth']:
                    s_pos = content['depth']
                else:
                    s_pos = -1
                if content['offset']:
                    e_pos = content['offset']
                else:
                    e_pos = -1
                self.range['absolute'] = (s_pos, e_pos)
            if content['distance'] or content['within']:
                if content['distance']:
                    s_pos = content['distance']
                else:
                    s_pos = -1
                if content['within']:
                    e_pos = content['within']
                else:
                    e_pos = -1
                self.range['relative'] = (s_pos, e_pos)
        return True

    def construct_from_pcre(self, pcre):
        self.sig_type = "pcre"
        if pcre["sticky"] != '':
            self.sticky_buffer = pcre['sticky']
        self.pattern_str = pcre['pattern']
        return True


class FuzzStrategySigCombine(FuzzStrategyFlowBase):
    def __init__(self, rule_file, protocols, target, max_rule_num=10, iteration=5):
        super(FuzzStrategySigCombine, self).__init__('sig_combine', rule_file, protocols, target)
        self.rule_list = self.rule_file.get_rule_set(is_active=True)  # list of rules as SnortRule
        self._combined_sig_dict = {}
        self._adopted_rules = []
        self.rule_groups = None
        self._combined_rule_num = 0
        self.max_rule_num = max_rule_num
        self.iteration = iteration

    def get_combined_signatures(self):
        return self._combined_sig_dict

    def rule_selection(self):
        # group rules by protocols
        self.rule_groups = {}
        for rule in self.rule_list:
            rule_proto = RuleInfo(rule).protocol_info()
            for proto in rule_proto[2]['flag']:
                if proto in self.protocol_list:
                    if proto in self.rule_groups.keys():
                        self.rule_groups[proto].append(rule)
                    else:
                        self.rule_groups[proto] = []
                        self.rule_groups[proto].append(rule)
                else:
                    print("Unsupported protocol:", proto)
        #print(self.rule_groups)

    def rule_trim(self):
        return

    def implement_strategy(self):
        considered_rules = []
        if self.rule_groups is None:
            print("Please run rule_selection first.\n")
        else:
            for proto, rules in self.rule_groups.items():
                if len(rules) < self.max_rule_num:
                    considered_rules.append(rules)
                else:
                    for i in range(self.iteration):
                        rule_pool = rules
                        considered_rules.append(random.sample(rules, self.max_rule_num))
                        rules_to_combine = [rule for rule in rule_pool if rule not in considered_rules]
                        for rule in rules_to_combine:
                            rule_attr = SnortRuleAttr(rule)
                            rule_id = '-'.join([str(rule_attr.get_opt_gid()), str(rule_attr.get_opt_sid())])
                            contents = rule_attr.get_opt_content()
                            previous_signature = Signature(rule_id)
                            previous_signature.construct_from_content(contents[0])
                            rule_adopt_flag = True
                            for content in contents:
                                signature = Signature(rule_id)
                                signature.construct_from_content(content)
                                if content['distance'] is not None or content['within'] is not None:
                                    if self._fit_signature_into_combined_list(signature, previous_signature):
                                        continue
                                    else:
                                        self._pop_out_signatures(rule_id)
                                        rule_adopt_flag = False
                                        break
                                else:
                                    if self._fit_signature_into_combined_list(signature):
                                        continue
                                    else:
                                        self._pop_out_signatures(rule_id)
                                        rule_adopt_flag = False
                                        break
                            if rule_adopt_flag:
                                self._adopted_rules.append(rule)
                                self._combined_rule_num += 1
        return self._combined_sig_dict

    def _fit_signature_into_combined_list(self, signature, pre_sig=None):
        """
        Try to fit a signatures into the list of precedently combined signatures.
        If the combination succeeds, the index of each signature in the same sticky buffer
        would be updated as well.
        :param signature: signatures to combine
        :return: True if the combination succeeds, False otherwise.
        """

        sticky_buffer = signature.sticky_buffer
        if sticky_buffer is None:
            sticky_buffer = "none"

        # no previous signature of the same sticky buffer
        if sticky_buffer not in self._combined_sig_dict.keys():
            self._combined_sig_dict[sticky_buffer] = []
            if signature.range is not None:
                if 'absolute' in signature.range.keys():
                    # if signature has depth modifier
                    if signature.range['absolute'][0] != -1:
                        signature.start_pos = signature.range['absolute'][0]
                    else:
                        # put the signature at the beginning of the sticky buffer
                        signature.start_pos = 0
            self._combined_sig_dict[sticky_buffer].append(signature)
            return True
        else:
            # if the signature has no range modifiers, put it at the rear
            if signature.range is None:
                signature.index = len(self._combined_sig_dict[sticky_buffer])
                ########################################################################################################################length 是个啥玩意
                signature.start_pos = self._combined_sig_dict[sticky_buffer][0].start_pos + self._combined_sig_dict[sticky_buffer][0].length
                self._combined_sig_dict[sticky_buffer].append(signature)
                return True
            # if the signature does have range modifier, parse the absolute and relative modifiers in turn
            else:
                available_pos = self._get_currently_available_positions(sticky_buffer, previous_sig=pre_sig)
                # pick the first available position into which the signature can fit
                if available_pos == None:
                    return False
                for pos in available_pos:
                    # check absolute modifiers first
                    if 'absolute' in signature.range.keys():
                        # offset modifier
                        if signature.range['absolute'][0] != -1:
                            if pos[1] == -1:
                                if signature.range['absolute'][0] >= pos[0]:
                                    start = signature.range['absolute'][0]
                                else:
                                    start = pos[0]
                            elif signature.range['absolute'][0] < pos[1]:
                                if signature.range['absolute'][0] < pos[0]:
                                    start = pos[0]
                                else:
                                    # start denotes the proper position after which the signature can start
                                    start = signature.range['absolute'][0]
                            else:
                                continue
                        else:
                            start = pos[0]
                        # depth modifier
                        if signature.range['absolute'][1] != -1:
                            if pos[1] != -1:
                                if signature.range['absolute'][1] > pos[0]:
                                    if signature.range['absolute'][1] < pos[1]:
                                        # end denotes the position before which the signature ought to end
                                        end = signature.range['absolute'][1]
                                    else:
                                        end = pos[1]
                                else:
                                    continue
                            else:
                                end = pos[1]
                        else:
                            end = pos[1]
                        # verify if the signature can fit into the available position in question
                        if end - start < signature.length:
                            continue
                        abs_range = (start, end)
                    else:
                        if pos[1] - pos[0] < signature.length:
                            continue
                        else:
                            abs_range = (pos[0], pos[1])
                    # check relative modifiers then
                    if 'relative' in signature.range.keys():
                        if pre_sig is None:
                            raise Exception('Previous signature is not given for sig:{}'.format(signature.pattern_str))
                        elif pre_sig.start_pos >= abs_range[1]:
                            continue
                        else:
                            # distance modifier
                            if signature.range['relative'][0] != -1:
                                start = pre_sig.start_pos + pre_sig.length + signature.range['relative'][0]
                                if start < abs_range[0]:
                                    continue
                            else:
                                start = abs_range[0]
                            # within modifier
                            if signature.range['relative'][1] != -1:
                                end = pre_sig.start_pos + pre_sig.length + signature.range['relative'][1]
                                if end >= abs_range[1]:
                                    continue
                            else:
                                end = abs_range[1]
                            # check if relative range is reasonable
                            if end - start < signature.length:
                                continue
                            else:
                                # combine succeeded! Set the signature and put it into the combined list
                                signature.start_pos = start
                                return True
                    else:
                        signature.start_pos = abs_range[0]
                        return True

    def _pop_out_signatures(self, rule_id):
        for sig_list in self._combined_sig_dict.values():
            for sig in sig_list:
                if sig.rule_id == rule_id:
                    sig_list.remove(sig)

    def _sort_list_by_sig_index(self):
        for sig_list in self._combined_sig_dict.values():
            sig_list.sort(key=self._get_signature_start_position)
            index = 0
            for sig in sig_list:
                sig.index = index
                index += 1

    @staticmethod
    def _get_signature_start_position(signature):
        return signature.start_pos

    def _get_currently_available_positions(self, sticky_buffer, previous_sig=None):
        """
        Get the curretly available position sections between the combined sigantures.
        If the previous_sig is given, start searching from the given siganture.
        :param sticky_buffer:
        :param previous_sig:
        :return:
        """
        if sticky_buffer not in self._combined_sig_dict.keys():
            print("The sticky buffer:", sticky_buffer, " is not specified yet.")
            return None
        else:
            # there would be at least one available position in the list, namely the position that
            # follows the last signature
            available_positions = []
            if previous_sig:
                
                if previous_sig in self._combined_sig_dict[sticky_buffer]:
                    previous_sig_end = previous_sig.start_pos + previous_sig.length
                else:
                    raise ValueError("The given previous signature is not in the combined diction.")
            else:
                previous_sig_end = 0
            for sig in self._combined_sig_dict[sticky_buffer]:
                if sig.start_pos - previous_sig_end > 0:
                    pos = (previous_sig_end, sig.start_pos)
                    available_positions.append(pos)
                previous_sig_end = sig.start_pos + sig.length
            rear_pos = (previous_sig_end, -1)
            available_positions.append(rear_pos)
            return available_positions

    def fuzz_code_generation(self):
        return

    def _update_sig_index(self):
        pass

# -------------------------------------
# test codes
# -------------------------------------
if __name__== "__main__":
    rule_file_path = "/root/github/internet_product_safe_test/snortrules/protocol/oneRule_2.rules"
    fuzz_strategy = FuzzStrategySigCombine(rule_file_path, ['ftp'], ('172.17.0.2', 21))
    fuzz_strategy.rule_selection()
    fuzz_strategy.implement_strategy()
    fuzz_strategy.fuzz_code_generation()
    print(fuzz_strategy.session)