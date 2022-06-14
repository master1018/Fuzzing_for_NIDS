"""
This file contains classes and methods for parsing Snort rule files and Snort rules in them
"""

import spacy
from string import digits

sticky_buffer_keyword_lst = [
    'file_data',
    'http_client_body',
    'http_cookie',
    'http_header',
    'http_uri',
    'http_raw_uri',
    'http_raw_header',
    'http_raw_cookie',
    'http_stat_code',
    'http_stat_msg',
    'http_method',
    'pkt_data',
    'raw_data',
    'sip_body',
    'sip_header'
]


class RuleFile(object):
    """
    Including operations for parsing and counting rules in one Snort rule file.
    Takes in a path of a snort rule file and parse it into multiple rules.
    """
    rule_number = 0
    active_rule_number = 0
    commented_rule_number = 0
    keywords = []

    def __init__(self, rule_file_path):
        self.rule_file_path = rule_file_path
        self.fo = open(self.rule_file_path, "r")

#    def __del__(self):
#        if self.fo:
#            self.fo.close()

    def get_file_name(self):
        names = self.rule_file_path.split("/")
        return names[-1]

    def get_rule_set(self, is_active=False):
        rule_list = []
        for line in self.fo:
            fields = line.split(" ")
            if fields[0] == '#' and len(fields) > 1 and not is_active:
                if fields[1] == ("alert" or "drop"):
                    rule_list.append(SnortRule(line))
            elif fields[0] == ("alert" or "drop"):
                rule_list.append(SnortRule(line))
        return rule_list

    def rule_counts(self):
        for line in self.fo:
            fields = line.split(" ")
            if fields[0] == '#' and len(fields) > 1:
                if fields[1] == ("alert" or "drop"):
                    self.rule_number += 1
                    self.commented_rule_number += 1
            elif fields[0] == ("alert" or "drop"):
                self.rule_number += 1
                self.active_rule_number += 1
        print("Rule file:", self.get_file_name(), ", rule number =", self.rule_number, ", active rule =",
              self.active_rule_number, ", commented rule =", self.commented_rule_number)
        return self.rule_number, self.active_rule_number, self.commented_rule_number


class SnortRule(object):
    """
    Takes in a Snort rule and parse it for later use
    """
    def __init__(self, rule):
        self.rule = rule
        self.rule_header = []
        self.rule_options = []
        self.opt_keyword_list = []
        self.rule_opt_pairs = {}
        # ---------------------------------------------------
        # Start parsing Snort rules
        self._set_rule_header()
        self._set_rule_options()
        self._parse_rule_options()

    # ------------------------------------------------------
    # Parses Snort rules and provides interfaces for use
    def _set_rule_header(self):
        if not self.is_rule(self.rule):
            return
        if not self.is_active(self.rule):
            tmp = self.rule.strip("# ")
            headers = tmp.split(" (")
        else:
            headers = self.rule.split(" (")
        self.rule_header = headers[0].split(" ")

    def _set_rule_options(self):
        if self.is_rule(self.rule):
            options = self.rule.split(" ( ")
            option_list = options[1].split("; ")
            # delete the first space at the beginning of each option
            self.rule_options = [elem.strip() for elem in option_list]
            # delete the last ")"
            del (self.rule_options[-1])
            self.__proc_special_block()

    def __proc_special_block(self):
        """
        This method is to deal with rule options that have special characters in them,
        such as pcre, msg. They usually include '; ', '"' and ':' which makes it hard to
        split the rule options simply with the given character ';'.
        """
        for elem in self.rule_options[:]:
            tmp = elem.split(":")
            if tmp[0] == ("pcre" or "msg"):
                m = self.rule_options.index(elem)
                n = m
                while self.rule_options[n][-1] != '"':
                    n += 1
                j = m
                while j != n:
                    j += 1
                    self.rule_options[m] = self.rule_options[m] + self.rule_options[j]
                del self.rule_options[m+1:j+1]
                break

    def _parse_rule_options(self):
        for elem in self.rule_options:
            tmp = elem.split(":")
            # deal with special options (e.g., pcre, msg or content) that contain ':'
            if len(tmp) > 2:
                i = 2
                while i < len(tmp):
                    tmp[1] += tmp[i]
                    i += 1
            # build up option keyword list for the rule
            self.opt_keyword_list.append(tmp[0])
            self.opt_keyword_list = list(set(self.opt_keyword_list))
            # build up dictionary for keyword-value pairs
            if len(tmp) > 1:
                if tmp[0] in self.rule_opt_pairs:
                    self.rule_opt_pairs[tmp[0]].append(tmp[1])
                else:
                    self.rule_opt_pairs.setdefault(tmp[0], []).append(tmp[1])
            else:
                self.rule_opt_pairs[tmp[0]] = None
            #if tmp[0] == 'flowbits':
            #    print(self.rule)

    def get_action(self):
        return self.rule_header[0]

    def get_src_ip(self):
        return self.rule_header[2]

    def get_dst_ip(self):
        return self.rule_header[5]

    def get_src_port(self):
        return self.rule_header[3]

    def get_dst_port(self):
        return self.rule_header[6]

    def get_proto(self):
        return self.rule_header[1]

    def get_direction(self):
        return self.rule_header[4]

    @classmethod
    def is_active(cls, rule):
        fields = rule.split(" ")
        if fields[0] == "#" and len(fields) > 1:
            return False
        else:
            return True

    @classmethod
    def is_rule(cls, rule):
        fields = rule.split(" ")
        if fields[0] == '#' and len(fields) > 1:
            if fields[1] == ("alert" or "drop"):
                return True
            else:
                return False
        elif fields[0] == ("alert" or "drop"):
            return True
        else:
            return False


class SnortRuleAttr(object):
    """
    This class provides APIs for accessing each option in Snort rules
    """
    def __init__(self, snortrule):
        self.snortrule = snortrule
        self.sticky_buffer = self.__parse_opt_sticky_buffer_blocks()

    # ----------------------------------------------
    # APIs for general rule options
    def parse_opt_msg(self):
        """
        TO-BE-DONE
        """
        txt = self.snortrule.rule_opt_pairs['msg'][0]
        nlp = spacy.load("en_core_web_sm")
        msg = nlp(txt)
        print(msg)
        return

    def get_opt_reference(self):
        ref_lst = []
        if 'reference' in self.snortrule.rule_opt_pairs:
            ref_lst = self.snortrule.rule_opt_pairs['reference']
        ref_dict = {}
        for ref in ref_lst:
            tmp = ref.split(',')
            ref_dict.setdefault(tmp[0], []).append(tmp[1])
        return ref_dict, ref_dict.keys()

    def get_opt_classtype(self):
        if 'classtype' in self.snortrule.rule_opt_pairs:
            return self.snortrule.rule_opt_pairs['classtype'][0]
        else:
            return None

    def get_opt_metadata(self):
        metadata_dict = {}
        if 'metadata' in self.snortrule.rule_opt_pairs:
            description = self.snortrule.rule_opt_pairs['metadata'][0].split(',')
            for desc in description:
                tmp = desc.split()
                if len(tmp) < 3:
                    metadata_dict[tmp[0]] = tmp[1]
                elif tmp[0] not in metadata_dict:
                    metadata_dict[tmp[0]] = []
                    metadata_dict[tmp[0]].append(tmp[1:])
                else:
                    metadata_dict[tmp[0]].append(tmp[1:])
            return metadata_dict
        else:
            return None

    def get_opt_gid(self):
        if 'gid' in self.snortrule.rule_opt_pairs:
            return int(self.snortrule.rule_opt_pairs['gid'][0])
        else:
            return -1

    def get_opt_sid(self):
        if 'sid' in self.snortrule.rule_opt_pairs:
            return int(self.snortrule.rule_opt_pairs['sid'][0])
        else:
            return -1

    def get_opt_rev(self):
        if 'rev' in self.snortrule.rule_opt_pairs:
            return int(self.snortrule.rule_opt_pairs['rev'][0])
        else:
            return -1

    # -----------------------------------------------
    # Payload rule options
    def get_opt_content(self):
        if 'content' in self.snortrule.opt_keyword_list:
            index_list = self.__option_index("content")
            content_list = self.snortrule.rule_opt_pairs["content"]
            contents = []
            for item in content_list:
                content = {'match': item.split(',')[0].strip('"'), 'nocase': 0, 'rawbytes': 0, 'fast_pattern': 0,
                           'depth': None, 'offset': None, 'distance': None, 'within': None, 'sticky': '', 'neg': 0}
                if content['match'][0] == '!':
                    content['neg'] = 1
                    content['match'] = content['match'][1:].strip('"')
                modifiers = item.split(',')[1:]
                for m in modifiers:
                    if m == 'nocase' or m == 'rawbytes' or m == 'fast_pattern':
                        content[m] = 1
                    else:
                        content[m.split()[0]] = self.__is_name_or_num(m.split()[1])
                index = index_list[content_list.index(item)]
                content['opt_index'] = index
                for key, value in self.sticky_buffer.items():
                    if index < value:
                        continue
                    elif index > value:
                        content['sticky'] = key
                contents.append(content)
            return contents
        else:
            return None

    def get_opt_isdataat(self):
        if 'isdataat' in self.snortrule.rule_opt_pairs:
            isdataat = {'neg': 0, 'pos': 0, 'relative': 0, 'rawbytes': 0, 'sticky': ''}
            tmp = self.snortrule.rule_opt_pairs["isdataat"][0].split(',')
            if tmp[0][0] == '!':
                isdataat['neg'] = 1
                isdataat['pos'] = self.__is_name_or_num(tmp[0].strip('!'))
            else:
                isdataat['pos'] = self.__is_name_or_num(tmp[0])
            if len(tmp) > 1:
                if tmp[1] == 'relative':
                    isdataat['relative'] = 1
                else:
                    isdataat['rawbytes'] = 1
            index = self.__option_index('isdataat')[0]
            isdataat['opt_index'] = index
            for key, value in self.sticky_buffer.items():
                if index < value:
                    continue
                elif index > value:
                    isdataat['sticky'] = key
            return isdataat
        else:
            return None

    def get_opt_pcre(self):
        if 'pcre' in self.snortrule.rule_opt_pairs:
            pcre_list = []
            index_list = self.__option_index("pcre")
            list_index = 0
            for pcre in self.snortrule.rule_opt_pairs['pcre']:
                exp = pcre.strip('"')
                re = {'pattern': '', 'options': '', 'sticky': ''}
                if exp[-1] == "/":
                    re['pattern'] = exp[1:-1]
                else:
                    tmp = exp[1:]
                    i = len(tmp)
                    while tmp[i-1] != "/":
                        i -= 1
                    re['pattern'] = tmp[:i-1]
                    re['options'] = tmp[i:]
                re['index'] = index_list[list_index]

                for key, value in self.sticky_buffer.items():
                    if re['index'] < value:
                        continue
                    elif re['index'] > value:
                        re['sticky'] = key
                pcre_list.append(re)
                list_index += 1
            return pcre_list
        else:
            return None

    def get_opt_cvs(self):
        if 'cvs' in self.snortrule.rule_opt_pairs:
            return self.snortrule.rule_opt_pairs["cvs"][0]
        else:
            return None

    def get_opt_asn1(self):
        if 'asn1' in self.snortrule.rule_opt_pairs:
            asn1 = {'bt_string': 0, 'db_overflow': 0, 'os_len': 0, 'ab_offset': 0, 're_offset': 0}
            tmp = self.snortrule.rule_opt_pairs['asn1'][0].split(', ')
            for elem in tmp:
                if elem == "bitstring_overflow":
                    asn1['bt_string'] = 1
                elif elem == 'double_overflow':
                    asn1['db_overflow'] = 1
                else:
                    key = elem.split()[0]
                    value = int(elem.split()[1])
                    if key == 'oversize_length':
                        asn1['os_len'] = value
                    elif key == 'absolute_offset':
                        asn1['ab_offset'] = value
                    else:
                        asn1['re_offset'] = value
            return asn1
        else:
            return None

    def get_opt_byte_test(self):
        if 'byte_test' in self.snortrule.opt_keyword_list:
            parsed_byte_test_lst = []
            byte_test_option_list = self.snortrule.rule_opt_pairs['byte_test']
            index_list = self.__option_index('byte_test')
            for item in byte_test_option_list:
                tmp = item.split(',')
                byte_test = {'bytes': int(tmp[0]), 'operator': tmp[1].strip(), 'value': 0, 'offset': self.__is_name_or_num(tmp[3])}
                if len(tmp) > 4:
                    for elem in tmp[4:]:
                        elem = elem.strip()
                        s = elem.split()[0]
                        if s == 'relative':
                            byte_test['relative'] = 1
                        elif s == 'big':
                            byte_test['endian'] = 'big'
                        elif s == 'little':
                            byte_test['endian'] = 'little'
                        elif s == 'hex':
                            byte_test['string'] = 'hex'
                            try:
                                byte_test['value'] = int(tmp[2], 16)
                            except ValueError:
                                byte_test['value'] = tmp[2]
                        elif s == 'oct':
                            byte_test['string'] = 'oct'
                            try:
                                byte_test['value'] = int(tmp[2], 8)
                            except ValueError:
                                byte_test['value'] = tmp[2]
                        elif s == 'dec':
                            byte_test['string'] = 'dec'
                            try:
                                byte_test['value'] = int(tmp[2])
                            except ValueError:
                                byte_test['value'] = tmp[2]
                        elif s == 'dce':
                            byte_test['dec'] = 1
                        elif s == 'bitmask':
                            byte_test['bitmask'] = int(elem.split()[1], 16)
                        else:
                            continue
                else:
                    if tmp[2][:2] == '0x':
                        byte_test['value'] = int(tmp[2], 16)
                    elif tmp[2][:2] == '0o':
                        byte_test['value'] = int(tmp[2], 8)
                    else:
                        byte_test['value'] = int(tmp[2])
                byte_test['sticky'] = self._get_option_sticky_buffer(index_list[byte_test_option_list.index(item)])
                parsed_byte_test_lst.append(byte_test)
            return parsed_byte_test_lst
        else:
            return None

    def get_opt_byte_jump(self):
        if 'byte_jump' in self.snortrule.opt_keyword_list:
            byte_jump_option_lst = self.snortrule.rule_opt_pairs['byte_jump']
            parsed_byte_jump_lst = []
            index_lst = self.__option_index('byte_jump')
            for item in byte_jump_option_lst:
                tmp = item.split(',')
                byte_jump = {'bytes': int(tmp[0]), 'offset': self.__is_name_or_num(tmp[1])}
                if len(tmp) > 2:
                    for elem in tmp[2:]:
                        if len(elem.split()) > 1:
                            byte_jump[elem.split()[0]] = int(elem.split()[1])
                        elif elem.split()[0] == ('little' or 'big'):
                            byte_jump['endian'] = elem.split()[0]
                        else:
                            byte_jump[elem.split()[0]] = 1
                byte_jump['sticky'] = self._get_option_sticky_buffer(index_lst[byte_jump_option_lst.index(item)])
                parsed_byte_jump_lst.append(byte_jump)
            return parsed_byte_jump_lst
        else:
            return None

    def get_opt_byte_extract(self):
        if 'byte_extract' in self.snortrule.opt_keyword_list:
            byte_extract_option_lst = self.snortrule.rule_opt_pairs['byte_extract']
            parsed_byte_extract_lst = []
            index_lst = self.__option_index('byte_extract')
            for item in byte_extract_option_lst:
                tmp = item.split(',')
                byte_extract = {'bytes': int(tmp[0]), 'offset': int(tmp[1]), 'name': tmp[2]}
                if len(tmp) > 3:
                    for elem in tmp[3:]:
                        s = elem.split()
                        if s[0] == 'multiplier':
                            byte_extract['multiplier'] = int(s[1])
                        elif s[0] == ('little' or 'big'):
                            byte_extract['endian'] = s[0]
                        elif s[0] == 'bitmask':
                            byte_extract['bitmask'] = s[1]
                        else:
                            byte_extract[s[0]] = 1
                byte_extract['sticky'] = self._get_option_sticky_buffer(index_lst[byte_extract_option_lst.index(item)])
                parsed_byte_extract_lst.append(byte_extract)
            return parsed_byte_extract_lst
        else:
            return None

    def get_opt_byte_math(self):
        if 'byte_math' in self.snortrule.opt_keyword_list:
            byte_math_option_lst = self.snortrule.rule_opt_pairs['byte_math']
            index_lst = self.__option_index('byte_math')
            parsed_byte_math_lst = []
            for item in byte_math_option_lst:
                tmp = item.split(',')
                byte_math = {}
                for elem in tmp:
                    elem = elem.strip()
                    s = elem.split()
                    if len(s) > 1:
                        byte_math[s[0]] = self.__is_name_or_num(s[1])
                    else:
                        if s[0] == 'big' or s[0] == 'little':
                            byte_math['endian'] = s[0]
                        else:
                            byte_math[s[0]] = 1
                byte_math['sticky'] = self._get_option_sticky_buffer(index_lst[byte_math_option_lst.index(item)])
                parsed_byte_math_lst.append(byte_math)
            return parsed_byte_math_lst
        else:
            return None

    def get_opt_dce(self):
        dce = {}
        if 'dce_iface' in self.snortrule.opt_keyword_list:
            tmp = self.snortrule.rule_opt_pairs['dce_iface'][0].split(', ')
            dce = {'dce_iface': {'uuid': tmp[0].split()[1]}}
            if len(tmp) > 1:
                for elem in tmp[1:]:
                    if elem == 'any_frag':
                        dce['dce_iface']['any_frag'] = 1
                    else:
                        dce['dce_iface']['operator'] = elem
        if 'dce_opnum' in self.snortrule.opt_keyword_list:
            dce['dce_opnum'] = self.snortrule.rule_opt_pairs['dce_opnum'][0]
        if 'dce_stub_data' in self.snortrule.opt_keyword_list:
            dce['dce_stub_data'] = 1
        return dce

    def get_opt_sip(self):
        sip = {}
        if 'sip_method' in self.snortrule.opt_keyword_list:
            sip['sip_method'] = []
            sip_tmp = self.snortrule.rule_opt_pairs['sip_method'][0].split(',')
            for elem in sip_tmp:
                sip['sip_method'].append(elem)
        if 'sip_stat_code' in self.snortrule.opt_keyword_list:
            sip['sip_stat_code'] = []
            sip_tmp = self.snortrule.rule_opt_pairs['sip_stat_code'][0].split(',')
            for elem in sip_tmp:
                sip['sip_stat_code'].append(elem)
        return sip

    def get_opt_ssl(self):
        ssl = {}
        if 'ssl_version' in self.snortrule.opt_keyword_list:
            ssl['ssl_version'] = []
            ssl_tmp = self.snortrule.rule_opt_pairs['ssl_version'][0].split(',')
            for elem in ssl_tmp:
                ssl['ssl_version'].append(elem)
        if 'ssl_state' in self.snortrule.opt_keyword_list:
            ssl['ssl_state'] = []
            ssl_tmp = self.snortrule.rule_opt_pairs['ssl_state'][0].split(',')
            for elem in ssl_tmp:
                ssl['ssl_state'].append(elem)
        return ssl

    # ------------------------------------------------
    # None-payload rule options
    """
    Options for IP header fields
    """
    def get_opt_id(self):  # IP ID field
        if 'id' in self.snortrule.opt_keyword_list:
            return int(self.snortrule.rule_opt_pairs['id'][0])
        else:
            return None

    def get_opt_ttl(self):  # IP time-to-live value
        if 'ttl' in self.snortrule.opt_keyword_list:
            return self.__get_range(self.snortrule.rule_opt_pairs['ttl'][0])
        else:
            return None

    def get_opt_tos(self):
        if 'tos' in self.snortrule.opt_keyword_list:
            return self.__get_range(self.snortrule.rule_opt_pairs['tos'][0])
        else:
            return None

    def get_opt_ipopts(self):  # IP protocol header
        if 'ipopts' in self.snortrule.opt_keyword_list:
            return self.snortrule.rule_opt_pairs['ipopts'][0]
        else:
            return None

    def get_opt_frags(self):
        frags = {}
        if 'fragebits' in self.snortrule.opt_keyword_list:
            frags['fragbits'] = self.snortrule.rule_opt_pairs['fragbits'][0]
        if 'frageoffset' in self.snortrule.opt_keyword_list:
            frags['fragoffset'] = self.snortrule.rule_opt_pairs['fragoffset'][0]
        return frags

    def get_opt_ip_proto(self):
        if 'ip_proto' in self.snortrule.opt_keyword_list:
            return self.__is_name_or_num(self.snortrule.rule_opt_pairs['ip_proto'][0])
        else:
            return None

    """
    Options for TCP/UDP headers
    """
    def get_opt_flow(self):
        if 'flow' in self.snortrule.opt_keyword_list:
            flow = []
            tmp = self.snortrule.rule_opt_pairs['flow'][0].replace(" ", "").split(',')
            for elem in tmp:
                flow.append(elem)
            return flow
        else:
            return None

    def get_opt_seq(self):
        if 'seq' in self.snortrule.opt_keyword_list:
            return int(self.snortrule.rule_opt_pairs['seq'][0])
        else:
            return None

    def get_opt_ack(self):
        if 'ack' in self.snortrule.opt_keyword_list:
            return int(self.snortrule.rule_opt_pairs['ack'][0])
        else:
            return None

    def get_opt_window(self):
        if 'window' in self.snortrule.opt_keyword_list:
            return self.__get_range(self.snortrule.rule_opt_pairs['window'][0])
        else:
            return None

    def get_opt_flags(self):
        if 'flags' in self.snortrule.opt_keyword_list:
            flags = {'bits': '', 'mask': ''}
            flag_str = self.snortrule.rule_opt_pairs['flags'][0]
            flags['bits'] = flag_str.split(',')[0]
            if len(flag_str.split(',')) > 1:
                flags['mask'] = flag_str.split(',')[1]
            return flags
        else:
            return None

    """
    Options for ICMP headers
    """
    def get_opt_icmp(self):
        icmp = {}
        if 'itype' in self.snortrule.opt_keyword_list:
            icmp['itype'] = self.__get_range(self.snortrule.rule_opt_pairs['itype'][0])
        if 'icode' in self.snortrule.opt_keyword_list:
            icmp['icode'] = self.__get_range(self.snortrule.rule_opt_pairs['icode'][0])
        if 'icmp_id' in self.snortrule.opt_keyword_list:
            icmp['icmp_id'] = int(self.snortrule.rule_opt_pairs['icmp_id'][0])
        if 'icmp_seq' in self.snortrule.opt_keyword_list:
            icmp['icmp_seq'] = int(self.snortrule.rule_opt_pairs['icmp_seq'][0])
        return icmp

    """
    Other options
    """
    def get_opt_service(self):
        if 'service' in self.snortrule.opt_keyword_list:
            return self.snortrule.rule_opt_pairs['service'][0].split(', ')
        else:
            return None

    def get_opt_dsize(self):
        if 'dsize' in self.snortrule.opt_keyword_list:
            return self.__get_range(self.snortrule.rule_opt_pairs['dsize'][0])
        else:
            return None

    def get_opt_flowbits(self):
        if 'flowbits' in self.snortrule.opt_keyword_list:
            flowbits = []
            fb_strs = self.snortrule.rule_opt_pairs['flowbits']
            for fb in fb_strs:
                fb_str = fb.split(',')
                flowbit = {'command': fb_str[0]}
                if len(fb_str) > 1:
                    flowbit['bits'] = fb_str[1]
                flowbits.append(flowbit)
            return flowbits
        else:
            return None

    def get_opt_rpc(self):
        if 'rpc' in self.snortrule.opt_keyword_list:
            rpc = {'application': 0}
            tmp = self.snortrule.rule_opt_pairs['rpc'][0].split(',')
            rpc['application'] = int(tmp[0])
            if len(tmp) > 1:
                rpc['version'] = self.__is_name_or_num(tmp[1])
                rpc['procedure'] = self.__is_name_or_num(tmp[2])
            return rpc
        else:
            return None

    def get_opt_bufferlen(self):
        if 'bufferlen' in self.snortrule.opt_keyword_list:
            buffer_len = {'sticky': '', 'length': self.__get_range(self.snortrule.rule_opt_pairs['bufferlen'][0])}
            bl_index = self.__option_index('bufferlen')
            for key, value in self.sticky_buffer.items():
                if value < bl_index[0]:
                    buffer_len['sticky'] = key
                else:
                    continue
            return buffer_len
        else:
            return None

    # -------------------------------------
    # Post-Detection rule options
    def get_opt_detection_filter(self):
        if 'detection_filter' in self.snortrule.opt_keyword_list:
            detection_filter = {'track': '', 'count': 0, 'seconds': 0}
            filter_fields = self.snortrule.rule_opt_pairs['detection_filter'][0].split(', ')
            for elem in filter_fields:
                tmp = elem.split()
                if tmp[0] == 'track':
                    detection_filter['track'] = tmp[1]
                if tmp[0] == 'count':
                    detection_filter['count'] = int(tmp[1])
                if tmp[0] == 'seconds':
                    detection_filter['seconds'] = int(tmp[1])
            return detection_filter
        else:
            return None

    def get_opt_tag(self):
        if 'tag' in self.snortrule.opt_keyword_list:
            tag_strs = self.snortrule.rule_opt_pairs['tag'][0].split(',')
            tag = {'type': tag_strs[0]}
            if len(tag_strs) > 1:
                tag['metric'] = tag_strs[1].split()[0]
                tag['count'] = int(tag_strs[1].split()[1])
                if len(tag_strs) > 2:
                    tag['other'] = tag_strs[2]
            return tag
        else:
            return None

    def get_opt_replace(self):
        if 'replace' in self.snortrule.opt_keyword_list:
            replace = []
            content_index = self.__option_index('content')
            replace_index = self.__option_index('replace')
            i = 0
            for rep_index in replace_index:
                rep = {'content_index': 0, 'content': '', 'replace': self.snortrule.rule_opt_pairs['replace'][i]}
                j = 0
                for con_index in content_index:
                    if rep_index > con_index:
                        rep['content_index'] = con_index
                        rep['content'] = self.snortrule.rule_opt_pairs['content'][j]
                    j += 1
                replace.append(rep)
                i += 1
            return replace
        else:
            return

    # --------------------------------------------
    # Other private methods
    def _get_option_sticky_buffer(self, option_index):
        for key, value in self.sticky_buffer.items():
            if option_index < value:
                continue
            elif option_index > value:
                return key
        return ''

    def __option_index(self, name):
        # get the index of a rule option in the rule by name
        opt_index = []
        for opt in self.snortrule.rule_options:
            if opt.split(':')[0] == name:
                opt_index.append(self.snortrule.rule_options.index(opt))
        return opt_index

    def __parse_opt_sticky_buffer_blocks(self):
        sticky_buffer = {}
        for opt in self.snortrule.rule_options:
            if opt in sticky_buffer_keyword_lst:
                sticky_buffer[opt] = self.snortrule.rule_options.index(opt)
        return sticky_buffer

    def __is_name_or_num(self, string):
        try:
            value = int(string)
            return value
        except ValueError:
            return string

    def __get_range(self, num_exp, min_num=0, max_num=255, inclusive=0):
        assert type(num_exp) == str, 'Input must be a string!\n'
        num_range = []
        remove_digits = str.maketrans('', '', digits)
        operator = num_exp.translate(remove_digits)
        if operator == '':
            num_range = int(num_exp)
            return num_range
        elif operator[0] == '!':
            num_range = {'neg': 1, 'num': int(num_exp.strip('!'))}
            return num_range
        else:
            if len(operator) > 1:
                if operator == '<=':
                    num_range.append(min_num)
                    num_range.append(int(num_exp[2:]))
                elif operator == '>=':
                    num_range.append(int(num_exp[2:]))
                    num_range.append(max_num)
                elif operator == '<>':
                    pos = num_exp.find('<>')
                    if inclusive:
                        num_range.append(int(num_exp[:pos]))
                        num_range.append(int(num_exp[pos+2:]))
                    else:
                        num_range.append(int(num_exp[:pos])+1)
                        num_range.append(int(num_exp[pos+2:])-1)
                elif operator == '<=>':
                    pos = num_exp.find('<=>')
                    num_range.append(int(num_exp[:pos]))
                    num_range.append(int(num_exp[pos+3:]))
                else:
                    print('Unsupported operator:', operator, '\n')
            else:
                if operator == '-':
                    pos = num_exp.find('-')
                    if pos == 0:
                        num_range.append(min_num)
                        num_range.append(int(num_exp[1:]))
                    elif num_exp[-1] == '-':
                        num_range.append(int(num_exp[:-1]))
                        num_range.append(max_num)
                    else:
                        num_range.append(int(num_exp[:pos]))
                        num_range.append(int(num_exp[pos+1:]))
                elif operator == '<':
                    num_range.append(min_num)
                    num_range.append(int(num_exp[1:])-1)
                elif operator == '>':
                    num_range.append(int(num_exp[1:])+1)
                    num_range.append(max_num)
                elif operator == '=':
                    num_range.append(int(num_exp[1:]))
                else:
                    print('Unsupported operator:', operator, '\n')
            return num_range


def snort_rule_option_statistic(rulefile, keyword):
    keyword_inquiry = {}
    fo = open(rulefile, "r")
    for line in fo:
        if SnortRule.is_rule(line):
            snortrule = SnortRule(line)
            if keyword in snortrule.opt_keyword_list:
                for opt in snortrule.rule_opt_pairs[keyword]:
                    # if keyword == 'service':
                    #     if opt.find('ftp-data'):
                    #         print(line)
                    if opt not in keyword_inquiry:
                        keyword_inquiry[opt] = 1
                    else:
                        keyword_inquiry[opt] += 1
                # else:
                    # print(keyword, ": No such rule option activated in this rule!\n", line, "\n\n")
    fo.close()
    return keyword_inquiry


def snort_rule_header_statistic(rulefile):
    header_keyword_inquiry = {}
    fo = open(rulefile, "r")
    for line in fo:
        if SnortRule.is_rule(line):
            if SnortRule.is_active(line):
                proto = SnortRule(line).get_proto()
                # if proto == "udp":
                    # print(line)
                if proto not in header_keyword_inquiry:
                    header_keyword_inquiry[proto] = 1
                else:
                    header_keyword_inquiry[proto] += 1
    fo.close()
    return header_keyword_inquiry
