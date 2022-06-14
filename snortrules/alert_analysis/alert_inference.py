"""
This file contains class and methods for inferring the number of alerts that ought to
be triggered by the targeted Snort rule(s) in each fuzzing iteration and comparing the
alerts with the inferred number to check if Snort runs as expected. Fuzz logger would
be used to record the results.
"""

import re

from boofuzz import *


from rule_parse.snort_rules import *

# from protocol.ftpServer import formatCheck

#print("警告捏")

def hex_str_to_char_str(hex_str):
    char_str = ""
    for hex_c in hex_str.split():
        char_str += chr(int(hex_c, 16))
        # char_str += r'\x' + hex_c
    return char_str


def byte_str_to_char_str(data_str):
    char_str = ""
    for byte_c in data_str:
        char_str += chr(byte_c)
    return char_str


class AlertInference(object):
    def __init__(self, rules, check_time, target: Target, logger: FuzzLogger, session: Session):
        self.current_rule_input = []
        self._get_valid_rules(rules)
        self.target = target
        self.logger = logger
        self.session = session
        self.check_time = check_time
        self.current_primitive = session.fuzz_node.mutant
        self.current_node = session.fuzz_node
        # indicates the end of the previous matched content
        self.content_match_cursor = 0
        # name of the sticky buffer that is under match now
        self.current_buffer_name = ''
        # variable name and value pairs of variables extracted by byte_extract rule option
        # or calculated by byte_math rule option
        self.bytes_variables = {}

    def _get_valid_rules(self, rules):
        for rule in rules:
            if SnortRule.is_rule(rule):
                if SnortRule.is_active(rule):
                    self.current_rule_input.append(rule)

    def _content_check(self, rule):
        """
        This method works to check if the fuzzing strings generated in current session
        can match the content option defined in certain Snort rule.
        :return:
        """
        # get content list of the rule
        content_lst = SnortRuleAttr(rule).get_opt_content()
        if not content_lst:
            self.logger.log_info("Checking content but not found.")
            return True

        self._byte_extract_preprocess(rule)
        self._byte_math_preprocess(rule)

        for content in content_lst:
            # some content match strings contain hex strings. Switch them into ASCII chars.
            content_match_lst = content['match'].split('|')
            if len(content_match_lst) >= 3:
                index = 1
                content['match'] = ''
                while index < len(content_match_lst):
                    content['match'] += content_match_lst[index - 1] + hex_str_to_char_str(content_match_lst[index])
                    index += 2
                content['match'] += content_match_lst[index - 1]

            # get content related fuzzing string of a HTTP sticky buffer
            match_str = self._content_sticky(content['sticky'])[0]
            if self.current_buffer_name != content['sticky']:
                self.content_match_cursor = 0
                self.current_buffer_name = content['sticky']

            # only check content with position when rule contains content modifiers
            # tackle modifiers
            if (content['depth'] is not None
                    or content['offset'] is not None
                    or content['distance'] is not None
                    or content['within'] is not None):
                if not self._content_with_position(content, match_str):
                    return False
            else:
                if not self._content_only(content, match_str):
                    return False

            # check bytes options:
            if not self._bytes_check(rule):
                return False

            # check isdataat option:
            if not self._isdataat_check(rule):
                return False

        return True

    def _content_with_position(self, content, match_str):
        # examine a give position of the fuzzing string to check if the content exists
        # deal with 'offset' and 'depth' modifiers
        if content['offset'] is not None:
            if content['depth'] is not None:
                if not self._string_match(match_str[content['offset']:content['offset'] + content['depth']], content):
                    return False
            else:
                if not self._string_match(match_str[content['offset']:], content):
                    return False
        else:
            if content['depth'] is not None:
                if not self._string_match(match_str[:content['depth']], content):
                    return False
            else:
                if not content['distance'] and not content['within']:
                    if not self._string_match(match_str, content):
                        return False

        # deal with 'distance' and 'within' modifiers
        if content['distance'] is not None:
            if content['within'] is not None:
                if not self._string_match(match_str[
                                          self.content_match_cursor + content['distance']:self.content_match_cursor +
                                                                                          content['distance'] + content[
                                                                                              'within']], content):
                    return False
            else:
                if not self._string_match(match_str[self.content_match_cursor + content['distance']:], content):
                    return False
        else:
            if content['within'] is not None:
                if not self._string_match(
                        match_str[self.content_match_cursor:self.content_match_cursor + content['within']], content):
                    return False

        return True

    def _content_only(self, content, match_str):
        # match the content without looking at a specific position
        return self._string_match(match_str, content)

    def _string_match(self, match_str, content):
        result = match_str.find(content['match'])
        if not content['neg']:
            if result != -1:
                if content['distance']:
                    self.content_match_cursor += content['distance'] + result + len(content['match'])
                else:
                    self.content_match_cursor += 0 + result + len(content['match'])
                return True
            else:
                return False
        else:
            if result != -1:
                return False
            elif content['within']:
                self.content_match_cursor += content['within']
                return True
            elif content['depth']:
                self.content_match_cursor = content['depth']
                return True

    def _content_sticky(self, sticky, mode="string"):
        """
        This method is used to parse the sticky buffer of content or isdataat options.
        It returns the buffer defined.
        :param sticky: sticky buffer definition
        :param mode: return a string or a bytes array
        :return: 1. the specific part of the fuzzing string designated by the sticky buffer
                 2. the start position of the returned sub string in the fuzzing string
        """
        fuzz_str = self.session.last_send
        if sticky == '':
            if mode == "string":
                return byte_str_to_char_str(self.session.last_send), 0
            elif mode == "bytes":
                return self.session.last_send, 0
            else:
                print("Unsupported content mode:", mode)
                return None
        elif sticky == 'http_header':
            pos = fuzz_str.find(b'\r\n\r\n')
            if mode == "string":
                return byte_str_to_char_str(fuzz_str[:pos] + b'\r\n'), 0
            else:
                return fuzz_str[:pos] + b'\r\n', 0
        elif sticky == 'http_uri':
            pos_tmp = fuzz_str.find(b'\r\n')
            pos_e = fuzz_str[0:pos_tmp].find(b'HTTP')
            pos1 = fuzz_str[0:pos_e].find(b' ')
            pos2 = fuzz_str[0:pos_e].find(b'\t')
            if pos1 < pos2:
                if pos1 == -1:
                    pos_s = pos2
                else:
                    pos_s = pos1
            else:
                if pos2 == -1:
                    pos_s = pos1
                else:
                    pos_s = pos2
            if mode == "string":
                return byte_str_to_char_str(fuzz_str[pos_s:pos_e]), pos_s
            else:
                return fuzz_str[pos_s:pos_e], pos_s
        elif sticky == 'http_method':
            pos1 = fuzz_str.find(b' ')
            pos2 = fuzz_str.find(b'\t')
            if pos1 < pos2:
                if pos1 == -1:
                    pos = pos2
                else:
                    pos = pos1
            else:
                if pos2 == -1:
                    pos = pos1
                else:
                    pos = pos2
            if mode == "string":
                return byte_str_to_char_str(fuzz_str[0:pos]), 0
            else:
                return fuzz_str[0:pos], 0
        elif sticky == 'http_stat_code':
            pos = fuzz_str.find(b'\r\n')
            if mode == "string":
                return byte_str_to_char_str(fuzz_str[0:pos].split()[1]), len(fuzz_str[0:pos].split()[0]) + 1
            else:
                return fuzz_str[0:pos].split()[1], len(fuzz_str[0:pos].split()[0]) + 1
        elif sticky == 'http_stat_msg':
            pos = fuzz_str.find(b'\r\n')
            if mode == "string":
                return byte_str_to_char_str(fuzz_str[0:pos].split()[2]), pos - len(fuzz_str[0:pos].split()[2])
            else:
                return fuzz_str[0:pos].split()[2], pos - len(fuzz_str[0:pos].split()[2])
        elif sticky == 'http_cookie':
            # locating header first
            pos = fuzz_str.find(b'\r\n\r\n')
            http_header_pair_list = fuzz_str[:pos].split(b'\r\n')[1:]
            pos = fuzz_str.find(b'\r\n')
            pos += 2
            for pair in http_header_pair_list:
                if pair.split(b':')[0].find(b'Cookie') != -1:
                    if mode == "string":
                        return byte_str_to_char_str(pair.split(b':')[1]), pos
                    else:
                        return pair.split(b':')[1], pos
                else:
                    pos += len(pair) + 2
            self.logger.log_info("No cookie found in the header.")
            if mode == "string":
                return '', 0
            else:
                return b'', 0
        elif sticky == 'http_client_body':
            pos = fuzz_str.find(b'\r\n\r\n')
            if mode == "string":
                return byte_str_to_char_str(fuzz_str[pos + 4:]), pos + 4
            else:
                return fuzz_str[pos + 4:], pos + 4
        else:
            self.logger.log_info("Not supported sticky buffer key: %s" % sticky)
            if mode == 'string':
                return byte_str_to_char_str(self.session.last_send), 0
            elif mode == 'bytes':
                return self.session.last_send, 0

    def _pcre_check(self, rule):
        if 'pcre' in rule.opt_keyword_list:
            pcre = SnortRuleAttr(rule).get_opt_pcre()
            flags = 0
            if pcre:
                # set the pcre flags
                for f in pcre[0]['options']:
                    if f == 's':
                        flags = flags | re.S
                    if f == 'm':
                        flags = flags | re.M
                    if f == 'i':
                        flags = flags | re.I
                    if f == 'x':
                        flags = flags | re.X

            # match the pcre string
            if re.match(pcre[0]['pattern'], byte_str_to_char_str(self.session.last_send), flags=flags):
                return True
            else:
                return False
        # else the pcre option is not under fuzzing
        else:
            return True

    def _byte_extract_preprocess(self, rule):
        """
        Get the value of variables from byte_extract rule options that dont have 'relative' field
        in case of using in content match
        :param rule: current snort rule
        """
        byte_extract_lst = SnortRuleAttr(rule).get_opt_byte_extract()
        if byte_extract_lst:
            for byte_field in byte_extract_lst:
                if 'relative' in byte_field:
                    continue
                match_str = self._content_sticky(byte_field['sticky'])[0]
                bytes_value = self._byte_preprocess(match_str, byte_field)
                if 'multiplier' in byte_field:
                    bytes_value *= byte_field['multiplier']
                self.bytes_variables[byte_field['name']] = bytes_value

    def _byte_math_preprocess(self, rule):
        """
        Get the value of variables from byte_math rule options that dont have 'relative' field
        in case of using in content match
        :param rule: current snort rule
        """
        byte_math_lst = SnortRuleAttr(rule).get_opt_byte_math()
        if byte_math_lst:
            for byte_field in byte_math_lst:
                if 'relative' in byte_field:
                    continue
                match_str = self._content_sticky(byte_field['sticky'])[0]
                bytes_value = self._byte_preprocess(match_str, byte_field)
                if isinstance(byte_field['rvalue'], str):
                    if byte_field['rvalue'] in self.bytes_variables:
                        byte_field['rvalue'] = self.bytes_variables[byte_field['rvalue']]
                    else:
                        continue
                self._byte_math_calc(byte_field, bytes_value)

    def _byte_math_calc(self, byte_field, bytes_value):
        if byte_field['oper'] == '+':
            self.bytes_variables[byte_field['result']] = bytes_value + byte_field['rvalue']
        elif byte_field['oper'] == '-':
            self.bytes_variables[byte_field['result']] = bytes_value + byte_field['rvalue']
        elif byte_field['oper'] == '*':
            self.bytes_variables[byte_field['result']] = bytes_value * byte_field['rvalue']
        elif byte_field['oper'] == '/':
            self.bytes_variables[byte_field['result']] = bytes_value / byte_field['rvalue']
        elif byte_field['oper'] == '<<':
            self.bytes_variables[byte_field['result']] = bytes_value << byte_field['rvalue']
        elif byte_field['oper'] == '>>':
            self.bytes_variables[byte_field['result']] = bytes_value >> byte_field['rvalue']
        else:
            print("Unsupported operator in byte_math option:", byte_field['oper'])

    def _byte_preprocess(self, match_str, byte_field):
        # STEP 1: get the bytes to convert
        if isinstance(byte_field['offset'], str):
            if byte_field['offset'] in self.bytes_variables:
                byte_field['offset'] = self.bytes_variables[byte_field['offset']]
            else:
                print("Unresolved byte variable name:", byte_field['offset'])
                byte_field['offset'] = None
        if 'relative' in byte_field:
            start_pos = self.content_match_cursor + byte_field['offset']
        else:
            start_pos = byte_field['offset']
        bytes_to_convert = match_str[start_pos:start_pos + byte_field['bytes']]

        # STEP 2: process the bytes as defined
        if 'string' in byte_field:
            if byte_field['string'] == 'dec':
                try:
                    bytes_value = int(bytes_to_convert)
                except ValueError:
                    return None
            elif byte_field['string'] == 'hex':
                try:
                    bytes_value = int(bytes_to_convert, 16)
                except ValueError:
                    return None
            elif byte_field['string'] == 'oct':
                try:
                    bytes_value = int(bytes_to_convert, 8)
                except ValueError:
                    return None
            else:
                print('Unsupported number type:', byte_field['string'])
                return None
        else:
            if 'endian' in byte_field:
                bytes_value = int.from_bytes(bytes_to_convert, byteorder=byte_field['endian'])
            else:
                bytes_value = int.from_bytes(bytes_to_convert, byteorder='big')
        if 'bitmask' in byte_field:
            bytes_value &= byte_field['bitmask']

        return bytes_value

    def _bytes_check(self, rule):
        """
        This method works to do the byte math with regards to the byte_test, byte_jump,
        byte_math, byte_extract rule options defined in Snort.
        :return:
        """
        rule_options = SnortRuleAttr(rule)
        match_str, str_pos = self._content_sticky(self.current_buffer_name, mode="bytes")

        # byte_extract
        byte_extract_lst = rule_options.get_opt_byte_extract()
        if byte_extract_lst:
            for byte_field in byte_extract_lst:
                if byte_field['sticky'] != self.current_buffer_name or 'relative' not in byte_field:
                    continue
                bytes_value = self._byte_preprocess(match_str, byte_field)
                if bytes_value is None:
                    return False
                if 'multiplier' in byte_field:
                    bytes_value *= byte_field['multiplier']
                self.bytes_variables[byte_field['name']] = bytes_value

        # byte_math
        byte_math_lst = rule_options.get_opt_byte_math()
        if byte_math_lst:
            for byte_field in byte_math_lst:
                if byte_field['sticky'] != self.current_buffer_name or 'relative' not in byte_field:
                    continue
                bytes_value = self._byte_preprocess(match_str, byte_field)
                if bytes_value is None:
                    return False
                if isinstance(byte_field['rvalue'], str):
                    if byte_field['rvalue'] in self.bytes_variables:
                        byte_field['rvalue'] = self.bytes_variables[byte_field['rvalue']]
                self._byte_math_calc(byte_field, bytes_value)

        # byte_jump
        byte_jump_lst = rule_options.get_opt_byte_jump()
        if byte_jump_lst:
            for byte_field in byte_jump_lst:
                if byte_field['sticky'] != self.current_buffer_name:
                    continue
                bytes_value = self._byte_preprocess(match_str, byte_field)
                if bytes_value is None:
                    return False
                if 'multiplier' in byte_field:
                    bytes_value *= byte_field['multiplier']
                if 'align' in byte_field:
                    if bytes_value % 4 != 0:
                        bytes_value = int(bytes_value / 4 + 1) * 4
                if 'from_beginning' in byte_field:
                    if self.current_buffer_name == '':
                        self.content_match_cursor = bytes_value
                    else:
                        self.content_match_cursor = bytes_value - str_pos
                elif 'from_end' in byte_field:
                    if self.current_buffer_name == '':
                        self.content_match_cursor = len(self.session.last_send) - bytes_value
                else:
                    self.content_match_cursor += bytes_value
                if 'post_offset' in byte_field:
                    pass

        # byte_test
        byte_test_lst = rule_options.get_opt_byte_test()
        if byte_test_lst:
            for byte_field in byte_test_lst:
                if byte_field['sticky'] != self.current_buffer_name:
                    continue
                if isinstance(byte_field['value'], str):
                    if byte_field['value'] in self.bytes_variables:
                        byte_field['value'] = self.bytes_variables[byte_field['value']]
                    else:
                        print("Unresolved byte variable name:", byte_field['value'])
                        byte_field['value'] = None
                bytes_value = self._byte_preprocess(match_str, byte_field)
                if bytes_value is None:
                    return False
                operator = byte_field['operator']
                if operator[0] == '!':
                    neg = True
                    operator = operator[1:]
                else:
                    neg = False
                if operator == '<':
                    if not (bytes_value < byte_field['value'] and not neg):
                        return False
                elif operator == '=':
                    if not (bytes_value == byte_field['value'] and not neg):
                        return False
                elif operator == '>':
                    if not (bytes_value > byte_field['value'] and not neg):
                        return False
                elif operator == '<=':
                    if not (bytes_value <= byte_field['value'] and not neg):
                        return False
                elif operator == '>=':
                    if not (bytes_value >= byte_field['value'] and not neg):
                        return False
                elif operator == '&':
                    if not (bytes_value & byte_field['value'] and not neg):
                        return False
                elif operator == '^':
                    if not (bytes_value ^ byte_field['value'] and not neg):
                        return False
                else:
                    print("Unsupported operator in bytes_test option:", operator)
                    return False

        return True

    def _isdataat_check(self, rule):
        """
        This method is used to check if there is data at the specific position of the fuzzing
        packets and if the data is as expected.
        :return:
        """
        isdataat = SnortRuleAttr(rule).get_opt_isdataat()
        if isdataat:
            if isdataat['sticky'] == self.current_buffer_name:
                match_str = self._content_sticky(isdataat['sticky'])[0]
                if len(match_str[self.content_match_cursor:]) - isdataat['pos'] >= 0:
                    if isdataat['neg'] == 0:
                        return True
                    else:
                        return False
                else:
                    if isdataat['neg'] == 0:
                        return False
                    else:
                        return True
        else:
            return True

    def _is_legal_message(self):
        """
        Check if the format of the request message generated from the block
        is a legal message.
        TODO: Current implementation only checks when the delimiter is ' ' or '\t'.
        """
        if isinstance(self.current_primitive, Delim):
            if self.current_primitive.name.split('-')[0] == 'space':
                if self.current_primitive.original_value == b' ':
                    if self.current_primitive.render() == b'':
                        return False

                    for byte in self.current_primitive.render():
                        # ASCII of space is 32 and of '\t' is 9
                        if byte == 10:
                            break
                        if byte != 32 and byte != 9 and byte != 13:
                            return False
                    return True
            elif self.current_primitive.name.split('-')[0] == 'delim':
                # if self.current_primitive.render() == b"'" or self.current_primitive.render() == b'"':
                #     return False
                if len(self.current_primitive.render()) == len(self.current_primitive.original_value):
                    return True
                else:
                    return False
        else:
            return True
        # return formatCheck(byte_str_to_char_str(self.session.last_send), "ftp")

    def _is_primitive_fuzzed(self):
        # Check if the primitive has mutated
        if self.current_primitive.render() == self.current_primitive.original_value:
            return True
        else:
            return False

    def inferred_alert_num(self):
        alert_num = 0
        if self._is_legal_message():
            for rule in self.current_rule_input:
                # always check content first
                if self._content_check(SnortRule(rule)):
                    # if content matched, check pcre then
                    if self._pcre_check(SnortRule(rule)):
                        alert_num += 1
        print(alert_num)
        return alert_num
