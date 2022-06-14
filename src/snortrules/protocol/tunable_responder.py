#! /usr/bin/env python
# -*- coding: UTF-8 -*-
# 211.69.198.63
'''Class of Tunable Responder'''
from scapy.all import *
import socket
import json
from protocol.get_status_code_server import GetStatusCodeServer


# [TODO] 添加长度length的限制  感觉好像没有明显的作用，value已经做到限制了
# [TODO] 优化ftp-json相应内容
class TunableResponder(Thread):

    def __init__(self, host='localhost', protocal='ftp'):
        super(TunableResponder, self).__init__()
        self.host = host
        self.protocal = protocal
        protocal_specification_string = protocal + "_protocol_specification.json"
        self.protocal_specification = json.loads(open(protocal_specification_string, encoding='utf-8').read())
        self.port = self.protocal_specification['protocol-info']['port']
        self.addr = (self.host, self.port)
        print('OOPServer ', self.addr)
        self.parameter = {}
        self.bufsiz = 4096
        self.gscs = GetStatusCodeServer()
        self.gscs.start()

    def data_str_to_char_str(self, data_str):
        # Converts non-displayable strings
        char_str = ""
        for c in data_str:
            char_str += chr(c)
        return char_str

    def check_mandatory_and_unrepeatable(self, packet, values):
        '''
        在format_check函数使用，用于生成必要并且不重复内容的正则表达式并判断该块是否合法，
        参数：packet是剩余的数据包字符串，values为json文件中每个块中的value，自动获取并且放置在里面
        返回值：先返回是否匹配 True/False  再返回剩余的字符串
        '''
        print(values)
        regex = ''
        for item in values:
            regex = regex + item + '|'
        regex = regex[:-1]

        print('regex=', regex)
        pattern = re.compile(regex)
        match = pattern.match(packet)
        if match:
            print('Match!')
            rest = packet[match.end():]
            return True, rest
        else:
            return False, None

    def check_mandatory_and_repeatable(self, packet, values):
        '''
        在format_check函数使用，用于生成必要并且重复内容的正则表达式并判断该块是否合法，
        参数：packet是剩余的数据包字符串，values为json文件中每个块的value，自动获取并且放置在里面
        返回值：先返回是否匹配 True/False  再返回剩余的字符串
        '''
        print(values)
        regex = ''
        for item in values:
            regex = regex + item + '|'
        regex = regex[:-1]
        regex = '(' + regex + ')+'
        print('regex=', regex)
        pattern = re.compile(regex)
        match = pattern.match(packet)
        if match:
            print('Match!')
            rest = packet[match.end():]
            return True, rest
        else:
            return False, None

    def construct_regex_when_unmandatory(self, regex, values, is_repeatable, type):
        '''
        construct temporary regex   return new regex
        在format_check函数使用，用于生成unmandatory的正则表达式，
        参数：regex为之前已生成的正则表达式， values为当前块可选值，is_repeatable为当前块是否重复，type为当前块类型，都在json文件中定义
        返回值：经过该块生成的正则表达式
        '''

        temp_regex = ''
        for item in values:
            temp_regex = temp_regex + item + '|'
        if temp_regex == '':  # value is void
            if type == 'string':
                temp_regex = '.*'
                return_regex = regex + temp_regex
                print('return_regex=', return_regex)
                return return_regex
            else:
                temp_regex = '.'
        else:  # normal value
            temp_regex = temp_regex[:-1]
        if is_repeatable == True:
            temp_regex = '(' + temp_regex + ')*'
        else:  # NonRepeatable
            temp_regex = '(' + temp_regex + ')?'
        return_regex = regex + temp_regex
        print('return_regex=', return_regex)
        return return_regex

    # 6.1修改，变成多个定义进行依次判断，满足则输出
    def format_check(self, packet):
        """
        结合上述check&construct函数 与 json文件，完成格式检查
        输入：数据包内容
        返回值：是否通过判断 ture/false
        """
        formatting_rule_all = self.protocal_specification['request']
        pass_flag = False
        for formatting_rule_single in formatting_rule_all:
            if pass_flag:
                break
            remain = packet
            keyname = []
            visit = []
            for key in formatting_rule_single:
                keyname.append(key)
                visit.append(False)
            print("keyname:", keyname)
            loop = -1
            loop_flag = True
            for key in formatting_rule_single:
                # print(key)
                loop += 1  # keyname[loop]为当前key值
                if visit[loop] == False:
                    visit[loop] = True
                else:
                    continue
                # print(keyname[loop],key)
                obj = formatting_rule_single[key]
                print('Now check ', key)
                type = obj['type']
                value = obj['value']
                is_mandatory = obj['mandatory']
                is_repeatable = obj['repeatable']
                # if is Mandatory and the string size is void,return false
                if is_mandatory and len(remain) == 0:
                    print('didn\'t finish the whole examine,failed')
                    # return False
                    loop_flag = False
                    break

                elif is_mandatory and not is_repeatable:
                    flag, remain = self.check_mandatory_and_unrepeatable(remain, value)
                    if (flag == False):
                        print('check fail!')
                        # return False
                        loop_flag = False
                        break
                    else:
                        print('check success,continue \nRest:', remain)
                        continue

                elif is_mandatory and is_repeatable:
                    flag, remain = self.check_mandatory_and_repeatable(remain, value)
                    if (flag == False):
                        print('check fail!')
                        loop_flag = False
                        # return False
                        break
                    else:
                        print('check success,continue \nRest:', remain)
                        continue

                elif is_mandatory == False and len(value) == 0 and (
                        type == 'string' or (type == 'Char' and is_repeatable == True) or type == 'undefine'):
                    # [TODO] examine this part
                    # need the next mandatory key value-->next keyname[loop+1]
                    # continue seraching until one key is mandatory
                    temp_regex = ''
                    temp_regex = self.construct_regex_when_unmandatory(temp_regex, value, is_repeatable, type)
                    if type == 'undefine':  # undefine is a special type ,means any letter can be ignore[including blank&nextline]
                        temp_regex = '(\s|\S)*'

                    path_flag = False
                    for x in range(loop + 1, len(visit)):
                        # presentkeyname: keyname[x]
                        pres_obj = formatting_rule_single[keyname[x]]
                        print('Now check for use (not really check):', keyname[x])
                        pres_type = pres_obj['type']
                        pres_value = pres_obj['value']
                        pres_is_mandatory = pres_obj['mandatory']
                        pres_is_repeatable = pres_obj['repeatable']
                        regex = ''
                        if pres_is_mandatory == False:
                            # |mark visit |add regex| continue
                            visit[x] = True
                            temp_regex = self.construct_regex_when_unmandatory(temp_regex, pres_value,
                                                                               pres_is_repeatable, pres_type)
                            continue
                        else:  # pres_is_mandatory=True
                            print(pres_value)
                            for item in pres_value:
                                regex = regex + item + '|'
                            regex = regex[:-1]
                            regex = '(' + regex + ')'
                            print('regex:', regex)
                            if pres_is_repeatable == True:
                                regex = regex + '+'
                            print('regex:', regex)
                            finalregex = temp_regex + r'(?=' + regex + r')'
                            print('finalregex=', finalregex)
                            # print('finalregex=', ord(finalregex[11]))

                            final_pattern = re.compile(finalregex)
                            final_match = final_pattern.match(remain)
                            if final_match:
                                print('Match!')
                                print(final_match.end())
                                rest = remain[final_match.end():]
                                remain = rest
                                print('check success,continue \nRest:', remain)
                                path_flag = True
                                break
                            else:
                                print('did not find,still continue \nRest:', remain)
                                path_flag = True
                                break
                    if path_flag:
                        continue
                    # break the loop, before breaking still can not find mandatory item, return true
                    print('success,can not find mandatory one,which means ', remain, 'will pass')
                    pass_flag = True
                    break
                    # return True

                else:
                    temp_regex = ''
                    temp_regex = self.construct_regex_when_unmandatory(temp_regex, value, is_repeatable, type)
                    print('temp_regex=', temp_regex)
                    temp_pattern = re.compile(temp_regex)
                    final_match = temp_pattern.match(remain)
                    if final_match:
                        print('Match!')
                        rest = remain[final_match.end():]
                        remain = rest
                        print('check success,continue \nRest:', remain)
                        continue
                    else:
                        print('check success,continue \nRest:', remain)
                        continue
            if loop_flag == True:
                pass_flag = True
        if pass_flag:
            print("FINAL PASSSSSSSSSSS！")
            return True
        else:
            return False

    def choose_protocal(self, Aprotocal):
        # 最初用于选择该服务端的协议，Aprotocal可选值为ftp/http，作用是切换定义的文件
        if Aprotocal == 'http':
            self.bad_request_response = 'HTTP/1.1 400 Bad Request\r\n\r\n'
        if Aprotocal == 'ftp':
            self.dataPort = 20  # [TODO]如何把这类信息不仅仅是dataport从json文件中读出来
            self.bad_request_response = '500 Syntax error, command unrecognized.\r\n'
            self.bad_sequence_response = '503 Bad sequence of commands.\r\n'

    def start_data_sock(self, data_sock_addr, data_sock_port, data_socket):
        # 用于ftp开启数据链接
        # data_sock_addr data_sock_port are from boofuzz port command
        # global data_socket
        try:
            data_socket.connect((data_sock_addr, data_sock_port))
        except socket.error as err:
            # log('start_data_sock',err)
            print('Error occured!', err)

    def stop_data_sock(self, data_socket):
        # 用于ftp关闭数据链接
        # data_sock_addr data_sock_port are from boofuzz port command
        # global data_socket
        try:
            data_socket.shutdown(2)
            data_socket.close()
        except socket.error as err:
            print('Error occured!', err)

    def send_command(self, cmd):
        # 用于发送返回指令 cmd为返回的指令字符串    self.conn_sock为当前会话建立的套接字
        self.conn_sock.send(cmd.encode('utf-8'))

    def send_data(data, data_socket):
        # 用于ftp数据通路发送数据
        data_socket.send(data.encode('utf-8'))

    def bind(self):
        try:
            self.server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.server_sock.bind(self.addr)
            self.server_sock.listen(5)
        except:
            print('OOP_Server bind failed')

    def unbind(self):
        try:
            self.conn_sock.close()
        except:
            print('OOP_server conn_cosk close failed')
        try:
            self.server_sock.close()
        except:
            print('OOP_Server server_sock close failed')

    def run(self):
        self.choose_protocal('ftp')  # [TODO]
        self.bind()
        CWD = os.getenv('HOME')
        cwd = CWD
        while True:
            print('\n\nOOP_Server Waiting for connection')
            try:
                self.conn_sock, addr = self.server_sock.accept()
            except:
                print('OOP_server accept failed')
                time.sleep(1)
                continue
            print('Connect from:', addr)
            if (self.protocal_specification['protocol-info']['is_continuous'] == True):
                is_continuous = True
                temp = self.protocal_specification['protocol-info']['state']
                for key, value in temp.items():  # [TODO]可以仿照这样的模式 ，将每个协议特有的信息放在一个state里面然后用字典存起来
                    self.parameter[key] = value
            while True:
                try:
                    data = ''
                    while True:
                        data_str = self.conn_sock.recv(self.bufsiz)
                        if not data_str: break
                        tmp_data = self.data_str_to_char_str(data_str)  # 将非法字符也转换
                        data = data + tmp_data
                    print("Receive data", data)
                    cmd = self.data_str_to_char_str(data)
                    primitive_check = self.format_check(cmd)  # 进行格式判断
                    # log('Received data', cmd)
                    if not cmd:
                        self.conn_sock.close()
                        break  # [NEW] 这里改为了break，因为有两层循环
                    if primitive_check == False:
                        print("primitive_check Failed!")
                        self.conn_sock.sendall(self.bad_request_response.encode("utf8"))
                        self.conn_sock.close()
                        break
                except socket.error as err:
                    print("Socket Error!", err)
                    self.conn_sock.close()
                    break

                # if pass the primitive_check
                try:
                    # cmd=cmd[:cmd.find(' ')].strip().upper()
                    cmd, arg = cmd[:4].strip().upper(), cmd[4:].strip() or None  # [TODO] 4??? 如何放到json里面
                except TypeError:
                    print("byte cmd:", cmd)
                    try:
                        cmd = cmd[:cmd.find(' '.encode('utf-8'))].decode('utf-8').strip().upper()  # 提取解析报文内容，是什么指令
                    except UnicodeDecodeError:
                        self.conn_sock.sendall(self.bad_request_response.encode("utf8"))
                        self.conn_sock.close()
                        break
                print("Cmd", cmd)
                # 修改/改为在当前状态的所有可能边里面查看action中是否有这个值，如果没有则返回乱序

                # [NEW]增加一个针对restrictRequest的判断 如果不在大if中则不加约束
                if is_continuous == True:  # 连续的才可能存在状态
                    transition = self.protocal_specification['stateMachine']['transition']

                    # print(transition)

                    legal_flag = False

                    for i in transition[self.parameter['position']]:  # 找是不是在边中有这个触发条件
                        print(i)
                        # for item in i['event']:
                        item = i['event']['FTP-command']
                        print(item)
                        if cmd == item:
                            print('find! up there!')
                            legal_flag = True
                            # 获取response并切换状态
                            print(i['response'])
                            remainder_num, statecode = self.gscs.get_remaindernum_and_statecode()
                            if remainder_num > 0:
                                if statecode in i['response']:
                                    respond_key = statecode
                                else:
                                    print(
                                        'The given status code ' + statecode + ' is not in the setting status code ' + str(
                                            i['response']))
                            else:
                                respond_key = i['response'][random.randint(0, i['response'].__len__() - 1)]
                            new_state = i['to']
                            print("respondDKey", respond_key)
                            print("new_state", new_state)
                            # break  match for item in i['event']
                        if (legal_flag):
                            break;

                    if not legal_flag:
                        self.conn_sock.sendall(self.bad_sequence_response.encode("utf8"))
                        self.conn_sock.close()
                        break

                #     if state['position'] in Define['restrictRequestByPosition'] :
                #         if cmd not in Define['restrictRequestByPosition'][state['position']]:
                #             #不在可能的候选项中，则返回错误指令
                #             self.conn_sock.sendall(bad_sequence_response.encode("utf8"))
                #             self.conn_sock.close()
                #             break
                #
                # if cmd not in Define['requestToRespond']:
                #     print("request illegal!")
                #     self.conn_sock.sendall(bad_request_response.encode("utf8"))
                #     self.conn_sock.close()
                #     break
                # [NEW]修改关于requestToRespond的选择，包括以下内容1）格式更换了，现在包含key和value
                # 2） 现在选择完以后要修改当前状态

                # respondDict = Define['requestToRespond'][cmd][
                #     random.randint(0, Define['requestToRespond'][cmd].__len__() - 1)]
                # respond_key=list(respondDict.keys())[0]
                # new_state=list(respondDict.values())[0]
                # 修改当前状态
                if is_continuous == True:
                    self.parameter['position'] = new_state

                # for ftp STOR command:
                # if protocal=='ftp' and cmd=='STOR':
                #     data_socket = socket(AF_INET, SOCK_STREAM)
                #     data_socket.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)
                #     data_socket.bind((host, dataPort))
                #     send_command('150 OK to send data.\r\n')
                #     time.sleep(0.3)
                #     start_data_sock('172.17.0.2',50000,data_socket) #目前是强制的，也可以改为读取
                #     try:
                #         pathname = os.path.join(cwd, arg)
                #     except TypeError as err:
                #         print('TypeError occured!', err)
                #         pathname='EMPTY'
                #     if pathname!='EMPTY':
                #         print('pathname:',pathname)
                #         try:
                #             file = open(pathname, 'wb')
                #             while True:
                #                 data = data_socket.recv(1024)
                #                 if not data: break
                #                 file.write(data)
                #             file.close()
                #         except (OSError,ValueError) as err:
                #             print('Error occured!',err)
                #
                #     stop_data_sock(data_socket)
                #     #send_command('226 Transfer completed.\r\n')
                #
                # # for ftp LIST command:
                # if protocal == 'ftp' and cmd == 'LIST':
                #     data_socket = socket(AF_INET, SOCK_STREAM)
                #     data_socket.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)
                #     data_socket.bind((host, dataPort))
                #     send_command('150 Here comes the directory listing.\r\n')
                #     time.sleep(0.3)
                #     start_data_sock('172.17.0.2', 50000,data_socket)  # 目前是强制的，也可以改为读取
                #     #pathname = os.path.join(cwd, arg)
                #     #print('pathname:', pathname)
                #     # try:
                #     #     file = open(pathname, 'wb')
                #     # except OSError as err:
                #     #     print('Error occured!', err)
                #     # while True:
                #     #     data = data_socket.recv(1024)
                #     #     if not data: break
                #     #     file.write(data)
                #     #time.sleep(5)
                #     send_data('drwxrwxrwx  2 0  0  4096 Apr 07 11:06 write\r\n',data_socket)
                #     #file.close()
                #     stop_data_sock(data_socket)
                #     #send_command('226 Directory send OK.\r\n')

                # respond  回复
                responds = ''
                for key, value in self.protocal_specification['response'][respond_key].items():
                    responds = responds + value
                print('Ready to send! Responds', responds)
                self.conn_sock.sendall(responds.encode("utf8"))
                print('SendComplete! Responds', responds)
                # 针对持续连接和不持续连接的区别
                if is_continuous == False:
                    self.conn_sock.close()
                    break
