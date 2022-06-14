#!/usr/bin/env python
# coding=utf-8

from socket import *
import os
import re
import json
import random
import time

#本程序尽量做到在不理解协议的前提下完成解析和发包工作 ，在TCP层之上解析
#[TODO]解决多端口同时开启监听的问题 (http->8080,ftp->21)->感觉没什么必要
#故目前还是单端口
f = open('ftpDefine427.json', encoding='utf-8')
test = f.read()
ftpDefine = json.loads(test)
# f=open('httpDefineNew413.json',encoding='utf-8')
# test=f.read()
# httpDefine=json.loads(test)
#Initialize
Define = httpDefine
serverPort = 21
dataPort = 20
protocal = 'ftp'
host = '172.16.39.141'
badRequestResponse = ''
badSequenceResponse = ''


def data_str_to_char_str(data_str):
    char_str = ""
    for c in data_str:
        #print(type(hex_c))
       # print(int(hex_c,16))
       # print(chr(hex_c))
        char_str += chr(c)
    return char_str


def checkMandaNonrepeat(packet, values):
    # means mandatory and non-repeatable check
    # values is the possible value
    print(values)
    regex = ''
    for item in values:
        regex = regex+item+'|'
    regex = regex[:-1]
    print('regex=', regex)
    pattern = re.compile(regex)
    match = pattern.match(packet)
    if match:
        print('Match!')
        rest = packet[match.end():]
        return True,rest
    else:
        return False,None


def checkMandaRepeat(packet,values):
    # means mandatory and repeatable check
    # values is the possible value
    print(values)
    regex = ''
    for item in values:
        regex = regex+item+'|'
    regex = regex[:-1]
    regex = '('+regex+')+'
    print('regex=',regex)
    pattern = re.compile(regex)
    match = pattern.match(packet)
    if match:
        print('Match!')
        rest = packet[match.end():]
        return True, rest
    else:
        return False, None


def constructRegexNonmandatory(regex,values,isRepeatable,type):
    # function used when it is unmandatory
    # construct temporary regex   return new regex
    tempregex = ''
    for item in values:
        tempregex = tempregex + item + '|'
    if tempregex == '':  # means value is void
        if type == 'string':
            tempregex = '.*'
            # tempregex = '(\s|\S)*'
            returnregex = regex + tempregex
            print('returnregex=', returnregex)
            return returnregex
        else:
            tempregex = '.'
    else:  # normal status
        tempregex = tempregex[:-1]
    if isRepeatable == True:
        tempregex = '(' + tempregex + ')*'
    else:  # NonRepeatable
        tempregex = '(' + tempregex + ')?'
    returnregex = regex+tempregex
    print('returnregex=', returnregex)
    return returnregex


def formatCheck(packet):
    formatDefine = Define['formatCheck']
    remain = packet
    flag = True
    keyname = []
    visit = []
    for key in formatDefine:
        keyname.append(key)
        visit.append(False)
    print("keyname:",keyname)
    loop = -1
    for key in formatDefine:
        #print(key)
        loop += 1  #keyname[loop]为当前key值
        if visit[loop] == False:
            visit[loop] = True
        else:
            continue
        #print(keyname[loop],key)
        obj = formatDefine[key]
        print('Now check ',key)
        type = obj['type']
        value = obj['value']
        isMandatory = obj['mandatory']
        isRepeatable = obj['repeatable']
        #if is Mandatory and the string size is void,return false
        if isMandatory and len(remain) == 0:
            print('didn\'t finish the whole examine,failed')
            return False

        elif isMandatory and not isRepeatable:
            flag,remain = checkMandaNonrepeat(remain,value)
            if(flag == False):
                print('check fail!')
                return False
            else:
                print('check success,continue \nRest:',remain)
                continue

        elif isMandatory and isRepeatable:
            flag,remain = checkMandaRepeat(remain,value)
            if (flag == False):
                print('check fail!')
                return False
            else:
                print('check success,continue \nRest:', remain)
                continue

        elif isMandatory == False and len(value)==0 and (type=='string' or (type=='Char' and isRepeatable==True) or type=='undefine') :
            #need the next mandatory key value-->next keyname[loop+1]
            #continue seraching until one key is mandatory
            tempregex = ''
            tempregex=constructRegexNonmandatory(tempregex,value,isRepeatable,type)
            if type=='undefine':  #undefine is a special type ,means any letter can be ignore[including blank&nextline]
                tempregex='(\s|\S)*'

            pathflag=False
            for x in range(loop+1,len(visit)):
                #presentkeyname: keyname[x]
                presobj = formatDefine[keyname[x]]
                print('Now check for use (not really check):', keyname[x])
                prestype = presobj['type']
                presvalue = presobj['value']
                presisMandatory = presobj['mandatory']
                presisRepeatable = presobj['repeatable']
                regex=''
                if presisMandatory==False:
                    #|mark visit |add regex| continue
                    visit[x]=True
                    tempregex=constructRegexNonmandatory(tempregex,presvalue,presisRepeatable,prestype)
                    continue
                else:  #presisMandatory=True
                    print(presvalue)
                    for item in presvalue:
                        regex = regex + item + '|'
                    regex = regex[:-1]
                    regex='(' + regex + ')'
                    print('regex:',regex)
                    if presisRepeatable==True:
                        regex=regex+'+'
                    print('regex:',regex)
                    finalregex=tempregex+r'(?='+regex+r')'
                    print('finalregex=', finalregex)
                    #print('finalregex=', ord(finalregex[11]))

                    finalpattern = re.compile(finalregex)
                    finalmatch = finalpattern.match(remain)
                    if finalmatch:
                        print('Match!')
                        print(finalmatch.end())
                        rest = remain[finalmatch.end():]
                        remain=rest
                        print('check success,continue \nRest:', remain)
                        pathflag=True
                        break
                    else:
                        print('did not find,still continue \nRest:', remain)
                        pathflag=True
                        break
            if pathflag:
                continue
            #break the loop, before breaking still can not find mandatory item, return true
            print('success,can not find mandatory one,which means ',remain,'will pass')
            return True

        else:
            tempregex = ''
            tempregex=constructRegexNonmandatory(tempregex, value, isRepeatable, type)
            print('tempregex=', tempregex)
            temppattern = re.compile(tempregex)
            finalmatch = temppattern.match(remain)
            if finalmatch:
                print('Match!')
                rest = remain[finalmatch.end():]
                remain = rest
                print('check success,continue \nRest:', remain)
                continue
            else:
                print('check success,continue \nRest:', remain)
                continue
    return True


def chooseProtocal(Aprotocal):
    global  Define,serverPort,badRequestResponse,badSequenceResponse,protocal
    if Aprotocal=='http':
        protocal='http'
        Define=httpDefine
        serverPort=8080
        badRequestResponse='HTTP/1.1 400 Bad Request\r\n\r\n'
    if Aprotocal=='ftp':
        protocal='ftp'
        Define=ftpDefine
        serverPort=21
        dataPort = 20
        badRequestResponse='500 Syntax error, command unrecognized.\r\n'
        badSequenceResponse='503 Bad sequence of commands.\r\n'

def startDataSock(dataSockAddr,dataSockPort,dataSocket):
    # dataSockAddr dataSockPort are from boofuzz port command
    #global dataSocket
    try:
        dataSocket.connect((dataSockAddr, dataSockPort))
    except error as err:
        #log('startDataSock',err)
        print('Error occured!',err)

def stopDataSock(dataSocket):
    # dataSockAddr dataSockPort are from boofuzz port command
    #global dataSocket
    try:
        dataSocket.shutdown(2)
        dataSocket.close()
    except error as err:
        print('Error occured!',err)

def sendCommand(cmd):
    connectionSocket.send(cmd.encode('utf-8'))

def sendData(data,dataSocket):
    dataSocket.send(data.encode('utf-8'))

#[step1] choose protocal etc.http/ftp
#--------------------------------#
                                 #
chooseProtocal('ftp')            #
                                 #
#--------------------------------#



# 创建了服务器的套接字，其中AF_INET表示使用的是IPV4协议，SOCKER_STREAM表示使用的是TCP套接字
serverSocket = socket(AF_INET, SOCK_STREAM)
#dataSocket = socket(AF_INET, SOCK_STREAM)
# 表示将服务端端口与套接字连接起来
serverSocket.bind((host, serverPort))
#Attention 这里直接bind可能不太可取
#dataSocket.bind((host, dataPort))
# 让服务器聆听TCP连接，参数为请求连接的最大数目
serverSocket.listen(5)
CWD = os.getenv('HOME')
cwd = CWD
print('Servering port %d ' % serverPort)

# 一直循环等待请求连接
while True:
    # 当有客户机相应时，建立TCP连接,并且返回新套接字用于处理该对话
    connectionSocket, addr = serverSocket.accept()
    isContinuous = False  # 协议是否为可连续模式,默认为否 可在json文件中定义
    #[NEW]在这里建立状态机
    state={}
    if(Define['isContinuous']==True):
        isContinuous=True
        temp=Define['state']
        for key,value in temp.items():
            state[key]=value
    #则目前state[position]为当前状态

    while True:
        try:
            data = connectionSocket.recv(1024)
            # try:
            #     cmd = data.decode('utf-8')
            #     primitiveCheck=checkFormat(cmd)
            # except (AttributeError,UnicodeDecodeError):
            #     cmd = data
            #     primitiveCheck=checkFormat2(cmd)
            #使用data_str_to_char_str()目前未发生报错，取消上述分支
            cmd = data_str_to_char_str(data)
            primitiveCheck=formatCheck(cmd)
            #log('Received data', cmd)
            if not cmd:
                connectionSocket.close()
                break   #[NEW] 这里改为了break，因为有两层循环
            if primitiveCheck==False:
                print("primitiveCheckFailed!")
                connectionSocket.sendall(badRequestResponse.encode("utf8"))
                connectionSocket.close()
                break
        except error as err:
            print("Socket Error!",err)
            connectionSocket.close()
            break

        #if pass the primitiveCheck
        try:
            #cmd=cmd[:cmd.find(' ')].strip().upper()
            cmd, arg = cmd[:4].strip().upper(), cmd[4:].strip() or None
        except TypeError:
            print("byte cmd:",cmd)
            try:
                cmd=cmd[:cmd.find(' '.encode('utf-8'))].decode('utf-8').strip().upper()
            except UnicodeDecodeError:
                connectionSocket.sendall(badRequestResponse.encode("utf8"))
                connectionSocket.close()
                break
        print("Cmd",cmd)

        #[NEW]增加一个针对restrictRequest的判断 如果不在大if中则不加约束
        if isContinuous==True: #连续的才可能存在状态
            if state['position'] in Define['restrictRequestByPosition'] :
                if cmd not in Define['restrictRequestByPosition'][state['position']]:
                    #不在可能的候选项中，则返回错误指令
                    connectionSocket.sendall(badSequenceResponse.encode("utf8"))
                    connectionSocket.close()
                    break

        if cmd not in Define['requestToRespond']:
            print("request illegal!")
            connectionSocket.sendall(badRequestResponse.encode("utf8"))
            connectionSocket.close()
            break
        #[NEW]修改关于requestToRespond的选择，包括以下内容1）格式更换了，现在包含key和value
        #2） 现在选择完以后要修改当前状态

        respondDict = Define['requestToRespond'][cmd][
            random.randint(0, Define['requestToRespond'][cmd].__len__() - 1)]
        respondKey=list(respondDict.keys())[0]
        changeStatus=list(respondDict.values())[0]
        #修改当前状态
        if isContinuous==True:
            if changeStatus!='STILL':
                state['position']=changeStatus

        #for ftp STOR command:
        if protocal=='ftp' and cmd=='STOR':
            dataSocket = socket(AF_INET, SOCK_STREAM)
            dataSocket.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)
            dataSocket.bind((host, dataPort))
            sendCommand('150 OK to send data.\r\n')
            time.sleep(1)
            startDataSock('172.17.0.2 ',50000,dataSocket) #目前是强制的，也可以改为读取
            pathname = os.path.join(cwd, arg)
            print('pathname:',pathname)
            try:
                file = open(pathname, 'wb')
            except OSError as err:
                print('Error occured!',err)
            while True:
                data = dataSocket.recv(1024)
                if not data: break
                file.write(data)
            file.close()
            stopDataSock(dataSocket)
            #sendCommand('226 Transfer completed.\r\n')

        # for ftp LIST command:
        if protocal == 'ftp' and cmd == 'LIST':
            dataSocket = socket(AF_INET, SOCK_STREAM)
            dataSocket.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)
            dataSocket.bind((host, dataPort))
            sendCommand('150 Here comes the directory listing.\r\n')
            time.sleep(1)
            startDataSock('172.17.0.2 ', 50000,dataSocket)  # 目前是强制的，也可以改为读取
            #pathname = os.path.join(cwd, arg)
            #print('pathname:', pathname)
            # try:
            #     file = open(pathname, 'wb')
            # except OSError as err:
            #     print('Error occured!', err)
            # while True:
            #     data = dataSocket.recv(1024)
            #     if not data: break
            #     file.write(data)
            #time.sleep(5)
            sendData('drwxrwxrwx  2 0  0  4096 Apr 07 11:06 write\r\n',dataSocket)
            #file.close()
            stopDataSock(dataSocket)
            #sendCommand('226 Directory send OK.\r\n')

         #respond
        responds=''
        for key, value in Define['respond'][respondKey].items():
            responds=responds+value
        connectionSocket.sendall(responds.encode("utf8"))
        print('SendComplete! Responds',responds)
        #针对持续连接和不持续连接的区别
        if isContinuous==False:
            connectionSocket.close()
            break
