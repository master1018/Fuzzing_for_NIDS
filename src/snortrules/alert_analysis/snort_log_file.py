#! /usr/bin/env python
import os
import abc
import json
import linecache
from threading import Thread
from threading import Lock
from time import sleep


LOG_DIR = "/var/log/snort"


class LogFile(object):
    def __init__(self, filename, path):
        self.log_path = path
        self.filename = filename

    @abc.abstractmethod
    def findnewlines(self):
        pass

    @abc.abstractmethod
    def getcertainline(self, desired_line_num):
        pass


def transfer_to_json(lines):
    line_dicts = []
    if isinstance(lines, str):
        return json.loads(lines)
    else:
        for elem in lines:
            line_dicts.append(json.loads(elem))
        return line_dicts


class JsonLogFile(LogFile):
    pos = 0
    previous_line = 0

    def __init__(self, filename='alert_json.txt', path=LOG_DIR):
        super(JsonLogFile, self).__init__(filename, path)
        self.tmp = 6

    def set_log_file_path(self, path, filename):
        self.filename = filename
        self.log_path = path

    def initialize_line_num(self):
        JsonLogFile.previous_line = -1
        with open(os.path.join(self.log_path, self.filename), 'r') as f:
            for JsonLogFile.previous_line, line in enumerate(f):
                pass
            JsonLogFile.previous_line += 1
            JsonLogFile.pos = f.tell()

    def getcertainline(self, desired_line_num):
        """
        This function returns the desired line in json format. It uses an approach with better
        performance instead of linecache module.
        :param desired_line_num: The No. of the line to get.
        :return: desired line in json format.
        """
        with open(os.path.join(self.log_path, self.filename), 'r') as logfile:
            line_content = ''
            if desired_line_num >= 1:
                pointer = 0
                for current_line_num, line in enumerate(logfile):
                    pointer += len(line)
                    if current_line_num == desired_line_num - 1:
                        line_content = line
                        break
                JsonLogFile.pos = pointer
                JsonLogFile.previous_line = desired_line_num

        return transfer_to_json(line_content)

    def getcertainline_v2(self, desired_line_num):
        """This method provides another approach for getting a certain desired line via linecache
        module.
        """
        JsonLogFile.previous_line = desired_line_num
        self._set_pos_to_line(desired_line_num)
        return linecache.getline(LOG_DIR + '/' + self.filename, desired_line_num)

    def findnewlines(self):
        # time.sleep(0.2)
        with open(os.path.join(self.log_path, self.filename), 'r') as logfile:
            lines = []
            if JsonLogFile.previous_line == 0:
                lines = logfile.readlines()
                JsonLogFile.pos = logfile.tell()
            else:
                logfile.seek(JsonLogFile.pos, 0)
                line = logfile.readline()
                while line:
                    lines.append(line)
                    line = logfile.readline()
                JsonLogFile.pos = logfile.tell()

        JsonLogFile.previous_line += len(lines)
        # print(lines)
        # return lines
        return transfer_to_json(lines)

    def write_test(self):
        with open(os.path.join(self.log_path, self.filename), 'a') as logfile:
            line = "".join(str(self.tmp) * 4 + "\n")
            logfile.write(line)
            self.tmp += 1

    def _set_pos_to_line(self, line_num):
        # Set the file pointer to the rear of a specific line.
        with open(os.path.join(self.log_path, self.filename), 'r') as logfile:
            if line_num >= 1:
                pointer = 0
                for current_line_num, line in enumerate(logfile):
                    pointer += len(line)
                    if current_line_num == line_num - 1:
                        break
                self.pos = pointer


class SnortJsonLog(Thread):
    new_lines_list = []
    list_operate_lock = Lock()

    def __init__(self):
        super(SnortJsonLog, self).__init__()
        self.log_file = JsonLogFile()
        self.line_buffer = []

    def run(self):
        while True:
            sleep(0.5)
            lines = self.log_file.findnewlines()
            for line in lines:
                milisec = int(line['timestamp'].split('.')[1])
                line['timestamp'] = float(line['seconds'] + milisec / 1000000)
                self.line_buffer.append(line)
            if SnortJsonLog.list_operate_lock.acquire(blocking=False):
                for line in self.line_buffer:
                    SnortJsonLog.new_lines_list.append(line)
                self.line_buffer.clear()
                SnortJsonLog.list_operate_lock.release()


# For test only
"""
LF = JsonLogFile()
#print(LF.getcertainline_v2(10))
# print(LF.getcertainline(71))
print(LF.pos)
print(LF.previous_line)
print(LF.findnewlines())
print(LF.pos)
print(LF.previous_line)
"""
