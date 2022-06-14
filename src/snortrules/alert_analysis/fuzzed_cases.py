#! /usr/bin/env python
from asyncore import write
from alert_analysis.alert_inference import *
from alert_analysis.snort_unix_socket import SnortUnixSocket
from alert_analysis.snort_log_file import *


time_window = 5
match_loop = 10


def get_msec_from_timestamp(timestamp):
    if timestamp < 0:
        if abs(timestamp) <= 1:
            millisecond = abs(timestamp) * 1000 % 1000
        else:
            millisecond = -1
    elif timestamp > 1:
        millisecond = -1
    else:
        millisecond = timestamp * 1000 % 1000
    return millisecond


class FuzzedCase(object):
    rule_triggered_case_list = []
    false_negative_case_list = []
    fuzzed_case_list = []
    match_loop_counter = match_loop

    def __init__(self, rules, check_time, target: Target, logger: FuzzLogger, session: Session, mode="unixsock"):
        self.session = session
        self.target = target
        self.logger = logger
        self.check_time = check_time
        self.mode = mode
        self.rules = rules

    def _create_case_dict(self):
        keys = ["timestamp", "case_no", "pkt", "alert_num"]
        values = [self.check_time, self.session.total_mutant_index, self.session.last_send, 0]
        return dict(zip(keys, values))

    def _match_unixsock(self, alert_inference):
        # STEP 1: put fuzzed cases that are supposed to trigger rules into list
        alert_num = alert_inference.inferred_alert_num()
        case_dict = self._create_case_dict()
        if alert_num > 0:
            case_dict['alert_num'] = alert_num
            FuzzedCase.rule_triggered_case_list.append(case_dict)
        FuzzedCase.fuzzed_case_list.append(case_dict)

        # STEP 2: compare the case list and alert list to filter out the correctly triggered alerts
        #         as well as their corresponding cases
        case_index_lst, alert_index_lst = self.compare_lists(FuzzedCase.rule_triggered_case_list, SnortUnixSocket.alerts_list)

        # STEP 3: pop the matched cases as well as alerts from each list
        self.pop_items_from_list(case_index_lst, alert_index_lst)

    def _match_json_logfile(self, alert_inference):
        alert_num = alert_inference.inferred_alert_num()
        if alert_num > 0:
            case = self._create_case_dict()
            FuzzedCase.rule_triggered_case_list.append(case)

        case_index_lst, alert_index_lst = FuzzedCase.compare_lists(FuzzedCase.rule_triggered_case_list, SnortJsonLog.new_lines_list)

        self.pop_items_from_list(case_index_lst, alert_index_lst, mode='json')

    def match_alert(self):
        alert_inference = AlertInference(self.rules, self.check_time, self.target, self.logger, self.session)

        # Process the precedent rule triggering cases. Pop them out if they get timed out (more than 5s).
        if FuzzedCase.match_loop_counter == 0:
            for case in FuzzedCase.rule_triggered_case_list:
                if self.check_time - case['timestamp'] > time_window:
                    FuzzedCase.false_negative_case_list.append(case)
                    FuzzedCase.rule_triggered_case_list.remove(case)
            FuzzedCase.match_loop_counter = match_loop
        else:
            FuzzedCase.match_loop_counter -= 1

        if self.mode == "unixsock":
            SnortUnixSocket.list_operate_lock.acquire()
            self._match_unixsock(alert_inference)
            SnortUnixSocket.list_operate_lock.release()
        elif self.mode == "json":
            SnortJsonLog.list_operate_lock.acquire()
            self._match_json_logfile(alert_inference)
            SnortJsonLog.list_operate_lock.release()
        else:
            self.logger.log_error("Unsupported matching mode: {}".format(self.mode))

    @staticmethod
    def compare_lists(rule_triggered_case_list, alerts_list):
        case_index_lst = []
        alert_index_lst = []
        if SnortUnixSocket.alerts_list:
            for case_index, case in enumerate(rule_triggered_case_list):
                for alert_index, alert in enumerate(alerts_list):
                    if 0 <= get_msec_from_timestamp(case['timestamp'] - alert['timestamp']) <= 4:
                        case['alert_num'] -= 1
                        alert['matched_case_no'] = case['case_no']
                        alert_index_lst.append(alert_index)
                if case['alert_num'] == 0:
                    case_index_lst.append(case_index)
        return case_index_lst, alert_index_lst

    @staticmethod
    def pop_items_from_list(case_index_lst, alert_index_lst, mode='unixsock'):
        if case_index_lst:
            for index in case_index_lst[::-1]:
                # print("Case {} match succeeded.".format(FuzzedCase.rule_triggered_case_list[index]['case_no']))
                print("Poping case index: %d," % index,
                      "case no = %d," % FuzzedCase.rule_triggered_case_list[index]['case_no'],
                      "case timestamp = %.4f" % FuzzedCase.rule_triggered_case_list[index]['timestamp'],
                      "case list num = %d," % len(FuzzedCase.rule_triggered_case_list))
                
                # output to the file
                f = open("/root/github/internet_product_safe_test/result_analysis/test_log", "a+")
                pop_msg = "Poping case index: %d" % index + "case no = %d," % FuzzedCase.rule_triggered_case_list[index]['case_no'] \
                            + "case timestamp = %.4f" % FuzzedCase.rule_triggered_case_list[index]['timestamp'] + "case list num = %d," % len(FuzzedCase.rule_triggered_case_list) + '\n'
                f.write("*********************************************************************\n")
                f.write(pop_msg)
                f.write("*********************************************************************\n")
                print("")
                f.close()

                
                FuzzedCase.rule_triggered_case_list.pop(index)
        if alert_index_lst:
            alert_index_lst.sort()
            if mode == 'unixsock':
                for index in alert_index_lst[::-1]:
                    print("Poping alert index: %d," % index,
                          "alert matched case no: %d," % SnortUnixSocket.alerts_list[index]['matched_case_no'],
                          "alert timestamp = %.4f" % SnortUnixSocket.alerts_list[index]['timestamp'],
                          "alert list num = %d" % len(SnortUnixSocket.alerts_list))

                    # output to the file
                    f = open("/root/github/internet_product_safe_test/result_analysis/test_log", "a+")
                    pop_msg = "Poping alert index: %d," % index + "alert matched case no: %d," % SnortUnixSocket.alerts_list[index]['matched_case_no'] \
                            + "alert timestamp = %.4f" % SnortUnixSocket.alerts_list[index]['timestamp'] + "alert list num = %d" % len(SnortUnixSocket.alerts_list) + '\n'
                    f.write("*********************************************************************\n")
                    f.write(pop_msg)
                    f.write("*********************************************************************\n")
                    print("")
                    f.close()

                    SnortUnixSocket.alerts_list.pop(index)
            elif mode == 'json':
                for index in alert_index_lst[::-1]:
                    SnortJsonLog.new_lines_list.pop(index)
            else:
                print("Unsupported mode.\n")
