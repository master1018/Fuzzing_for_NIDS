#!/usr/bin/env python

path = "/root/github/internet_product_safe_test/snortrules"

from imp import reload
import sys
reload(sys)

sys.path.append(path)


from boofuzz import *

from boofuzz import Target, FuzzLogger, Session
import exrex
from alert_analysis.alert_inference import *
from alert_analysis.snort_unix_socket import *
from alert_analysis.fuzzed_cases import FuzzedCase

cnt_number = 0

with open('/root/github/internet_product_safe_test/snortrules/protocol/oneRule_2.rules', 'r') as f:
    rules = f.readlines()


def get_localtime_from_timestamp(timestamp):
    s = time.strftime("[%Y-%m-%d %H:%M:%S", time.localtime(timestamp))
    s += ",%03d]" % (timestamp * 1000 % 1000)
    return s


def alert_check_each_node_callback(target, fuzz_data_logger, session, node, edge, *args, **kwargs):
    fuzz_data_logger.log_check("Each request(node) callback!")
    # print(node)
    # print(edge)


def alert_check_post_case_callback(target, fuzz_data_logger, session, *args, **kwargs):
    fuzz_data_logger.log_check('Post case callback!')
    check_time = time.time()
    global cnt_number
    cnt_number = cnt_number + 1
    # s = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(check_time))
    # s += ",%03d" % (check_time * 1000 % 1000)
    # print("Checking time: {}".format(s))
    current_case = FuzzedCase(rules, check_time, target, fuzz_data_logger, session)
    current_case.match_alert()
    #case_index_lst, alert_index_lst = FuzzedCase.compare_lists(FuzzedCase.rule_triggered_case_list, SnortUnixSocket.alerts_list)
    #FuzzedCase.pop_items_from_list(case_index_lst, alert_index_lst)
    #测试一百次输出一次结果分析
    if cnt_number % 100 == 0:
        # output to the file
        f = open("/root/github/internet_product_safe_test/result_analysis/result_analyze.txt", "w")
        f.write("Result analyze:\n")
        # clean up the two lists
        time.sleep(2)
        f.write("***************************************************************")
        f.write("\n\nAll alert list:\n")
        for alert in SnortUnixSocket.all_alerts_list:
            f.write("alert time:")
            f.write(get_localtime_from_timestamp(alert['timestamp']) + "\n")
        #把所有警报中正常触发的警报弹出来之后剩下的就是误报
        f.write("\n\nUnusual generated alert list:\n")
        for alert in SnortUnixSocket.alerts_list:
            f.write("alert time:")
            f.write(get_localtime_from_timestamp(alert['timestamp']) + "\n")
        f.write("\n\nUnmatched case list:\n")
        for case in FuzzedCase.false_negative_case_list:
            f.write(case['case_no'])
            f.write(get_localtime_from_timestamp(case['timestamp']) + "\n")
        for case in FuzzedCase.rule_triggered_case_list:
            f.write(case['case_no'])
            f.write(get_localtime_from_timestamp(case['timestamp']) + "\n")
        f.close()

def main():
    session = Session(
        restart_sleep_time=1,
        target=Target(connection=TCPSocketConnection("192.168.1.42", port=21)),
        ignore_connection_issues_when_sending_fuzz_data=False,
        post_test_case_callbacks=[alert_check_post_case_callback]
    )

    # snort_log = JsonLogFile()
    # snort_log.initialize_line_num()
    # snort_log_handler = SnortJsonLog()
    # snort_log_handler.start()

    #
    # s_initialize(name="Request")
    # with s_block("Request-Line"):
    #     s_string("GET", name='content-1-HTTP-Method', fuzzable=False)
    #     s_delim(" ", name='space-1', fuzzable=True)
    #     s_string("//svchost.exe", name='content-2-HTTP-URI', fuzzable=False)
    #     s_delim(" ", name='space-2', fuzzable=True)
    #     s_string('HTTP/1.1', name='HTTP-Version', fuzzable=False)
    #     s_static("\r\n", name='CRLF-1')
    # with s_block("Request-Headers"):
    #     s_static("HOST:")
    #     s_string(pcre_str, name='pcre', fuzzable=False)
    #     s_static("\r\n")
    #     s_static("Cookie:")
    #     s_string("qweqsad", name='content-3-HTTP-Cookie', fuzzable=False)
    #     s_static("\r\n")
    # s_static("\r\n", name="CRLF-2")

    s_initialize('Default-USER')
    s_static('USER anonymous\r\n')

    s_initialize('Default-PASS')
    s_static('PASS anonymous\r\n')

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

    s_initialize(name="MKD")
    s_string("MKD", name="content-1", fuzzable=False)
    s_delim(" ", name="space", fuzzable=True)
    pcre = r"^MKD(?!\n)\s[^\n]{150}"
    s_string(exrex.getone(pcre), name='pcre', fuzzable=True)
    s_static("\r\n", name="CRLF")


    s_initialize(name="RMD")
    s_string("RMD", name="content-1", fuzzable=False)
    s_delim(" ", name="space", fuzzable=True)
    pcre = r"^RMD(?!\n)\s[^\n]{100}"
    s_string(exrex.getone(pcre), name='pcre', fuzzable=True)
    s_static("\r\n", name="CRLF")

    s_initialize(name="MDTM-1")
    s_string("MDTM", name="content-1", fuzzable=False)
    s_delim(" ", name="space", fuzzable=True)
    pcre = r"^MDTM(?!\n)\s[^\n]{100}"
    s_string(exrex.getone(pcre), name='pcre', fuzzable=True)
    s_static("\r\n", name="CRLF")

    s_initialize(name="XMKD")
    s_string("XMKD", name="content-1", fuzzable=False)
    s_delim(" ", name="space", fuzzable=True)
    pcre = r"^XMKD(?!\n)\s[^\n]{200}"
    s_string(exrex.getone(pcre), name='pcre', fuzzable=True)
    s_static("\r\n", name="CRLF")

    s_initialize(name="ALLO")
    s_string("ALLO", name="content-1", fuzzable=False)
    s_delim(" ", name="space", fuzzable=True)
    pcre = r"^ALLO(?!\n)\s[^\n]{200}/smi"
    s_string(exrex.getone(pcre), name='pcre', fuzzable=True)
    s_static("\r\n", name="CRLF")

    s_initialize(name="RNTO")
    s_string("RNTO", name="content-1", fuzzable=False)
    s_delim(" ", name="space", fuzzable=True)
    pcre = r"^RNTO(?!\n)\s[^\n]{200}"
    s_string(exrex.getone(pcre), name='pcre', fuzzable=True)
    s_static("\r\n", name="CRLF")

    s_initialize(name="STOU")
    s_string("STOU", name="content-1", fuzzable=False)
    s_delim(" ", name="space", fuzzable=True)
    pcre = r"^STOU\s[^\n]{200}"
    s_string(exrex.getone(pcre), name='pcre', fuzzable=True)
    s_static("\r\n", name="CRLF")

    s_initialize(name="APPE")
    s_string("APPE", name="content-1", fuzzable=False)
    s_delim(" ", name="space", fuzzable=True)
    pcre = r"^APPE(?!\n)\s[^\n]{200}"
    s_string(exrex.getone(pcre), name='pcre', fuzzable=True)
    s_static("\r\n", name="CRLF")

    s_initialize(name="RETR")
    s_string("RETR", name="content-1", fuzzable=False)
    s_delim(" ", name="space", fuzzable=True)
    pcre = r"^RETR(?!\n)\s[^\n]{200}"
    s_string(exrex.getone(pcre), name='pcre', fuzzable=True)
    s_static("\r\n", name="CRLF")

    s_initialize(name="STOR")
    s_string("STOR", name="content-1", fuzzable=False)
    s_delim(" ", name="space", fuzzable=True)
    s_random("A", min_length=0, max_length=250, fuzzable=True)
    s_string("\x0D", name="content-2", fuzzable=True)
    s_string("\x0A", name="content-3", fuzzable=True)
    s_string("\x00", name="content-4", fuzzable=True)
    s_static("\r\n", name="CRLF")

    s_initialize(name="CEL")
    s_string("CEL", name="content-1", fuzzable=False)
    s_delim(" ", name="space", fuzzable=True)
    pcre = r"^CEL(?!\n)\s[^\n]{100}"
    s_string(exrex.getone(pcre), name='pcre', fuzzable=True)
    s_static("\r\n", name="CRLF")

    s_initialize(name="XCWD")
    s_string("XCWD", name="content-1", fuzzable=False)
    s_delim(" ", name="space", fuzzable=True)
    pcre = r"^XCWD(?!\n)\s[^\n]{100}"
    s_string(exrex.getone(pcre), name='pcre', fuzzable=True)
    s_static("\r\n", name="CRLF")

    s_initialize(name="SITE-1")
    s_string("SITE", name="content-1", fuzzable=False)
    s_delim(" ", name="space", fuzzable=True)
    s_string("CHMOD", name="content-2", fuzzable=False)
    pcre = r"^SITE\s+CHMOD\s[^\n]{200}"
    s_string(exrex.getone(pcre), name='pcre', fuzzable=True)
    s_static("\r\n", name="CRLF")

    s_initialize(name="SITE-2")
    s_string("SITE", name="content-1", fuzzable=False)
    s_delim(" ", name="space", fuzzable=True)
    s_string("NEWER", name="content-2", fuzzable=False)
    pcre = r"^SITE\s+NEWER\s[^\n]{100}"
    s_string(exrex.getone(pcre), name='pcre', fuzzable=True)
    s_static("\r\n", name="CRLF")

    s_initialize(name="USER")
    s_string("USER", name="content-1", fuzzable=False)
    s_delim(" ", name="space", fuzzable=True)
    pcre = r"^USER(?!\n)\s[^\n]{100}"
    s_string(exrex.getone(pcre), name='pcre', fuzzable=True)
    s_static("\r\n", name="CRLF")

    s_initialize(name="PASS")
    s_string("PASS", name="content-1", fuzzable=False)
    s_delim(" ", name="space", fuzzable=True)
    pcre = r"^PASS(?!\n)\s[^\n]{100}"
    s_string(exrex.getone(pcre), name='pcre', fuzzable=True)
    s_static("\r\n", name="CRLF")

    s_initialize(name="REST")
    s_string("REST", name="content-1", fuzzable=False)
    s_delim(" ", name="space", fuzzable=True)
    pcre = r"^REST(?!\n)\s[^\n]{100}"
    s_string(exrex.getone(pcre), name='pcre', fuzzable=True)
    s_static("\r\n", name="CRLF")

    s_initialize(name="DELE")
    s_string("DELE", name="content-1", fuzzable=False)
    s_delim(" ", name="space", fuzzable=True)
    pcre = r"^DELE(?!\n)\s[^\n]{100}"
    s_string(exrex.getone(pcre), name='pcre', fuzzable=True)
    s_static("\r\n", name="CRLF")

    s_initialize(name="HELP")
    s_string("HELP", name="content-1", fuzzable=False)
    s_delim(" ", name="space", fuzzable=True)
    pcre = r"^HELP(?!\n)\s[^\n]{200}"
    s_string(exrex.getone(pcre), name='pcre', fuzzable=False)
    s_static("\r\n", name="CRLF")

    s_initialize(name="PORT")
    s_string("PORT ", name="content-1", fuzzable=False)
    s_delim(" ", name="space", fuzzable=True)
    pcre = r"^PORT\x20[^\n]{400}"
    s_string(exrex.getone(pcre), name='pcre', fuzzable=True)
    s_static("\r\n", name="CRLF")

    s_initialize(name="PASV")
    s_string("PASV", name="content-1", fuzzable=False)
    s_delim(" ", name="space", fuzzable=True)
    pcre = r"^PASV(?!\n)\s[^\n]{493}"
    s_string(exrex.getone(pcre), name='pcre', fuzzable=True)
    s_static("\r\n", name="CRLF")

    s_initialize(name="MDTM-2")
    s_string("MDTM", name="content-1", fuzzable=False)
    s_delim(" ", name="space", fuzzable=True)
    pcre = r"^MDTM \d+[-+]\D"
    s_string(exrex.getone(pcre), name='pcre', fuzzable=True)
    s_static("\r\n", name="CRLF")

    s_initialize(name="SITE-3")
    s_string("SITE", name="content-1", fuzzable=False)
    s_delim(" ", name="space", fuzzable=True)
    s_string("EXEC", name="content-2", fuzzable=False)
    pcre = r"^SITE\s+EXEC\s[^\n]*?%[^\n]*?%"
    s_string(exrex.getone(pcre), name='pcre', fuzzable=True)
    s_static("\r\n", name="CRLF")

    s_initialize(name="RENAME")
    s_string("RENAME", name="content-1", fuzzable=False)
    s_delim(" ", name="space", fuzzable=True)
    pcre = r"^RENAME\s[^\n]*?%[^\n]*?%"
    s_string(exrex.getone(pcre), name='pcre', fuzzable=True)
    s_static("\r\n", name="CRLF")

    s_initialize(name="LIST")
    s_string("LIST", name="content-1", fuzzable=False)
    s_delim(" ", name="space", fuzzable=True)
    pcre = r"^LIST\s+\x22-W\s+\d+"
    s_string(exrex.getone(pcre), name='pcre', fuzzable=True)
    s_static("\r\n", name="CRLF")

    s_initialize(name="EPRT")
    s_string("EPRT ", name="content-1", fuzzable=False)
    s_delim(" ", name="space", fuzzable=True)
    pcre = r"^EPRT\x20[^\n]{128}"
    s_string(exrex.getone(pcre), name='pcre', fuzzable=True)
    s_static("\r\n", name="CRLF")

    s_initialize(name="STAT")
    s_string("STAT", name="content-1", fuzzable=False)
    s_delim(" ", name="space", fuzzable=True)
    pcre = r"^STAT(?!\n)\s[^\n]{190}"
    s_string(exrex.getone(pcre), name='pcre', fuzzable=True)
    s_static("\r\n", name="CRLF")

    s_initialize(name="ACCT")
    s_string("ACCT", name="content-1", fuzzable=False)
    s_delim(" ", name="space", fuzzable=True)
    pcre = r"^ACCT(?!\n)\s[^\n]{200}"
    s_string(exrex.getone(pcre), name='pcre', fuzzable=True)
    s_static("\r\n", name="CRLF")
    

    # start listening to Snort's unix socket for alerts
    snort_un_sock = SnortUnixSocket()
    snort_un_sock.start()

    #session.connect(s_get("HELP"))
    # session.connect(s_get("USER"))
    # session.connect(s_get("CEL"))
    # session.connect(s_get("RENAME"))
    session.connect(s_get("Default-USER"))
    session.connect(s_get("Default-USER"), s_get("PASS"))
    #session.connect(s_get("Default-USER"), s_get("Default-PASS"))
    # session.connect(s_get("Default-PASS"), s_get("MKD"))
    # session.connect(s_get("Default-PASS"), s_get("RMD"))
    # session.connect(s_get("Default-PASS"), s_get("MDTM-1"))
    # session.connect(s_get("Default-PASS"), s_get("MDTM-2"))
    #session.connect(s_get("Default-PASS"), s_get("XMKD"))
    #session.connect(s_get("Default-PASS"), s_get("ALLO"))
    #session.connect(s_get("Default-PASS"), s_get("STOU"))
    #session.connect(s_get("Default-PASS"), s_get("XCWD"))
    # session.connect(s_get("Default-PASS"), s_get("SITE-1"))
    # session.connect(s_get("Default-PASS"), s_get("SITE-2"))
    # session.connect(s_get("Default-PASS"), s_get("SITE-3"))
    # session.connect(s_get("Default-PASS"), s_get("REST"))
    # session.connect(s_get("Default-PASS"), s_get("DELE"))
    # session.connect(s_get("Default-PASS"), s_get("PASV"))
    # session.connect(s_get("Default-PASS"), s_get("EPRT"))
    # session.connect(s_get("Default-PASS"), s_get("STAT"))
    # session.connect(s_get("Default-PASS"), s_get("ACCT"))
    # session.connect(s_get("Default-PASS"), s_get("Default-PORT"))
    #session.connect(s_get("Default-PORT"), s_get("APPE"))
    #session.connect(s_get("Default-PORT"), s_get("RETR"))
    # session.connect(s_get("Default-PORT"), s_get("STOR"))
    # session.connect(s_get("Default-PORT"), s_get("LIST"))
    # session.connect(s_get("Default-PASS"), s_get("Default-PASV"))
    # session.connect(s_get("Default-PASS"), s_get("Default-REST"))
    # session.connect(s_get("Default-PASS"), s_get("Default-RNFR"))
    # session.connect(s_get("Default-RNFR"), s_get("RNTO"))
    # session.connect(s_get("Default-QUIT"))

    session.fuzz()

    print("结果分析:\n")
    # clean up the two lists
    time.sleep(2)
    print("***************************************************************")
    case_index_lst, alert_index_lst = FuzzedCase.compare_lists(FuzzedCase.rule_triggered_case_list, SnortUnixSocket.alerts_list)
    FuzzedCase.pop_items_from_list(case_index_lst, alert_index_lst)

    print("\n\nAll alert list:")
    for alert in SnortUnixSocket.all_alerts_list:
        print("alert time:", get_localtime_from_timestamp(alert['timestamp']))
    print("\n\nUnusual generated alert list:")
    for alert in SnortUnixSocket.alerts_list:
        print("alert time:", get_localtime_from_timestamp(alert['timestamp']))
    print("\n\nUnmatched case list:")
    for case in FuzzedCase.false_negative_case_list:
        print(case['case_no'], get_localtime_from_timestamp(case['timestamp']))
    for case in FuzzedCase.rule_triggered_case_list:
        print(case['case_no'], get_localtime_from_timestamp(case['timestamp']))

if __name__ == '__main__':
    main()
