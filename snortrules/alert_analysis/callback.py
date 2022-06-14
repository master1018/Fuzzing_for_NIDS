import time
from alert_analysis.fuzzed_cases import FuzzedCase

def alert_check_each_node_callback(target, fuzz_data_logger, session, node, edge, *args, **kwargs):
    fuzz_data_logger.log_check("Each request(node) callback!")
    # print(node)
    # print(edge)


def alert_check_post_case_callback(target, fuzz_data_logger, session, *args, **kwargs):
    fuzz_data_logger.log_check('Post case callback!')
    check_time = time.time()
    # s = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(check_time))
    # s += ",%03d" % (check_time * 1000 % 1000)
    # print("Checking time: {}".format(s))
    current_case = FuzzedCase(rules, check_time, target, fuzz_data_logger, session)
    current_case.match_alert()