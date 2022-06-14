import os
from rule_model.ruleModel import *
from snort_rules import *

PROJECT_DIR_PATH = os.path.dirname(os.path.abspath(os.path.abspath(__file__)))
file_path = os.path.join(PROJECT_DIR_PATH, "Rule_samples.rules")


def main():
    rf = RuleFile(file_path)
    ruleset = rf.get_rule_set()
    rule_set_model = RuleSetModel(ruleset)
    i = 1
    for rule in ruleset:
        print("Rule number:", i)
        rm = RuleModel(rule)
        print(rm.attack)
        print(rm.flowbits)
        print(RuleInfo(rule).protocol_info())
        print(rm.node_lst_l3, rm.node_lst_l4, rm.node_lst_l5)
        for node in rm.node_lst:
            print(node.get_link())
        print("\n")
        i += 1


if __name__ == "__main__":
    main()
