from abc import ABC
from boofuzz import *

path = "/root/github/internet_product_safe_test/snortrules"

import sys

sys.path.append(path)
from fuzz_tactics.fuzz_flow_base import FuzzStrategyFlowBase
from fuzz_exec.rule_selection import RuleSelector
from fuzz_exec.fuzz_code_generator import FuzzCodeGenerator, FuzzPrimitive, generate_data_from_rule
from rule_parse.snort_rules import SnortRule, SnortRuleAttr, RuleFile


class FuzzStrategySequential(FuzzStrategyFlowBase):
    def __init__(self, rule_file, protocols, target):
        super(FuzzStrategySequential, self).__init__('sequential', rule_file, protocols, target)
        self.fuzz_primitives = None

    def rule_selection(self):
        if self.rule_select_method:
            rule_selector = RuleSelector(self.rule_file, 'ftp', self.rule_select_method)
        else:
            rule_selector = RuleSelector(self.rule_file, 'ftp', 'sequence')
        if rule_selector.select_rules_by_method():
            self.selected_rules = rule_selector.selected_rules

    def rule_trim(self):
        if self.selected_rules:
            pass
        else:
            pass

    def implement_strategy(self):
        fuzz_primitives = FuzzPrimitive()
        if self.selected_rules:
            for path, rules in self.selected_rules.items():
                if isinstance(path, str):
                    if not fuzz_primitives.has_request("Default-" + path):
                        fuzz_primitives.add_request("Default-" + path)
                else:
                    for elem in path:
                        if not fuzz_primitives.has_request("Default-" + elem):
                            fuzz_primitives.add_request("Default-" + elem)
                for rule in rules:
                    options = SnortRuleAttr(rule)
                    request_name = "-".join(["REQ", str(options.get_opt_gid()),
                                             str(options.get_opt_sid()), str(options.get_opt_rev())])
                    request_data = generate_data_from_rule(rule, 'ftp')
                    fuzz_primitives.add_request(request_name)
                    fuzz_primitives.add_data_to_request(request_name, request_data)
                    # add request relationship
                    if isinstance(path, str):
                        fuzz_primitives.add_request_relationship("Default-" + path, request_name)
                    else:
                        fuzz_primitives.add_request_relationship("Default-" + path[-1], request_name)
        self.fuzz_primitives = fuzz_primitives

    def fuzz_code_generation(self):
        code_generator = FuzzCodeGenerator(self.fuzz_primitives, 'ftp', ("172.17.0.2", 21))
        session = code_generator.generate_codes()
        if not session:
            pass
        else:
            self.session = session

    def result_output(self):
        pass


# -------------------------------------
# test codes
# -------------------------------------
rule_file_path = "/root/github/internet_product_safe_test/snortrules/protocol/oneRule_2.rules"
# rf = RuleFile(rule_file_path)
fuzz_strategy = FuzzStrategySequential(rule_file_path, ['ftp'], ('172.17.0.2', 21))
fuzz_strategy.rule_selection()
fuzz_strategy.implement_strategy()
fuzz_strategy.fuzz_code_generation()
print(fuzz_strategy.session)
