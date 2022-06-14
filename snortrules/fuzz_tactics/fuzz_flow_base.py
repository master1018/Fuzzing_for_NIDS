"""
This file defines the base fuzzing steps for each fuzzing tactics.
"""
import abc
from rule_parse.snort_rules import RuleFile
from boofuzz import *


class FuzzStrategyFlowBase(object):
    def __init__(self, strategy_name, rule_file, protocol_list, target):
        self.strategy_name = strategy_name
        self.rule_file = RuleFile(rule_file)
        self.target = target
        self.protocol_list = protocol_list
        self.session = None
        self.rule_select_method = None
        self.selected_rules = None

    @abc.abstractmethod
    def rule_selection(self):
        pass

    def rule_trim(self):
        pass

    @abc.abstractmethod
    def implement_strategy(self):
        pass

    @abc.abstractmethod
    def fuzz_code_generation(self):
        pass

    def fuzz(self):
        if self.session:
            self.session.fuzz()
        else:
            print("No session defined.")

    def result_output(self):
        pass
