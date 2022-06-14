import unittest
from fuzz_tactics.fuzz_flow_sig_combine import FuzzStrategySigCombine, Signature
from rule_parse.snort_rules import SnortRule,SnortRuleAttr


class MyTestCase(unittest.TestCase):
    def setUp(self):
        print("Actions before test execution=====================")
        self.rule_file = "/root/github/internet_product_safe_test/snortrules/unit_test/test.rules"
        self.strategy = FuzzStrategySigCombine(self.rule_file, ['ftp'], ('211.69.198.54', 8080))
        self.signature = Signature(rule_id='1-16667',pattern_str="|44 44 44 44 44|a|41 41 41|dff", sig_type="content")
        self.rule_string = "alert tcp $EXTERNAL_NET $HTTP_PORTS -> $HOME_NET any " \
                    "( msg:\"BROWSER-CHROME Google Chrome GURL cross origin bypass attempt\"; " \
                    "flow:to_client,established; file_data; content:\"|3C|iframe\",nocase; " \
                    "content:\"src=|22|https|3A 2F 2F|www.google.com|2F|accounts|2F|ManageAccount?hl=fr|22|\"," \
                    "within 100,nocase; " \
                    "content:\"window.open|28 27|\",within 500; content:\"alert|28|document.cookie|29 27|\"," \
                    "within 75; " \
                    "pcre:\"/window\.open\x28\x27[\w\W]{0,35}\x3aalert\x28document\.cookie\x29\x27/smi\"; " \
                    "metadata:policy max-detect-ips drop; service:http; reference:bugtraq,39813; " \
                    "reference:cve,2010-1663; classtype:attempted-user; sid:16667; rev:12; )"
        self.rule = SnortRule(self.rule_string)
        self.rule_attr = SnortRuleAttr(self.rule)

    def tearDown(self):
        print("Actions after test execution======================")

    def test_rule_selection(self):
        self.strategy.rule_selection()
        # print(self.strategy.rule_groups)
        # self.assertEqual(True, False)

    def test_implement_strategy(self):
        self.strategy.rule_selection()
        print(self.strategy.implement_strategy())

    def test_signature(self):
        print(self.signature.get_transformed_pattern())
        print(len(self.signature.get_transformed_pattern()))
        self.signature.set_sig("s|00|p|00|_|00|r|00|e|00|p|00|l|00|w|00|r|00|i|00|t|00|e|00|t|00|o|00|v|00|a|00|r|00|b|00|i|00|n|00|")
        print(self.signature.get_transformed_pattern())
        print(self.signature.length)


if __name__ == '__main__':
    unittest.main()
