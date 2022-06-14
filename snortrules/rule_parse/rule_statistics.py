import os
from rule_parse.snort_rules import *

PROJECT_DIR_PATH = os.path.dirname(os.path.abspath(os.path.abspath(__file__)))
DIR_PATH = "/root/github/internet_product_safe_test/snortrules/snort_rules"
files = os.listdir(DIR_PATH)
total_count = 0
commented_count = 0
deleted_count = 0
active_count = 0
keywords_list = []


def is_suffix_rules(file_suffix: str):
    if file_suffix == ".rules":
        return True


def line_counting(rule_file):
    global total_count
    global commented_count
    global deleted_count
    global active_count
    file_path = os.path.join(DIR_PATH, rule_file)
    fo = open(file_path, "r", encoding='UTF-8')
    if rule_file == "snort3-deleted.rules":
        for line in fo:
            fields = line.split(" ")
            if fields[0] == '#' and len(fields) > 1:
                if fields[1] == ("alert" or "drop"):
                    deleted_count += 1
                    total_count += 1
            elif fields[0] == ("alert" or "drop"):
                deleted_count += 1
                total_count += 1
    else:
        rf = RuleFile(file_path)
        result = rf.rule_counts()
        total_count += result[0]
        active_count += result[1]
        commented_count += result[2]
    fo.close()


def keyword_counting(rule_file, keyword):
    file_path = os.path.join(DIR_PATH, rule_file)
    return snort_rule_option_statistic(file_path, keyword)


def header_counting(rule_file):
    file_path = os.path.join(DIR_PATH, rule_file)
    return snort_rule_header_statistic(file_path)


def rule_filtration(rule_file, option, keyword):
    file_path = os.path.join(DIR_PATH, rule_file)
    rule_list = []
    with open(file_path, "r") as fo:
        for line in fo:
            if SnortRule.is_rule(line):
                rule = SnortRule(line)
                if option in rule.opt_keyword_list:
                    for item in rule.rule_opt_pairs[option]:
                        if item.find(keyword) != -1:
                            rule_list.append(line)
    return rule_list


def main():
    """
    for f in files:
        name, suffix = os.path.splitext(f)
        if is_suffix_rules(suffix):
            line_counting(f)
            # keyword_counting(f)
        else:
            continue
    print("Total rules =", total_count)
    print("Deleted rules=", deleted_count)
    print("Commented rules =", commented_count)
    print("Active rules =", active_count)
    print("\n\n")
    """

    keyword_count = {}
    header_count = {}
    filtered_rules = []
    for f in files:
        name, suffix = os.path.splitext(f)
        if is_suffix_rules(suffix):
            if name == "snort3-deleted":
                continue
            kc = keyword_counting(f, "service")
            for key, value in kc.items():
                if key in keyword_count:
                    keyword_count[key] += value
                else:
                    keyword_count[key] = value
            hc = header_counting(f)
            for key, value in hc.items():
                if key in header_count:
                    header_count[key] += value
                else:
                    header_count[key] = value
            rf = rule_filtration(f, 'flowbits', 'smb')
            for rule in rf:
                filtered_rules.append(rule)
        else:
            continue
    opt_sum = 0
    for value in keyword_count.values():
        opt_sum += value
    print(keyword_count, "\n\n")
    print(header_count, "\n\n")
    print(opt_sum, "\n\n")
    print(filtered_rules, "\n\n")

    for f in files:
        name, suffix = os.path.splitext(f)
        if name == "snort3-protocol-ftp":
            print(keyword_counting(f, 'pcre'), "\n\n")
            print(keyword_counting(f, 'content'), "\n\n")
            print(keyword_counting(f, 'isdataat'), "\n\n")
            print(keyword_counting(f, 'service'), "\n\n")

    rule = "alert tcp $EXTERNAL_NET any -> $HOME_NET 21 ( " \
           "msg:\"PROTOCOL-FTP WS-FTP REST command overly large file creation attempt\"; " \
           "flow:to_server,established; " \
           "content:\"REST \"; byte_test:10,>,1000000000, 0, relative, string, dec; " \
           "byte_extract: 2, 0, var_match, relative, bitmask 0x03ff; " \
           "byte_math: bytes 2, offset 0, oper -, rvalue 100, result var, relative, bitmask 0x7FF0; " \
           "metadata:policy max-detect-ips drop; service:ftp; reference:bugtraq,9953; reference:cve,2004-1848; " \
           "classtype:attempted-dos; sid:43239; rev:2; )"
    snortrule = SnortRule(rule)
    print(snortrule.rule_opt_pairs)
    # print(snortrule.get_proto(), "\n\n")
    # print(snortrule.opt_keyword_list, "\n\n")
    # print(snortrule.rule_opt_pairs, "\n\n")
    print(SnortRuleAttr(snortrule).get_opt_content(), "\n\n")
    print(SnortRuleAttr(snortrule).get_opt_byte_math(), "\n\n")
    print(SnortRuleAttr(snortrule).get_opt_isdataat())
    # keywords_list.sort()
    # print(keywords_list)
    # print(len(keywords_list))
    # print(snortrule.rule_options)


if __name__ == "__main__":
    main()
