import os
from snort_rules import *

PROJECT_DIR_PATH = os.path.dirname(os.path.abspath(os.path.abspath(__file__)))
DIR_PATH = os.path.join(PROJECT_DIR_PATH, "snort_rules")
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
    local_total_count = 0
    local_commented_count = 0
    local_active_count = 0
    file_path = os.path.join(PROJECT_DIR_PATH, "snort_rules", rule_file)
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


def keyword_counting(rule_file, keyword):
    file_path = os.path.join(PROJECT_DIR_PATH, "snort_rules", rule_file)
    return snort_rule_option_statistic(file_path, keyword)


def header_counting(rule_file):
    file_path = os.path.join(PROJECT_DIR_PATH, "snort_rules", rule_file)
    return snort_rule_header_statistic(file_path)


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
    for f in files:
        name, suffix = os.path.splitext(f)
        if is_suffix_rules(suffix):
            if name == "snort3-deleted":
                continue
            kc = keyword_counting(f, "flowbits")
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
        else:
            continue
    opt_sum = 0
    for value in keyword_count.values():
        opt_sum += value
    print(keyword_count, "\n\n")
    print(header_count, "\n\n")
    print(opt_sum, "\n\n")

    # rule = ""
    # snortrule = SnortRule(rule)
    # print(snortrule.get_proto(), "\n\n")
    # print(snortrule.opt_keyword_list, "\n\n")
    # print(snortrule.rule_opt_pairs, "\n\n")
    # print(SnortRuleAttr(snortrule).get_opt_metadata(), "\n\n")
    # keywords_list.sort()
    # print(keywords_list)
    # print(len(keywords_list))


if __name__ == "__main__":
    main()
