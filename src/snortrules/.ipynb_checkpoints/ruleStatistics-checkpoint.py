import os
from snort_rules import SnortRule
from snort_rules import RuleFile

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
                    '''commented_count += 1'''
            elif fields[0] == ("alert" or "drop"):
                deleted_count += 1
                total_count += 1
    else:
        for line in fo:
            fields = line.split(" ")
            if fields[0] == '#' and len(fields) > 1:
                if fields[1] == ("alert" or "drop"):
                    total_count += 1
                    local_total_count += 1
                    commented_count += 1
                    local_commented_count += 1
            elif fields[0] == ("alert" or "drop"):
                total_count += 1
                local_total_count += 1
                local_active_count += 1
                active_count += 1
        print(rule_file, "contains rule number =", local_total_count,
              ", including commented rules = ", local_commented_count, " and activated rules = ", local_active_count)
    return True


def keyword_counting(rule_file):
    global keywords_list
    file_path = os.path.join(PROJECT_DIR_PATH, "snort_rules", rule_file)
    fo = open(file_path, "r")
    for line in fo:
        if SnortRule.is_rule(line):
            # print(line, "\n\n")
            keywords_list += SnortRule(line).opt_keyword_list
            keywords_list = list(set(keywords_list))


def main():
    """
    for f in files:
        name, suffix = os.path.splitext(f)
        if is_suffix_rules(suffix):
            line_counting(f)
            keyword_counting(f)
        else:
            continue
    print("Total rules =", total_count)
    print("Deleted rules=", deleted_count)
    print("Commented rules =", commented_count)
    print("Active rules =", active_count)
    print("\n\n")
    """
    rule = "alert tcp $EXTERNAL_NET any -> $HOME_NET 21 ( msg:\"PROTOCOL-FTP MKD overflow attempt\"; " \
           "flow:to_server,established; content:\"MKD\",nocase; isdataat:150,relative; " \
           "pcre:\"/^MKD(?!\n)\s[^\n]{150}/smi\"; metadata:policy max-detect-ips drop,ruleset community; " \
           "service:ftp; reference:bugtraq,11772; reference:bugtraq,15457; reference:bugtraq,39041; " \
           "reference:bugtraq,612; reference:bugtraq,7278; reference:bugtraq,9872; reference:cve,1999-0911; " \
           "reference:cve,2004-1135; reference:cve,2005-3683; reference:cve,2009-3023; reference:cve,2010-0625; " \
           "reference:nessus,12108; reference:url,technet.microsoft.com/en-us/security/bulletin/MS09-053; " \
           "reference:url,www.kb.cert.org/vuls/id/276653; classtype:attempted-admin; sid:1973; rev:31; )"
    snortrule = SnortRule(rule)
    print(snortrule.rule, "\n\n")
    print(snortrule.rule_options, "\n\n")
    print(snortrule.rule_opt_pairs, "\n\n")
    print(snortrule.opt_keyword_list)
    # keywords_list.sort()
    # print(keywords_list)
    # print(len(keywords_list))


if __name__ == "__main__":
    main()