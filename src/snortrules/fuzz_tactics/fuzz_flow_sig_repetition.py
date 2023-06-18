#!/usr/bin/env python
import random,math,string,exrex

path = "/root/github/internet_product_safe_test/snortrules"

import sys

sys.path.append(path)

from rule_parse.snort_rules import *
from fuzz_exec.rule_selection import RuleInfo
from fuzz_tactics.fuzz_flow_base import FuzzStrategyFlowBase
from alert_analysis.alert_inference import hex_str_to_char_str
from fuzz_tactics.fuzz_flow_sig_combine import Signature


class FuzzStrategySigRepetition(FuzzStrategyFlowBase):
    def __init__(self, rule_file, protocols, target, max_rule_num=10, iteration=5,looptime=5):
        super(FuzzStrategySigRepetition, self).__init__('sig_repetition', rule_file, protocols, target)
        self.rule_list = self.rule_file.get_rule_set(is_active=True)  # list of rules as SnortRule
        self.repeated_sig_dict = {}
        self._adopted_rules = []
        self.rule_groups = None
        self._repeated_rule_num = 0
        self.max_rule_num = max_rule_num
        self.iteration = iteration
        self.looptime=looptime
        self.snortrule_attr = None
        self.content_and_pcre = []
        self.data = ""
        self.datalen = 0

    def get_repeated_signatures(self):
        return self.repeated_sig_dict

    def rule_selection(self):
        # group rules by protocols
        # do not use this one now , still use the whole rule_list
        self.rule_groups = {}
        for rule in self.rule_list:
            rule_proto = RuleInfo(rule).protocol_info()
            for proto in rule_proto[2]['flag']:
                if proto in self.protocol_list:
                    if proto in self.rule_groups.keys():
                        self.rule_groups[proto].append(rule)
                    else:
                        self.rule_groups[proto] = []
                        self.rule_groups[proto].append(rule)
                else:
                    print("Unsupported protocol:", proto)

    def rule_trim(self):
        return

    def implement_strategy(self):
        for single_rule in self.rule_list:
            self.snortrule_attr=SnortRuleAttr(single_rule)
            self.content_and_pcre=[]
            self.data=""
            self.datalen=0
            single_sig_dict={}
            self.converge_content_and_pcre()
            self.construct_data_one_by_one()
            #self.data_add_last_pcre() #optionial, default closed
            single_sig_dict['one_by_one']=self.data
            self.data=""
            self.datalen=0
            self.construct_data_group()
            #self.data_add_last_pcre()  #optionial, default closed
            single_sig_dict['group'] = self.data
            self.repeated_sig_dict[self.snortrule_attr.get_opt_sid()]=single_sig_dict   #[TODO]:dict的key值也可以直接是顺序的，以方便之后的fuzz操作,目前是sid
            print(self.repeated_sig_dict)

        return self.repeated_sig_dict

    def converge_content_and_pcre(self):
        print(self.snortrule_attr.get_opt_content())
        self.content_and_pcre = self.snortrule_attr.get_opt_content()
        #if len(self.snortrule_attr.option_index('pcre'))==0:
        #    return
        self.content_and_pcre.append(self.snortrule_attr.get_opt_pcre())
        # pcre_index = self.snortrule_attr.option_index('pcre')[0]
        # index = -1
        # add_flag = False
        # for num in self.snortrule_attr.option_index('content'):
        #     index = index + 1
        #     if num < pcre_index:
        #         continue
        #     else:
        #         self.content_and_pcre.insert(index, self.snortrule_attr.get_opt_pcre())
        #         add_flag = True
        # if not add_flag:
        #     self.content_and_pcre.append(self.snortrule_attr.get_opt_pcre())
        # for case in self.content_and_pcre:
        #     print(case)

    def show_content_and_pcre(self):
        for case in self.content_and_pcre:
            print(case)

    def construct_data_one_by_one(self):    #method 1; construct AAAAABBBBBCCCCCD
        length=len(self.content_and_pcre)
        index=0
        if length==2: return    #two conte nt or one content and one pcre
        while index <= length-2:
            #basic information gather
            current_dic=self.content_and_pcre[index]
            next_dic=self.content_and_pcre[index+1]
            next_has_within = False
            next_has_distance = False
            current_has_depth=False
            current_has_offset=False
            if 'within' in next_dic and next_dic['within'] !=None:
                next_has_within=True   #current increase should less than within
            if 'distance' in next_dic and next_dic['distance'] !=None:
                next_has_distance=True  #for later use
            if 'depth' in next_dic and current_dic['depth'] !=None:
                current_has_depth=True  #for later use
            if 'offset' in next_dic and current_dic['offset'] !=None:
                current_has_offset=True  #for later use

            if 'match' in current_dic:
                mode='content'
            else:mode='pcre'
            ceil_loop_time=self.looptime   #[TODO]  Default 150
            floor_loop_time=1
            #caculate proper current_dic loop time
            if mode=='content':
                seed=current_dic['match']
                seed_len=len(seed)
                if next_has_within:
                    max_loop_time=self.max_loop_time_decide_by_within(seed_len,next_dic['within'])
                    if max_loop_time<ceil_loop_time:
                        ceil_loop_time=max_loop_time
                if next_has_distance:
                    min_loop_time=self.min_loop_time_decide_by_distance(seed_len,next_dic['distance'])
                    if min_loop_time>floor_loop_time:
                        floor_loop_time=min_loop_time
                if current_has_depth:
                    max_loop_time=self.max_loop_time_decide_by_depth(self.datalen,seed_len,current_dic['depth'])
                    if max_loop_time==None: pass
                    if max_loop_time<ceil_loop_time:
                        ceil_loop_time=max_loop_time
                if current_has_offset:
                    status=self.min_loop_time_decide_by_offset(self.datalen,seed_len,current_dic['offset'])
                    if status==False:   #means need to pack the blank
                        self.data=self.data+''.join(random.sample(string.ascii_letters + string.digits, self.datalen-current_dic['offset']))
                #loop_time=random.randint(ceil_loop_time,ceil_loop_time) #[TODO] both are ceil_loop_time
                final_loop_time=ceil_loop_time
                self.data=self.data+self.loop_seed(seed,final_loop_time)
                self.datalen=len(self.data)
            if mode=='pcre':
                pass  # presume pcre is always the last one in content_and_pcre
            index=index+1
        # self.data = self.data + ''.join(
        #     random.sample(string.ascii_letters + string.digits, 10))
    def construct_data_group(self):
        length=len(self.content_and_pcre)
        if length == 2: return
        loop=0
        while loop<self.looptime:    #looptime=4  0,1,2,3
            index=0
            while index <= length-2:
                current_dic = self.content_and_pcre[index]
                seed = current_dic['match']
                self.data = self.data + self.loop_seed(seed, 1)
                index=index+1
            loop=loop+1

    def data_add_last_pcre(self):   #can decide weather add this last pcre|content or not
        """
        Add the pcre part to make the data  match the rule    or add last content if there is no pcre
        """
        if len(self.content_and_pcre[len(self.content_and_pcre)-1])!=3: #no pcre and add content
            self.data += self.content_and_pcre[len(self.content_and_pcre)-1]['match']
            return
        pcre=self.content_and_pcre[len(self.content_and_pcre)-1]['pattern']
        self.data=self.data+exrex.getone(pcre)


    def max_loop_time_decide_by_within(self,seed_len,next_within_number):
        """
        Decide current seed max loop time by current seed length
        and next seed 'within' number
        """
        return math.floor(next_within_number/seed_len)+1

    def min_loop_time_decide_by_distance(self,seed_len,next_distance_number):
        """
        Decide current seed min loop time by current seed length
        and next seed 'distance' number
        """
        return math.ceil(next_distance_number/seed_len)+1

    def max_loop_time_decide_by_depth(self,datalen,seed_len,current_depth_number):
        """
        Decide current seed max loop time by current seed length,current datalen
        and current seed 'depth' number
        """
        if datalen >=current_depth_number: return None
        allowed_length=current_depth_number-datalen
        return max(math.floor(allowed_length/seed_len),1)

    def min_loop_time_decide_by_offset(self,datalen,seed_len,current_offset_number):
        """
        Decide current seed max loop time by current seed length,current datalen
        and current seed 'offset' number
        """
        if datalen <=current_offset_number: return False    #need 补充字节到指定长度以后再进行构造
        allowed_length=datalen-current_offset_number   #不做限制了 随意匹配
        return True

    def loop_seed(self,seed,loop_time):
        """

        :param seed: current content
        :param loop_time:
        :return: current data
        """
        data=""
        t=0
        while t<loop_time:
            data=data+seed
            t=t+1
        return data



    def fuzz_code_generation(self):
        return

    def _update_sig_index(self):
        pass

# -------------------------------------
# test codes
# -------------------------------------
rule_file_path = "/root/github/internet_product_safe_test/snortrules/protocol/oneRule.rules"
#rule_file_path="./expRules.rules"
#rf = RuleFile(rule_file_path)
fuzz_strategy = FuzzStrategySigRepetition(rule_file_path, ['ftp'], ('192.168.1.42', 21))
#fuzz_strategy.rule_selection()
fuzz_strategy.implement_strategy()
fuzz_strategy.fuzz_code_generation()
print(fuzz_strategy.session)