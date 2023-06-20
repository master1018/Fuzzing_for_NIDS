import base64
import time
import sys
from graphviz import Graph
from pathlib import Path
import os
import streamlit as st
from matplotlib import pyplot as plt
import numpy as np
import pandas as pd
from st_aggrid import AgGrid, DataReturnMode, GridUpdateMode, GridOptionsBuilder
from streamlit_echarts import st_echarts
from streamlit_option_menu import option_menu
from streamlit_ace import st_ace
from PIL import Image
from streamlit_elements import elements, mui, html
from streamlit_elements import dashboard
import random
from plt_t import *

def static():
    sum_lines = 0
    for file in st.session_state.show_rule:
        fp = open("./db/snort/" + file, "r")
        while True:
            line = fp.readline()
            if not line:
                break
            if len(line) >= 10 and line[0 : 5] == "alert":
                sum_lines += 1
    assert(sum_lines > 0)
    return sum_lines

def aggrid(df, key, keys=0):

    gb = GridOptionsBuilder.from_dataframe(df)
    if keys == 0:
        selection_mode = 'multiple' # 定义单选模式，多选为'multiple'
    else:
        selection_mode = 'single'
    enable_enterprise_modules = True # 设置企业化模型，可以筛选等
    #gb.configure_default_column(editable=True) #定义允许编辑
    
    return_mode_value = DataReturnMode.FILTERED  #__members__[return_mode]
    gb.configure_selection(selection_mode, use_checkbox=True) # 定义use_checkbox
    
    gb.configure_side_bar()
    gb.configure_grid_options(domLayout='normal')
    gb.configure_pagination(paginationAutoPageSize=False, paginationPageSize=10)
    #gb.configure_default_column(editable=True, groupable=True)
    gridOptions = gb.build()
    
    update_mode_value = GridUpdateMode.MODEL_CHANGED
    
    grid_response = AgGrid(
                        df, 
                        gridOptions=gridOptions,
                        fit_columns_on_grid_load = True,
                        data_return_mode=return_mode_value,
                        update_mode=update_mode_value,
                        enable_enterprise_modules=enable_enterprise_modules,
                        theme='streamlit'
                        )  
    #df = grid_response['data']
    selected = grid_response['selected_rows']
    if len(selected) == 0:
        return -1
    else:
        if keys == 0:
            return_list = []
            for i in range(0, len(selected)):
                return_list.append(selected[i][key])
            return return_list
        else:
            return [selected[0][keys[0]], selected[0][keys[1]]]


def list_to_df(src_list, colums_name):
    src_array = np.array(src_list)
    df = pd.DataFrame(src_array)
    df.columns = colums_name
    return df


def read_markdown_file(filepath):
    with open(filepath, 'r', encoding='utf-8') as f:
        return f.read()

def callback1():
    st.session_state.res = 1
    st.session_state.loading = 1
        

def get_rules_file(path, type):
    dir = os.listdir(path)
    file_list = []
    for file in dir:
        if type in file:
            file_list.append([file])
    return file_list

def callback3():
    st.session_state.res = 2

def res1():
    if st.session_state.res == 2:
        res2()
        return 0
    
    if st.session_state.product == 1:
        st.header("Snort接口导入成功")
        with st.expander("版本信息"):
            text = read_markdown_file("./markdown/1.md")
            st.markdown(text, unsafe_allow_html=True)
        rules_list = get_rules_file("./db/snort/", "rules")
        df = list_to_df(rules_list, ["规则集文件"])
        c1, c2 = st.columns(2)
        with c1:
            st.markdown("""
            <video width="400" autoplay="true" muted="true" loop="true" align="center">
            <source 
                    src="https://www.jfrogchina.com/wp-content/uploads/2020/02/Realtime-Vul-R1-Animation-400X400.mp4" 
                    type="video/mp4" />
            </video>
            """, unsafe_allow_html=True)
        with c2:
            st.session_state.show_rule = aggrid(df, "规则集文件")
        if st.session_state.show_rule != "null" and st.session_state.show_rule != -1:
            for i in range(0, len(st.session_state.show_rule)):
                rule_file = "./db/snort/" + st.session_state.show_rule[i]
                fp = open(rule_file, "r")
                buff = fp.read()
                fp.close()
                with st.expander(st.session_state.show_rule[i]):
                    st.code(buff)
        
            st.button("导入选中规则集", on_click=callback3)

def callback2():
    st.session_state.foot = 2

def show_loading1():
    c1, c2 = st.columns(2)
    with c1:
        st.image("./image/loading.gif", width=300)
    ele = c2.empty()
    with ele:
        st.header("Loading...")
    st.write(" ")
    st.write(" ")
    st.write(" ")
    st.write(" ")
    time.sleep(0.3)
    with ele:
        st.header("Finish!")
    st.button("下一页", on_click=callback2)
    st.session_state.loading = 0
    

def ui1():
    st.markdown("""
            <video width="1000" autoplay="true" muted="true" loop="true" align="center">
            <source 
                    src="https://video.3wt.eduingame.cn/2023/06-19/39f9d0628ca44247bb3e627ce1e311d33wcn470624.mp4" 
                    type="video/mp4" />
            </video>
            """, unsafe_allow_html=True)
    for i in range(0, 10):
        st.write(" ")

    st.markdown("""
            <video width="1000" autoplay="true" muted="true" loop="true" align="center">
            <source 
                    src="http://localhost:8000/2023%20%281%29.mp4" 
                    type="video/mp4" />
            </video>
            """, unsafe_allow_html=True)

def callback4():
    st.session_state.run = 1


def res2():
    m = st.markdown("""
    <style>
    div.stButton > button:first-child {
        background-color: #f44336; /* Green */
        border: none;
        color: white;
        padding: 20px 40px;
        text-align: center;
        text-decoration: none;
        display: inline-block;
        font-size: 16px;
    }
    </style>""", unsafe_allow_html=True)
    c1, c2, c3 = st.columns(3)
    st.session_state.count += 1
    with c1:
        st.markdown("""
            <video width="250" autoplay="true" muted="true" loop="true" align="center">
            <source 
                    src="https://www.jfrogchina.com/wp-content/uploads/2020/02/efficient.mp4" 
                    type="video/mp4" />
            </video>
            <h3 align="center">运行时间</h3>
                """, unsafe_allow_html=True)
   # c1, c2 = st.columns(2)
    with c2:
        st.markdown("""
            <video width="250" autoplay="true" muted="true" loop="true">
            <source 
                    src="https://www.jfrogchina.com/wp-content/uploads/2017/10/artifactory-feature-4-1.mp4" 
                    type="video/mp4" />
            </video>
            <h3 align="center">运行测试样例</h3>
            """, unsafe_allow_html=True)
    with c3:
        st.markdown("""
            <video width="250" autoplay="true" muted="true" loop="true">
            <source 
                    src="https://www.jfrogchina.com/wp-content/uploads/2020/02/delivering-trust.mp4" 
                    type="video/mp4" />
            </video>
            <h3 align="center">检测到配置漏洞</h3>
            """, unsafe_allow_html=True)
    if st.session_state.run == 0:
        ele1 = c1.empty()
        ele2 = c2.empty()
        ele3 = c3.empty()
        with ele1:
            st.markdown("""
                    <p align="center">等待开始</p>
                """, unsafe_allow_html=True)
        with ele2:
            st.markdown("""
                    <p align="center">等待开始</p>
                """, unsafe_allow_html=True)
        with ele3:
            st.markdown("""
                    <p align="center">等待开始</p>
                """, unsafe_allow_html=True)
        #ele1.empty()
        #ele2.empty()
        #ele3.empty()
    else:
        for i in range(0, 10):
            ele1 = c1.empty()
            ele2 = c2.empty()
            ele3 = c3.empty()

            if (i < 9):
                with ele1:
                    st.markdown("""
                        <p align="center">Time {0}</p>
                    """.format(i + 1), unsafe_allow_html=True)
                with ele2:
                    st.markdown("""
                        <p align="center">Case {0}</p>
                    """.format(i + 1), unsafe_allow_html=True)
                with ele3:
                    st.markdown("""
                        <p align="center">Exp {0}</p>
                    """.format(i + 1), unsafe_allow_html=True)
            else:
                with ele1:
                    st.markdown("""
                        <p align="center">✅ Time {0}</p>
                    """.format(i + 1), unsafe_allow_html=True)
                with ele2:
                    st.markdown("""
                        <p align="center">✅ Case {0}</p>
                    """.format(i + 1), unsafe_allow_html=True)
                with ele3:
                    st.markdown("""
                        <p align="center">✅ Exp {0}</p>
                    """.format(i + 1), unsafe_allow_html=True)
                st.session_state.show_res = 1
            time.sleep(1)
            if i < 9:
                ele1.empty()
                ele2.empty()
                ele3.empty()
    c2.button("开始测试", on_click=callback4)

def ui2():
    if st.session_state.res == 2:
        st.header("正在运行差分测试框架")
        res2()
        st.write(" ")
        return 0
    if st.session_state.loading == 1:
        show_loading1()
        return 0
    if st.session_state.res == 1:
        res1()
        return 0
    
    c1, c3, c4 = st.columns([0.7,  0.2, 0.1])
    #c1.write("logo")
    #c2.header("测试产品导入")
    c1.image("./image/2023.jpg")

    select = c3.selectbox("测试接口选择", ["Snort", "Suricata", "Zeek"])
    if select == "Snort":
        st.session_state.product = 1
    elif select == "Suricata":
        st.session_state.product = 2
    elif select == "Zeek":
        st.session_state.product = 3
    c4.write(" ")
    c4.write(" ")
    c4.button("导入", on_click=callback1)

    c4, c5, c6 = st.columns(3)

    with c4:
        with elements("nested_children1"):
            with mui.Paper(elevation=6):
                with mui.Typography():
                    html.h1(html.font("Snort", color="purple"))
                    html.img(src="https://tse1-mm.cn.bing.net/th/id/OIP-C.GYAifr9OSYJ639QjBASNRwHaE8?w=256&h=180&c=7&r=0&o=5&dpr=2&pid=1.7", width=300, height=250)
                    html.div("Snort是一个广泛使用的开源网络入侵检测和防御系统。它由Martin Roesch于1998年创建，并且现在由Cisco Systems的Talos安全组织进行维护和支持。",css={"text-indent":"2em"})
                    html.div("从入侵检测的分类上看，Snort应当属于基于网络的误用检测。针对每一种入侵行为，都提炼出它的特征并按照规范写成规则，从而形成一个规则库，将捕获的数据包对照规则库逐一匹配，若匹配成功，则认为该入侵行为成立。",css={"text-indent":"2em"})
                with mui.Button(align="bottom",color="inherit", size="small",variant="string"):
                        mui.icon.DoubleArrow()
                        mui.Typography("Read More")
    
    with c5:
        with elements("nested_children2"):
            with mui.Paper(elevation=6):
                with mui.Typography():
                    html.h1(html.font("Suricata", color="purple"))
                    html.img(src="https://suricata.io/wp-content/uploads/2021/01/Logo-FINAL_Vertical_Color_Whitetext.png", width=300, height=250)
                    html.div("Suricata IDS是一款开源的网络入侵检测系统，具有高性能和多功能的特点。它最初由Open Information Security Foundation（OISF）开发，并且得到了广泛的支持和贡献。",css={"text-indent":"2em"})
                    html.div("Suricata使用强大而广泛的规则和签名语言来检查网络流量，并提供强大的Lua脚本支持来检测复杂的威胁。其输出文件格式为YAML或JSON，方便与其他数据库或安全数据分析平台集成。",css={"text-indent":"2em"})
                with mui.Button(align="bottom",color="inherit", size="small",variant="string"):
                        mui.icon.DoubleArrow()
                        mui.Typography("Read More")
    
    with c6:
        with elements("nested_children3"):
            with mui.Paper(elevation=6):
                with mui.Typography():
                    html.h1(html.font("Zeek", color="purple"))
                    html.img(src="https://github.com/master1018/Fuzzing_for_NIDS/blob/main/Zeek.png?raw=true", width=300, height=250)
                    html.div("Zeek是一种开源网络安全监控和分析工具，旨在帮助用户检测、分析和应对网络中的安全事件。它最初由加州大学伯克利分校的国际计算机科学研究所（ICSI）开发，并在2005年发布，起初被称为Bro。在2018年，该项目更名为Zeek。",css={"text-indent":"2em"})
                    html.div("Zeek通过监控网络流量来捕获各种网络活动，并提供了一个强大的脚本编程语言，允许用户自定义和扩展其功能，能够解析网络流量中的各种协议。",css={"text-indent":"2em"})
                with mui.Button(align="bottom",color="inherit", size="small",variant="string"):
                        mui.icon.DoubleArrow()
                        mui.Typography("Read More")

def visual_data(sum_lines):
    return 0

def ui3():
    if st.session_state.show_res == 0:
        st.write("no result")
        return 0
    elif st.session_state.show_res == 1:
        st.header("测试结果分析")
        res_list = []
        fp = open("./tmp/res")
        while True:
            line = fp.readline()
            if not line:
                break
            if line[len(line) - 1] == "\n":
                line = line[0: len(line) - 1]
            res_list.append(line.split(" "))
        
        sum_lines = static()
        res1_list = [0, 0, 0, 0, 0]
        res2_map = {}
        for i in range(0, len(res_list)):
            if res_list[i][1] not in res2_map:
                res2_map[res_list[i][1]] = [0, 0, 0, 0]
            if res_list[i][3] == "SIGN_OVERLAP":
                res1_list[1] += 1
                res2_map[res_list[i][1]][0] += 1
            elif res_list[i][3] == "SIGN_REPEAT":
                res1_list[2] += 1
                res2_map[res_list[i][1]][1] += 1
            elif res_list[i][3] == "SIGN_ALGORITHM":
                res1_list[3] += 1
                res2_map[res_list[i][1]][2] += 1
            else:
                res1_list[4] += 1
                res2_map[res_list[i][1]][3] += 1
        res1_list[0] = sum_lines - res1_list[1] - res1_list[2] - res1_list[3] - res1_list[4]
        for i in range(0, len(res1_list)):
            option_pie["dataset"]["source"][i + 1][1] = res1_list[i]
        
        option_bar["xAxis"]["data"] = []
        for c in res2_map:
            option_bar["xAxis"]["data"].append(str(c))
        

        st_echarts(option_pie)

        df = list_to_df(res_list, ["IDS名", "规则集索引", "规则项索引", "漏洞"])
        a = aggrid(df, 0,["规则集索引", "规则项索引"])

def init():
    if "foot" not in st.session_state:
        st.session_state.foot = 1
    if "product" not in st.session_state:
        st.session_state.product = 0
    if "res" not in st.session_state:
        st.session_state.res = 0
    if "show_rule" not in st.session_state:
        st.session_state.show_rule = "null"
    if "loading" not in st.session_state:
        st.session_state.loading = 0
    if "count" not in st.session_state:
        st.session_state.count = 0
    if "run" not in st.session_state:
        st.session_state.run = 0
    if "show_res" not in st.session_state:
        st.session_state.show_res = 0

def main():
    init()
    with st.sidebar:
        st.image("./image/NIDFuzzer (1).gif")
        selected = option_menu("菜单", ["主页", '接口导入', '系统检测'],
                            icons=['house', 'bar-chart', 'file-earmark-check', 'file-earmark-code', 'exclamation-circle'], menu_icon="cast", default_index=0)
    if selected == "主页":
        st.session_state.foot = 1
    elif selected == "接口导入":
        st.session_state.foot = 2
    elif selected == "系统检测":
        st.session_state.foot = 3
    
    if st.session_state.foot == 1:
        ui1()
    elif st.session_state.foot == 2:
        ui2()
    elif st.session_state.foot == 3:
        st.session_state.show_res = 1
        st.session_state.show_rule = ["snort3-browser-chrome.rules", "snort3-sql.rules", "snort3-protocol-ftp.rules", "snort3-protocol-tftp.rules", "snort3-protocol-telnet.rules"]
        ui3()
    

if __name__ == "__main__":
    st.set_page_config(
        "面向网络入侵检测系统的查分测试框架",
        "📊",
        initial_sidebar_state="expanded",
        layout="wide",
    )
    main()
