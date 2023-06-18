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

def aggrid(df, key):
    gb = GridOptionsBuilder.from_dataframe(df)
    selection_mode = 'single' # 定义单选模式，多选为'multiple'
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
        return selected[0][key]  


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
        

def get_rules_file(path, type):
    dir = os.listdir(path)
    file_list = []
    for file in dir:
        if type in file:
            file_list.append([file])
    return file_list

def res1():
    if st.session_state.product == 1:
        st.header("Snort接口导入成功")
        with st.expander("版本信息"):
            text = read_markdown_file("./markdown/1.md")
            st.markdown(text, unsafe_allow_html=True)
        rules_list = get_rules_file("./db/snort/", "rules")
        print(rules_list)
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
            rule_file = "./db/snort/" + st.session_state.show_rule
            fp = open(rule_file, "r")
            buff = fp.read()
            fp.close()
            with st.expander(st.session_state.show_rule):
                st.code(buff)

def ui1():
    st.header("这是主页")

def ui2():
    if st.session_state.res == 1:
        res1()
        return 0
    c1, c2, c3, c4 = st.columns([0.3, 0.4, 0.2, 0.1])
    c1.write("logo")
    c2.header("测试产品导入")
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

def ui3():
    st.header("这是检测")

def init():
    if "foot" not in st.session_state:
        st.session_state.foot = 1
    if "product" not in st.session_state:
        st.session_state.product = 0
    if "res" not in st.session_state:
        st.session_state.res = 0
    if "show_rule" not in st.session_state:
        st.session_state.show_rule = "null"


def main():
    init()
    with st.sidebar:
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
    

if __name__ == "__main__":
    st.set_page_config(
        "Tamer：代码克隆检测系统",
        "📊",
        initial_sidebar_state="expanded",
        layout="wide",
    )
    main()
