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


def read_markdown_file(filepath):
    with open(filepath, 'r', encoding='utf-8') as f:
        return f.read()

def callback1():
    st.session_state.res = 1
        

def res1():
    if st.session_state.product == 1:
        st.header("Snort接口导入成功")
        with st.expander("版本信息"):
            text = read_markdown_file("./markdown/1.md")
            st.markdown(text, unsafe_allow_html=True)
        

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
                    html.img(src="https://tse1-mm.cn.bing.net/th/id/OIP-C.GYAifr9OSYJ639QjBASNRwHaE8?w=256&h=180&c=7&r=0&o=5&dpr=2&pid=1.7", width=250, height=150)
                    html.div("Snort是一个广泛使用的开源网络入侵检测和防御系统。它由Martin Roesch于1998年创建，并且现在由Cisco Systems的Talos安全组织进行维护和支持。",css={"text-indent":"2em"})
                with mui.Button(align="bottom",color="inherit", size="small",variant="string"):
                        mui.icon.DoubleArrow()
                        mui.Typography("Read More")
    
    with c5:
        with elements("nested_children2"):
            with mui.Paper(elevation=6):
                with mui.Typography():
                    html.h1(html.font("Suricata", color="purple"))
                    html.img(src="https://suricata.io/wp-content/uploads/2021/01/Logo-FINAL_Vertical_Color_Whitetext.png", width=250, height=150)
                    html.div("Suricata IDS是一款开源的网络入侵检测系统，具有高性能和多功能的特点。它最初由Open Information Security Foundation（OISF）开发，并且得到了广泛的支持和贡献。",css={"text-indent":"2em"})
                with mui.Button(align="bottom",color="inherit", size="small",variant="string"):
                        mui.icon.DoubleArrow()
                        mui.Typography("Read More")
    
    with c6:
        with elements("nested_children3"):
            with mui.Paper(elevation=6):
                with mui.Typography():
                    html.h1(html.font("Snort", color="purple"))
                    html.img(src="data:image/png;base64,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", width=250, height=150)
                    html.div("Zeek IDS（原名Bro IDS）是一款强大的开源网络入侵检测系统（Intrusion Detection System）。它以高级协议分析为基础，提供了广泛的网络安全监测和分析功能。",css={"text-indent":"2em"})
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
