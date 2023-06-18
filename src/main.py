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


def callback1():
    st.write("success")

def ui1():
    st.header("这是主页")

def ui2():
    c1, c2, c3 = st.columns([0.3, 0.6, 0.1])
    c1.write("logo")
    c2.header("测试产品导入")
    c3.button("开始导入")

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
                    html.img(src="file:///Users/haoranyan/git_rep/Fuzzing_for_NIDS/src/image/2.png", width=250, height=150)
                    html.div("Snort是一个广泛使用的开源网络入侵检测和防御系统。它由Martin Roesch于1998年创建，并且现在由Cisco Systems的Talos安全组织进行维护和支持。",css={"text-indent":"2em"})
                with mui.Button(align="bottom",color="inherit", size="small",variant="string"):
                        mui.icon.DoubleArrow()
                        mui.Typography("Read More")
    
    with c6:
        with elements("nested_children3"):
            with mui.Paper(elevation=6):
                with mui.Typography():
                    html.h1(html.font("Snort", color="purple"))
                    html.img(src="https://tse1-mm.cn.bing.net/th/id/OIP-C.GYAifr9OSYJ639QjBASNRwHaE8?w=256&h=180&c=7&r=0&o=5&dpr=2&pid=1.7", width=250, height=150)
                    html.div("Snort是一个广泛使用的开源网络入侵检测和防御系统。它由Martin Roesch于1998年创建，并且现在由Cisco Systems的Talos安全组织进行维护和支持。",css={"text-indent":"2em"})
                with mui.Button(align="bottom",color="inherit", size="small",variant="string"):
                        mui.icon.DoubleArrow()
                        mui.Typography("Read More")

def ui3():
    st.header("这是检测")

def init():
    if "foot" not in st.session_state:
        st.session_state.foot = 1
    if "show_product" not in st.session_state:
        st.session_state.show_product = 0
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
