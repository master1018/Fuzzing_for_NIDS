import streamlit as st
import time


fp = open("test.txt", "r")

res = []

while True:
    line = fp.readline()
    if not line:
        break
    #if len(line) >= 100:
    #    line = line[0:100]
    res.append(line)

ele_list = []

for i in range(0, 10):
    ele = st.empty()
    ele_list.append(ele)


for i in range(0, 1000000):
    for j in range(0, 10):
        cur =  (i + j) % len(res)
        with ele_list[j]:
            st.empty()
            st.write(res[cur])
    time.sleep(0.5)




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