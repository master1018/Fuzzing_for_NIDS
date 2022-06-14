#coding=utf-8
import requests as r
import re
import time
import datetime


#cve中文漏洞信息库 - scap中文社区
class cve_scap:
    #获取所有漏洞集合
    def get_cve_404(self,url,keyword):
        headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/70.0.3538.110 Safari/537.36'}
        #定义提交数据 qcvCname 检索的词，pageno 页数 一般是抓取第一页
        data = {"search_type":"t_keyword","keyword":keyword}
        #post数据
        result = r.get(url,params=data).text
        filter_result = re.findall("<td class='hidden-xs'>.*?<a href=(.*?)>\n                            (.*?)\n                        </a>.*?<td class='hidden-xs hidden-sm'>(.*?)</td>.*?title='(.*?)' class='grade",result,re.S)
        return filter_result

    #对单个漏洞信息获取
    def get_cve_404_mes(self,url):
        header = {'User-Agent': 'Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/70.0.3538.110 Safari/537.36'}
        try:
            result = r.get(url,headers=header).text
            filter_result = re.findall("pad30T pad30B mrg0B' style='word-wrap: break-word;'>\n                        (.*?)</p>",result,re.S)
            if filter_result is not None:
                return filter_result[0]
            else:
                return ""
        except:
            print("timeout: " + url)

    #信息获取
    def write_file(self,keylist,date_time):
        #定义post的url
        url = "http://cve.scap.org.cn/vulns/1"
        #定义数组，存放信息
        mes_list = []
        for keyword in keylist:
            #爬取网站
            html_filter = self.get_cve_404(url,keyword)
            #定义后面组合信息需要的域名
            url_domain = "http://cve.scap.org.cn"
            for res in html_filter:
                if date_time in res[2]:
                    try:
                        mes_url = url_domain + res[0].strip('"')
                        message = self.get_cve_404_mes(mes_url)
                        mes = "漏洞编号：" + res[1] + " | " + "等级：" + res[3] + " | " + "时间：" + res[2] + " | " + "详情地址：" + mes_url + " | " + "漏洞简介：" + message.replace("\n","")
                        mes_list.append(mes)
                    except:
                        print("timeout: "+mes_url)

        return mes_list


if __name__ == "__main__":
    # 需要查找的关键字数组
    keylist = ['nginx', 'openssl', 'openssh']
    # 获取本年的日期
    date_time = time.strftime("%Y", time.localtime())
    # 打开写入log文件
    files = open("404_message.log", "w+", encoding='utf-8')

    cve = cve_scap()
    files.write("#cve中文漏洞信息库:\n")
    for i in cve.write_file(keylist, date_time):
        files.write(i + "\n")
    files.write("\n")
    files.close()
