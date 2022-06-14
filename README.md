# Fuzzing_for_NIDS

## 项目环境配置

### 运行环境

Linux系统即可，windows也可兼容，但需要更改snort的配置，比较麻烦。

### snort3的安装

参考https://www.codeleading.com/article/51584487457/

### python相关依赖库

`boofuzz`及其依赖库，可以运行时根据报错进行增加

### 代码配置

项目的运行需要根据自己的IP来调节代码中的IP地址的赋值，例如`main.py` 中TCP连接地址需要修改。由于项目中客户端和服务端的建立，都可以在一台机器上进行，只是端口号不同，因此为方便可以将所有的IP地址改为运行项目的机器的IP地址，而端口号可以自行更改。



## 项目运行

1. 开启三个终端。
2. 执行指令`snort -i lo -c SNORT_CONFIG_PATH -A unsock -k none`，开启snort网络入侵模式进行监测。
3. `python3 /src/snortrules/protocol/ftpServer.py`，开启协议服务。
4. `python3 /src/snortrules/protocol/main.py`，开启主程序进行测试。

项目使用boofuzz作为测试框架，当测试结束时，或将相关信息打印到`/src/result_analysis`中，而测试使用的案例信息全部保存在`/src/snortrules/protocol/boofuzz-results`中，可以使用boofuzz自带的命令 `boo open`查看，或者使用项目自行编写的`demo.py`进行测试案例提取。