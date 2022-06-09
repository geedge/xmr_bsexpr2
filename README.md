# 实验二实验代码文件说明

环境：Ubuntu。运行所需软件：
- sudo apt install tshark lua lua-cjson。
- python库：paddlepaddle 2.2.0

## 实验原始流量


## 构造实验数据集
pcap2date 文件夹下
1. printTcp.lua：提取TCP流特征的 tshark lua 脚本
2. make_sample_pure.py：构造实验数据集

## 实验二神经网络模型代码
paddle文件夹下：
1. paddle_Config.py 模型参数配置
2. paddle_gru.py 神经网络模型代码

# 获得实验结果
1. 依次运行 pcap2date/printSubTcp.py、pcap2date/mergeSubTcp.py、pcap2date/make_sample_pure.py，构造实验数据集。
2. 运行 paddle/paddle_gru.py 获得论文表 4.5 实验结果；运行 paddle/paddle_gru_division.py 获得论文表 4.7 实验结果。

