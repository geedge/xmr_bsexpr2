from enum import EnumMeta
import re
from sklearn import metrics
import torch
import torch.nn as nn
import torch.optim as optim
import csv
from torch.utils.data import Dataset
from torch.utils.data import DataLoader
import numpy as np
import matplotlib.pyplot as plt
import time
import os
import json
from torch.nn.utils.rnn import pack_padded_sequence
# https://pytorch.org/docs/master/generated/torch.nn.utils.rnn.pack_padded_sequence.html
import math
from DS import TLS,PKT,Feature
from itertools import groupby
from tqdm import tqdm

from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, classification_report

from Config import conf


# 1：加载数据
class NameDataset(Dataset):
    def __init__(self, file, percentage):
        self.samples = []
        self.lables = []
        
        all_sample_cnt = 0

        with open(file, "r", encoding="utf-8") as f:
            lines = f.readlines()
            
            all_sample_cnt = int( len(lines) * percentage )

            lines = lines[0:all_sample_cnt]

            for line in tqdm( lines ):

                sample = []
                line = line.strip()
                items1 = str.split(line, " ")
                self.lables.append( int( items1[0] ) )

                for pkt in items1[3:]:
                    items2 = str.split( pkt[1:-1], "," )
                    feature = []
                    for i in items2:
                        feature.append( float(i) )

                    sample.append( feature )

                self.samples.append(sample)

        self.samples = torch.tensor(self.samples, dtype = torch.float32)
        self.lables = torch.tensor(self.lables, dtype = torch.long)

    def __getitem__(self, index):
        return self.samples[index], self.lables[index]

    def __len__(self):
        return len(self.samples)

# 2：构造模型
class GRUClassifier(nn.Module):
    """
    这里的bidirectional就是GRU是不是双向的，双向的意思就是既考虑过去的影响，也考虑未来的影响（如一个句子）
    具体而言：正向hf_n=w[hf_{n-1}, x_n]^T,反向hb_0,最后的h_n=[hb_0, hf_n],方括号里的逗号表示concat。
    """
    def __init__(self, hidden_size = 6, output_size = 2, n_layers = 2, bidirectional = True):
        super(GRUClassifier, self).__init__()
        self.hidden_size = hidden_size
        self.n_layers = n_layers
        self.n_directions = 2 if bidirectional else 1 # 双向2、单向1

		#
		# self.embedding_1 = nn.Embedding()

        # nn.GRU 构造一个 GRU 网络，参数：输入维度、输出维度、层数、bidirectional
        self.gru = nn.GRU(
            input_size = hidden_size,
            hidden_size = hidden_size,
            num_layers = n_layers,
            bidirectional = bidirectional
        )

        # 全连接层
        self.fc = nn.Linear(hidden_size * self.n_directions, output_size)

    # 工具函数，作用是创建初始的隐藏层h0
    def hidden_layer(self, batch_size):
        hidden = torch.zeros(self.n_layers * self.n_directions, batch_size, self.hidden_size)
        hidden = hidden.to(conf.device)
        return hidden

    # torch.nn.Module 类的 __call__ 中调用了 forward
    def forward(self, input):
        # 输入的input为三维的，大小为：batch_size * seq_length * feature_size
        # 需把 input 的大小转化为：seq_length * batch_size * feature_size，作为 GRU 的输入
        # pytorch 的官方文档规定 GRU 的输入为：seq_len, batch, input_size，其中的 input_size 就是 feature_size。
        input = input.transpose(0,1)
        batch_size = input.size(1)

        # 隐藏层 h0 大小：4 * batch_size * hidden_size
        h_0 = self.hidden_layer(batch_size)

        # h_n 大小：shape (num_layers * num_direction, batch, hidden_size)
        # h_n 存储着 GRU 网络每层、每个方向的最后一个 GRU 单元的隐藏层输出
        # 比如 h_n[0] 表示第一层正向 GRU 单元的隐藏层输出、h_n[1] 表示第一层反向 GRU 单元的隐藏层输出
        output, h_n = self.gru(input, h_0)

        if self.n_directions == 2:
            # 双向的，则需要拼接起来
            hidden_cat = torch.cat([h_n[-1], h_n[-2]], dim=1)
        else:
            # 单向的，则不用处理
            hidden_cat = h_n[-1]
        fc_output = self.fc(hidden_cat)
        return fc_output

def create_tensor(tensor):  # 是否使用GPU
    if conf.USE_GPU:
        tensor = tensor.to(conf.device)
    return tensor

# 4：训练和测试模型
def trainModel(trainloader, classifier, criterion, optimizer, train_set_size, epoch):
    total_loss = 0
    for i, (samples, lables) in enumerate(trainloader, 1): # 记载的下标从1开始

        if conf.USE_GPU:
            samples = samples.to(conf.device)
            lables = lables.to(conf.device)

        output = classifier( samples ) # 预测输出
        loss = criterion(output, lables) # 求出损失
        optimizer.zero_grad() # 清除之前的梯度
        loss.backward() # 梯度反传
        optimizer.step() # 更新参数

        total_loss += loss.item()
    return total_loss

def testModel(testloader, classifier, test_set_size):
    correct = 0

    true_lables = []
    pred_lables = []
    with torch.no_grad():
        for _, (samples, lables) in enumerate(testloader, 1):

            if conf.USE_GPU:
                samples = samples.to(conf.device)
                lables = lables.to(conf.device)
            
            for lable in lables:
                true_lables.append( lable.item() )

            output = classifier(samples)
            # 预测出来是个向量，里面的值相当于概率，取最大的
            pred = output.max(dim=1, keepdim=True)[1]

            correct += pred.eq(lables.view_as(pred)).sum().item()

            for lable in pred:
                pred_lables.append( lable[0].item() )

    x = []
    y = []
    for l in true_lables:
        x.append( True if l == 1 else False )
    
    for l in pred_lables:
        y.append( True if l == 1 else False )
    
    # compute_sample_weight
    _metrics = classification_report(true_lables, pred_lables, output_dict=True)

    return _metrics['1']["precision"], _metrics['1']["recall"], _metrics['1']["f1-score"], \
            accuracy_score(true_lables, pred_lables), precision_score(true_lables, pred_lables, average="weighted"), \
            recall_score(true_lables, pred_lables, average="weighted"), f1_score(true_lables, pred_lables, average="weighted")
    

def time_since(since):
    s = time.time() - since
    m = math.floor(s / 60)
    s -= m * 60
    return "%dm %ds" % (m, s)

# # 样本序列中数据包个数
# samples_size_list = [50] # [50, 100, 200, 500, 1000]
# # 每轮训练的样本数量
# batch_size_list = [16] # [2048, 1025, 512, 256, 128, 64]

# # 隐藏层
# HIDDEN_SIZE = 6

# # RNN的层数
# N_LAYER = 2
# # train的轮数
# N_EPOCHS = 30

# # 这个就是总的类别的数量
# N_LABEL = 2

# # 是否使用GPU
# USE_GPU = True
# device = torch.device("cuda:0")

# DEBUG = True

# if __name__ == "__main__":
#     stream_file_dir = os.path.join( os.path.abspath( os.path.curdir ), "data", "raw_data")
#     sample_root_dir = os.path.join(os.path.abspath( os.path.curdir ), "data", "Seq")

#     SEQ_LEN = [100, 150, 200, 300, 400, 500] # 25, 50, 75, 100, 150, 200, 300, 400, 500
#     BATCH_SIZE = [16, 32, 64, 128, 256] # 16, 32, 64, 128, 256
#     SAMPLING = [1, 2, 3, 4, 5] # 
#     if DEBUG:
#         SEQ_LEN = [50]
#         BATCH_SIZE = [32]
#         SAMPLING = [1]

#     stream_files = os.listdir( stream_file_dir )
#     if DEBUG:
#         stream_files = ["1_19_tcp_dns_json.txt"]

#     for _, stream_file in enumerate( stream_files, start=1):
#         # TASK
#         for sample_size in SEQ_LEN:
#             for batch_size in BATCH_SIZE:

#                 sample_file = os.path.join( sample_root_dir, str(sample_size), stream_file)
#                 pos_dict, neg_dict = load_sample( sample_file )


#     for i, sample_size in enumerate( samples_size_list ):

#         train_file = os.path.join(data_root, str(sample_size) + "_train.txt")
#         test_file  = os.path.join(data_root, str(sample_size) + "_test.txt")

#         train_set = NameDataset( train_file, 0.05 )
#         test_set = NameDataset( test_file, 0.05 )

#         trainloader = DataLoader(train_set, batch_size = batch_size_list[i], shuffle = True)
#         testloader = DataLoader(test_set, batch_size = batch_size_list[i], shuffle = False)

#         # 定义模型
#         classifier = GRUClassifier(HIDDEN_SIZE, N_LABEL, N_LAYER)
#         print(classifier)

#         if USE_GPU:
#             classifier.to(device)

#         # 第三步：定义损失函数和优化器
#         criterion = torch.nn.CrossEntropyLoss() # 分类问题使用交叉熵损失函数
#         optimizer = torch.optim.Adam(classifier.parameters(), lr=0.001) # 使用了随机梯度下降法

#         start = time.time()
#         print("Training for %d epochs..." % N_EPOCHS)
#         acc_list = []

#         for epoch in range(1, N_EPOCHS + 1):
#             # Train cycle
#             trainModel(trainloader, classifier, criterion, optimizer, len(train_set), epoch)
#             acc = testModel(testloader, classifier, len(test_set))
#             acc_list.append(acc) # 存入列表，后面画图使用

#         # 画图
#         epoch = np.arange(1, len(acc_list) + 1, 1) # 步长为1
#         acc_list = np.array(acc_list)
#         plt.plot(epoch, acc_list)
#         plt.xlabel("Epoch")
#         plt.ylabel("Accuracy")
#         plt.grid() # 显示网格线 1=True=默认显示；0=False=不显示
#         plt.show()

