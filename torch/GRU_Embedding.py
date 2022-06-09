from enum import EnumMeta
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

# 1：加载数据
class NameDataset(Dataset):
    def __init__(self, file, percentage):
        self.samples = []
        self.lables = []

        self.ja3_set = set()
        self.sni_set = set()

        with open(file, "r", encoding="utf-8") as f:
            
            lines = f.readlines()
            lines = lines[0:int( len(lines) * percentage )]

            for line in tqdm( lines ):

                sample = []
                line = line.strip()
                items1 = str.split(line, " ")
                self.lables.append( items1[0] + " " + str(items1[1]) + " " + str(items1[2]))
                self.ja3_set.add( items1[1] )
                self.sni_set.add( items1[2] )

                for pkt in items1[3:]:
                    items2 = str.split( pkt[1:-1], "," )
                    feature = []
                    for i in items2:
                        feature.append( float(i) )

                    sample.append( feature )

                self.samples.append(sample)

        self.samples = torch.tensor(self.samples, dtype = torch.float32)

    def __getitem__(self, index):
        return self.samples[index], self.lables[index]

    def __len__(self):
        return len(self.samples)

# 2：构造模型
class RNNClassifier(nn.Module):
    """
    这里的bidirectional就是GRU是不是双向的，双向的意思就是既考虑过去的影响，也考虑未来的影响（如一个句子）
    具体而言：正向hf_n=w[hf_{n-1}, x_n]^T,反向hb_0,最后的h_n=[hb_0, hf_n],方括号里的逗号表示concat。
    """
    def __init__(self, hidden_size = 6, output_size = 2, n_layers = 2, bidirectional = True):
        super(RNNClassifier, self).__init__()
        self.hidden_size = hidden_size
        self.n_layers = n_layers
        self.n_directions = 2 if bidirectional else 1 # 双向2、单向1

		#
		# self.embedding_1 = nn.Embedding()

        # nn.GRU 构造一个 GRU 网络，参数：输入维度、输出维度、层数、bidirectional
        self.gru = nn.GRU(hidden_size, hidden_size, n_layers, bidirectional = bidirectional)
        # 全连接层
        self.fc = nn.Linear(hidden_size * self.n_directions, output_size)

    # 工具函数，作用是创建初始的隐藏层h0
    def hidden_layer(self, batch_size, hidden_lables):
        hidden = torch.zeros(self.n_layers * self.n_directions, batch_size, self.hidden_size)

        for l_d in hidden:
            for index, sample in enumerate(l_d):
                    sample[0] = hidden_lables[index][0]
                    sample[1] = hidden_lables[index][1]
                    sample[2] = hidden_lables[index][0]
                    sample[3] = hidden_lables[index][1]
                    sample[4] = hidden_lables[index][0]
                    sample[5] = hidden_lables[index][1]

        hidden = hidden.to(device)
        return hidden

    # torch.nn.Module 类的 __call__ 中调用了 forward
    def forward(self, input, hidden_lables):
        # 输入的input为三维的，大小为：batch_size * seq_length * feature_size
        # 需把 input 的大小转化为：seq_length * batch_size * feature_size，作为 GRU 的输入
        input = input.transpose(0, 1)
        batch_size = input.size(1)

        # 隐藏层 h0 大小：4 * batch_size * hidden_size
        h_0 = self.hidden_layer(batch_size, hidden_lables)

        output, h_n = self.gru(input, h_0) # 只需要hidden
        if self.n_directions == 2:
            # 双向的，则需要拼接起来
            hidden_cat = torch.cat([h_n[-1], h_n[-2]], dim=1)
        else:
            # 单向的，则不用处理
            hidden_cat = h_n[-1]
        fc_output = self.fc(hidden_cat)
        return fc_output

def create_tensor(tensor):  # 是否使用GPU
    if USE_GPU:
        device = torch.device("cuda:0")
        tensor = tensor.to(device)
    return tensor

# 4：训练和测试模型
def trainModel(trainloader, classifier, criterion, optimizer, epoch, train_set_size, ja3_dict, sni_dict):
    total_loss = 0
    for i, (samples, lables) in enumerate(trainloader, 1): # 记载的下标从1开始

        real_lables = []
        hidden_lables = []
        for lable in lables:
            lable_items = str.split( lable, " " )
            real_lables.append( int(lable_items[0]) )
            hidden_lables.append( (ja3_dict[lable_items[1]], sni_dict[lable_items[2]] ) )

        real_lables = torch.tensor(real_lables, dtype = torch.long)

        if USE_GPU:
            samples = samples.to(device)
            real_lables = real_lables.to(device)

        output = classifier( samples, hidden_lables ) # 预测输出
        loss = criterion(output, real_lables) # 求出损失
        optimizer.zero_grad() # 清除之前的梯度
        loss.backward() # 梯度反传
        optimizer.step() # 更新参数

        total_loss += loss.item()
        if i % 10 ==0:
            print(f'[ { time_since( start ) } ] Epoch { epoch }', end = '')
            print(f'[ { i * len( samples ) } / { train_set_size }]', end = '')
            print(f'loss = { total_loss / (i * len(samples)) }')

    return total_loss

def testModel(testloader, classifier, test_set_size, ja3_dict, sni_dict):
    correct = 0
    print("evaluating trained model...")
    with torch.no_grad():
        for _, (samples, lables) in enumerate(testloader, 1):

            real_lables = []
            hidden_lables = []
            for lable in lables:
                lable_items = str.split( lable, " " )
                real_lables.append( int(lable_items[0]) )
                hidden_lables.append( (ja3_dict[lable_items[1]], sni_dict[lable_items[2]] ) )

            real_lables = torch.tensor(real_lables, dtype = torch.long)

            if USE_GPU:
                samples = samples.to(device)
                real_lables = real_lables.to(device)

            output = classifier( samples, hidden_lables )
            # 预测出来是个向量，里面的值相当于概率，取最大的
            pred = output.max(dim=1, keepdim=True)[1]

            # 预测和实际标签相同则正确率加1
            correct += pred.eq(real_lables.view_as(pred)).sum().item()

        percent = '%.2f' % (100 * correct / test_set_size)
        print(f'Test set:Accuracy{correct} / {test_set_size} {percent}%')

    return correct / test_set_size

def time_since(since):
    s = time.time() - since
    m = math.floor(s / 60)
    s -= m * 60
    return "%dm %ds" % (m, s)

# 样本序列中数据包个数
samples_size_list = [500] # [50, 100, 200, 500, 1000]
# 每轮训练的样本数量
batch_size_list = [256] # [2048, 1025, 512, 256, 128]

# 隐藏层
HIDDEN_SIZE = 6

# RNN的层数
N_LAYER = 2
# train的轮数
N_EPOCHS = 30

# 是否使用GPU
USE_GPU = True
device = torch.device("cuda:0")

if __name__ == "__main__":
    data_root = os.path.join( os.path.abspath( os.path.curdir ), "data" )

    for i, sample_size in enumerate( samples_size_list ):

        train_file = os.path.join(data_root, str(sample_size) + "_train.txt")
        test_file  = os.path.join(data_root, str(sample_size) + "_test.txt")

        train_set = NameDataset( train_file, 0.05 )
        test_set = NameDataset( test_file, 0.05 )

        # 处理两个 dataset 中的 ja3 和 sni
        ja3_dict, sni_dict = dict(), dict()
        for ja3 in train_set.ja3_set:
            if ja3 not in ja3_dict.keys():
                ja3_dict[ja3] = len(ja3_dict)

        for ja3 in test_set.ja3_set:
            if ja3 not in ja3_dict.keys():
                ja3_dict[ja3] = len(ja3_dict)

        for sni in train_set.sni_set:
            if sni not in sni_dict.keys():
                sni_dict[sni] = len(sni_dict)

        for sni in test_set.sni_set:
            if sni not in sni_dict.keys():
                sni_dict[sni] = len(sni_dict)



        trainloader = DataLoader(train_set, batch_size = batch_size_list[i], shuffle = True)
        testloader = DataLoader(test_set, batch_size = batch_size_list[i], shuffle = False)

        # 这个就是总的类别的数量
        N_LABEL = 2

        # 定义模型
        classifier = RNNClassifier(HIDDEN_SIZE, N_LABEL, N_LAYER)
        print(classifier)

        if USE_GPU:
            classifier.to(device)

        # 第三步：定义损失函数和优化器
        criterion = torch.nn.CrossEntropyLoss() # 分类问题使用交叉熵损失函数
        optimizer = torch.optim.Adam(classifier.parameters(), lr=0.001) # 使用了随机梯度下降法

        start = time.time()
        print("Training for %d epochs..." % N_EPOCHS)
        acc_list = []

        for epoch in range(1, N_EPOCHS + 1):
            # Train cycle
            trainModel(trainloader, classifier, criterion, optimizer, epoch, len(train_set), ja3_dict, sni_dict)
            acc = testModel(testloader, classifier, len(test_set), ja3_dict, sni_dict)
            acc_list.append(acc) # 存入列表，后面画图使用

        # 画图
        epoch = np.arange(1, len(acc_list) + 1, 1) # 步长为1
        acc_list = np.array(acc_list)
        plt.plot(epoch, acc_list)
        plt.xlabel("Epoch")
        plt.ylabel("Accuracy")
        plt.grid() # 显示网格线 1=True=默认显示；0=False=不显示
        plt.show()
