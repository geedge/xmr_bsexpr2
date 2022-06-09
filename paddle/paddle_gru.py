import os
import time
import random
import numpy as np
from collections.abc import Sequence, Mapping
import numbers

import paddle
from paddle.io import Dataset, DataLoader
import paddle.nn as nn
from paddle.fluid import layers
import math
from tqdm import tqdm
from sklearn.preprocessing import KBinsDiscretizer
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, classification_report

from paddle_Config import Conf

def pd21_default_collate_fn(batch):
    sample = batch[0]
    if isinstance(sample, np.ndarray):
        batch = np.stack(batch, axis=0)
        return batch
    elif isinstance(sample, paddle.Tensor):
        return layers.stack(batch, axis=0)
    elif isinstance(sample, numbers.Number):
        batch = np.array(batch)
        return batch
    elif isinstance(sample, (str, bytes)):
        return batch
    elif isinstance(sample, Mapping):
        return {
            key: pd21_default_collate_fn([d[key] for d in batch])
            for key in sample
        }
    elif isinstance(sample, Sequence):
        sample_fields_num = len(sample)
        if not all(len(sample) == sample_fields_num for sample in iter(batch)):
            raise RuntimeError(
                "fileds number not same among samples in a batch")
        return [pd21_default_collate_fn(fields) for fields in zip(*batch)]

    raise TypeError("batch data con only contains: tensor, numpy.ndarray, "
                    "dict, list, number, but got {}".format(type(sample)))

def load_sample( sample_file : str, pos_dict : dict, neg_dict : dict, pos_conf ) -> tuple:
    with open( sample_file, "r", encoding="utf-8" ) as f:
        lines = f.readlines()
        items = []

        for line in tqdm(lines):
            line = line.strip()
            items = str.split(line, " ")

            # 
            tls_client_str = items[1] + " " + items[2] + items[3]
            cur_dict = pos_dict

            if items[0] == "1":  # 负样本
                cur_dict = neg_dict

            if tls_client_str not in cur_dict.keys():
                cur_dict[tls_client_str] = list()
            
            sample = list()

            for pkt in items[4:]:
                time_step_features = []
                time_step_feature_strs = str.split( pkt[1:-1], "," )
                
                for i in range(0, 6):
                    if ( (1 << (5 - i)) & conf.USE_FEATURE ):
                        temp = float( time_step_feature_strs[i] )
                        if( ( 5 - i ) == 5 ):
                            temp = temp if temp >= 0.0 else 0.0

                        if( (5 - i) == 3 ):
                            temp = temp if temp <= 1500.0 else 1500.0
                        time_step_features.append( float( temp ) )

                sample.append( time_step_features )

            cur_dict[tls_client_str].append( (sample, items[0]) )

def sampling( pos_dict : dict, neg_dict : dict, sampling : int ) -> tuple:
    samples = list()
    lables = list()
    neg_sample_not_selected = list()

    for tls_client_str, neg_seqs_and_types in neg_dict.items():
        if tls_client_str in pos_dict.keys():
            pos_seq_cnt = int( sampling * len( pos_dict[tls_client_str] ) )
            for index, neg_seq_and_type in enumerate( neg_seqs_and_types ):            
                if index < pos_seq_cnt:
                    samples.append( ( neg_seq_and_type[0], tls_client_str ) )
                    lables.append( 0 )
                else:
                    neg_sample_not_selected.append( ( neg_seq_and_type[0], tls_client_str )  )
        else:
            for neg_seq_and_type in neg_seqs_and_types:
                neg_sample_not_selected.append( ( neg_seq_and_type[0], tls_client_str ) )
    
    
    need_random_select = sum(len( pos_seqs_and_types ) for pos_seqs_and_types in pos_dict.values()) * sampling - len( samples )
    
    random.shuffle( neg_sample_not_selected )

    for index, neg_seq_and_type in enumerate( neg_sample_not_selected, start = 1):
        if index > need_random_select:
            break
        samples.append( neg_seq_and_type )
        lables.append( 0 )

    for tls_client_str, pos_seqs_and_types in pos_dict.items():
        for pos_seq_and_type in pos_seqs_and_types:
            samples.append( (pos_seq_and_type[0], tls_client_str))
            lables.append( 1 )

    if ( 1 << 5 & conf.USE_FEATURE):
        times = []
        for sample in samples:
            for time_step in sample[0]:
                times.append( time_step[0] )
        
        times = np.array( times ).reshape( -1,1 )
        est = KBinsDiscretizer(n_bins=256, encode='ordinal', strategy='uniform')
        est.fit( times )

        for sample in samples:
            for time_step in sample[0]:
                time_step[0] = est.transform( np.array( time_step[0] ).reshape(1, -1) ).item()
                time_step[0] = time_step[0]

    return samples, lables

class SeqDataset(Dataset):
    def __init__(self, time_step: list, tls_client : list, lables: list):
        self.time_step = time_step
        self.tls_client = tls_client
        self.lables = lables

    def __getitem__(self, index):
        return self.time_step[index], self.tls_client[index], self.lables[index]

    def __len__(self):
        return len(self.time_step)

def combination( samples, lables, resf, conf ):
    print( conf.TIME_STEP[0], end = " " )
    print( conf.BATCH_SIZE[0], end = " " )
    if conf.SINGLE_FILE:
        print( conf.STREAM_FILES[0], end = " " )
    else:
        print( "ALL_FILES", end=" " )
    print( conf.SAMPLING[0], end = "\n" )


    X_train, X_test, y_train, y_test = train_test_split(samples, lables)

    time_step = []
    tls_client = []
    for _ in X_train:
        time_step.append( _[0] )
        temp = []
        for s in _[1]:
            if len(temp) < 100:
                temp.append( ord(s) )
        while len(temp) < 100:
            temp.append( 0 )
        tls_client.append( temp )
    train_set = SeqDataset(np.array( time_step ), np.array(tls_client), np.array( y_train ))

    time_step_1 = []
    tls_client_1 = []
    for _ in X_test:
        time_step_1.append( _[0] )
        temp = []
        for s in _[1]:
            if len( temp ) < 100:
                temp.append( ord(s) )
        while len(temp) < 100:
            temp.append( 0 )
        tls_client_1.append( temp )
    test_set = SeqDataset(np.array( time_step_1 ), np.array( tls_client_1 ), np.array( y_test ))

    train_loader = DataLoader( dataset = train_set, batch_size = conf.BATCH_SIZE[0], shuffle = True )
    test_loader = DataLoader( dataset = test_set, batch_size = conf.BATCH_SIZE[0], shuffle = True )

    classifier = GRUClassifier( conf )

    criterion = paddle.nn.CrossEntropyLoss()
    optimizer = paddle.optimizer.Adam(learning_rate = 0.001, parameters = classifier.parameters())
        
    trainModel(train_loader, classifier, criterion, optimizer, conf)
    
    _metrics = testModel(test_loader, classifier, len(test_set))

    # 打印训练结果
    # resf.write( str(conf.EMBEDDING_SIZE) + " " )
    # resf.write( str(conf.HIDDEN_SIZE) + " " )
    # resf.write( str(conf.TIME_STEP[0]) + " " )
    # resf.write( str(conf.BATCH_SIZE[0])  + " ")
    # if ( conf.SINGLE_FILE ):
    #     resf.write( conf.STREAM_FILES[0] + " ")
    # else:
    #     resf.write( "ALL_FILES " )
    # resf.write( str(sum(lables)) + " ")
    # resf.write( str(len(lables) - sum(lables)) + " ")
    # temp = list( "{0:0>6b}".format( conf.USE_FEATURE ) )
    # temp.insert( 2, "_" )
    # resf.write( "0b" + ''.join( temp ) + " " )
    # if conf.USE_TLS_CLIENT:
    #     resf.write( "tls " )
    # resf.write( "\n" )
    # resf.write( str(_metrics) + "\n")
    return _metrics[3],_metrics[0],_metrics[1],_metrics[2]

class GRUClassifier(nn.Layer):
    def __init__(self, conf : Conf):
        super(GRUClassifier, self).__init__()

        # 数据包特征一共有 6 个，分别是 time, dir, size, flag, s_t, flow_cnt
        if (1 << 5 & conf.USE_FEATURE):
            self.time_embedding = nn.Embedding(256, conf.EMBEDDING_SIZE)
        
        if (1 << 4 & conf.USE_FEATURE):
            self.dir_embedding = nn.Embedding(2, conf.EMBEDDING_SIZE)

        if (1 << 3 & conf.USE_FEATURE):
            self.size_embedding = nn.Embedding(1500 + 1, conf.EMBEDDING_SIZE)

        if (1 << 2 & conf.USE_FEATURE):
            self.flag_embedding = nn.Embedding(64, conf.EMBEDDING_SIZE)

        if (1 << 1 & conf.USE_FEATURE):
            self.st_embedding = nn.Embedding(conf.TIME_STEP[0], conf.EMBEDDING_SIZE)

        if (1 << 0 & conf.USE_FEATURE):
            self.flow_embedding = nn.Embedding(conf.TIME_STEP[0], conf.EMBEDDING_SIZE)
        
        if( conf.USE_TLS_CLIENT ):
            self.tls_embedding = nn.Embedding(256, conf.EMBEDDING_SIZE)
            self.conv1d = nn.Conv1D(
                in_channels = conf.EMBEDDING_SIZE,
                out_channels = conf.INPUT_SIZE,
                kernel_size = conf.KERNEL_SIZE
            )
            self.maxpool1D = nn.MaxPool1D(
                kernel_size = 100 - conf.KERNEL_SIZE + 1,
                stride = 1,
                padding = 0,
                return_mask = False
            )

        self.gru = nn.GRU(
            input_size = conf.INPUT_SIZE,
            hidden_size = conf.HIDDEN_SIZE,
            num_layers = conf.N_LAYER,
            direction = "bidirectional" if conf.bidirectional else "forward",
            dropout = 0.1
        )

        # 
        self.fc = nn.Linear( conf.HIDDEN_SIZE * conf.n_directions, 10 )
        self.fc2 = nn.Linear( 10, 2 )
    
    def forward(self, time_step, tls_client):
        batch_size = time_step.shape[0]

        used_dim = conf.FEATURE_CNT
        ts = 0

        # 数据包特征一共有 6 个，分别是 time, dir, size, flag, s_t, flow_cnt
        if (1 << 5 & conf.USE_FEATURE):
            out1 = time_step[:, :, conf.FEATURE_CNT - used_dim]
            out1 = paddle.unsqueeze(out1, axis = 2)
            out1 = self.time_embedding( out1 )
            out1 = paddle.squeeze( out1, axis = 2 )
            # to_be_concat.append( out1 )
            ts = out1
            used_dim = used_dim - 1
        
        if (1 << 4 & conf.USE_FEATURE):
            out2 = time_step[:, :, conf.FEATURE_CNT - used_dim]
            out2 = paddle.unsqueeze(out2, axis = 2)
            out2 = self.dir_embedding( out2 )
            out2 = paddle.squeeze( out2, axis = 2 )
            # to_be_concat.append( out2 )
            ts = out2
            used_dim = used_dim - 1

        if (1 << 3 & conf.USE_FEATURE):
            out3 = time_step[:, :, conf.FEATURE_CNT - used_dim]
            out3 = paddle.unsqueeze(out3, axis = 2)
            out3 = self.size_embedding( out3 )
            out3 = paddle.squeeze( out3, axis = 2 )
            # to_be_concat.append( out3 )
            ts = out3
            used_dim = used_dim - 1

        if (1 << 2 & conf.USE_FEATURE):
            out4 = time_step[:, :, conf.FEATURE_CNT - used_dim]
            out4 = paddle.unsqueeze(out4, axis = 2)
            out4 = self.flag_embedding( out4 )
            out4 = paddle.squeeze( out4, axis = 2 )
            # to_be_concat.append( out4 )
            ts = out4
            used_dim = used_dim - 1

        if (1 << 1 & conf.USE_FEATURE):
            out5 = time_step[:, :, conf.FEATURE_CNT - used_dim]
            out5 = paddle.unsqueeze(out5, axis = 2)
            out5 = self.st_embedding( out5 )
            out5 = paddle.squeeze( out5, axis = 2 )
            # to_be_concat.append( out5 )
            ts = out5
            used_dim = used_dim - 1

        if (1 << 0 & conf.USE_FEATURE):
            out6 = time_step[:, :, conf.FEATURE_CNT - used_dim]
            out6 = paddle.unsqueeze(out6, axis = 2)
            out6 = self.flow_embedding( out6 )
            out6 = paddle.squeeze( out6, axis = 2 )
            # to_be_concat.append( out6 )
            ts = out6
        
        if conf.USE_TLS_CLIENT:
            tls_client_e = self.tls_embedding( tls_client )
            tls_client_e = paddle.transpose( tls_client_e, perm = [0, 2, 1] )
            tls_client_c = self.conv1d( tls_client_e )
            tls_client_m = self.maxpool1D( tls_client_c )
            tls_client_m = paddle.transpose( tls_client_m, perm = [0, 2, 1] )

            tls_client_m = paddle.tanh(tls_client_m)


            ts = paddle.concat( x = [tls_client_m, ts], axis = 1 )

        outputs, final_states = self.gru( ts ) 

        fc_input = paddle.concat( (final_states[-2], final_states[-1]), axis = 1 )

        fc_output = self.fc( fc_input )

        fc_output = paddle.nn.functional.selu(fc_output)
        
        # prelu(fc_output, paddle.to_tensor(np.array([0.25]).astype('float32')))

        fc_output = self.fc2( fc_output )

        fc_output = paddle.nn.functional.softmax(fc_output)

        return fc_output

def trainModel(trainloader, classifier, criterion, optimizer, conf):
    for epoch in range( conf.N_EPOCHS ):
        for batch_id, data in enumerate(trainloader, 1): # 记载的下标从1开始
            time_step = paddle.to_tensor(data[0], dtype = "int64") 

            tls_client = paddle.to_tensor( data[1], dtype = "int64" )

            lables = paddle.to_tensor(data[2], dtype = "int64") # 标签
            lables = paddle.unsqueeze( lables, axis = 1 )
            
            predicts = classifier( time_step, tls_client ) # 预测输出
            
            loss = criterion(predicts, lables) # 求出损失

            acc = paddle.metric.accuracy(predicts, lables)

            loss.backward() # 反向传播

            if batch_id % 10 == 0:
                print("epoch: {}, batch_id: {}, loss is: {}, acc is: {}".format(epoch, batch_id, loss.numpy(), acc.numpy()))

            optimizer.step() # 更新参数

            optimizer.clear_grad() # 梯度清零

@paddle.no_grad()
def testModel(testloader, classifier, test_set_size):
    true_lables = []
    pred_lables = []

    for _, data in enumerate(testloader, 1):
        time_step = paddle.to_tensor(data[0], dtype = "int64") 

        tls_client = paddle.to_tensor( data[1], dtype = "int64" )

        lables = paddle.to_tensor(data[2], dtype = "int64") # 标签

        lables = lables.numpy()
        for lable in lables:
            true_lables.append( lable.item() )

        output = classifier( time_step, tls_client )

        pred = np.argmax( output.numpy() , axis = 1)

        for lable in pred:
            pred_lables.append( lable.item() )
    
    # compute_sample_weight
    _metrics = classification_report(true_lables, pred_lables, output_dict=True)

    return round(_metrics['1']["precision"], 4), round(_metrics['1']["recall"], 4), round(_metrics['1']["f1-score"], 4), \
            round(accuracy_score(true_lables, pred_lables), 4), round(precision_score(true_lables, pred_lables, average="weighted"), 4), \
            round(recall_score(true_lables, pred_lables, average="weighted"), 4), round(f1_score(true_lables, pred_lables, average="weighted"),4)

if __name__ == "__main__":
    conf = Conf()
    resf = open("temp.txt", "a")
    pos_dict = dict()
    neg_dict = dict()

    for stream_file in conf.stream_files:
        sample_file = os.path.join( conf.sample_root_dir, str( conf.TIME_STEP[0] ), stream_file)
        load_sample( sample_file, pos_dict, neg_dict, conf )

    # 0b00_0100, 0b00_0010, 0b00_0001
    # self.USE_FEATURE = 0b00_1010  # 数据包特征一共有 6 个，分别是 time, dir, size, flag, s_t, flow_cnt
    conf.USE_FEATURE = 0b00_0001
    conf.USE_TLS_CLIENT = False
    samples, lables = sampling( pos_dict, neg_dict, conf.SAMPLING[0] )
    As,Ps,Rs,F1s = [],[],[],[]
    for i in range(10):
        A,P,R,F1 = combination( samples, lables, resf, conf )
        As.append(A)
        Ps.append(P)
        Rs.append(R)
        F1s.append(F1)
    resf.write("序列特征为：数据包的TCP流ID；不使用 1-D CNN 网络。准确率：{}，精准率：{}，召回率：{}，F1值：{}。".format(round(sum(As)/len(As),4), round(sum(Ps)/len(Ps),4), round(sum(Rs)/len(Rs),4), round(sum(F1s)/len(F1s),4)))
    resf.write( "\n" )

    conf.USE_FEATURE = 0b00_0001
    conf.USE_TLS_CLIENT = True
    samples, lables = sampling( pos_dict, neg_dict, conf.SAMPLING[0] )
    As,Ps,Rs,F1s = [],[],[],[]
    for i in range(10):
        A,P,R,F1 = combination( samples, lables, resf, conf )
        As.append(A)
        Ps.append(P)
        Rs.append(R)
        F1s.append(F1)
    resf.write("序列特征为：数据包的TCP流ID；使用 1-D CNN 网络。准确率：{}，精准率：{}，召回率：{}，F1值：{}。".format(round(sum(As)/len(As),4), round(sum(Ps)/len(Ps),4), round(sum(Rs)/len(Rs),4), round(sum(F1s)/len(F1s),4)))
    resf.write( "\n" )

    conf.USE_FEATURE = 0b00_0010
    conf.USE_TLS_CLIENT = False
    samples, lables = sampling( pos_dict, neg_dict, conf.SAMPLING[0] )
    As,Ps,Rs,F1s = [],[],[],[]
    for i in range(10):
        A,P,R,F1 = combination( samples, lables, resf, conf )
        As.append(A)
        Ps.append(P)
        Rs.append(R)
        F1s.append(F1)
    resf.write("序列特征为：数据包的Session Ticket；不使用 1-D CNN 网络。准确率：{}，精准率：{}，召回率：{}，F1值：{}。".format(round(sum(As)/len(As),4), round(sum(Ps)/len(Ps),4), round(sum(Rs)/len(Rs),4), round(sum(F1s)/len(F1s),4)))
    resf.write( "\n" )

    conf.USE_FEATURE = 0b00_0010
    conf.USE_TLS_CLIENT = True
    samples, lables = sampling( pos_dict, neg_dict, conf.SAMPLING[0] )
    As,Ps,Rs,F1s = [],[],[],[]
    for i in range(10):
        A,P,R,F1 = combination( samples, lables, resf, conf )
        As.append(A)
        Ps.append(P)
        Rs.append(R)
        F1s.append(F1)
    resf.write("序列特征为：数据包的Session Ticket；使用 1-D CNN 网络。准确率：{}，精准率：{}，召回率：{}，F1值：{}。".format(round(sum(As)/len(As),4), round(sum(Ps)/len(Ps),4), round(sum(Rs)/len(Rs),4), round(sum(F1s)/len(F1s),4)))
    resf.write( "\n" )

    conf.USE_FEATURE = 0b00_0001
    conf.USE_TLS_CLIENT = False
    samples, lables = sampling( pos_dict, neg_dict, conf.SAMPLING[0] )
    As,Ps,Rs,F1s = [],[],[],[]
    for i in range(10):
        A,P,R,F1 = combination( samples, lables, resf, conf )
        As.append(A)
        Ps.append(P)
        Rs.append(R)
        F1s.append(F1)
    resf.write("序列特征为：数据包的TCP Flag；不使用 1-D CNN 网络。准确率：{}，精准率：{}，召回率：{}，F1值：{}。".format(round(sum(As)/len(As),4), round(sum(Ps)/len(Ps),4), round(sum(Rs)/len(Rs),4), round(sum(F1s)/len(F1s),4)))
    resf.write( "\n" )

    conf.USE_FEATURE = 0b00_0001
    conf.USE_TLS_CLIENT = True
    samples, lables = sampling( pos_dict, neg_dict, conf.SAMPLING[0] )
    As,Ps,Rs,F1s = [],[],[],[]
    for i in range(10):
        A,P,R,F1 = combination( samples, lables, resf, conf )
        As.append(A)
        Ps.append(P)
        Rs.append(R)
        F1s.append(F1)
    resf.write("序列特征为：数据包的TCP Flag；使用 1-D CNN 网络。准确率：{}，精准率：{}，召回率：{}，F1值：{}。".format(round(sum(As)/len(As),4), round(sum(Ps)/len(Ps),4), round(sum(Rs)/len(Rs),4), round(sum(F1s)/len(F1s),4)))
    resf.write( "\n" )

    conf.USE_FEATURE = 0b00_0001
    conf.USE_TLS_CLIENT = False
    samples, lables = sampling( pos_dict, neg_dict, conf.SAMPLING[0] )
    As,Ps,Rs,F1s = [],[],[],[]
    for i in range(10):
        A,P,R,F1 = combination( samples, lables, resf, conf )
        As.append(A)
        Ps.append(P)
        Rs.append(R)
        F1s.append(F1)
    resf.write("序列特征为：数据包的TCP负载大小；不使用 1-D CNN 网络。准确率：{}，精准率：{}，召回率：{}，F1值：{}。".format(round(sum(As)/len(As),4), round(sum(Ps)/len(Ps),4), round(sum(Rs)/len(Rs),4), round(sum(F1s)/len(F1s),4)))
    resf.write( "\n" )

    conf.USE_FEATURE = 0b00_0001
    conf.USE_TLS_CLIENT = True
    samples, lables = sampling( pos_dict, neg_dict, conf.SAMPLING[0] )
    As,Ps,Rs,F1s = [],[],[],[]
    for i in range(10):
        A,P,R,F1 = combination( samples, lables, resf, conf )
        As.append(A)
        Ps.append(P)
        Rs.append(R)
        F1s.append(F1)
    resf.write("序列特征为：数据包的TCP负载大小；使用 1-D CNN 网络。准确率：{}，精准率：{}，召回率：{}，F1值：{}。".format(round(sum(As)/len(As),4), round(sum(Ps)/len(Ps),4), round(sum(Rs)/len(Rs),4), round(sum(F1s)/len(F1s),4)))
    resf.write( "\n" )

    resf.close()
