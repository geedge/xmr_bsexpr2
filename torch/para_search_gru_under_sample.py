import os
import random
from matplotlib.pyplot import cla
from tqdm import tqdm
from sklearn.model_selection import train_test_split
import warnings
warnings.filterwarnings("ignore")

import torch
from torch.utils.data import Dataset
from torch.utils.data import DataLoader
from GRU import GRUClassifier, trainModel, testModel
from multiprocessing import Pool
import time
import math
from DS import TLS
from Config import conf



N_EPOCHS = 30
HIDDEN_SIZE = 6
N_LABEL = 2
N_LAYER = 2

def load_sample( sample_file : str) -> tuple:    
    pos_dict = dict()
    neg_dict = dict()
    
    with open( sample_file, "r", encoding="utf-8" ) as f:
        lines = f.readlines()
        for line in lines:
            line = line.strip()
            items = str.split(line, " ")

            tls_client_str = items[1] + items[2]
            cur_dict = pos_dict

            if items[0] == "1":  # 正样本
                cur_dict = neg_dict

            if tls_client_str not in cur_dict.keys():
                cur_dict[tls_client_str] = list()
            
            sample = list()
            for pkt in items[3:]:
                sample.append( list( float(feature) for feature in str.split( pkt[1:-1], "," ) ) )

            cur_dict[tls_client_str].append( (sample, items[0]) )
    
    return pos_dict, neg_dict


def sampling( pos_dict : dict, neg_dict : dict, sampling : int) -> tuple:
    samples = list()
    lables = list()
    neg_sample_not_selected = list()

    for tls_client_str, neg_seqs_and_types in neg_dict.items():
        for index, neg_seq_and_type in enumerate( neg_seqs_and_types ):            
            if tls_client_str in pos_dict.keys() and index < int( sampling * len(pos_dict[tls_client_str]) ):
                samples.append( neg_seq_and_type[0] )
                lables.append( 0 )
            else:
                neg_sample_not_selected.append( neg_seq_and_type )
    
    
    need_random_select = sum(len( pos_seqs_and_types ) for pos_seqs_and_types in pos_dict.values()) * sampling - len( samples )
    
    random.shuffle( neg_sample_not_selected )

    for index, neg_seq_and_type in enumerate( neg_sample_not_selected, start = 1):
        if index > need_random_select:
            break
        samples.append( neg_seq_and_type[0] )
        lables.append( 0 )

    for pos_seqs_and_types in pos_dict.values():
        for pos_seq_and_type in pos_seqs_and_types:
            samples.append( pos_seq_and_type[0] )
            lables.append( 1 )

    return samples, lables

class SeqDataset(Dataset):
    def __init__(self, samples: list, lables: list):
        self.samples = torch.tensor(samples, dtype = torch.float32)
        self.lables = torch.tensor(lables, dtype = torch.long)

    def __getitem__(self, index):
        return self.samples[index], self.lables[index]

    def __len__(self):
        return len(self.samples)

def test(samples, lables, sample_size, batch_size, stream_file, percent, resf):
    print( sample_size, end = " " )
    print( batch_size, end = " " )
    print( stream_file, end = " " )
    print( percent, end = "\n" )
    time.sleep(1)


def combination( samples, lables, sample_size, batch_size, stream_file, percent, resf ):
    since = time.time()

    print( sample_size, end = " " )
    print( batch_size, end = " " )
    print( stream_file, end = " " )
    print( percent, end = "\n" )

    X_train, X_test, y_train, y_test = train_test_split(samples, lables)
    train_set = SeqDataset(X_train, y_train)
    test_set = SeqDataset(X_test, y_test)

    train_loader = DataLoader( train_set, batch_size, shuffle = True )
    test_loader = DataLoader( test_set, batch_size, shuffle = True )

    classifier = GRUClassifier( HIDDEN_SIZE, N_LABEL, N_LAYER )

    if conf.USE_GPU:
        classifier.to(conf.device)

    criterion = torch.nn.CrossEntropyLoss()
    optimizer = torch.optim.Adam(classifier.parameters(), lr=0.0001)


    for epoch in tqdm(range(N_EPOCHS)):
        trainModel(train_loader, classifier, criterion, optimizer, len(train_set), epoch)
    
    _metrics = testModel(test_loader, classifier, len(test_set))

    s = time.time() - since
    s = s - math.floor(s / 60) * 60
    print( "%ds" % s, end="\n" )

    resf.write( str(sample_size) + " " )
    resf.write( str(batch_size)  + " ")
    resf.write( stream_file + " ")
    resf.write( str(sum(lables)) + " ")
    resf.write( str(len(lables) - sum(lables)) + "\n")
    resf.write( str(_metrics) + "\n")

def get_processed() -> set:
    processed_dict = dict()
    with open( "processed.txt", "r", encoding="utf-8" ) as f:
        for line in f.readlines():
            x = str.strip( line )
            if x[0] == "(" or x == "":
                continue
            
            key = ",".join( str.split(x, " ")[:-2] )
            if key not in processed_dict.keys():
                processed_dict[ key ] = list()
            processed_dict[ key ].append( int( int(str.split(x, " ")[-1]) / int( str.split(x, " ")[-2] ) )  )

            
    return processed_dict


if __name__ == "__main__":
    stream_file_dir = os.path.join( os.path.abspath( os.path.curdir ), "data", "raw_data")
    sample_root_dir = os.path.join(os.path.abspath( os.path.curdir ), "data", "Seq")


    SEQ_LEN = [100, 150, 200, 300, 400, 500] # 25, 50, 75, 100, 150, 200, 300, 400, 500
    BATCH_SIZE = [16, 32, 64, 128, 256] # 16, 32, 64, 128, 256
    SAMPLING = [1, 2, 3, 4, 5] # 
    if conf.DEBUG:
        SEQ_LEN = [50]
        BATCH_SIZE = [16]
        SAMPLING = [1]

    stream_files = os.listdir( stream_file_dir )
    if conf.DEBUG:
        stream_files = ["1_19_tcp_dns_json.txt"]

    # processed_dict = get_processed()

    resf = open("temp.txt", "w")

    # exec_pool = Pool(2)
    
    for _, stream_file in enumerate( stream_files, start=1):
        # TASK
        for sample_size in SEQ_LEN:
            for batch_size in BATCH_SIZE:

                to_be_processed = str(sample_size) + "," + str(batch_size) + "," + stream_file
                sample_file = os.path.join( sample_root_dir, str(sample_size), stream_file)

                sampling_pos = 0
                # if to_be_processed in processed_dict.keys():
                #     if len(processed_dict[to_be_processed]) == len(SAMPLING):
                #         continue
                #     else:
                #         sampling_pos = len(processed_dict[to_be_processed])

                pos_dict, neg_dict = load_sample( sample_file )
    
                for index in range(sampling_pos, len(SAMPLING)):
                    samples, lables = sampling( pos_dict, neg_dict, SAMPLING[index] )
                    combination( samples, lables, sample_size, batch_size, 
                            stream_file, SAMPLING[index], resf)

                    # exec_pool.apply_async( test, args=( samples, lables, sample_size, batch_size, stream_file, percent, resf,) )

    # exec_pool.close()
    # exec_pool.join()
    resf.close()

