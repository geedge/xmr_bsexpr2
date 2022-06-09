import os
from matplotlib.pyplot import cla
from tqdm import tqdm
from sklearn.model_selection import train_test_split
from sklearn import metrics

import torch
from torch.utils.data import Dataset
from torch.utils.data import DataLoader
from GRU import GRUClassifier, trainModel, testModel
from multiprocessing import Pool

DEBUG = False

USE_GPU = True
device = torch.device("cuda:0")

N_EPOCHS = 30
HIDDEN_SIZE = 6
N_LABEL = 2
N_LAYER = 2


def load_samples( sample_file:str ) -> tuple:

    samples = []
    lables = []
    
    with open( sample_file, "r", encoding="utf-8" ) as f:
        lines = f.readlines()
        for line in lines:
            sample = []
            line = line.strip()
            items1 = str.split(line, " ")

            if items1[0] == "1":
                lables.append( 0 )
            else:
                lables.append( 1 )

            for pkt in items1[3:]:
                items2 = str.split( pkt[1:-1], "," )
                feature = []
                for i in items2:
                    feature.append( float(i) )

                sample.append( feature )

            samples.append(sample)

    return samples, lables


class SeqDataset(Dataset):
    def __init__(self, samples: list, lables: list):
        self.samples = torch.tensor(samples, dtype = torch.float32)
        self.lables = torch.tensor(lables, dtype = torch.long)

    def __getitem__(self, index):
        return self.samples[index], self.lables[index]

    def __len__(self):
        return len(self.samples)



if __name__ == "__main__":
    stream_file_dir = os.path.join( os.path.abspath( os.path.curdir ), "data_2", "raw_data")
    sample_root_dir = os.path.join(os.path.abspath( os.path.curdir ), "data_2", "Seq")

    if not DEBUG:
        SEQ_LEN = [25, 50, 75, 100, 150, 200, 300, 400, 500]
        BATCH_SIZE = [32, 64, 128, 256, 512, 1024]
    else:
        SEQ_LEN = [100]
        BATCH_SIZE = [32]

    stream_files = os.listdir( stream_file_dir )

    resf = open("resf.txt", "w")

    if DEBUG:
        stream_files = ["1_20_all_am_json.txt"]

    for file_index, stream_file in enumerate( stream_files, start=1):

        # TASK
        for sample_size in SEQ_LEN:
            for batch_size in BATCH_SIZE:
                
                sample_file = os.path.join( sample_root_dir, str(sample_size), stream_file)
                samples, lables = load_samples( sample_file )

                X_train, X_test, y_train, y_test = train_test_split(samples, lables)

                # print( len(X_train) )
                # print( len(X_test) )

                train_set = SeqDataset(X_train, y_train)
                test_set = SeqDataset(X_test, y_test)

                train_loader = DataLoader( train_set, batch_size, shuffle = True )
                test_loader = DataLoader( test_set, batch_size, shuffle = True )

                classifier = GRUClassifier( HIDDEN_SIZE, N_LABEL, N_LAYER )

                if USE_GPU:
                    classifier.to(device)

                criterion = torch.nn.CrossEntropyLoss()
                optimizer = torch.optim.Adam(classifier.parameters(), lr=0.0001)


                print(str(file_index), end="\t")
                print(stream_file, end="\t")
                print(str(sample_size), end="\t")
                print(str(batch_size), end="\n")

                for epoch in tqdm(range(N_EPOCHS)):
                    trainModel(train_loader, classifier, criterion, optimizer, len(train_set), epoch)
                
                acc, pre, rec, f1 = testModel(test_loader, classifier, len(test_set))
                
                resf.write( stream_file )
                resf.write( " " )
                resf.write( str(sample_size) )
                resf.write( " " )
                resf.write( str(batch_size) )
                resf.write( "\n" )

                resf.write( str(acc) )
                resf.write( " " )
                resf.write( str(pre) )
                resf.write( " " )
                resf.write( str(rec) )
                resf.write( " " )
                resf.write( str(f1) )
                resf.write( "\n" )    
    resf.close()