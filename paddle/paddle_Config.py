import os
import math

# Feature(round(pkt.time - pkts[i-1].time, 4), pkt.ndir, pkt.size, pkt.flag, s_t_dict[pkt.s_t], flow_dict[pkt.flow])

class Conf():
    def __init__(self) -> None:
        self.SINGLE_FILE = False
        father_path = os.path.dirname( os.path.abspath(os.path.curdir) )
        self.stream_file_dir = os.path.join( father_path, "data", "raw_data" )
        self.sample_root_dir = os.path.join( father_path, "data", "Syn_Seq_Pure" )

        self.TIME_STEP = [50]
        self.BATCH_SIZE = [32]
        self.SAMPLING = [1]


        if self.SINGLE_FILE:
            self.stream_files = [ "1_18_tcp_dns_json.txt" ]
        else:
            self.stream_files = os.listdir( self.stream_file_dir )

        self.USE_FEATURE = 0b00_0010  # 数据包特征一共有 6 个，分别是 time, dir, size, flag, s_t, flow_cnt
        self.FEATURE_CNT = 1

        self.EMBEDDING = True
        self.N_EPOCHS = 15
        self.N_LABEL = 2
        self.N_LAYER = 1
        self.bidirectional = True
        self.n_directions = 2 if self.bidirectional else 1 # 双向2、单向1

        self.EMBEDDING_SIZE = 100
        self.INPUT_SIZE = self.EMBEDDING_SIZE
        self.HIDDEN_SIZE = 100

        self.USE_TLS_CLIENT = False
        self.KERNEL_SIZE = 3


# class RunConf():
#     def __init__( self ) -> None:

