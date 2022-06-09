import os
import numpy as np
import torch
import torch.nn as nn
import torch.nn.functional as F

class Config:
    def __init__(self) -> None:
        self.emdding_size = 100
        self.out_channels = 100
        self.max_text_len = 100

        self.tls_client_size = 100
        self.tls_client_cnt

        # tls client parameter
        # ja3_md5 + ip + port + sni = 16 + 4 + 2 + 58 = 80 （sni 超过 62 则截断）
        self.t_c_size = 80
        self.t_c_embedding_dim = 50
        self.t_c_conv_out_channel = 30
        self.t_c_conv_kernel_size = 4

        # tlc_client pakcet sequence parameter
        self.seq_len = 100

        self.gru_hidden_size = 50
        self.gru_layer = 1
        self.gru_bidir = True


class TextCNN(nn.Module):
    def __init__(self, config):
        super(TextCNN, self).__init__()
        self.is_training = True
        self.dropout_rate = config.dropout_rate
        self.num_class = config.num_class
        self.use_element = config.use_element
        self.config = config
 
        self.embedding = nn.Embedding(num_embeddings=config.vocab_size, embedding_dim=config.embedding_size)

        self.convs = nn.ModuleList([

            nn.Sequential(
                            nn.Conv1d(
                                in_channels=config.embedding_size,
                                out_channels=config.feature_size,
                                kernel_size=h
                            ),
                            # nn.BatchNorm1d(num_features=config.feature_size), 
                            nn.ReLU(),
                            nn.MaxPool1d(kernel_size=config.max_text_len-h+1)
            )
                    for h in config.window_sizes
        ])

        self.fc = nn.Linear(
                            in_features=config.feature_size*len(config.window_sizes),
                            out_features=config.num_class
        )

        if os.path.exists(config.embedding_path) and config.is_training and config.is_pretrain:
            print("Loading pretrain embedding...")
            self.embedding.weight.data.copy_(torch.from_numpy(np.load(config.embedding_path)))    
    
    def forward(self, x):
        embed_x = self.embedding(x)
        
        # print('embed size 1',embed_x.size())  # 32*35*256
        # batch_size x text_len x embedding_size  -> batch_size x embedding_size x text_len
        embed_x = embed_x.permute(0, 2, 1)
        # print('embed size 2',embed_x.size())  # 32*256*35
        out = [conv(embed_x) for conv in self.convs]  # out[i]:batch_size x feature_size*1
        # for o in out:
        #    print('o',o.size())  # 32 * 100 * 1
        out = torch.cat(out, dim=1)  # 对应第二个维度（行）拼接起来，比如说5*2*1,5*3*1的拼接变成5*5*1
        #print(out.size(1)) # 32*400*1
        out = out.view(-1, out.size(1)) 
        #print(out.size())  # 32*400 
        if not self.use_element:
            out = F.dropout(input=out, p=self.dropout_rate)
            out = self.fc(out)
        return out


#       https://pytorch.org/docs/1.2.0/nn.html?highlight=gru#torch.nn.GRU

class OneDimensionCNN( nn.Module ):
    def __init__(self, conf):
        self.embedding_1 = nn.Embedding(
            num_embeddings = 256,
            embedding_dim = conf.t_c_embedding_dim
        )

        self.conv1d = nn.Conv1d(
            in_channels = conf.t_c_embedding_dim,
            out_channels = conf.t_c_conv_out_channel,
            kernel_size = conf.t_c_conv_kernel_size
        )

        nn.ReLU()

        self.maxpool1d = nn.MaxPool1d(
            # global maxpool
            kernel_size = conf.t_c_size - conf.t_c_conv_kernel_size + 1
        )

        nn.Linear(
            in_features = conf.t_c_conv_out_channel
            out_features = 
        )

        self.embedding_2 = nn.Embedding(
            num_embeddings = 
        )

        self.embedding_3 = nn.Embedding(

        )




        self.gru = nn.GRU(input_size=  )