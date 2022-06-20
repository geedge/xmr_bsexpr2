from genericpath import isdir
import itertools
from ntpath import join
import operator
import os
import platform
import json
import shutil
import copy
import numpy as np
from scipy.stats import entropy
from tqdm import tqdm
from itertools import *
from operator import *
from multiprocessing import Pool

from DS import TLS,PKT,Feature

def entropy1(labels, base=None):
  value, counts = np.unique(labels, return_counts=True)
  return entropy(counts, base=base)

def gen_samples(data_file: str, SEQ_LEN: list, output_file_dirs: list):

    # 混合流量的（不同源 IP 流量混合）的 tls 客户端报文序列
    mixed_cip_tc_seq = {}
    
    # 生成每个源 IP 的 tls 客户端报文序列
    per_cip_tc_seq = {}

    # 每个源 IP 的 tcp 流的 tcp_fp 集合
    per_cip_tcp_fp = {}

    with open(data_file, "r", encoding = "ISO-8859-1") as f:
        lines = f.readlines()
        for line in lines:
            stream = json.loads(line)
            if stream["src_ip"] not in per_cip_tcp_fp:
                per_cip_tcp_fp[stream["src_ip"]] = []
            
            per_cip_tcp_fp[stream["src_ip"]].append( stream["tcp_fp"] )

    to_be_delete = set()
    for cip, tcp_fps in per_cip_tcp_fp.items():
        if( entropy1( tcp_fps ) > 0.25 ):
            to_be_delete.add( cip )

    with open(data_file, "r", encoding = "ISO-8859-1") as f:

        s_t_dict = {}
        flow_cnt = 0

        lines = f.readlines()
        for line in tqdm(lines):
            stream = json.loads(line)

            if stream["src_ip"] in to_be_delete:
                continue

            # 判断 tcp 流是否是 tls 流
            if "ja3_md5" not in stream:
                continue

            # 有 session ticket 扩展就一定不是 tls 1.3，
            # 本实验中只用 tls 1.2 版本的流量。
            # 有 session ticket 扩展不一定就有 session ticket，
            # session ticket 可能为空值"EMPTY".
            if "s_t" not in stream:
                continue

            if (("sni" not in stream) or (stream["sni"] == "")):
                continue

            tc = TLS(stream["ja3_md5"], stream["sni"], stream["dst_ip"], str(stream["dst_port"]))
            if tc not in mixed_cip_tc_seq.keys():
                mixed_cip_tc_seq[tc] = []

            if stream["s_t"] not in s_t_dict:
                length = len(s_t_dict)
                if stream["s_t"] == "EMPTY":
                    s_t_dict["EMPTY"] = -1
                else:
                    s_t_dict[stream["s_t"]] = length + 1
            
            flow_cnt = flow_cnt + 1

            for pkt in stream["pkts"]:
                items = str.split(pkt, " ")

                # 包时间
                pkt_time = float(items[0])

                # 包方向
                ndir = 0 if items[1] == "c" else 1

                # 包大小
                size = int(items[2])
                
                # 包标志位
                flag = sum( (2**i if c != "." else 0 for i,c in enumerate(items[3][::-1])) )
                # if items[3] == "....S.":
                #     input()

                # 包 session_ticket
                s_t = s_t_dict[stream["s_t"]]
                
                pkt = PKT(pkt_time, ndir, size, flag, s_t, flow_cnt, stream["src_ip"])

                mixed_cip_tc_seq[tc].append(pkt)

    # 生成每个源 IP 的 tls 客户端报文序列
    for tc,all_pkts in mixed_cip_tc_seq.items():

        all_pkts.sort(key = lambda x: x.client_ip) # 注意，这里改变了数据包的时间顺序

        for cip, pkts in groupby(all_pkts, key=lambda x: x.client_ip):

            if cip not in per_cip_tc_seq.keys():
                per_cip_tc_seq[cip] = dict()
            
            per_cip_tc_seq[cip][tc] = list(pkts)

    # 把数据包按照时间顺序排序
    for tc, all_pkts in mixed_cip_tc_seq.items():
        all_pkts.sort(key = lambda x: x.time)

    for cip, tc_seq in per_cip_tc_seq.items():
        for tc, _ in tc_seq.items():
            per_cip_tc_seq[cip][tc].sort(key = lambda x: x.time)

    # 生成序列长度不同的正负样本，并存储到不同的文件中去
    for index, sample_size in enumerate( SEQ_LEN ):
        output_file = os.path.join( output_file_dirs[index], os.path.basename(data_file) ) 
        print( output_file )
        with open( output_file, "w", encoding = "ISO-8859-1" ) as of:

            # 生成正样本
            for tc, all_pkts in mixed_cip_tc_seq.items():
                for index, pkt in enumerate( all_pkts ):
                    if pkt.flag == 2: # 每个样本以 syn 包开始
                        if index + sample_size <= len( all_pkts ):
                            write_sample(tc, all_pkts[index : index + sample_size] , 1, of)
                        else:
                            break

            # 以组合方式生成正样本：应该没什么用
            # for x in combinations(per_cip_tls_clients, 2):

            tls_sample_cnt = dict()

            # 生成负样本
            for cip, tc_seq in per_cip_tc_seq.items():

                for tc, pkts in tc_seq.items():

                    if tc not in tls_sample_cnt:
                        tls_sample_cnt[tc] = 0

                    for index, pkt in enumerate( pkts ):
                        if pkt.flag == 2:
                            # if (index + sample_size <= len( pkts )) and (tls_sample_cnt[tls] < 200):
                            if index + sample_size <= len( pkts ):
                                # flag = 
                                write_sample(tc, pkts[index : index + sample_size] , 0, of)
                                # tls_sample_cnt[tls] = (tls_sample_cnt[tls] + 1) if flag else tls_sample_cnt[tls]
                            else:
                                break

def write_sample(tc: TLS, pkts: list, label: int, of) -> bool:

    # 检验报文序列中包是否真的来自多个源 IP
    client_ips = set()
    if label == 1:
        for pkt in pkts:
            client_ips.add( pkt.client_ip )
        if len(client_ips) == 1:
            return False

    s_t_dict = {}
    flow_dict = {}
    for pkt in pkts:
        if pkt.s_t not in s_t_dict:
            length = len(s_t_dict)
            s_t_dict[pkt.s_t] = length
        
        if pkt.flow not in flow_dict:
            length = len(flow_dict)
            flow_dict[pkt.flow] = length

    # 这并不意味着这种 tls 客户端不带 session_ticket !!!
    # 这只意味着这个样本对模型来说是不可学习的（没有特征的）。
    if (len(s_t_dict) == 1) and (-1 in s_t_dict.keys()):
        return False
    
    if label == 0:
        of.write( "1" )
    else:
        of.write( str( len(client_ips) ) )

    of.write(" ")
    of.write(tc.ja3)
    of.write(" ")
    of.write(tc.sni)
    of.write(" ")
    of.write(tc.server_ip)
    of.write(" ")
    # of.write(tc.server_port)

    for i,pkt in enumerate(pkts):
        if i == 0:
            feature = Feature(round(0.0, 4), pkt.ndir, pkt.size, pkt.flag, s_t_dict[pkt.s_t], flow_dict[pkt.flow])
        else:
            feature = Feature(round(pkt.time - pkts[i-1].time, 4), pkt.ndir, pkt.size, pkt.flag, s_t_dict[pkt.s_t], flow_dict[pkt.flow])
            # if round(pkt.time - pkts[i-1].time, 4) < 0.0:
            #     a = 1
            #     b = a + 1
        
        of.write(str(feature))
        of.write(" ")
    
    of.write("\n")

    return True


if __name__ == "__main__":

    # SEQ_LEN = [30, 40, 50, 60, 70, 80, 90, 100, 110, 120, 130, 140, 150, 160, 170]
    # SEQ_LEN = [1000]

    SEQ_LEN = [100]

    print( os.path.dirname( os.path.abspath(os.path.curdir) ) )

    data_dir = os.path.join( os.path.dirname( os.path.abspath(os.path.curdir) ) , "data")
    raw_dir = os.path.join(data_dir, "raw_data")
    output_root_dir = os.path.join(data_dir, "Syn_Seq")

    exec_pool = Pool(4)

    output_dirs = list()
    for seq_len in SEQ_LEN:
        output_dir = os.path.join(output_root_dir, str(seq_len))
        # 先删除老的样本输出目标文件夹，去掉旧的输出内容
        if ( os.path.exists( output_dir ) and os.path.isdir( output_dir ) ):
            shutil.rmtree( output_dir )
        # 创建样本输出目标文件夹
        os.mkdir( output_dir )
        output_dirs.append( output_dir )

    for data_file in os.listdir( raw_dir ):
        print( os.path.join(raw_dir, data_file) )

        gen_samples( os.path.join(raw_dir, data_file), SEQ_LEN, output_dirs )

        # exec_pool.apply_async(gen_samples, args=(os.path.join(raw_dir, data_file), SEQ_LEN, output_dirs, ))

    exec_pool.close()
    exec_pool.join()
