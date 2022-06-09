from genericpath import isdir
import itertools
from ntpath import join
import operator
import os
import platform
import json
import shutil
import copy
from tqdm import tqdm
from itertools import *
from operator import *
from multiprocessing import Pool

from DS import TLS,PKT,Feature

SAMPLE_SIZE_LIST = [50, 100, 200, 500, 1000]

def gen_samples(data_file: str, SEQ_LEN: list, output_file_dirs: list):

    # 生成混合流量的（不同源 IP 流量混合）的 tls 客户端报文序列
    mixed_tls_clients = {}
    with open(data_file, "r", encoding = "ISO-8859-1") as f:


        s_t_dict = {}
        flow_cnt = 0

        lines = f.readlines()
        for line in lines:
            flow = json.loads(line)

            if "ja3_md5" not in flow:
                continue

            if ("sni" not in flow) or (flow["sni"] == ""):
                continue

            if "s_t" not in flow:
                continue

            tls = TLS(flow["ja3_md5"], flow["sni"], flow["dst_ip"], str(flow["dst_port"]))
            if tls not in mixed_tls_clients.keys():
                mixed_tls_clients[tls] = []

            if flow["s_t"] not in s_t_dict:
                length = len(s_t_dict)
                if flow["s_t"] == "EMPTY":
                    s_t_dict["EMPTY"] = -1
                else:
                    s_t_dict[flow["s_t"]] = length + 1
            
            flow_cnt = flow_cnt + 1

            for pkt in flow["pkts"]:
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
                s_t = s_t_dict[flow["s_t"]]
                
                pkt = PKT(pkt_time, ndir, size, flag, s_t, flow_cnt, flow["src_ip"])

                mixed_tls_clients[tls].append(pkt)

    # 生成每个源 IP 的 tls 客户端报文序列
    per_cip_tls_clients = dict()
    for tls,all_pkts in mixed_tls_clients.items():

        all_pkts.sort(key = lambda x: x.client_ip)

        for cip, pkts in groupby(all_pkts, key=lambda x: x.client_ip):

            if cip not in per_cip_tls_clients.keys():
                per_cip_tls_clients[cip] = dict()
            
            per_cip_tls_clients[cip][tls] = list(pkts)
        
    # 生成每个源 IP 的 tls 客户端报文序列
    for cip,tls_set in per_cip_tls_clients.items():
        for tls, _ in tls_set.items():
            per_cip_tls_clients[cip][tls].sort(key = lambda x: x.time)

    # 生成序列长度不同的正负样本，并存储到不同的文件中去
    for index, sample_size in enumerate( SEQ_LEN ):
        output_file = os.path.join( output_file_dirs[index], os.path.basename(data_file) ) 
        with open( output_file, "w", encoding = "ISO-8859-1" ) as of:

            

            # 生成正样本
            for tls, all_pkts in mixed_tls_clients.items():

                pkts_size = len(all_pkts)
                cnt = int( pkts_size / sample_size )

                for i in range(cnt):
                    write_sample(tls, all_pkts[i * sample_size: i * sample_size + sample_size], 1, of)

            tls_sample_cnt = dict()

            # 生成负样本
            for _, tls_set in per_cip_tls_clients.items():

                for tls, pkts in tls_set.items():

                    if tls not in tls_sample_cnt:
                        tls_sample_cnt[tls] = 0

                    pkts_size = len(pkts)
                    cnt = int( pkts_size / sample_size )

                    for i in range( cnt ):
                        if (tls_sample_cnt[tls] < 30):
                            flag = write_sample(tls, pkts[i * sample_size: i * sample_size + sample_size] , 0, of)
                            tls_sample_cnt[tls] = (tls_sample_cnt[tls] + 1) if flag else tls_sample_cnt[tls]
                        else:
                            break

def write_sample(tls: TLS, pkts: list, label: int, of) -> bool:

    # 检验报文序列中包是否真的来自多个源 IP
    client_ips = set()

    for pkt in pkts:
        client_ips.add( pkt.client_ip )

    if (len(client_ips) == 1) and ( label == 1 ):
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

    # 这意味着这种 tls 客户端不带 session_ticket !!!
    if (len(s_t_dict) == 1) and (-1 in s_t_dict.keys()):
        return False

    if label == 0:
        of.write( "1" )
    else:
        of.write( str( len(client_ips) ) )

    of.write(" ")
    of.write(tls.ja3)
    of.write(" ")
    of.write(tls.sni)
    of.write(" ")

    for i,pkt in enumerate(pkts):
        if i == 0:
            feature = Feature(round(0.0, 4), pkt.ndir, pkt.size, pkt.flag, s_t_dict[pkt.s_t], flow_dict[pkt.flow])
        else:
            feature = Feature(round(pkt.time - pkts[i-1].time, 4), pkt.ndir, pkt.size, pkt.flag, s_t_dict[pkt.s_t], flow_dict[pkt.flow])
        
        of.write(str(feature))
        of.write(" ")
    
    of.write("\n")

    return True




if __name__ == "__main__":

    SEQ_LEN = [25, 50, 75, 100, 150, 200, 300, 400, 500, 600, 700, 800, 900, 1000]
    # SEQ_LEN = [1000]

    data_dir = os.path.join( os.path.abspath( os.path.curdir ), "data_2")
    raw_dir = os.path.join(data_dir, "raw_data")
    output_root_dir = os.path.join(data_dir, "Seq")

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
        # gen_samples( os.path.join(raw_dir, data_file), SEQ_LEN, output_dirs )

        exec_pool.apply_async(gen_samples, args=(os.path.join(raw_dir, data_file), SEQ_LEN, output_dirs, ))

    exec_pool.close()
    exec_pool.join()
