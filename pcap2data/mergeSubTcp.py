from io import BufferedReader
import os
import platform
import json
from tqdm import tqdm
from DS import FLOW

# 注意，rootdir 应该为实验原始流量文件夹的绝对路径！
rootdir = "/home/xmr/expr2/data/PCAPS/"

if __name__ == "__main__":
    pcap_files = os.listdir( rootdir )

    # pcap_files = ["1_18_tcp_dns.pcap"]

    for pcap_file in pcap_files:
        if str.split(pcap_file, ".")[-1] != "pcap":
            continue

        sub_json_dir = os.path.join(rootdir, str.split(pcap_file, ".")[0] + "_json")

        json_files = os.listdir( sub_json_dir )

        flows = dict()
        all_streams = []

        json_file = os.path.join(rootdir, str.split(pcap_file, ".")[0] + "_json.txt")
        jf = open(json_file, "w", encoding="utf-8")
        
        for k, sub_json_file in enumerate(json_files):
            print( sub_json_file )
            with open(os.path.join(sub_json_dir, sub_json_file) , "r", encoding="ISO-8859-1") as f:
                lines = f.readlines()

                for line in tqdm(lines):
                    if line == "\n":
                        continue
                    line = line[:-1]
                    
                    stream = json.loads(line)

                    c_ip = stream["src_ip"]
                    c_port = stream["src_port"]
                    s_ip = stream["dst_ip"]
                    s_port = stream["dst_port"]

                    flow = FLOW(c_ip, c_port, s_ip, s_port)

                    # 分析一下，tcp 流以(s_ip, s_port, d_ip, d_port)四元组确定，
                    # 同时存在的两个 tcp 流的(s_ip, s_port, d_ip, d_port)四元组一定不会一样。
                    if flow not in flows.keys():
                        flows[flow] = stream
                        continue
                    
                    # 在这种情况下，存在三种情况：
                    # 1. 一个 TCP 流被分割到了不同的 pcap 文件中，这种情况又可被分为两种
                    #   1.1 一个 TCP 流的 syn 包文发生了重传，导致 syn 包文分散在不同的 pcap 文件中
                    #   1.2 一个 TCP 流的包文分散在不同的 pcap 文件中，但 syn 包文没有分割在不同 pcap 文件中
                    # 2. 两个 TCP 流的(s_ip, s_port, d_ip, d_port)四元组相同
                    # 
                    # 如何区分这三种情况呢，因为 tcp 一定以 Syn 开始，所以若当前流
                    # 的第一个包文为 SYN 包文，则只能是情况 1.1、情况 2，还若当前
                    # 流的第一个包文不为 SYN 包文，则一定为情况 1.2。
                    pkts = stream["pkts"]

                    if str.split(stream["pkts"][0], " ")[3] == "....S.":
                        flag_2 = False
                        for pkt in flows[flow]["pkts"]:
                            if str.split(pkt, " ")[3] != "....S.":
                                flag_2 = True
                                continue
                        
                        if flag_2: # 情况 2
                            all_streams.append( flows[flow] )
                            flows[flow] = stream
                        else: # 情况 1.1
                            # 这种情况下，因为 flows[flow] 中全为 SYN 包，而 stream["pkts"][0] 也是 SYN 包，因此 flows[flow] 可以直接丢弃
                            flows[flow] = stream

                    else: # 情况 1.2
                        flows[flow]["pkts"] = flows[flow]["pkts"] + stream["pkts"]
                        # 可能 flows[flow] 只含有 tcp 流的少量信息
                        for k in stream.keys():
                            if k == "pkts":
                                continue
                            if k not in flows[flow].keys():
                                flows[flow][k] = stream[k]


        for stream in flows.values():
            all_streams.append( stream )

        all_streams = sorted(all_streams, key = lambda stream: float(str.split(stream["pkts"][0], " ")[0]) )

        for stream in all_streams:
            # 保证所有的流都是从 SYN 报文开始的，是完整的流
            if str.split(stream["pkts"][0], " ")[3] != "....S.":
                continue
            
            all_syn_flag = True

            for pkt in stream["pkts"]:
                if str.split(pkt, " ")[3] != "....S.":
                    all_syn_flag = False
                    break
            
            if (not all_syn_flag):
                jf.write( json.dumps(stream) )
                jf.write( "\n" )
        
        jf.close()
