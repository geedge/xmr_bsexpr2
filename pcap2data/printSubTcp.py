import os
import platform
from tqdm import tqdm
from multiprocessing import Pool

rootdir = "/home/xmr/sda3/PCAPS/"

def handle_one_sub_pcap(sub_pcap_path: str, sub_json_path: str):
    print( sub_pcap_path + " " + sub_json_path )
    os.system( "tshark -X lua_script:printTcp.lua -r " + sub_pcap_path + " -q > " + sub_json_path )
    print( "\n" )

if __name__ == "__main__":
    pcap_files = os.listdir(rootdir)
    
    exec_pool = Pool(4)

    # pcap_files = ["1_5_nt_all.pcap", "1_6_am_all.pcap"]

    for pcap_file in pcap_files:
        print( pcap_file )
        if str.split(pcap_file, ".")[-1] != "pcap":
            continue

        sub_pcap_dir = os.path.join(rootdir, str.split(pcap_file, ".")[0] + "_sub")
        
        if not os.path.exists( sub_pcap_dir ):
            os.mkdir( sub_pcap_dir )
            sub_pcap_dir = False

        if not sub_pcap_dir:
            sub_pcap_dir = os.path.join(rootdir, str.split(pcap_file, ".")[0] + "_sub")
            # 分割 Pcap：editcap -c 1000000 .\1_8_all.pcap  .\subPcap\1_8_all.pcap
            os.system("editcap -c 100000 " + os.path.join(rootdir, pcap_file) + " " + os.path.join(sub_pcap_dir, pcap_file) )

        sub_json_dir = os.path.join(rootdir, str.split(pcap_file, ".")[0] + "_json")

        if not os.path.exists( sub_json_dir ):
            os.mkdir( sub_json_dir )
            sub_json_dir = False
        
        if not sub_json_dir:
            sub_json_dir = os.path.join(rootdir, str.split(pcap_file, ".")[0] + "_json")
            sub_pcaps = os.listdir( sub_pcap_dir )
            for sub_pcap in sub_pcaps:
                sub_pcap_path = os.path.join(sub_pcap_dir, sub_pcap)
                sub_json_path = os.path.join( sub_json_dir, str.split(sub_pcap, ".")[0] + ".txt" )
                
                exec_pool.apply_async(handle_one_sub_pcap, args=(sub_pcap_path, sub_json_path, ))
            
            # merge sub_json
        
    exec_pool.close()
    exec_pool.join()    
