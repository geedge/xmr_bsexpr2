import os
from tqdm import tqdm




SAMPLE_SIZE_LIST = [50, 100, 200, 500, 1000]

if __name__ == "__main__":
    data_root = os.path.join( os.path.abspath( os.path.pardir ), "data" )
    
    for sample_size in SAMPLE_SIZE_LIST:
        
        train_file = os.path.join(data_root, str(sample_size) + "_train.txt")
        test_file  = os.path.join(data_root, str(sample_size) + "_test.txt")

        ja3_set = set()
        sni_set = set()

        train_sample_cnt = 0
        train_pos_cnt    = 0
        train_neg_cnt    = 0

        test_sample_cnt  = 0
        test_pos_cnt     = 0
        test_neg_cnt     = 0

        with open( train_file, "r", encoding="utf-8" ) as f:
            for line in tqdm(f.readlines()):
                
                line = line.strip()
                if line == "": continue

                train_sample_cnt = train_sample_cnt + 1
                items = str.split( line, " " )
                ja3_set.add(items[1])
                sni_set.add(items[2])

                if( items[0] == "0"):
                    train_pos_cnt = train_pos_cnt + 1
                else:
                    train_neg_cnt = train_neg_cnt + 1
        

        with open( test_file, "r", encoding="utf-8" ) as f:
            for line in tqdm(f.readlines()):
                
                line = line.strip()
                if line == "": continue

                test_sample_cnt = test_sample_cnt + 1
                items = str.split( line, " " )
                ja3_set.add(items[1])
                sni_set.add(items[2])

                if( items[0] == "0"):
                    test_pos_cnt = test_pos_cnt + 1
                else:
                    test_neg_cnt = test_neg_cnt + 1

        print( f"包序列为 {sample_size} 时:\n" )
        print( f"训练样本数量为 {train_sample_cnt}，其中正样本为 {train_pos_cnt}，负样本为 {train_neg_cnt}\n" )
        print( f"测试样本数量为 {test_sample_cnt}，其中正样本为 {test_pos_cnt}，负样本为 {test_neg_cnt}" )
        print( f"ja3 的个数为 { len(ja3_set) }" )
        print( f"sni 的个数为 { len(sni_set) }" )
                