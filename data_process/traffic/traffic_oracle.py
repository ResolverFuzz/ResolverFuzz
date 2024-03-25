import os
import argparse
import pandas as pd

from traffic_analyzer import TrafficAnalyzer

# Instantiate the parser
parser = argparse.ArgumentParser(description='Configure the path to the result folder.')

# Built-in DNS software list
dns_sw_list = ['bind9', 'knot', 'maradns', 'powerdns', 'unbound', 'technitium']

def save_to_csv(data: dict, filename: str):
    df = pd.DataFrame(data)
    df = df.round(2)
    df.to_csv(filename)

def traffic_analyze(res_folder: str):
    ratio_count = {}
    ratio_size = {}
    for sw in dns_sw_list:
        ratio_count[sw] = []
        ratio_size[sw] = []
    total = 0
    if os.path.isdir(res_folder):
        for s in os.listdir(res_folder):
            if not s.startswith("conf"):
                dir_layer_1 = os.path.join(res_folder, s)
                if os.path.isdir(dir_layer_1):
                    for m in os.listdir(dir_layer_1):
                        dir_layer_2 = os.path.join(dir_layer_1, m)
                        if os.path.isdir(dir_layer_2):
                            for p in dns_sw_list:
                                dir_layer_3 = os.path.join(dir_layer_2, p)
                                filename = os.path.join(dir_layer_3, 'tcpdump.pcap')
                                if os.path.exists(filename):
                                    tmp = TrafficAnalyzer(filepath=filename)
                                    ratio_count[p].append(tmp.ratio_count)
                                    ratio_size[p].append(tmp.ratio_size)
                                    total += 1
    print("Total number of traffic files: ", total)
    save_to_csv(ratio_count, 'ratio_count.csv')
    save_to_csv(ratio_size, 'ratio_size.csv')


if __name__ == '__main__':
    # Add the arguments
    parser.add_argument('--res_folder', type=str, help='Path to the result folder.', required=True)
    args = parser.parse_args()
    traffic_analyze(res_folder=args.res_folder)
