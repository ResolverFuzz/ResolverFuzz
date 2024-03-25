import os
import argparse
from scapy.layers.dns import DNS

# Instantiate the parser
parser = argparse.ArgumentParser(description='Configure the path to the result folder.')

def decode_query(filepath: str):
    with open(filepath, 'r') as f:
        content = f.read()
    try:
        query_packet = DNS(bytes.fromhex(content))
        return query_packet.show(dump=True)
    except:
        return "Query cannot be parsed."


def parse_query(res_folder: str):
    with open(res_folder + '/parse_query_unsuccessful.txt', 'w') as f:
        f.write("")
    if os.path.isdir(res_folder):
        for s in os.listdir(res_folder):
            if not s.startswith("conf"):
                dir_layer_1 = os.path.join(res_folder, s)
                if os.path.isdir(dir_layer_1):
                    for m in os.listdir(dir_layer_1):
                        dir_layer_2 = os.path.join(dir_layer_1, m)
                        if os.path.isdir(dir_layer_2):
                            filename = os.path.join(dir_layer_2, 'query.txt')
                            if os.path.exists(filename):
                                query_parsed = decode_query(filename)
                                if query_parsed == "Query cannot be parsed.":
                                    with open(res_folder + '/parse_query_unsuccessful.txt', 'a') as f:
                                        f.write(str(dir_layer_2) + '\n')
                                with open(os.path.join(dir_layer_2, 'query_parsed.txt'), 'w') as f:
                                    f.write(query_parsed)
                            else:
                                with open(res_folder + '/parse_query_unsuccessful.txt', 'a') as f:
                                    f.write(str(dir_layer_2) + '\n')
    print("Parsing query finished.")

if __name__ == '__main__':
    # Add the arguments
    parser.add_argument('--res_folder', type=str, help='Path to the result folder.', required=True)
    args = parser.parse_args()
    parse_query(args.res_folder)
