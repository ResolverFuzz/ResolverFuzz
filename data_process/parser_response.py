import os
import argparse
from scapy.layers.dns import DNS

# Instantiate the parser
parser = argparse.ArgumentParser(description='Configure the path to the result folder.')

# Built-in software list
dns_sw_list = ['bind9', 'knot', 'maradns', 'powerdns', 'unbound', 'technitium']


def decode_response(filepath: str):
    if os.path.exists(filepath) and os.path.isfile(filepath):
        with open(filepath, 'r') as f:
            res = f.read()
        if res.startswith("No"):
            return "_"
        try:
            return DNS(bytes.fromhex(res[2:-2]))
        except Exception:
            return None
    return "_"


def parse_response(res_folder: str):
    with open(res_folder + '/parse_response_unsuccessful.txt', 'w') as f:
        f.write("")
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
                                filename = os.path.join(dir_layer_3, 'response.txt')
                                if os.path.exists(filename):
                                    reponse_parsed = decode_response(filename)
                                    if reponse_parsed == "_":
                                        with open(os.path.join(dir_layer_3, 'response_parsed.txt'), 'w') as response_parsed_obj:
                                            response_parsed_obj.write('No response, timed out')
                                    elif reponse_parsed:
                                        reponse_parsed_dump = reponse_parsed.show(dump=True)
                                        with open(os.path.join(dir_layer_3, 'response_parsed.txt'), 'w') as response_parsed_obj:
                                            response_parsed_obj.write(reponse_parsed_dump)
                                    else:
                                        with open(res_folder + '/parse_response_unsuccessful.txt', 'a') as f:
                                            f.write(str(dir_layer_3) + "\n")
    print("Parsing response finished.")

if __name__ == '__main__':
    # Add the arguments
    parser.add_argument('--res_folder', type=str, help='Path to the result folder.', required=True)
    args = parser.parse_args()
    parse_response(args.res_folder)
