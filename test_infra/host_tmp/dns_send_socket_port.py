#!/usr/bin/env python
# -*- encoding: utf-8 -*-

## python3 dns_send_socket.py [dns_payload] [src_ip] [dst_ip]

import binascii
import socket
import sys

from scapy import *
from scapy.layers import dns
from scapy.layers.inet import IP, UDP
from scapy.packet import Raw
from scapy.sendrecv import send, sr, sr1

src_ip = '172.20.10.1' # example ip

def send_dns_query(src_ip, src_port, dst_ip, dst_port, payload_hex_str):
	dns_query = Raw(binascii.a2b_hex(payload_hex_str))

	client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
	client.bind((src_ip, src_port))
	client.settimeout(5) # add in case of no response
	
	try:
		client.sendto(bytes(dns_query), (dst_ip, dst_port))
		data, _ = client.recvfrom(65535)
	except:
		print('No response for 5 seconds, timed out')
		return

	# store the data in string format
	data_str = binascii.b2a_hex(data)
	print(data_str)

	return

dns_payload = sys.argv[1]
src_ip = sys.argv[2]
src_port = int(sys.argv[3])
dns_ip = sys.argv[4]

dns_payload_hex_str = dns_payload

send_dns_query(src_ip, src_port, dns_ip, 53, dns_payload_hex_str)
