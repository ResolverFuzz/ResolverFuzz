#!/usr/bin/env python
# -*- encoding: utf-8 -*-
"""
@File    :   dns_authority_example.py
@Contact :   
@License :   (C)Copyright 2020

@Modify Time        @Author     @Version    @Description
----------------    --------    --------    -----------
18/7/2021 22:38     idealeer    0.0         None
"""
import queue
import sys
from _thread import *
import socket

from scapy.layers.dns import DNS
from select import select

DNS_SERVER_IP = ""
PORT_OF_SERVER = 53
header_count_hex = ""
annsar_hex = ""


# Generate DNS-format NAME
def makeDNSName(name):
	name = name.decode("UTF-8")
	name = name.rstrip(".") + "."
	res = ""
	labels = name.split(".")
	for ele in labels:
		res += chr(len(ele)) + ele
	return res.encode()


# Generate bytes stream
def bytesField(inp, bytesCount):
	return inp.to_bytes(bytesCount, byteorder="big")


# Generate two bytes stream
def twoBytesField(inp):
	return bytesField(inp, 2)


def qd_to_bytes(qd):
	return makeDNSName(qd.qname) + twoBytesField(qd.qtype) + twoBytesField(qd.qclass)


def sys_argv_handler():
	global header_count_hex, annsar_hex, DNS_SERVER_IP
	header_count_hex = sys.argv[1]
	annsar_hex = sys.argv[2]
	DNS_SERVER_IP = sys.argv[3]


def tcp_thread(s):
	global header_count_hex, annsar_hex

	c, addr = s.accept()
	data = c.recv(4096)
	dns = DNS(data[2:])
	txid = dns.id.to_bytes(2, byteorder="big")
	qd = dns.qd

	# print(txid, qd)
	# print("from %s (TCP) : '%s'" % (addr, data))
	# time.sleep(5)
	# c.send(data)

	dns_response = txid + bytes.fromhex(header_count_hex) + qd_to_bytes(qd) + bytes.fromhex(annsar_hex)
	dns_response = twoBytesField(len(dns_response)) + dns_response
	c.sendall(dns_response)
	c.close()


def udp_thread(s):
	global header_count_hex, annsar_hex

	data, addr = s.recvfrom(4096)
	dns = DNS(data)
	txid = dns.id.to_bytes(2, byteorder="big")
	qd = dns.qd

	# print(txid, qd)
	# print("from %s (UDP) : '%s'" % (addr, data))
	# time.sleep(5)
	# s.sendto(data, addr)

	dns_response = txid + bytes.fromhex(header_count_hex) + qd_to_bytes(qd) + bytes.fromhex(annsar_hex)
	s.sendto(dns_response, addr)


def run(header=None, annsar=None):
	global header_count_hex, annsar_hex, DNS_SERVER_IP, PORT_OF_SERVER
	if header or annsar:
		header_count_hex = header
		annsar_hex = annsar
	print(header_count_hex, annsar_hex)
	print("Start DNS Authority ...")

	# create tcp socket
	s_tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	s_tcp.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
	s_tcp.bind((DNS_SERVER_IP, PORT_OF_SERVER))
	s_tcp.listen(5)

	# create udp socket
	s_udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
	s_udp.bind((DNS_SERVER_IP, PORT_OF_SERVER))

	inputs = [s_tcp, s_udp]
	outputs = []
	message_queues = {}

	while inputs:
		input_ready, output_ready, except_ready = select(inputs, outputs, inputs)

		for s in input_ready:
			if s is s_tcp:
				# start_new_thread(tcp_thread, (s,))
				c, addr = s.accept()
				c.setblocking(0)
				inputs.append(c)

				message_queues[c] = queue.Queue()
			elif s is s_udp:
				start_new_thread(udp_thread, (s,))
			else:
				data = s.recv(4096)
				if data:
					dns = DNS(data[2:])
					txid = dns.id.to_bytes(2, byteorder="big")
					qd = dns.qd
					dns_response = txid + bytes.fromhex(header_count_hex) + qd_to_bytes(qd) + bytes.fromhex(
						annsar_hex)
					dns_response = twoBytesField(len(dns_response)) + dns_response
					message_queues[s].put(dns_response)
					if s not in outputs:
						outputs.append(s)
				else:
					if s in outputs:
						outputs.remove(s)
					inputs.remove(s)
					s.close()

					del message_queues[s]
		for s in output_ready:
			try:
				next_msg = message_queues[s].get_nowait()
			except queue.Empty:
				outputs.remove(s)
			else:
				s.send(next_msg)

		for s in except_ready:
			inputs.remove(s)
			if s in outputs:
				outputs.remove(s)
			s.close()

			del message_queues[s]


if __name__ == "__main__":
	sys_argv_handler()
	run()
