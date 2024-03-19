import binascii
from scapy import *
from scapy.all import *
from scapy.layers.dns import DNS, DNSRR

import docker
import multiprocessing as mp
import sys
import os
import time
import subprocess
import requests
import json
import argparse

parser = argparse.ArgumentParser(description='ResolverFuzz config options')

from input_generation import dns_fuzzer as dns_fuzzer
client = docker.from_env()

total_payload_num = 5 # #payloads (e.g, pair of queries and responses) to be tested for each unit
unit_size = 5 # #units to be deployed

dnstap_save_interval = 100
tcpdump_wait_time = 1
res_time_stamp = 0.

## ns names:	ns[unit_num]
## test names:	test[unit_num]

## control table for DNS sw to evaluate
is_bind9_eval = True
is_unbound_eval = True
is_powerdns_eval = True
is_knot_eval = True
is_maradns_eval = True
is_technitium_eval = True

is_debug = False

dns_sw_name_list = ['bind9', 'unbound', 'powerdns', 'knot', 'maradns', 'technitium']

## image tables
bind9_image = 'bind9:9.18.0'
unbound_image = 'unbound:1.16.0'
powerdns_image = 'powerdns:4.7.0'
knot_image = 'knot:5.5.0'
maradns_image = 'maradns:3.5.0022'
technitium_image = 'technitium:10.0.1'

dnstap_listener_image = 'dnstap-listener'

attacker_image = 'attacker'
auth_srv_image = 'auth-srv'

## DNS sw container names
test_name_suffix = 'concurrent'

docker_network_name = 'test_net_batch'
# attacker names: attacker-[unit No.]-[suffix]
# dns sw names: [dns sw name]-[unit No.]-[suffix]
# auth srv names: auth_srv-[unit No.]-[suffix]
# dnstap name: dnstap-[suffix]

## IP address range used for tests, a whole /16 IP range required
ip_addr_range = '172.22'

bind9_ip_addr_prefix = '{}.1'.format(ip_addr_range)
unbound_ip_addr_prefix = '{}.2'.format(ip_addr_range)
powerdns_ip_addr_prefix = '{}.3'.format(ip_addr_range)
knot_ip_addr_prefix = '{}.4'.format(ip_addr_range)
maradns_ip_addr_prefix = '{}.5'.format(ip_addr_range)
technitium_ip_addr_prefix = '{}.6'.format(ip_addr_range)

attacker_ip_addr_prefix = '{}.101'.format(ip_addr_range)
auth_srv_ip_addr_prefix = '{}.201'.format(ip_addr_range)

dnstap_ip_addr = '{}.50.1'.format(ip_addr_range)

# ports for sending queries from attacker containers
src_port_dict = {
	'bind9':		11000,
	'unbound':		12000,
	'powerdns':		13000,
	'knot':			14000,
	'maradns':		15000,
	'technitium':	16000
}


## file paths
## result folder structure: [result_folder_path]/[unit no.]/[round no.]/[dns_sw_name]
result_folder_path = os.path.abspath('./recursive_test_res')
conf_folder_path = os.path.abspath('../config/conf_recur_concurrent')
auth_srv_tmp_path = os.path.abspath('./auth-srv-tmp')

# dump folders may need to change due to multiple identical containers for one DNS sw
# for each dns sw container, the dump folder is: 
# dump_folder_path/[dns_sw_name]/[unit No.]
# OR
# (dnstap) dump_folder_path/dnstap/
dump_folder_path = os.path.abspath('./dump')
attacker_host_tmp_path = os.path.abspath('./host_tmp')


## classes for containers
class DNSTapContainer:
	def __init__(self,
		image_name = dnstap_listener_image, 
		container_name = 'dnstap-{suffix}'.format(
			suffix = test_name_suffix
			), 
		network_name = docker_network_name, 
		ipv4_addr = dnstap_ip_addr
		):
		
		global dump_folder_path, result_folder_path

		self.image_name = image_name
		self.container_name = container_name
		self.dump_folder = '{dump_folder_path}/dnstap'.format(
			dump_folder_path = dump_folder_path
		)
		self.res_folder = '{res_folder_path}'.format(
			res_folder_path = result_folder_path
		)
		
		self.network_name = network_name
		self.ipv4_addr = ipv4_addr
		return

	## remove the old container
	def clean(self):
		subprocess.call('sudo docker stop {}'.format(self.container_name), shell=True)
		subprocess.call('sudo docker container rm {}'.format(self.container_name), shell=True)
		return

	## create a new one
	def create(self):
		self.container = client.containers.run(
			image = self.image_name,
			name = self.container_name,
			volumes = [
				'{dump_folder}:/var/cache/dnstap'.format(
					dump_folder = self.dump_folder
				)],
			detach = True,
			tty = True
		)
		## connect to the local private network
		client.networks.get(self.network_name).connect(
			self.container, 
			ipv4_address = self.ipv4_addr
		)
		subprocess.call('sudo rm {dump_folder}/log.dnstap'.format(
			dump_folder = self.dump_folder
   		), shell=True)
		print('DNSTap created')
		return
	
	def clean(self):
		subprocess.call('sudo docker stop {dnstap}'.format(
			dnstap = self.container_name
		), shell=True)
		subprocess.call('sudo docker container rm {dnstap}'.format(
			dnstap = self.container_name
		), shell=True)
		print('old DNSTap cleaned')
		return
	
	def start(self):
		exit_code, output = self.container.exec_run(
			['sh', '-c', 'dnstap -l 0.0.0.0:5353 -w /var/cache/dnstap/log.dnstap'], detach=True)
		## wait for DNSTap to fully start
		time.sleep(1)	
		print('DNSTap started')
		return

	def stop(self):
		self.container.stop()
		print('DNSTap stopped')		
		return

	def remove(self):
		self.container.remove()
		print('DNSTap removed')
		return

	def log_save(self, curr_unit_num, curr_round_num):
		subprocess.call('cp {dump_folder}/log.dnstap {res_folder}/{unit_num}/{round_num}/dnstap/'.format(
			dump_folder = self.dump_folder, 
			res_folder = self.res_folder, 
			unit_num = curr_unit_num, 
			round_num = curr_round_num
		), shell=True)
		
		print('='*15, 'DNATap log saved', '='*15)
		return

	def log_final_save(self):
		subprocess.call('cp {dump_folder}/log.dnstap {res_folder}/'.format(
			dump_folder = self.dump_folder, 
			res_folder = self.res_folder
		), shell=True)

		print('='*15, 'DNATap log saved finally', '='*15)
		return


class TestUnit:
	def __init__(self, unit_num:int, dnstap_interval:int = 10):
		global result_folder_path

		# attacker object
		self.attacker_obj: AttackerContainer = None
		
		# DNS sw objects
		self.bind9_obj: Bind9Container = None
		self.unbound_obj: UnboundContainer = None
		self.powerdns_obj: PowerDNSContainer = None
		self.knot_obj: KnotContainer = None
		self.maradns_obj: MaraDNSContainer = None
		self.technitium_obj: TechnitiumContainer = None

		# Auth server object
		self.auth_srv_obj: AuthSrvContainer = None

		# DNS Fuzzer
		self.dns_fuzzer_obj: DNSFuzzerGenerator = None

		# DNSTap server
		self.dnstap_obj: DNSTapContainer = None

		# unit num
		self.unit_num: int = unit_num

		# round num initialized to 0
		self.round_num: int = 0

		# res folder to record stats
		self.res_folder = '{res_folder}/{unit_num}'.format(
			res_folder = result_folder_path, 
			unit_num = self.unit_num
		)

		# interval for saving dnstap logs
		self.dnstap_interval = dnstap_interval
		return

	def create_res_folder(self):
		global dns_sw_name_list
		
		subprocess.call('sudo mkdir {res_folder}/{unit_num}/{round_num}'.format(
			res_folder = result_folder_path, 
			unit_num = self.unit_num, 
			round_num = self.round_num
		), shell=True)
		for curr_dns_sw_name in dns_sw_name_list:
			subprocess.call('sudo mkdir {res_folder}/{unit_num}/{round_num}/{dns_sw_name}'.format(
				res_folder = result_folder_path, 
				unit_num = self.unit_num, 
				round_num = self.round_num, 
				dns_sw_name = curr_dns_sw_name
			), shell=True)
		subprocess.call('sudo mkdir {res_folder}/{unit_num}/{round_num}/dnstap'.format(
			res_folder = result_folder_path, 
			unit_num = self.unit_num, 
			round_num = self.round_num
		), shell=True)
		return
	
	def save_query(self, curr_query):
		query_file_path = '{res_folder}/{unit_num}/{round_num}/query.txt'.format(
			res_folder = result_folder_path, 
			unit_num = self.unit_num, 
			round_num = self.round_num
		)
		with open(query_file_path, 'w') as query_file_obj:
			query_file_obj.write(curr_query)

		return

	def save_auth_payload(self, curr_response, json_data=None):
		if len(curr_response) != 2:
			return False
		auth_response = curr_response[0] + '\t' \
			+ curr_response[1] + '\n'

		response_file_path = '{res_folder}/{unit_num}/{round_num}/auth_payload.txt'.format(
			res_folder = result_folder_path, 
			unit_num = self.unit_num, 
			round_num = self.round_num
		)
		with open(response_file_path, 'w') as response_file_obj:
			response_file_obj.write(auth_response)
			if json_data:
				response_file_obj.write(json_data)

		return

	def bind9_pipeline(self, curr_query):
		## start tcpdump
		self.bind9_obj.tcpdump_start()
		
		## send payloads
		print('='*15, 'send query to bind9', '='*15)
		curr_bind9_response = self.attacker_obj.send_query(
			query_payload = curr_query, 
			curr_dns_ip = self.bind9_obj.ipv4_addr, 
			dns_sw_name = 'bind9'
		)
		print('curr bind9 response:', curr_bind9_response)
		
		## cache dump
		self.bind9_obj.cache_dump()

		## close tcpdump
		self.bind9_obj.tcpdump_stop()
		
		## save response
		self.bind9_obj.save_response(curr_bind9_response, self.round_num)

		## save cache
		self.bind9_obj.cache_save(self.round_num)

		## save, and then clear log
		self.bind9_obj.log_save(self.round_num)
		
		## save tcpdump
		self.bind9_obj.tcpdump_save(self.round_num)
		
		## cache flush
		self.bind9_obj.cache_flush()

		## crash detection
		bind9_is_crashed = self.bind9_obj.isCrashed()
		if bind9_is_crashed:
			self.bind9_obj.restart()
			self.bind9_obj.record_crash(self.round_num)
		else:
			pass

		return

	def unbound_pipeline(self, curr_query):
		## start tcpdump
		self.unbound_obj.tcpdump_start()

		## send query
		print('='*15, 'send query to unbound', '='*15)
		curr_unbound_response = self.attacker_obj.send_query(
			query_payload = curr_query, 
			curr_dns_ip = self.unbound_obj.ipv4_addr, 
			dns_sw_name = 'unbound'
		)
		print('curr unbound response:', curr_unbound_response)

		## cache dump
		self.unbound_obj.cache_dump()

		## close tcpdump
		self.unbound_obj.tcpdump_stop()

		## save response
		self.unbound_obj.save_response(curr_unbound_response, self.round_num)

		## save cache
		self.unbound_obj.cache_save(self.round_num)

		## save, and then clear log
		self.unbound_obj.log_save(self.round_num)

		## save tcpdump
		self.unbound_obj.tcpdump_save(self.round_num)

		## cache flush
		self.unbound_obj.cache_flush()

		## crash detection
		unbound_is_crashed = self.unbound_obj.isCrashed()
		if unbound_is_crashed:
			self.unbound_obj.restart()
			self.unbound_obj.record_crash(self.round_num)
		else:
			pass

		return

	def powerdns_pipeline(self, curr_query):
		## start tcpdump
		self.powerdns_obj.tcpdump_start()

		## send query
		print('='*15, 'send query to powerdns', '='*15)
		curr_powerdns_response = self.attacker_obj.send_query(
			query_payload = curr_query, 
			curr_dns_ip = self.powerdns_obj.ipv4_addr, 
			dns_sw_name = 'powerdns'
		)
		print('curr powerdns response:', curr_powerdns_response)

		## cache dump
		self.powerdns_obj.cache_dump()

		## close tcpdump
		self.powerdns_obj.tcpdump_stop()

		## save response
		self.powerdns_obj.save_response(curr_powerdns_response, self.round_num)

		## save cache
		self.powerdns_obj.cache_save(self.round_num)

		## save, and then clear log
		self.powerdns_obj.log_save(self.round_num)

		## save tcpdump
		self.powerdns_obj.tcpdump_save(self.round_num)

		## cache flush
		self.powerdns_obj.cache_flush()

		## crash detection
		powerdns_is_crashed = self.powerdns_obj.isCrashed()
		if powerdns_is_crashed:
			self.powerdns_obj.restart()
			self.powerdns_obj.record_crash(self.round_num)
		else:
			pass

		return

	def knot_pipeline(self, curr_query):
		## start tcpdump
		self.knot_obj.tcpdump_start()

		## send query
		print('='*15, 'send query to knot', '='*15)
		curr_knot_response = self.attacker_obj.send_query(
			query_payload = curr_query, 
			curr_dns_ip = self.knot_obj.ipv4_addr, 
			dns_sw_name = 'knot'
		)
		print('curr knot response:', curr_knot_response)

		## cache dump

		## close tcpdump
		self.knot_obj.tcpdump_stop()

		## save response
		self.knot_obj.save_response(curr_knot_response, self.round_num)

		## save cache

		## save log
		self.knot_obj.log_save(self.round_num)

		## save tcpdump
		self.knot_obj.tcpdump_save(self.round_num)

		## cache flush

		## Knot sw restart
		self.knot_obj.restart()

		return

	def maradns_pipeline(self, curr_query):
		## start tcpdump
		self.maradns_obj.tcpdump_start()

		## send query
		print('='*15, 'send query to maradns', '='*15)
		curr_maradns_response = self.attacker_obj.send_query(
			query_payload = curr_query, 
			curr_dns_ip = self.maradns_obj.ipv4_addr, 
			dns_sw_name = 'maradns'
		)
		print('curr maradns response:', curr_maradns_response)

		## cache dump

		## close tcpdump
		self.maradns_obj.tcpdump_stop()

		## save response
		self.maradns_obj.save_response(curr_maradns_response, self.round_num)
		
		## save cache

		## save log
		self.maradns_obj.log_save(self.round_num)

		## save tcpdump
		self.maradns_obj.tcpdump_save(self.round_num)

		## cache flush

		## maradns sw restart
		self.maradns_obj.restart()

		return

	def technitium_pipeline(self, curr_query):
		## start tcpdump
		self.technitium_obj.tcpdump_start()

		## send query
		print('='*15, 'send query to technitium', '='*15)
		curr_technitium_response = self.attacker_obj.send_query(
			query_payload = curr_query, 
			curr_dns_ip = self.technitium_obj.ipv4_addr, 
			dns_sw_name = 'technitium'
		)
		print('curr technitium response:', curr_technitium_response)

		## cache dump and save
		self.technitium_obj.cache_dump_save(self.round_num)

		## close tcpdump
		self.technitium_obj.tcpdump_stop()

		## save response
		self.technitium_obj.save_response(curr_technitium_response, self.round_num)

		## save log
		self.technitium_obj.log_save(self.round_num)

		## save tcpdump
		self.technitium_obj.tcpdump_save(self.round_num)

		## cache and log flush
		self.technitium_obj.cache_log_flush()

		## crash detection
		technitium_is_crashed = self.technitium_obj.isCrashed()
		if technitium_is_crashed:
			self.technitium_obj.restart()
			self.technitium_obj.record_crash(self.round_num)
		else:
			pass

		return

	def test_next_payload(self):
		# 0. generate next payload
		curr_query, curr_response = self.dns_fuzzer_obj.get_next_packet()
		
		curr_query_hex = curr_query
		print('curr query payload:', curr_query_hex)
		print('curr response payload:', curr_response)

		# 1. start auth srv
		try:
			self.auth_srv_obj.restart()
			self.auth_srv_obj.start(curr_response)
		except:
			print('response payload corrupted')
			# may need extra handling on response corruption
			return

		# 2. create result folder
		self.create_res_folder()

		# 3. save query and responses
		self.save_query(curr_query_hex)
		self.save_auth_payload(curr_response, self.dns_fuzzer_obj.get_dump_json())

		# 4. assign each DNS software with one process
		# multi-processing
		self.bind9_process = self.unbound_process = self.powerdns_process = self.knot_process = self.maradns_process = self.techitium_process = None
		
		if is_bind9_eval:
			if is_debug:
				self.bind9_pipeline(curr_query_hex)
			else:
				self.bind9_process = mp.Process(
				target = self.bind9_pipeline, 
				args = (curr_query_hex, )
			)
			self.bind9_process.start()

		if is_unbound_eval:
			if is_debug:
				self.unbound_pipeline(curr_query_hex)
			else:
				self.unbound_process = mp.Process(
					target = self.unbound_pipeline, 
					args = (curr_query_hex, )
				)
				self.unbound_process.start()

		if is_powerdns_eval:
			if is_debug:
				self.powerdns_pipeline(curr_query_hex)
			else:
				self.powerdns_process = mp.Process(
					target = self.powerdns_pipeline, 
					args = (curr_query_hex, )
				)
				self.powerdns_process.start()

		if is_knot_eval:
			if is_debug:
				self.knot_pipeline(curr_query_hex)
			else:
				self.knot_process = mp.Process(
					target = self.knot_pipeline, 
					args = (curr_query_hex, )
				)
				self.knot_process.start()

		if is_maradns_eval:
			if is_debug:
				self.maradns_pipeline(curr_query_hex)
			else:
				self.maradns_process = mp.Process(
					target = self.maradns_pipeline, 
					args = (curr_query_hex, )
				)
				self.maradns_process.start()	

		if is_technitium_eval:
			if is_debug:
				self.technitium_pipeline(curr_query_hex)
			else:
				self.techitium_process = mp.Process(
					target = self.technitium_pipeline, 
					args = (curr_query_hex, )
				)
				self.techitium_process.start()

		# merge all the processes
		if not is_debug:
			if is_bind9_eval:
				self.bind9_process.join()
			if is_unbound_eval:
				self.unbound_process.join()
			if is_powerdns_eval:
				self.powerdns_process.join()
			if is_knot_eval:
				self.knot_process.join()
			if is_maradns_eval:
				self.maradns_process.join()
			if is_technitium_eval:
				self.techitium_process.join()

		self.record_stats()
		if self.round_num % self.dnstap_interval == 0:
			self.dnstap_obj.log_save(self.unit_num, self.round_num)
		
		print('Unit #{} rounds completed:'.format(self.unit_num), self.round_num)
		self.round_num += 1
		
		return

	def isFinished(self):
		global total_payload_num
		if self.round_num < total_payload_num:
			return False
		else:
			return True
		return

	def record_stats(self):
		curr_res_folder = '{res_folder}/{round_num}'.format(
			res_folder = self.res_folder, 
			round_num = self.round_num
		)

		global global_start_time
		curr_time = time.time()
		
		time_consumed = curr_time - global_start_time
		avg_latency = time_consumed / (self.round_num+1)
		avg_thruput = (self.round_num+1) / time_consumed
		
		res = 'Total time consumed: {total_time}\nTotal payloads tested: {payload_num}\nAvg. latency: {latency}\nAvg. throughput: {thruput}'.format(
			total_time = time_consumed, 
			payload_num = self.round_num+1, 
			latency = avg_latency, 
			thruput = avg_thruput
		)
		
		with open('{res_folder}/stats_record.txt'.format(
			res_folder = curr_res_folder
		), 'w') as stats_record_obj:
			stats_record_obj.write(res)

		return

	def attacker_stop_remove(self):
		self.attacker_obj.stop()
		self.attacker_obj.remove()
		return

	def auth_srv_stop_remove(self):
		self.auth_srv_obj.stop()
		self.auth_srv_obj.remove()
		return

	def bind9_stop_remove(self):
		self.bind9_obj.stop()
		self.bind9_obj.remove()
		return

	def unbound_stop_remove(self):
		self.unbound_obj.stop()
		self.unbound_obj.remove()
		return
	
	def powerdns_stop_remove(self):
		self.powerdns_obj.stop()
		self.powerdns_obj.remove()
		return

	def knot_stop_remove(self):
		self.knot_obj.stop()
		self.knot_obj.remove()
		return

	def maradns_stop_remove(self):
		self.maradns_obj.stop()
		self.maradns_obj.remove()
		return

	def technitium_stop_remove(self):
		self.technitium_obj.stop()
		self.technitium_obj.remove()
		return
	
	def stop_remove(self):
		attacker_process = mp.Process(
			target = self.attacker_stop_remove
		)
		attacker_process.start()

		auth_srv_process = mp.Process(
			target = self.auth_srv_stop_remove
		)
		auth_srv_process.start()

		bind9_process = mp.Process(
			target = self.bind9_stop_remove
		)
		bind9_process.start()

		unbound_process = mp.Process(
			target = self.unbound_stop_remove
		)
		unbound_process.start()

		powerdns_process = mp.Process(
			target = self.powerdns_stop_remove
		)
		powerdns_process.start()

		knot_process = mp.Process(
			target = self.knot_stop_remove
		)
		knot_process.start()

		maradns_process = mp.Process(
			target = self.maradns_stop_remove
		)
		maradns_process.start()

		technitium_process = mp.Process(
			target = self.technitium_stop_remove
		)
		technitium_process.start()

		attacker_process.join()
		auth_srv_process.join()
		
		bind9_process.join()
		unbound_process.join()
		powerdns_process.join()
		knot_process.join()
		maradns_process.join()
		technitium_process.join()

		return

	def test_payloads(self):
		while not self.isFinished():
			self.test_next_payload()

		return	


class Bind9Container:
	def __init__(self,
		unit_num, 
		image_name = bind9_image, 
		network_name = docker_network_name
		):
		global conf_folder_path, dump_folder_path, result_folder_path, bind9_ip_addr_prefix

		self.unit_num = unit_num
		self.image_name = image_name
		## container name: [dns sw name]-[unit No.]-[suffix]
		self.container_name = 'bind9-{unit_num}-{suffix}'.format(
			unit_num = self.unit_num, 
			suffix = test_name_suffix
		)
		# dump_folder_path/[dns_sw_name]/[unit No.]
		self.dump_folder = '{dump_folder_path}/bind9/{unit_num}'.format(
			dump_folder_path = dump_folder_path, 
			unit_num = self.unit_num
		)
		self.network_name = network_name
		self.ipv4_addr = '{prefix}.{unit_num}'.format(
			prefix = bind9_ip_addr_prefix, 
			unit_num = self.unit_num
		)
		# [result_folder_path]/[unit no.]/[round no.]/[dns_sw_name]
		self.res_folder = '{result_folder_path}/{unit_num}'.format(
			result_folder_path = result_folder_path, 
			unit_num = self.unit_num
		)
		return

	def clean(self):
		subprocess.call('sudo docker stop {bind9}'.format(
			bind9 = self.container_name
		), shell=True)
		subprocess.call('sudo docker container rm {bind9}'.format(
			bind9 = self.container_name
		), shell=True)
		print('Unit #{} old bind9 cleaned'.format(self.unit_num))
		return

	def create(self):
		global conf_folder_path

		print('conf folder path:', '{conf_folder_path}/bind9'.format(conf_folder_path = conf_folder_path))
		print('dump folder path:', self.dump_folder)

		self.container = client.containers.run(self.image_name,
			name = self.container_name, 
			volumes = [
				'{conf_folder_path}/bind9:/etc/bind'.format(
					conf_folder_path = conf_folder_path
				), 
				'{dump_folder_path}:/var/cache/bind'.format(
					dump_folder_path = self.dump_folder
				)
			],
			detach=True,
			tty=True
		)
		# connect to networks
		client.networks.get(self.network_name).connect(self.container, ipv4_address=self.ipv4_addr)
		print('Unit #{} bind9 created'.format(self.unit_num))
		return
	
	def start(self):
		global dnstap_ip_addr

		exit_code, output = self.container.exec_run(
			'socat unix-listen:/var/run/dnstap.sock tcp-connect:{dnstap_ip}:5353'.format(dnstap_ip=dnstap_ip_addr), 
			detach = True,
			tty = True
		)
		exit_code, output = self.container.exec_run(['/bind-9.18.0/bin/named/named', '-f', '-d', '5', '-n', '1'], detach=True)
		print('Unit #{} bind9 started'.format(self.unit_num))
		return

	def restart(self):
		# This method `restart` is used to restart bind9 when it's crashed ONLY.
		# If it exits normally, please use cache flush instead of restarting the whole program!
		exit_code, output = self.container.exec_run(['pkill', '-9', 'named'])
		exit_code, output = self.container.exec_run(['/bind-9.18.0/bin/named/named', '-f', '-d', '5', '-n', '1'], detach=True)
		print('Unit #{} bind9 restarted'.format(self.unit_num))
		return

	def stop(self):
		self.container.stop()
		print('Unit #{} bind9 stopped'.format(self.unit_num))
		return

	def remove(self):
		self.container.remove()
		print('Unit #{} bind9 removed'.format(self.unit_num))
		return

	def isCrashed(self):
		exit_code, output = self.container.exec_run(['sh', '-c', 'ps -ef | grep -w named | grep -v grep | wc -l'])

		output_lines = output.split(b"\n")
		
		if int(output_lines[-2]) == 1:
			print('='*15, 'Unit #{} bind9 running normally'.format(self.unit_num), '='*15)
			return False
		elif int(output_lines[-2]) == 0:
			print('@'*15, 'Unit #{} bind9 crashed!'.format(self.unit_num), '@'*15)
			return True
	
	def record_crash(self, curr_round_num):
		curr_res_folder = '{res_folder}/{round_num}/bind9'.format(
			res_folder = self.res_folder, 
			round_num = curr_round_num
		)

		with open('{}/bind9_crash_report.txt'.format(curr_res_folder), 'w') as crash_report_obj:
			crash_report_obj.write('bind9 is crashed when testing this payload.')
		
		print('@'*15, 'Unit #{} bind9 recorded!'.format(self.unit_num), '@'*15)
		return

	def tcpdump_start(self):
		exit_code, output = self.container.exec_run(['tcpdump', '-U', '-i', 'any', '-w', '/var/cache/bind/tcpdump.pcap', '-vvv'], detach=True, tty=True)
		
		print('='*15, 'Unit #{} bind9 tcpdump started'.format(self.unit_num), '='*15)
		return

	def tcpdump_stop(self):
		'''
		******* Notice! *******
		kill -9 (i.e. SIGKILL) will result in pcap not dumped!
		tcpdump would exit normally ONLY when ctrl+c cmd is given, i.e. SIGINT
		that's -2 for kill/pkill cmd
		reference: https://www.ibm.com/docs/en/zos/2.2.0?topic=descriptions-kill-end-process-job-send-it-signal

		Also, we need to wait for a while in order to let tcpdump dump all the traffic into /var/cache/bind/tcpdump.pcap
		'''
		time.sleep(tcpdump_wait_time)
		exit_code, output = self.container.exec_run(['pkill', '-2', 'tcpdump'])
		time.sleep(tcpdump_wait_time)
		'''
		the waiting time depends on the size of the resolver's response
		may need larger waiting time if the response is very large (e.g., ANY/ALL record), or we found too many corruptted pcap files
		'''
		
		print('='*15, 'Unit #{} bind9 tcpdump stopped'.format(self.unit_num), '='*15)
		return

	def tcpdump_save(self, curr_round_num):
		subprocess.call('sudo cp {dump_folder}/tcpdump.pcap {res_folder}/{round_num}/bind9/'.format(
			dump_folder = self.dump_folder, 
			res_folder = self.res_folder, 
			round_num = curr_round_num
		), shell=True)

		print('='*15, 'Unit #{} bind9 tcpdump saved'.format(self.unit_num), '='*15)
		return

	def cache_dump(self):
		exit_code, output = self.container.exec_run('/usr/local/sbin/rndc dumpdb')
		
		print('='*15, 'Unit #{} bind9 cache dumped'.format(self.unit_num), '='*15)
		return

	def save_response(self, curr_response, curr_round_num):
		# folder path [result_folder_path]/[unit no.]/[round no.]/[dns_sw_name]
		curr_res_folder = '{res_folder}/{round_num}/bind9'.format(
			res_folder = self.res_folder, 
			round_num = curr_round_num
		)
		
		with open('{}/response.txt'.format(curr_res_folder), 'wb') as response_file_object:
			response_file_object.write(curr_response)
		
		print('='*15, 'Unit #{} bind9 response saved'.format(self.unit_num), '='*15)
		return

	def cache_save(self, curr_round_num):
		subprocess.call('cp {dump_folder}/named_dump.db {res_folder}/{round_num}/bind9/'.format(
			dump_folder = self.dump_folder, 
			res_folder = self.res_folder, 
			round_num = curr_round_num
		), shell=True)

		print('='*15, 'Unit #{} bind9 cache saved'.format(self.unit_num), '='*15)
		return

	def log_save(self, curr_round_num):
		subprocess.call('cp {dump_folder}/bind.log {res_folder}/{round_num}/bind9/'.format(
			dump_folder = self.dump_folder, 
			res_folder = self.res_folder, 
			round_num = curr_round_num
		), shell=True)
		
		print('='*15, 'Unit #{} bind9 log saved and cleaned'.format(self.unit_num), '='*15)
		return

	def cache_flush(self):
		exit_code, output = self.container.exec_run(['sh', '-c', '/usr/local/sbin/rndc flush && /usr/local/sbin/rndc reload'])

		print('='*15, 'Unit #{} bind9 cache flushed'.format(self.unit_num), '='*15)
		return


class UnboundContainer:
	def __init__(self,
		unit_num, 
		image_name = unbound_image, 
		network_name = docker_network_name
		):
		global conf_folder_path, dump_folder_path, result_folder_path, unbound_ip_addr_prefix

		self.unit_num = unit_num
		self.image_name = image_name
		## container name: [dns sw name]-[unit No.]-[suffix]
		self.container_name = 'unbound-{unit_num}-{suffix}'.format(
			unit_num = self.unit_num, 
			suffix = test_name_suffix
		)
		# dump_folder_path/[dns_sw_name]/[unit No.]
		self.dump_folder = '{dump_folder_path}/unbound/{unit_num}'.format(
			dump_folder_path = dump_folder_path, 
			unit_num = self.unit_num
		)
		self.network_name = network_name
		self.ipv4_addr = '{prefix}.{unit_num}'.format(
			prefix = unbound_ip_addr_prefix, 
			unit_num = self.unit_num
		)
		# [result_folder_path]/[unit no.]/[round no.]/[dns_sw_name]
		self.res_folder = '{result_folder_path}/{unit_num}'.format(
			result_folder_path = result_folder_path, 
			unit_num = self.unit_num
		)
		return

	def clean(self):
		subprocess.call('sudo docker stop {unbound}'.format(
			unbound = self.container_name
		), shell=True)
		subprocess.call('sudo docker container rm {unbound}'.format(
			unbound = self.container_name
		), shell=True)
		print('Unit #{} old unbound cleaned'.format(self.unit_num))
		return

	def create(self):
		global conf_folder_path

		print('conf folder path:', '{conf_folder_path}/unbound'.format(conf_folder_path = conf_folder_path))
		print('dump folder path:', self.dump_folder)

		self.container = client.containers.run(self.image_name,
			name = self.container_name, 
			volumes = [
				'{conf_folder_path}/unbound:/etc/unbound'.format(
					conf_folder_path = conf_folder_path
				), 
				'{dump_folder_path}:/var/cache/unbound'.format(
					dump_folder_path = self.dump_folder
				)
			],
			detach=True,
			tty=True
		)
		# connect to networks
		client.networks.get(self.network_name).connect(self.container, ipv4_address=self.ipv4_addr)
		print('Unit #{} unbound created'.format(self.unit_num))
		return

	def start(self):
		global dnstap_ip_addr

		exit_code, output = self.container.exec_run('/unbound-1.16.0/unbound -d', detach=True)
		print('Unit #{} unbound started'.format(self.unit_num))
		return

	def restart(self):
		# This method `restart` is used to restart  when it's crashed ONLY.
		# If it exits normally, please use cache flush instead of restarting the whole program!
		exit_code, output = self.container.exec_run(['pkill', '-9', 'unbound'])
		exit_code, output = self.container.exec_run('/unbound-1.16.0/unbound -d', detach=True)
		print('Unit #{} unbound restarted'.format(self.unit_num))
		return

	def stop(self):
		self.container.stop()
		print('Unit #{} unbound stopped'.format(self.unit_num))
		return

	def remove(self):
		self.container.remove()
		print('Unit #{} unbound removed'.format(self.unit_num))
		return

	def isCrashed(self):
		exit_code, output = self.container.exec_run(['sh', '-c', 'ps -ef | grep -w unbound | grep -v grep | wc -l'])

		output_lines = output.split(b"\n")
		
		if int(output_lines[-2]) == 1:
			print('='*15, 'Unit #{} unbound running normally'.format(self.unit_num), '='*15)
			return False
		elif int(output_lines[-2]) == 0:
			print('@'*15, 'Unit #{} unbound crashed!'.format(self.unit_num), '@'*15)
			return True

	def record_crash(self, curr_round_num):
		curr_res_folder = '{res_folder}/{round_num}/unbound'.format(
			res_folder = self.res_folder, 
			round_num = curr_round_num
		)

		with open('{}/unbound_crash_report.txt'.format(curr_res_folder), 'w') as crash_report_obj:
			crash_report_obj.write('unbound is crashed when testing this payload.')
		
		print('@'*15, 'Unit #{} unbound recorded!'.format(self.unit_num), '@'*15)
		return

	def tcpdump_start(self):
		exit_code, output = self.container.exec_run(['tcpdump', '-U', '-i', 'any', '-w', '/var/cache/unbound/tcpdump.pcap', '-vvv'], detach=True, tty=True)
		
		print('='*15, 'Unit #{} unbound tcpdump started'.format(self.unit_num), '='*15)
		return

	def tcpdump_stop(self):
		time.sleep(tcpdump_wait_time)
		exit_code, output = self.container.exec_run(['pkill', '-2', 'tcpdump'])
		time.sleep(tcpdump_wait_time)
		
		print('='*15, 'Unit #{} unbound tcpdump stopped'.format(self.unit_num), '='*15)
		return

	def tcpdump_save(self, curr_round_num):
		subprocess.call('sudo cp {dump_folder}/tcpdump.pcap {res_folder}/{round_num}/unbound/'.format(
			dump_folder = self.dump_folder, 
			res_folder = self.res_folder, 
			round_num = curr_round_num
		), shell=True)

		print('='*15, 'Unit #{} unbound tcpdump saved'.format(self.unit_num), '='*15)
		return

	def cache_dump(self):
		exit_code, output = self.container.exec_run(['sh', '-c', 'unbound-control dump_cache > /var/cache/unbound/unbound.cache.db'])
		
		print('='*15, 'Unit #{} unbound cache dumped'.format(self.unit_num), '='*15)
		return

	def save_response(self, curr_response, curr_round_num):
		# folder path [result_folder_path]/[unit no.]/[round no.]/[dns_sw_name]
		curr_res_folder = '{res_folder}/{round_num}/unbound'.format(
			res_folder = self.res_folder, 
			round_num = curr_round_num
		)
		
		with open('{}/response.txt'.format(curr_res_folder), 'wb') as response_file_object:
			response_file_object.write(curr_response)
		
		print('='*15, 'Unit #{} unbound response saved'.format(self.unit_num), '='*15)
		return

	def cache_save(self, curr_round_num):
		subprocess.call('cp {dump_folder}/unbound.cache.db {res_folder}/{round_num}/unbound/'.format(
			dump_folder = self.dump_folder, 
			res_folder = self.res_folder, 
			round_num = curr_round_num
		), shell=True)

		print('='*15, 'Unit #{} unbound cache saved'.format(self.unit_num), '='*15)
		return

	def log_save(self, curr_round_num):
		subprocess.call('cp {dump_folder}/unbound.log {res_folder}/{round_num}/unbound/'.format(
			dump_folder = self.dump_folder, 
			res_folder = self.res_folder, 
			round_num = curr_round_num
		), shell=True)
		subprocess.call('rm -rf {dump_folder}/unbound.log'.format(dump_folder = self.dump_folder), shell=True)
		
		print('='*15, 'Unit #{} unbound log saved and cleaned'.format(self.unit_num), '='*15)
		return

	def cache_flush(self):
		exit_code, output = self.container.exec_run('/unbound-1.16.0/unbound-control reload')

		print('='*15, 'Unit #{} unbound cache flushed'.format(self.unit_num), '='*15)
		return


class PowerDNSContainer:
	def __init__(self,
		unit_num, 
		image_name = powerdns_image, 
		network_name = docker_network_name
		):
		global conf_folder_path, dump_folder_path, result_folder_path, powerdns_ip_addr_prefix

		self.unit_num = unit_num
		self.image_name = image_name
		## container name: [dns sw name]-[unit No.]-[suffix]
		self.container_name = 'powerdns-{unit_num}-{suffix}'.format(
			unit_num = self.unit_num, 
			suffix = test_name_suffix
		)
		# dump_folder_path/[dns_sw_name]/[unit No.]
		self.dump_folder = '{dump_folder_path}/powerdns/{unit_num}'.format(
			dump_folder_path = dump_folder_path, 
			unit_num = self.unit_num
		)
		self.network_name = network_name
		self.ipv4_addr = '{prefix}.{unit_num}'.format(
			prefix = powerdns_ip_addr_prefix, 
			unit_num = self.unit_num
		)
		# [result_folder_path]/[unit no.]/[round no.]/[dns_sw_name]
		self.res_folder = '{result_folder_path}/{unit_num}'.format(
			result_folder_path = result_folder_path, 
			unit_num = self.unit_num
		)
		return

	def clean(self):
		subprocess.call('sudo docker stop {powerdns}'.format(
			powerdns = self.container_name
		), shell=True)
		subprocess.call('sudo docker container rm {powerdns}'.format(
			powerdns = self.container_name
		), shell=True)
		print('Unit #{} old powerdns cleaned'.format(self.unit_num))
		return
	
	def create(self):
		global conf_folder_path

		print('conf folder path:', '{conf_folder_path}/powerdns'.format(conf_folder_path = conf_folder_path))
		print('dump folder path:', self.dump_folder)

		self.container = client.containers.run(self.image_name,
			name = self.container_name, 
			volumes = [
				'{conf_folder_path}/powerdns:/etc/powerdns'.format(
					conf_folder_path = conf_folder_path
				), 
				'{dump_folder_path}:/var/cache/powerdns'.format(
					dump_folder_path = self.dump_folder
				)
			],
			detach=True,
			tty=True
		)
		# connect to networks
		client.networks.get(self.network_name).connect(self.container, ipv4_address=self.ipv4_addr)
		
		print('Unit #{} powerdns created'.format(self.unit_num))
		return

	def start(self):
		global dnstap_ip_addr

		exit_code, output = self.container.exec_run('/start.sh', detach=True)
		print('Unit #{} powerdns started'.format(self.unit_num))
		return

	def restart(self):
		# This method `restart` is used to restart  when it's crashed ONLY.
		# If it exits normally, please use cache flush instead of restarting the whole program!
		exit_code, output = self.container.exec_run(['pkill', '-9', 'start.sh'])
		exit_code, output = self.container.exec_run(['pkill', '-9', 'pdns'])
		exit_code, output = self.container.exec_run('/start.sh', detach=True)
		print('Unit #{} powerdns restarted'.format(self.unit_num))
		return

	def stop(self):
		self.container.stop()
		print('Unit #{} powerdns stopped'.format(self.unit_num))
		return

	def remove(self):
		self.container.remove()
		print('Unit #{} powerdns removed'.format(self.unit_num))
		return

	def isCrashed(self):
		exit_code, output = self.container.exec_run(['sh', '-c', 'ps -ef | grep -w pdns_recursor | grep -v grep | wc -l'])

		output_lines = output.split(b"\n")
		
		if int(output_lines[-2]) == 1:
			print('='*15, 'Unit #{} powerdns running normally'.format(self.unit_num), '='*15)
			return False
		elif int(output_lines[-2]) == 0:
			print('@'*15, 'Unit #{} powerdns crashed!'.format(self.unit_num), '@'*15)
			return True

	def record_crash(self, curr_round_num):
		curr_res_folder = '{res_folder}/{round_num}/powerdns'.format(
			res_folder = self.res_folder, 
			round_num = curr_round_num
		)

		with open('{}/powerdns_crash_report.txt'.format(curr_res_folder), 'w') as crash_report_obj:
			crash_report_obj.write('powerdns is crashed when testing this payload.')
		
		print('@'*15, 'Unit #{} powerdns recorded!'.format(self.unit_num), '@'*15)
		return

	def tcpdump_start(self):
		exit_code, output = self.container.exec_run(['tcpdump', '-U', '-i', 'any', '-w', '/var/cache/powerdns/tcpdump.pcap', '-vvv'], detach=True, tty=True)
		
		print('='*15, 'Unit #{} powerdns tcpdump started'.format(self.unit_num), '='*15)
		return

	def tcpdump_stop(self):
		time.sleep(tcpdump_wait_time)
		exit_code, output = self.container.exec_run(['pkill', '-2', 'tcpdump'])
		time.sleep(tcpdump_wait_time)
		
		print('='*15, 'Unit #{} powerdns tcpdump stopped'.format(self.unit_num), '='*15)
		return

	def tcpdump_save(self, curr_round_num):
		subprocess.call('sudo cp {dump_folder}/tcpdump.pcap {res_folder}/{round_num}/powerdns/'.format(
			dump_folder = self.dump_folder, 
			res_folder = self.res_folder, 
			round_num = curr_round_num
		), shell=True)

		print('='*15, 'Unit #{} powerdns tcpdump saved'.format(self.unit_num), '='*15)
		return

	def cache_dump(self):
		exit_code, output = self.container.exec_run('rm -f /var/cache/powerdns/powerdns.cache.db')
		exit_code, output = self.container.exec_run('rec_control dump-cache /var/cache/powerdns/powerdns.cache.db')
		
		print('='*15, 'Unit #{} powerdns cache dumped'.format(self.unit_num), '='*15)
		return

	def save_response(self, curr_response, curr_round_num):
		# folder path [result_folder_path]/[unit no.]/[round no.]/[dns_sw_name]
		curr_res_folder = '{res_folder}/{round_num}/powerdns'.format(
			res_folder = self.res_folder, 
			round_num = curr_round_num
		)
		
		with open('{}/response.txt'.format(curr_res_folder), 'wb') as response_file_object:
			response_file_object.write(curr_response)
		
		print('='*15, 'Unit #{} powerdns response saved'.format(self.unit_num), '='*15)
		return

	def cache_save(self, curr_round_num):
		subprocess.call('cp {dump_folder}/powerdns.cache.db {res_folder}/{round_num}/powerdns/'.format(
			dump_folder = self.dump_folder, 
			res_folder = self.res_folder, 
			round_num = curr_round_num
		), shell=True)

		print('='*15, 'Unit #{} powerdns cache saved'.format(self.unit_num), '='*15)
		return

	def log_save(self, curr_round_num):
		subprocess.call('cp {dump_folder}/powerdns.log {res_folder}/{round_num}/powerdns/'.format(
			dump_folder = self.dump_folder, 
			res_folder = self.res_folder, 
			round_num = curr_round_num
		), shell=True)
		subprocess.call('rm -rf {dump_folder}/powerdns.log'.format(dump_folder = self.dump_folder), shell=True)

		exit_code, output = self.container.exec_run('pkill pdns')
		self.start()
		
		print('='*15, 'Unit #{} powerdns log saved and cleaned'.format(self.unit_num), '='*15)
		return

	def cache_flush(self):
		exit_code, output = self.container.exec_run('rec_control wipe-cache *')

		print('='*15, 'Unit #{} powerdns cache flushed'.format(self.unit_num), '='*15)
		return


class KnotContainer:
	def __init__(self,
		unit_num, 
		image_name = knot_image, 
		network_name = docker_network_name
		):
		global conf_folder_path, dump_folder_path, result_folder_path, knot_ip_addr_prefix

		self.unit_num = unit_num
		self.image_name = image_name
		## container name: [dns sw name]-[unit No.]-[suffix]
		self.container_name = 'knot-{unit_num}-{suffix}'.format(
			unit_num = self.unit_num, 
			suffix = test_name_suffix
		)
		# dump_folder_path/[dns_sw_name]/[unit No.]
		self.dump_folder = '{dump_folder_path}/knot/{unit_num}'.format(
			dump_folder_path = dump_folder_path, 
			unit_num = self.unit_num
		)
		self.network_name = network_name
		self.ipv4_addr = '{prefix}.{unit_num}'.format(
			prefix = knot_ip_addr_prefix, 
			unit_num = self.unit_num
		)
		# [result_folder_path]/[unit no.]/[round no.]/[dns_sw_name]
		self.res_folder = '{result_folder_path}/{unit_num}'.format(
			result_folder_path = result_folder_path, 
			unit_num = self.unit_num
		)
		return

	def clean(self):
		subprocess.call('sudo docker stop {knot}'.format(
			knot = self.container_name
		), shell=True)
		subprocess.call('sudo docker container rm {knot}'.format(
			knot = self.container_name
		), shell=True)
		print('Unit #{} old knot cleaned'.format(self.unit_num))
		return

	def create(self):
		global conf_folder_path

		print('conf folder path:', '{conf_folder_path}/knot'.format(conf_folder_path = conf_folder_path))
		print('dump folder path:', self.dump_folder)

		self.container = client.containers.run(self.image_name,
			name = self.container_name, 
			volumes = [
				'{conf_folder_path}/knot:/etc/knot-resolver'.format(
					conf_folder_path = conf_folder_path
				), 
				'{dump_folder_path}:/var/cache/knot'.format(
					dump_folder_path = self.dump_folder
				)
			],
			detach=True,
			tty=True
		)
		# connect to networks
		client.networks.get(self.network_name).connect(self.container, ipv4_address=self.ipv4_addr)
		
		print('Unit #{} knot created'.format(self.unit_num))
		return

	def start(self):
		global dnstap_ip_addr

		exit_code, output = self.container.exec_run(['sh', '-c', 'socat unix-listen:/var/run/dnstap.sock tcp-connect:{dnstap_ip}:5353'.format(dnstap_ip=dnstap_ip_addr)], detach=True, tty=True)
		exit_code, output = self.container.exec_run(['sh', '-c', '/knot-resolver-5.5.0/build_dir/daemon/kresd -v -c /etc/knot-resolver/kresd.conf  > /var/cache/knot/knot.log'], detach=True, tty=True)

		print('Unit #{} knot started'.format(self.unit_num))
		return

	def restart(self):
		# This method `restart` is used to restart  when it's crashed ONLY.
		# If it exits normally, please use cache flush instead of restarting the whole program!
		exit_code, output = self.container.exec_run(['pkill', '-9', 'kresd'])

		exit_code, output = self.container.exec_run(['sh', '-c', '/knot-resolver-5.5.0/build_dir/daemon/kresd -v -c /etc/knot-resolver/kresd.conf  > /var/cache/knot/knot.log'], detach=True, tty=True)
		print('Unit #{} knot restarted'.format(self.unit_num))
		return

	def stop(self):
		self.container.stop()
		print('Unit #{} knot stopped'.format(self.unit_num))
		return

	def remove(self):
		self.container.remove()
		print('Unit #{} knot removed'.format(self.unit_num))
		return

	def isCrashed(self):
		exit_code, output = self.container.exec_run(['sh', '-c', 'ps -ef | grep -w kresd | grep -v grep | wc -l'])

		output_lines = output.split(b"\n")
		
		if int(output_lines[-2]) == 1:
			print('='*15, 'Unit #{} knot running normally'.format(self.unit_num), '='*15)
			return False
		elif int(output_lines[-2]) == 0:
			print('@'*15, 'Unit #{} knot crashed!'.format(self.unit_num), '@'*15)
			return True

	def record_crash(self, curr_round_num):
		curr_res_folder = '{res_folder}/{round_num}/knot'.format(
			res_folder = self.res_folder, 
			round_num = curr_round_num
		)

		with open('{}/knot_crash_report.txt'.format(curr_res_folder), 'w') as crash_report_obj:
			crash_report_obj.write('knot is crashed when testing this payload.')
		
		print('@'*15, 'Unit #{} knot recorded!'.format(self.unit_num), '@'*15)
		return

	def tcpdump_start(self):
		exit_code, output = self.container.exec_run(['tcpdump', '-U', '-i', 'any', '-w', '/var/cache/knot/tcpdump.pcap', '-vvv'], detach=True, tty=True)
		
		print('='*15, 'Unit #{} knot tcpdump started'.format(self.unit_num), '='*15)
		return

	def tcpdump_stop(self):
		time.sleep(tcpdump_wait_time)
		exit_code, output = self.container.exec_run(['pkill', '-2', 'tcpdump'])
		time.sleep(tcpdump_wait_time)
		
		print('='*15, 'Unit #{} knot tcpdump stopped'.format(self.unit_num), '='*15)
		return

	def tcpdump_save(self, curr_round_num):
		subprocess.call('sudo cp {dump_folder}/tcpdump.pcap {res_folder}/{round_num}/knot/'.format(
			dump_folder = self.dump_folder, 
			res_folder = self.res_folder, 
			round_num = curr_round_num
		), shell=True)

		print('='*15, 'Unit #{} knot tcpdump saved'.format(self.unit_num), '='*15)
		return

	def cache_dump(self):
		# cache dump not supported for Knot
		return
	
	def save_response(self, curr_response, curr_round_num):
		# folder path [result_folder_path]/[unit no.]/[round no.]/[dns_sw_name]
		curr_res_folder = '{res_folder}/{round_num}/knot'.format(
			res_folder = self.res_folder, 
			round_num = curr_round_num
		)
		
		with open('{}/response.txt'.format(curr_res_folder), 'wb') as response_file_object:
			response_file_object.write(curr_response)
		
		print('='*15, 'Unit #{} knot response saved'.format(self.unit_num), '='*15)
		return

	def cache_save(self, curr_round_num):
		# cache save not supported for Knot
		return

	def log_save(self, curr_round_num):
		subprocess.call('cp {dump_folder}/knot.log {res_folder}/{round_num}/knot/'.format(
			dump_folder = self.dump_folder, 
			res_folder = self.res_folder, 
			round_num = curr_round_num
		), shell=True)
		
		print('='*15, 'Unit #{} knot log saved'.format(self.unit_num), '='*15)
		return

	def cache_flush(self):
		# cache flush not supported for Knot
		return
	


class MaraDNSContainer:
	def __init__(self,
		unit_num, 
		image_name = maradns_image, 
		network_name = docker_network_name
		):
		global conf_folder_path, dump_folder_path, result_folder_path, maradns_ip_addr_prefix

		self.unit_num = unit_num
		self.image_name = image_name
		## container name: [dns sw name]-[unit No.]-[suffix]
		self.container_name = 'maradns-{unit_num}-{suffix}'.format(
			unit_num = self.unit_num, 
			suffix = test_name_suffix
		)
		# dump_folder_path/[dns_sw_name]/[unit No.]
		self.dump_folder = '{dump_folder_path}/maradns/{unit_num}'.format(
			dump_folder_path = dump_folder_path, 
			unit_num = self.unit_num
		)
		self.network_name = network_name
		self.ipv4_addr = '{prefix}.{unit_num}'.format(
			prefix = maradns_ip_addr_prefix, 
			unit_num = self.unit_num
		)
		# [result_folder_path]/[unit no.]/[round no.]/[dns_sw_name]
		self.res_folder = '{result_folder_path}/{unit_num}'.format(
			result_folder_path = result_folder_path, 
			unit_num = self.unit_num
		)
		return

	def clean(self):
		subprocess.call('sudo docker stop {maradns}'.format(
			maradns = self.container_name
		), shell=True)
		subprocess.call('sudo docker container rm {maradns}'.format(
			maradns = self.container_name
		), shell=True)
		print('Unit #{} old maradns cleaned'.format(self.unit_num))
		return
	
	def create(self):
		global conf_folder_path

		print('conf folder path:', '{conf_folder_path}/maradns'.format(conf_folder_path = conf_folder_path))
		print('dump folder path:', self.dump_folder)

		self.container = client.containers.run(self.image_name,
			name = self.container_name, 
			volumes = [
				'{conf_folder_path}/maradns:/etc/maradns_conf'.format(
					conf_folder_path = conf_folder_path
				), 
				'{dump_folder_path}:/var/cache/maradns'.format(
					dump_folder_path = self.dump_folder
				)
			],
			detach=True,
			tty=True
		)
		# connect to networks
		client.networks.get(self.network_name).connect(self.container, ipv4_address=self.ipv4_addr)
		
		print('Unit #{} maradns created'.format(self.unit_num))
		return

	def start(self):
		global dnstap_ip_addr

		exit_code, output = self.container.exec_run(['sh', '-c', '/usr/local/sbin/Deadwood -f /etc/maradns_conf/dwood3rc > /var/cache/maradns/maradns.log'], detach=True, tty=True)

		print('Unit #{} maradns started'.format(self.unit_num))
		return

	def restart(self):
		# This method `restart` is used to restart when it's crashed ONLY.
		# If it exits normally, please use cache flush instead of restarting the whole program!
		exit_code, output = self.container.exec_run(['pkill', '-9', 'Deadwood'])

		exit_code, output = self.container.exec_run(['sh', '-c', '/usr/local/sbin/Deadwood -f /etc/maradns_conf/dwood3rc > /var/cache/maradns/maradns.log'], detach=True, tty=True)
		print('Unit #{} maradns restarted'.format(self.unit_num))
		return
	
	def stop(self):
		self.container.stop()
		print('Unit #{} maradns stopped'.format(self.unit_num))
		return

	def remove(self):
		self.container.remove()
		print('Unit #{} maradns removed'.format(self.unit_num))
		return

	def isCrashed(self):
		exit_code, output = self.container.exec_run(['sh', '-c', 'ps -ef | grep -w Deadwood | grep -v grep | wc -l'])

		output_lines = output.split(b"\n")
		
		if int(output_lines[-2]) == 1:
			print('='*15, 'Unit #{} maradns running normally'.format(self.unit_num), '='*15)
			return False
		elif int(output_lines[-2]) == 0:
			print('@'*15, 'Unit #{} maradns crashed!'.format(self.unit_num), '@'*15)
			return True

	def record_crash(self, curr_round_num):
		curr_res_folder = '{res_folder}/{round_num}/maradns'.format(
			res_folder = self.res_folder, 
			round_num = curr_round_num
		)

		with open('{}/maradns_crash_report.txt'.format(curr_res_folder), 'w') as crash_report_obj:
			crash_report_obj.write('maradns is crashed when testing this payload.')
		
		print('@'*15, 'Unit #{} maradns recorded!'.format(self.unit_num), '@'*15)
		return

	def tcpdump_start(self):
		exit_code, output = self.container.exec_run(['tcpdump', '-U', '-i', 'any', '-w', '/var/cache/maradns/tcpdump.pcap', '-vvv'], detach=True, tty=True)
		
		print('='*15, 'Unit #{} maradns tcpdump started'.format(self.unit_num), '='*15)
		return

	def tcpdump_stop(self):
		time.sleep(tcpdump_wait_time)
		exit_code, output = self.container.exec_run(['pkill', '-2', 'tcpdump'])
		time.sleep(tcpdump_wait_time)
		
		print('='*15, 'Unit #{} maradns tcpdump stopped'.format(self.unit_num), '='*15)
		return

	def tcpdump_save(self, curr_round_num):
		subprocess.call('sudo cp {dump_folder}/tcpdump.pcap {res_folder}/{round_num}/maradns/'.format(
			dump_folder = self.dump_folder, 
			res_folder = self.res_folder, 
			round_num = curr_round_num
		), shell=True)

		print('='*15, 'Unit #{} maradns tcpdump saved'.format(self.unit_num), '='*15)
		return

	def cache_dump(self):
		# cache dump not supported for maradns
		return

	def save_response(self, curr_response, curr_round_num):
		# folder path [result_folder_path]/[unit no.]/[round no.]/[dns_sw_name]
		curr_res_folder = '{res_folder}/{round_num}/maradns'.format(
			res_folder = self.res_folder, 
			round_num = curr_round_num
		)
		
		with open('{}/response.txt'.format(curr_res_folder), 'wb') as response_file_object:
			response_file_object.write(curr_response)
		
		print('='*15, 'Unit #{} maradns response saved'.format(self.unit_num), '='*15)
		return

	def cache_save(self, curr_round_num):
		# cache save not supported for maradns
		return

	def log_save(self, curr_round_num):
		exit_code, output = self.container.exec_run('pkill Deadwood')
		subprocess.call('cp {dump_folder}/maradns.log {res_folder}/{round_num}/maradns/'.format(
			dump_folder = self.dump_folder, 
			res_folder = self.res_folder, 
			round_num = curr_round_num
		), shell=True)
		
		print('='*15, 'Unit #{} maradns log saved'.format(self.unit_num), '='*15)
		return

	def cache_flush(self):
		# cache flush not supported for maradns
		return



class TechnitiumContainer:
	def __init__(self,
		unit_num, 
		image_name = technitium_image, 
		network_name = docker_network_name
		):
		global dump_folder_path, result_folder_path, technitium_ip_addr_prefix, auth_srv_ip_addr_prefix

		self.unit_num = unit_num
		self.image_name = image_name
		## container name: [dns sw name]-[unit No.]-[suffix]
		self.container_name = 'technitium-{unit_num}-{suffix}'.format(
			unit_num = self.unit_num, 
			suffix = test_name_suffix
		)
		# dump_folder_path/[dns_sw_name]/[unit No.]
		self.dump_folder = '{dump_folder_path}/technitium/{unit_num}'.format(
			dump_folder_path = dump_folder_path, 
			unit_num = self.unit_num
		)
		self.network_name = network_name
		self.ipv4_addr = '{prefix}.{unit_num}'.format(
			prefix = technitium_ip_addr_prefix, 
			unit_num = self.unit_num
		)
		# [result_folder_path]/[unit no.]/[round no.]/[dns_sw_name]
		self.res_folder = '{result_folder_path}/{unit_num}'.format(
			result_folder_path = result_folder_path, 
			unit_num = self.unit_num
		)
		return

	def clean(self):
		subprocess.call('sudo docker stop {technitium}'.format(
			technitium = self.container_name
		), shell=True)
		subprocess.call('sudo docker container rm {technitium}'.format(
			technitium = self.container_name
		), shell=True)
		print('Unit #{} old technitium cleaned'.format(self.unit_num))
		return

	def create(self):
		print('dump folder path:', self.dump_folder)

		self.container = client.containers.run(self.image_name,
			name = self.container_name, 
			volumes = [
				'{dump_folder_path}:/var/cache/technitium'.format(
					dump_folder_path = self.dump_folder
				)
			],
			detach=True,
			tty=True
		)
		# connect to networks
		client.networks.get(self.network_name).connect(self.container, ipv4_address=self.ipv4_addr)
		print('Unit #{} technitium created'.format(self.unit_num))
		return

	def start(self):
		exit_code, output = self.container.exec_run(['sh', '-c', '/etc/technitium/start.sh'], detach=True, tty=True)
		
		time.sleep(1) # wait for technitium to be initialized
		self.set_config()
		
		print('Unit #{} technitium started'.format(self.unit_num))
		return

	def stop(self):
		self.container.stop()
		print('Unit #{} technitium stopped'.format(self.unit_num))
		return

	def remove(self):
		self.container.remove()
		print('Unit #{} technitium removed'.format(self.unit_num))
		return

	def tcpdump_start(self):
		exit_code, output = self.container.exec_run(['tcpdump', '-U', '-i', 'any', '-w', '/var/cache/technitium/tcpdump.pcap', '-vvv'], detach=True, tty=True)
		
		print('='*15, 'Unit #{} technitium tcpdump started'.format(self.unit_num), '='*15)
		return

	def tcpdump_stop(self):
		time.sleep(tcpdump_wait_time)
		exit_code, output = self.container.exec_run(['pkill', '-2', 'tcpdump'])
		time.sleep(tcpdump_wait_time)
		
		print('='*15, 'Unit #{} technitium tcpdump stopped'.format(self.unit_num), '='*15)
		return

	def tcpdump_save(self, curr_round_num):
		subprocess.call('sudo cp {dump_folder}/tcpdump.pcap {res_folder}/{round_num}/technitium/'.format(
			dump_folder = self.dump_folder, 
			res_folder = self.res_folder, 
			round_num = curr_round_num
		), shell=True)

		print('='*15, 'Unit #{} technitium tcpdump saved'.format(self.unit_num), '='*15)
		return

	def cache_dump_save(self, curr_round_num):
		tmp = self.get_cache()
		with open('{res_folder}/{round_num}/technitium/cache.json'.format(
				res_folder = self.res_folder,
				round_num = curr_round_num
		), 'w') as cache:
			cache.write(json.dumps(tmp))
		
		print('='*15, 'Unit #{} technitium cache dumped and saved'.format(self.unit_num), '='*15)
		return

	def save_response(self, curr_response, curr_round_num):
		# folder path [result_folder_path]/[unit no.]/[round no.]/[dns_sw_name]
		curr_res_folder = '{res_folder}/{round_num}/technitium'.format(
			res_folder = self.res_folder, 
			round_num = curr_round_num
		)
		
		with open('{}/response.txt'.format(curr_res_folder), 'wb') as response_file_object:
			response_file_object.write(curr_response)
		
		print('='*15, 'Unit #{} technitium response saved'.format(self.unit_num), '='*15)
		return

	def log_save(self, curr_round_num):
		tmp = self.get_log()
		with open('{res_folder}/{round_num}/technitium/log.txt'.format(
				res_folder = self.res_folder,
				round_num = curr_round_num
		), 'w') as log:
			log.write(tmp)
		
		print('='*15, 'Unit #{} technitium log saved'.format(self.unit_num), '='*15)
		return

	def cache_log_flush(self):
		tmp = self.flush_cache() + self.delete_log()

		print('='*15, 'Unit #{} technitium cache and log flushed'.format(self.unit_num), '='*15)
		return tmp

	def isCrashed(self):
		exit_code, output = self.container.exec_run(['sh', '-c', 'ps -ef | grep -w technitium | grep -v grep | wc -l'])

		output_lines = output.split(b"\n")
		
		if int(output_lines[-2]) == 1:
			print('='*15, 'Unit #{} technitium running normally'.format(self.unit_num), '='*15)
			return False
		elif int(output_lines[-2]) == 0:
			print('@'*15, 'Unit #{} technitium crashed!'.format(self.unit_num), '@'*15)
			return True

	def record_crash(self, curr_round_num):
		curr_res_folder = '{res_folder}/{round_num}/technitium'.format(
			res_folder = self.res_folder, 
			round_num = curr_round_num
		)

		with open('{}/technitium_crash_report.txt'.format(curr_res_folder), 'w') as crash_report_obj:
			crash_report_obj.write('technitium is crashed when testing this payload.')
		
		print('@'*15, 'Unit #{} technitium recorded!'.format(self.unit_num), '@'*15)
		return

	def restart(self):
		# This method `restart` is used to restart bind9 when it's crashed ONLY.
		# If it exits normally, please use cache flush instead of restarting the whole program!
		exit_code, output = self.container.exec_run(['pkill', '-9', 'start'])
		exit_code, output = self.container.exec_run(['pkill', '-9', 'technitium'])
		self.start()
		print('Unit #{} technitium restarted'.format(self.unit_num))
		return


	## utils functions for technitium docker containers
	def get_token(self, user="admin", password="admin"):
		payload = {'user': user, 'pass': password}

		r = requests.get('http://' + self.ipv4_addr + ':5380/api/login', params=payload)
		if r.status_code == 200:
			return r.json()['token']

		return None
	
	def set_config(self, user="admin", password="admin"):
		token = self.get_token(user, password)

		payload = {'token': token, 'dnssecValidation': 'false', 'logqueries': 'true'}
		r = requests.get('http://' + self.ipv4_addr + ':5380/api/settings/set', params=payload)
		print('technitium set_config request:', r.url)
		if r.status_code == 200 and r.json()['status'] == 'ok':
			return r.json()
		return None

	def get_cache(self, user="admin", password="admin"):
		token = self.get_token(user, password)
		target = [""]
		res = {}

		while target:
			tar = target.pop()
			r = self.get_cache_helper(token, tar)
			tmp = r['response']
			target.extend(tmp['zones'])
			for i in tmp['records']:
				if i['name'] == '':
					i['name'] = '.'
				if i['name'] in res:
					res[i['name']].append(i)
				else:
					res[i['name']] = [i]
		return res

	def get_cache_helper(self, token, domain=""):
		payload = {'token': token, 'domain': domain}
		r = requests.get('http://' + self.ipv4_addr + ':5380/api/cache/list', params=payload)
		if r.status_code == 200 and r.json()['status'] == 'ok':
			return r.json()
		return None

	def get_log(self, user="admin", password="admin"):
		res = []
		token = self.get_token(user, password)
		payload = {'token': token}

		r = requests.get('http://' + self.ipv4_addr + ':5380/api/listLogs', params=payload)
		if r.status_code == 200 and r.json()['status'] == 'ok':
			r = r.json()['response']['logFiles']
			for i in r[::-1]:
				tmp = self.get_log_helper(token, filename=i['fileName'])
				res.append(tmp)
			return "\n".join(res)
		return None

	def get_log_helper(self, token, filename):
		payload = {'token': token, 'filename': filename}
		r = requests.get('http://' + self.ipv4_addr + ':5380/api/logs/download', params=payload)
		if r.status_code == 200:
			return r.text
		return None

	def flush_cache(self, user="admin", password="admin"):
		token = self.get_token(user, password)
		payload = {'token': token}
		r = requests.get('http://' + self.ipv4_addr + ':5380/api/cache/flush', params=payload)
		if r.status_code == 200 and r.json()['status'] == 'ok':
			return 0
		return -1
	
	def delete_log(self, user="admin", password="admin"):
		token = self.get_token(user, password)
		payload = {'token': token}
		r = requests.get('http://' + self.ipv4_addr + ':5380/api/logs/deleteAll', params=payload)
		if r.status_code == 200 and r.json()['status'] == 'ok':
			return 0
		return -1


class AttackerContainer:
	def __init__(self, 
		unit_num, 
		image_name = attacker_image, 
		network_name = docker_network_name
		):
		global attacker_ip_addr_prefix

		self.unit_num = unit_num
		self.image_name = image_name
		## container name: attacker-[unit No.]-[suffix]
		self.container_name = 'attacker-{unit_num}-{suffix}'.format(
			unit_num = self.unit_num, 
			suffix = test_name_suffix
		)
		self.network_name = network_name
		self.ipv4_addr = '{prefix}.{unit_num}'.format(
			prefix = attacker_ip_addr_prefix, 
			unit_num = self.unit_num
		)
		return

	def clean(self):
		subprocess.call('sudo docker stop {attacker}'.format(
			attacker = self.container_name
		), shell=True)
		subprocess.call('sudo docker container rm {attacker}'.format(
			attacker = self.container_name
		), shell=True)
		print('Unit #{} old attacker cleaned'.format(self.unit_num))
		return
	
	def create(self):
		global attacker_host_tmp_path

		self.container = client.containers.run(self.image_name,
			name = self.container_name, 
			volumes = [
				'{}:/host_tmp'.format(attacker_host_tmp_path)
			], 
			detach=True,
			tty=True
		)
		# connect to the docker network
		client.networks.get(self.network_name).connect(self.container, ipv4_address=self.ipv4_addr)
		print('Unit #{} attacker created'.format(self.unit_num))
		return

	def stop(self):
		self.container.stop()
		print('Unit #{} attacker stopped'.format(self.unit_num))
		return

	def remove(self):
		self.container.remove()
		print('Unit #{} attacker removed'.format(self.unit_num))
		return

	def send_query(self, query_payload, curr_dns_ip, dns_sw_name):
		curr_src_port = src_port_dict[dns_sw_name]

		exit_code, output = self.container.exec_run(
		'python3 /host_tmp/dns_send_socket_port.py {dns_payload_hex_str} {src_ip} {src_port} {dns_ip}'.format(
			dns_payload_hex_str = query_payload,
			src_ip = self.ipv4_addr,
			src_port = curr_src_port, 
			dns_ip = curr_dns_ip))

		return output


class AuthSrvContainer:
	def __init__(self, 
		unit_num, 
		image_name = auth_srv_image, 
		network_name = docker_network_name
		):
		global auth_srv_ip_addr_prefix

		self.unit_num = unit_num
		self.image_name = image_name
		## container name: auth_srv-[unit No.]-[suffix]
		self.container_name = 'auth_srv-{unit_num}-{suffix}'.format(
			unit_num = self.unit_num, 
			suffix = test_name_suffix
		)
		self.network_name = network_name
		self.ipv4_addr = '{prefix}.{unit_num}'.format(
			prefix = auth_srv_ip_addr_prefix, 
			unit_num = self.unit_num
		)
		return
	
	def clean(self):
		subprocess.call('sudo docker stop {auth_srv}'.format(
			auth_srv = self.container_name
		), shell=True)
		subprocess.call('sudo docker container rm {auth_srv}'.format(
			auth_srv = self.container_name
		), shell=True)
		print('Unit #{} old auth_srv cleaned'.format(self.unit_num))
		return
	
	def create(self):
		global auth_srv_tmp_path

		self.container = client.containers.run(self.image_name, 
			name = self.container_name, 
			volumes = [
				'{}:/auth-srv-tmp'.format(auth_srv_tmp_path)
			],
			detach=True,
			tty=True
		)
		client.networks.get(self.network_name).connect(self.container, ipv4_address=self.ipv4_addr)
		print('Unit #{} auth_srv created'.format(self.unit_num))
		return
	
	def stop(self):
		self.container.stop()
		print('Unit #{} auth_srv stopped'.format(self.unit_num))
		return

	def remove(self):
		self.container.remove()
		print('Unit #{} auth_srv removed'.format(self.unit_num))
		return

	def start(self, response_payload):
		exit_code, output = self.container.exec_run('python3 /auth-srv-tmp/dns_auth_srv.py {response0} {response1} {auth_srv_ip}'.format(
				response0 = response_payload[0],
				response1 = response_payload[1], 
				auth_srv_ip = self.ipv4_addr
		), detach=True, tty=True)
		time.sleep(0.5)

		print('Unit #{} auth_srv started'.format(self.unit_num))
		return

	def restart(self):
		exit_code, output = self.container.exec_run('pkill python3')
		print('Unit #{} auth_srv restarted'.format(self.unit_num))
		return


class DNSFuzzerGenerator:
	def __init__(self, unit_num):
		self.domain_forward_only = 'test{}-fwd-only.qifanzhang.com'.format(unit_num)
		self.domain_forward_fallback = 'test{}-fwd-fallback.qifanzhang.com'.format(unit_num)
		self.domain_recursive = 'test{}-recursive.qifanzhang.com'.format(unit_num)
		
		self.dns_fuzzer = dns_fuzzer.DNSFuzzer(
			public_suffix = "./input_generation/public_suffix_list.dat", 
			domain_list = "./input_generation/tlds-alpha-by-domain.txt", 
			top_1m = "./input_generation/top-1m.csv", 
			domain_forward_only = self.domain_forward_only, 
			domain_forward_fallback = self.domain_forward_fallback, 
			domain_recursive = self.domain_recursive
		)
		return

	def get_next_packet(self):
		self.dns_fuzzer.Unset()
		curr_query = self.dns_fuzzer.Query()
		curr_response = self.dns_fuzzer.Response()
		return (curr_query, curr_response)

	def get_dump_json(self):
		return self.dns_fuzzer.DumpPkt()


## function declaration and implementation
def sys_argv_handler():
	## options for disabling testing DNS software
	parser.add_argument('--disable_bind9', 
					 	action='store_false')
	parser.add_argument('--disable_unbound', 
					 	action='store_false')
	parser.add_argument('--disable_knot', 
					 	action='store_false')
	parser.add_argument('--disable_powerdns', 
					 	action='store_false')
	parser.add_argument('--disable_technitium', 
					 	action='store_false')
	parser.add_argument('--disable_maradns', 
					 	action='store_false')
	
	## debug mode: if enabled, the program will be single-processed.
	parser.add_argument('--debug', 
					 	action='store_true', 
						help='enable the debug mode so that the program will be single-processed')
	
	## unit size: # units deployed and tested
	parser.add_argument('--unit_size', 
					 	type=int, 
						choices=range(1, 51), 
						help='# units deployed and tested, range:[1, 50], default: 5')
	
	## payload num: # payloads to be tested in each unit
	parser.add_argument('--payload_num',
					 	type=int, 
						help='# payloads to be tested in each unit, suggested less than 1000, default: 5')
	
	## result folder path: the folder to store fuzzing results
	parser.add_argument('--res_folder', 
					 	type=str,
						help='the folder to stare fuzzing results, default: ./recursive_test_res')
	
	## parse args
	args = parser.parse_args()
	global is_bind9_eval, is_unbound_eval, is_knot_eval, is_powerdns_eval, is_technitium_eval, is_maradns_eval, is_debug

	is_bind9_eval = args.disable_bind9
	is_unbound_eval = args.disable_unbound
	is_knot_eval = args.disable_knot
	is_powerdns_eval = args.disable_powerdns
	is_technitium_eval = args.disable_technitium
	is_maradns_eval = args.disable_maradns

	is_debug = args.debug

	if args.unit_size:
		global unit_size
		unit_size = args.unit_size

	if args.payload_num:
		global total_payload_num
		total_payload_num = args.payload_num

	if args.res_folder:
		global result_folder_path
		result_folder_path =  os.path.abspath(args.res_folder)
	

	print('bind9 eval:', is_bind9_eval)
	print('Unbound eval:', is_unbound_eval)
	print('PowerDNS eval:', is_powerdns_eval)
	print('Knot eval:', is_knot_eval)
	print('MaraDNS eval:', is_maradns_eval)
	print('Technitium eval:', is_technitium_eval)

	print('is_debug:', is_debug)

	print('unit_size:', unit_size)
	print('total_payload_num:', total_payload_num)

	print('result_folder_path:', result_folder_path)

	return


## clean and create result folders
## path: [result_folder_path]/[unit no.]/[round no.]/[dns_sw_name]
def clean_res_folder():
	subprocess.call('sudo rm -rf {res_folder}'.format(
		res_folder = result_folder_path
	), shell=True)
	subprocess.call('sudo mkdir {res_folder}'.format(
		res_folder = result_folder_path
	), shell=True)

	for curr_unit_num in range(unit_size):
		subprocess.call('sudo rm -rf {res_folder}/{unit_num}/'.format(
			res_folder = result_folder_path, 
			unit_num = curr_unit_num
		), shell=True)
		subprocess.call('sudo mkdir {res_folder}/{unit_num}/'.format(
			res_folder = result_folder_path, 
			unit_num = curr_unit_num
		), shell=True)
		print('result folder {} cleaned'.format(curr_unit_num))

	return

## clean and create dump folders
## path: [dump_folder_path]/[dns_sw_name]/[unit No.]
def clean_dump_folder():
	global dns_sw_name_list

	for curr_dns_sw_name in dns_sw_name_list:
		subprocess.call('sudo rm -rf {dump_folder}/{dns_sw_name}/'.format(
				dump_folder = dump_folder_path, 
				dns_sw_name = curr_dns_sw_name
			), shell=True)
		subprocess.call('sudo mkdir {dump_folder}/{dns_sw_name}/'.format(
			dump_folder = dump_folder_path, 
			dns_sw_name = curr_dns_sw_name
		), shell=True)

		for curr_unit_num in range(unit_size):
			subprocess.call('sudo rm -rf {dump_folder}/{dns_sw_name}/{unit_num}/'.format(
				dump_folder = dump_folder_path, 
				dns_sw_name = curr_dns_sw_name,
				unit_num = curr_unit_num
			), shell=True)
			subprocess.call('sudo mkdir {dump_folder}/{dns_sw_name}/{unit_num}/'.format(
				dump_folder = dump_folder_path, 
				dns_sw_name = curr_dns_sw_name, 
				unit_num = curr_unit_num
			), shell=True)
			print('dump folder {dns_sw_name}/{unit_num} cleaned'.format(
				dns_sw_name = curr_dns_sw_name, 
				unit_num = curr_unit_num
			))
	return


## assign each unit with a process
def unit_payload_test(curr_unit: TestUnit):
	curr_unit.test_payloads()
	return


if __name__ == '__main__':
	## 0. checck system cmd args
	sys_argv_handler()
	
	## 1. clean and start dnstap
	global_dnstap_obj = DNSTapContainer()
	# 1.1 clean the old DNSTap server
	global_dnstap_obj.clean()
	# 1.2 create and start the new DNSTap server
	global_dnstap_obj.create()
	global_dnstap_obj.start()

	## clean result folders
	clean_res_folder()

	## clean dump folders
	clean_dump_folder()

	## 2. start units
	print('='*15, 'start units', '='*15)
	unit_list = []
	for curr_unit_num in range(unit_size):
		curr_unit_obj = TestUnit(unit_num=curr_unit_num, dnstap_interval=dnstap_save_interval)

		## save dnstap container
		curr_unit_obj.dnstap_obj = global_dnstap_obj

		# 2.0 attacker client
		curr_atkr_obj = AttackerContainer(unit_num=curr_unit_num)
		# 2.0.0 clean old attacker container
		curr_atkr_obj.clean()
		# 2.0.1 create new attacker container
		curr_atkr_obj.create()
		# attacker client start completed
		curr_unit_obj.attacker_obj = curr_atkr_obj

		# 2.1 auth_srv
		curr_auth_srv_obj = AuthSrvContainer(unit_num=curr_unit_num)
		# 2.1.0 clean old auth_srv container
		curr_auth_srv_obj.clean()
		# 2.1.1 create new auth_srv container
		curr_auth_srv_obj.create()
		# auth_srv start completed
		curr_unit_obj.auth_srv_obj = curr_auth_srv_obj

		# 2.2 DNS Fuzzer
		curr_dns_fuzzer_obj = DNSFuzzerGenerator(unit_num=curr_unit_num)
		curr_unit_obj.dns_fuzzer_obj = curr_dns_fuzzer_obj

		# 2.3 bind9
		if is_bind9_eval:
			curr_bind9_obj = Bind9Container(unit_num=curr_unit_num)
			# 2.3.0 clean old bind9 container
			curr_bind9_obj.clean()
			# 2.3.1 create new bind9 container
			curr_bind9_obj.create()
			# 2.3.2 start new bind9 container: 1) start named, 2) connect dnstap
			curr_bind9_obj.start()
			# bind9 start completed, save to unit_obj attributes
			curr_unit_obj.bind9_obj = curr_bind9_obj
		
		# 2.4 Unbound
		if is_unbound_eval:
			curr_unbound_obj = UnboundContainer(unit_num=curr_unit_num)
			# 2.4.0 clean old unbound container
			curr_unbound_obj.clean()
			# 2.4.1 create new unbound container
			curr_unbound_obj.create()
			# 2.4.2 start new unbound container: start unbound
			curr_unbound_obj.start()
			# unbound start completed, save to unit_obj attributes
			curr_unit_obj.unbound_obj = curr_unbound_obj

		# 2.5 PowerDNS
		if is_powerdns_eval:
			curr_powerdns_obj = PowerDNSContainer(unit_num=curr_unit_num)
			# 2.5.0 clean old powerdns container
			curr_powerdns_obj.clean()
			# 2.5.1 create new powerdns container
			curr_powerdns_obj.create()
			# 2.5.2 start new powerdns container
			curr_powerdns_obj.start()
			# powerdns start completed, save to unit_obj attributes
			curr_unit_obj.powerdns_obj = curr_powerdns_obj

		# 2.6 Knot
		if is_knot_eval:
			curr_knot_obj = KnotContainer(unit_num=curr_unit_num)
			# 2.6.0 clean old powerdns container
			curr_knot_obj.clean()
			# 2.6.1 create new powerdns container
			curr_knot_obj.create()
			# 2.6.2 start new powerdns container
			curr_knot_obj.start()
			# knot start completed, save to unit_obj attributes
			curr_unit_obj.knot_obj = curr_knot_obj

		# 2.7 MaraDNS
		if is_maradns_eval:
			curr_maradns_obj = MaraDNSContainer(unit_num=curr_unit_num)
			# 2.7.0 clean old powerdns container
			curr_maradns_obj.clean()
			# 2.7.1 create new powerdns container
			curr_maradns_obj.create()
			# 2.7.2 start new powerdns container
			curr_maradns_obj.start()
			# knot start completed, save to unit_obj attributes
			curr_unit_obj.maradns_obj = curr_maradns_obj

		# 2.8 Technitium
		if is_technitium_eval:
			curr_technitium_obj = TechnitiumContainer(unit_num=curr_unit_num)
			# 2.8.0 clean old powerdns container
			curr_technitium_obj.clean()
			# 2.8.1 create new powerdns container
			curr_technitium_obj.create()
			# 2.8.2 start new powerdns container
			curr_technitium_obj.start()
			# technitium start completed, save to unit_obj attributes
			curr_unit_obj.technitium_obj = curr_technitium_obj

		## add current unit into the list
		unit_list.append(curr_unit_obj)

	## 3. running tests
	## multi-processing, store processes in the list
	
	global global_start_time
	global_start_time = time.time()
	
	unit_process_list = []
	for curr_unit in unit_list:
		if is_debug:
			unit_payload_test(curr_unit=curr_unit)
		else:
			curr_unit_process = mp.Process(
				target = unit_payload_test, 
				args=(curr_unit, )
			)
			curr_unit_process.start()
			unit_process_list.append(curr_unit_process)
	
	## test finished, then merge the processes
	if not is_debug:
		for curr_unit_process in unit_process_list:
			curr_unit_process.join()

	## dnstap log save
	global_dnstap_obj.log_final_save()
	
	## 4. stop containers, and remove old containers
	close_process_list = []
	for curr_unit_obj in unit_list:
		curr_close_process = mp.Process(
			target = curr_unit_obj.stop_remove
		)
		curr_close_process.start()
		close_process_list.append(curr_close_process)
	
	for curr_close_process in close_process_list:
		curr_close_process.join()


	global_dnstap_obj.stop()
	global_dnstap_obj.remove()

