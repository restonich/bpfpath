#!/usr/bin/python

import argparse
import socket
import pyroute2
import ctypes as ct
import keyboard

from bcc import BPF

from tc_bpf import tc_generate, tc_load, tc_unload
from kp_bpf import kp_load

def parse_tc_filter(args):
	'''
	Args:
		args (str): 

	Returns:
		tc_filter (dict):
			'link'
			'proto'
			'src'
			'dst'
			'port'
			'fwmark'
	'''
	tc_filter = {}

	ipr = pyroute2.IPRoute()
	link = ipr.link_lookup(ifname=args.link)
	if not link:
		print(f"Interface is not found: {args.link}")
		return None
	tc_filter['link'] = link[0]

	if not args.proto:
		tc_filter['proto'] = None
	else:
		tc_filter['proto'] = {
			'icmp' : socket.IPPROTO_ICMP,
			'tcp'  : socket.IPPROTO_TCP,
			'udp'  : socket.IPPROTO_UDP
		}[args.proto]

	if not args.src:
		tc_filter['src'] = None
	else:
		try:
			tc_filter['src'] = int.from_bytes(socket.inet_pton(socket.AF_INET, args.src), 'big')
		except OSError as e:
			print(f"Source IP is not valid: {e}")
			return None

	if not args.dst:
		tc_filter['dst'] = None
	else:
		try:
			tc_filter['dst'] = int.from_bytes(socket.inet_pton(socket.AF_INET, args.dst), 'big')
		except OSError as e:
			print(f"Destination IP is not valid: {e}")
			return None

	if args.port and args.port not in range(1, 65535):
		print(f"Port is not valid: {args.port}")
		return None

	tc_filter['port'] = args.port

	fwmark_bin = bin(int(args.fwmark, 16))
	fwmark_min = 2 ** (len(fwmark_bin) - fwmark_bin.rfind('1') - 1)
	fwmark_max = int(args.fwmark, 16)
	tc_filter['fwmark'] = (fwmark_min, fwmark_max)

	return tc_filter

# TASK_COMM_LEN = 16    # linux/sched.h
# class tracing_data(ct.Structure):
#     _fields_ = [("tgid_pid", ct.c_uint64),
# 				("gid_uid", ct.c_uint64),
# 				("task_comm", ct.c_char * TASK_COMM_LEN),
# 				("ip_ptr", ct.c_void_p),
#               ("timestamp", ct.c_uint64)]

if __name__ == '__main__':
	parser = argparse.ArgumentParser(
		description="Show network packet path through Linux kernel")
	
	parser.add_argument(
		'--link',
		type=str,
		required=True,
		help='Network interface where packet is expected')
	parser.add_argument(
		'--proto',
		choices=['icmp', 'tcp', 'udp'],
		type=str,
		help='IP protocol to filter')
	parser.add_argument(
		'--src',
		type=str,
		help="Source IP address (IPv4)")
	parser.add_argument(
		'--dst',
		type=str,
		help="Destination IP address (IPv4)")
	parser.add_argument(
		'--port',
		type=int,
		help="Port number of TCP/UDP. Source or destination")
	parser.add_argument(
		'--fwmark',
		type=str,
		default='0x3',
		help="Specify fwmark mask to mark the packets for tracing. Should not collide with other utilities using fwmark. Default is 0x3")

	args = parser.parse_args()
	tc_filter = parse_tc_filter(args)

	if not tc_filter:
		exit(1)

	print(tc_filter)

	bpf_text = tc_generate(tc_filter)
	bpf_obj = BPF(text=bpf_text)

	tc_load(bpf_obj, tc_filter['link'])
	kp_load(bpf_obj)

	def tracing_event(ctx, data, size):
		tr_data = bpf_obj["tracing_info"].event(data)

		pid = tr_data.tgid_pid >> 32
		tid = tr_data.tgid_pid & 0xFFFFFFFF
		gid = tr_data.gid_uid >> 32
		uid = tr_data.gid_uid & 0xFFFFFFFF
		ts = tr_data.timestamp
		comm = tr_data.task_comm.decode('utf-8')
		net_ns = tr_data.ns_index
		ifname = tr_data.ifname.decode('utf-8')

		if tr_data.ip_ptr is None:
			fn = "tc_ingress_hook"
		else:
			fn = bpf_obj.ksym(tr_data.ip_ptr).decode('utf-8')
		
		print(f"{ts} | [{comm}]({pid}.{tid}) {uid}({gid}) {fn}()  {net_ns}  {ifname} fwmark: {tr_data.fwmark}")
	
	bpf_obj['tracing_info'].open_ring_buffer(tracing_event)
	
	bpf_obj['skb_ptr'][0] = ct.c_uint64(0)
	print("Tracing started")
	try:
		while True:
			if bpf_obj['skb_ptr'][0].value == ct.c_uint64(-1).value:
				print("Tracing is finished. Press SPACE to run again.")
				keyboard.wait('space')
				print("\nStarting again")
				bpf_obj['skb_ptr'][0] = ct.c_uint64(0)
			bpf_obj.ring_buffer_poll()

			# bpf_obj.trace_print()
	except KeyboardInterrupt:
		print("\nUnloading programs...")
		tc_unload(tc_filter['link'])
