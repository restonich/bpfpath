#!/usr/bin/python

import os
import argparse
import time
import subprocess
import signal
import multiprocessing
import pyroute2
import keyboard

import ctypes as ct
from socket import IPPROTO_ICMP, IPPROTO_TCP, IPPROTO_UDP, AF_INET, inet_pton
from bcc import BPF

from tc_bpf import tc_generate, tc_attach, tc_unload
from kp_bpf import kp_attach

WORK_DIR=os.path.dirname(os.path.abspath(__file__))

def parse_tc_filter(args):
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
			'icmp' : IPPROTO_ICMP,
			'tcp'  : IPPROTO_TCP,
			'udp'  : IPPROTO_UDP
		}[args.proto]

	if not args.src:
		tc_filter['src'] = None
	else:
		try:
			tc_filter['src'] = int.from_bytes(inet_pton(AF_INET, args.src), 'big')
		except OSError as e:
			print(f"Source IP is not valid: {e}")
			return None

	if not args.dst:
		tc_filter['dst'] = None
	else:
		try:
			tc_filter['dst'] = int.from_bytes(inet_pton(AF_INET, args.dst), 'big')
		except OSError as e:
			print(f"Destination IP is not valid: {e}")
			return None

	if args.port and args.port not in range(1, 65535):
		print(f"Port is not valid: {args.port}")
		return None

	tc_filter['port'] = args.port

	# fwmark_bin = bin(int(args.fwmark, 16))
	# fwmark_min = 2 ** (len(fwmark_bin) - fwmark_bin.rfind('1') - 1)
	# fwmark_max = int(args.fwmark, 16)
	# tc_filter['fwmark'] = (fwmark_min, fwmark_max)

	return tc_filter

def generate_and_attach(tc_filter):
	bpf_obj = None

	try:
		bpf_text = tc_generate(tc_filter)
		bpf_obj = BPF(text=bpf_text)
	except Exception as e:
		print(f"Failed to create BPF object: {e}")
		exit(1)

	try:
		tc_attach(bpf_obj, tc_filter['link'])
	except Exception as e:
		print(f"Failed to attach TC programs: {e}")
		print("Detaching BPF programs...")
		tc_unload(tc_filter['link'])
		exit(1)

	try:
		kp_attach(bpf_obj)
	except Exception as e:
		print(f"Failed to attach KP programs: {e}")
		print("Detaching BPF programs...")
		tc_unload(tc_filter['link'])
		exit(1)

	return bpf_obj

class TerminateTracing(Exception):
	pass

def signal_handler(signum, frame):
	if signum == signal.SIGTERM:
		raise TerminateTracing

def bpf_trace_and_print(interval, bpf_obj, tc_filter):
	OUTPUR_COLS = ('TS', 'COMM', 'PID', 'UID', 'NETNS', 'IFNAME', 'FUNC')
	OUTPUT_FORMAT = "{:<16} {:<16} {:<6} {:<6} {:<16} {:<18} {}()"

	netns_names = {}
	netns_list = []
	try:
		netns_list = subprocess.check_output(
			"ls -1 -L -i /run/netns",
			shell=True,
			stderr=subprocess.STDOUT).decode('utf-8').splitlines()
	except subprocess.CalledProcessError as e:
		# print(f"Can't fetch network namespaces: {e}")
		print("Other netns not found")

	for line in netns_list:
		inode_name = line.split(' ')
		netns_names[int(inode_name[0], 10)] = inode_name[1]

	def tracing_event(ctx, data, size):
		tr_data = bpf_obj["tracing_info"].event(data)

		pid = tr_data.pid
		uid = tr_data.uid
		ts = tr_data.timestamp
		comm = tr_data.task_comm.decode('utf-8')
		ifname = tr_data.ifname.decode('utf-8')
		ifname = ifname if ifname != '' else '...'
		netns_name = netns_names.get(tr_data.netns_inode, "root")

		if tr_data.ip_ptr is None:
			func = "tc_ingress_hook"
		else:
			func = bpf_obj.ksym(tr_data.ip_ptr).decode('utf-8')

		print(OUTPUT_FORMAT.format(ts, comm, pid, uid, netns_name, ifname, func))

	bpf_obj['tracing_info'].open_ring_buffer(tracing_event)

	bpf_obj['skb_ptr'][0] = ct.c_uint64(0)
	print("Tracing started. Press Ctrl+C to exit")
	print(OUTPUT_FORMAT.format(*OUTPUR_COLS))
	try:
		while True:
			if bpf_obj['skb_ptr'][0].value == ct.c_uint64(-1).value:
				print("Tracing is finished")
				if interval:
					time.sleep(1)
				else:
					print("Press SPACE to run again")
					keyboard.wait('space')
				print("\nTracing started. Press Ctrl+C to exit")
				print(OUTPUT_FORMAT.format(*OUTPUR_COLS))
				bpf_obj['skb_ptr'][0] = ct.c_uint64(0)

			bpf_obj.ring_buffer_poll()
	except (KeyboardInterrupt, TerminateTracing):
		print("Terminate. Detaching BPF programs...")
		tc_unload(tc_filter['link'])

if __name__ == '__main__':
	parser = argparse.ArgumentParser(
		description="Show network packet path through Linux kernel")

	parser.add_argument(
		'-i',
		type=int,
		default=0,
		help="Interval in seconds between tracing events. Default is 0")
	parser.add_argument(
		'-t',
		type=int,
		default=0,
		help="Timeout in seconds to stop tracing. Default is 0")
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
	# parser.add_argument(
	# 	'--fwmark',
	# 	type=str,
	# 	default='0x3',
	# 	help="Specify fwmark mask to mark the packets for tracing. Should not collide with other utilities using fwmark. Default is 0x3")

	args = parser.parse_args()
	tc_filter = parse_tc_filter(args)

	if not tc_filter:
		exit(1)

	print(tc_filter)
	bpf_obj = generate_and_attach(tc_filter)

	signal.signal(signal.SIGTERM, signal_handler)

	tracing_proc = multiprocessing.Process(
		target=bpf_trace_and_print,
		name="Tracing process",
		args=(args.i, bpf_obj, tc_filter))

	tracing_proc.start()

	try:
		if args.t:
			tracing_proc.join(args.t)
		else:
			tracing_proc.join()

		if args.t != 0 and tracing_proc.is_alive():
			tracing_proc.terminate()
	except KeyboardInterrupt:
		pass

	exit(0)
