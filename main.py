#!/usr/bin/python

import argparse
import socket
import pyroute2

from tc_bpf_prog import tc_generate_and_load

# Abcent from socket
ETH_P_IP = 0x0800

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
	'''
	tc_filter = {}

	ipr = pyroute2.IPRoute()
	link = ipr.link_lookup(ifname=args.link)
	if not link:
		print(f"Interface is not found: {args.link}")
		return None
	tc_filter['link'] = link[0]

	tc_filter['proto'] = {
		'icmp' : socket.IPPROTO_ICMP,
		'tcp'  : socket.IPPROTO_TCP,
		'udp'  : socket.IPPROTO_UDP
	}[args.proto]

	try:
		tc_filter['src'] = int.from_bytes(socket.inet_pton(socket.AF_INET, args.src), 'big')
		tc_filter['dst'] = int.from_bytes(socket.inet_pton(socket.AF_INET, args.dst), 'big')
	except OSError as e:
		print(f"IP is not valid: {e}")
		return None

	if args.port and args.port not in range(1, 65535):
		print(f"Port is not valid: {args.port}")
		return None

	tc_filter['port'] = args.port

	return tc_filter

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
		required=True,
		help='IP protocol to filter')
	parser.add_argument(
		'--src',
		type=str,
		required=True,
		help="Source IP address (IPv4)")
	parser.add_argument(
		'--dst',
		type=str,
		required=True,
		help="Destination IP address (IPv4)")
	parser.add_argument(
		'--port',
		type=int,
		help="Port number of TCP/UDP. Source or destination")

	args = parser.parse_args()
	tc_filter = parse_tc_filter(args)

	if not tc_filter:
		exit(1)

	print(tc_filter)

	tc_generate_and_load(tc_filter)

