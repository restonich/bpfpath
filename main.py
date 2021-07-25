#!/usr/bin/python
import argparse
import socket

import tc_bpf_prog

# Abcent from socket
ETH_P_IP = 0x0800

def parse_filter(args):
	'''
	Args:
		args (str): 

	Returns:
		filter (dict):
			'proto'
			'src'
			'dst'
			'port'
	'''
	filter = {}

	filter['proto'] = {
		'icmp' : socket.IPPROTO_ICMP,
		'tcp'  : socket.IPPROTO_TCP,
		'udp'  : socket.IPPROTO_UDP
	}[args.proto]

	try:
		filter['src'] = int.from_bytes(socket.inet_pton(socket.AF_INET, args.src), 'big')
		filter['dst'] = int.from_bytes(socket.inet_pton(socket.AF_INET, args.dst), 'big')
	except OSError as e:
		print(f"IP is not valid: {e}")
		return None

	if args.port not in range(1, 65535):
		print(f"Port is not valid: {args.port}")
		return None

	filter['port'] = args.port

	return filter

if __name__ == '__main__':
	parser = argparse.ArgumentParser(
		description="Show network packet path through Linux kernel")

	parser.add_argument('--proto',
						choices=['icmp', 'tcp', 'udp'],
						type=str,
						required=True,
						help='IP protocol to filter')
	parser.add_argument('--src',
						type=str,
						required=True,
						help="Source IP address (IPv4)")
	parser.add_argument('--dst',
						type=str,
						required=True,
						help="Destination IP address (IPv4)")
	parser.add_argument('--port',
						type=int,
						help="Port number of TCP/UDP. Source or destination")

	args = parser.parse_args()
	filter = parse_filter(args)

	if filter is None:
		exit(1)

	print(filter)

