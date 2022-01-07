#!/usr/bin/python

import pyroute2
import socket
import ctypes as ct

from bcc import BPF

def tc_generate(tc_filter):
	bpf_text = open('bpf.c','r').read()
	
	# Check IP protocol
	if tc_filter['proto']:
		filter_proto = tc_filter['proto']
		bpf_text = bpf_text.replace(
			'IP_PROTO_FILTER',
			f"if (iph->protocol != {filter_proto}) return TC_ACT_UNSPEC;")
	else:
		bpf_text = bpf_text.replace('IP_PROTO_FILTER','')

	# Check source IP address
	if tc_filter['src']:
		filter_src_ip = tc_filter['src']
		bpf_text = bpf_text.replace(
			'SRC_IP_FILTER',
			f"if (iph->saddr != htonl({filter_src_ip})) return TC_ACT_UNSPEC;")
	else:
		bpf_text = bpf_text.replace('SRC_IP_FILTER','')

	# Check destination IP address
	if tc_filter['dst']:
		filter_dst_ip = tc_filter['dst']
		bpf_text = bpf_text.replace(
			'DST_IP_FILTER',
			f"if (iph->daddr != htonl({filter_dst_ip})) return TC_ACT_UNSPEC;")
	else:
		bpf_text = bpf_text.replace('DST_IP_FILTER','')
	
	if tc_filter['port'] and tc_filter['proto'] is not socket.IPPROTO_ICMP:
		filter_trans_hdr = "tcph" if tc_filter['proto'] is socket.IPPROTO_TCP else "udph"
		filter_port = tc_filter['port']

		# Bounds check to filter out small packets
		bpf_text = bpf_text.replace(
			'BOUNDS_CHECK',
			f"if (data + sizeof(*eth) + sizeof(*iph) + sizeof(*{filter_trans_hdr}) > data_end) return TC_ACT_OK;")

		# Check if either source or dest port fits
		bpf_text = bpf_text.replace(
			'PORT_FILTER',
			f"if ({filter_trans_hdr}->source != htons({filter_port}) && {filter_trans_hdr}->dest != htons({filter_port})) return TC_ACT_UNSPEC;")
	else:
		# Without transport header filtering check bounds only till IP header
		bpf_text = bpf_text.replace(
			'BOUNDS_CHECK',
			"if (data + sizeof(*eth) + sizeof(*iph) > data_end) return TC_ACT_OK;")
		bpf_text = bpf_text.replace('PORT_FILTER', "")

	tc_fwmark = tc_filter['fwmark'][0]
	bpf_text = bpf_text.replace('TC_FWMARK', str(tc_fwmark))

	return bpf_text

def tc_load(bpf_obj, link):
	tc_func = bpf_obj.load_func("filter", BPF.SCHED_CLS)

	ipr = pyroute2.IPRoute()
	ipr.tc("add", "clsact", link)
	ipr.tc("add-filter", "bpf", link, ":1", fd=tc_func.fd, name=tc_func.name,
		   parent="ffff:fff2", direct_action=True)

	bpf_obj['skb_ptr'][0] = ct.c_uint64(-1)

def tc_unload(link):
	ipr = pyroute2.IPRoute()
	ipr.tc("del", "clsact", link)