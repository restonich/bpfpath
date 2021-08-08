#!/usr/bin/python

import pyroute2
import socket

from bcc import BPF

tc_prog="""
#include <uapi/linux/if_ether.h>
#include <uapi/linux/ip.h>
#include <uapi/linux/tcp.h>
#include <uapi/linux/udp.h>

#include <uapi/linux/bpf.h>
#include <uapi/linux/pkt_cls.h>

BPF_TABLE_PUBLIC("array", u32, void*, skb_ptr, 1);

int filter(struct __sk_buff *skb)
{
	/* Check current pointer
	 * Key is always 0, skb_ptr array consists of only one element
	 * skb_val == 0       -- tracing just initiated
	 * skb_val == SKB_FIN -- tracing was concluded or not yet started
	 * other skb_val is the pointer to the traced packet
	 */
	u32 skb_key = 0;
	void **skb_val = NULL;
	skb_val = skb_ptr.lookup(&skb_key);
	if (skb_val  == NULL) return TC_ACT_OK;
	if (*skb_val != 0)    return TC_ACT_OK;

	/* Get header pointers for filtering */
	void          *data = (void *)(long)skb->data;
	void      *data_end = (void *)(long)skb->data_end;
	struct ethhdr  *eth = data;
	struct iphdr   *iph = data + sizeof(*eth);
	struct tcphdr *tcph = (void *)iph + sizeof(*iph);
	struct udphdr *udph = (void *)iph + sizeof(*iph);

	/* Return TC_ACT_UNSPEC to allow other filters process this packet
	 * Return TC_ACT_OK to stop all TC actions and continue
	 * packet proces by networking stack
	 */
	TRANS_HDR_BOUNDS_CHECK

	/* Check IPv4, if not -- stop all filtering */
	if (eth->h_proto != htons(ETH_P_IP)) return TC_ACT_OK;

	IP_PROTO_FILTER

	SRC_IP_FILTER

	DST_IP_FILTER

	PORT_FILTER

	//void *skb_ptr_store = (void *)skb;
	skb_ptr.update(&skb_key, (void **)&skb);

	u64 timestamp = bpf_ktime_get_ns();
	bpf_trace_printk("Timestamp: %llu", timestamp);

	return TC_ACT_OK;
}
"""

def tc_generate(tc_filter):
	global tc_prog
	# Check IP protocol
	filter_proto = tc_filter['proto']
	tc_prog = tc_prog.replace(
		'IP_PROTO_FILTER',
		f"if (iph->protocol != {filter_proto}) return TC_ACT_UNSPEC;")

	# Check source IP address
	filter_src_ip = tc_filter['src']
	tc_prog = tc_prog.replace(
		'SRC_IP_FILTER',
		f"if (iph->saddr != htonl({filter_src_ip})) return TC_ACT_UNSPEC;")

	# Check destination IP address
	filter_dst_ip = tc_filter['dst']
	tc_prog = tc_prog.replace(
		'DST_IP_FILTER',
		f"if (iph->daddr != htonl({filter_dst_ip})) return TC_ACT_UNSPEC;")
	
	if tc_filter['port'] and tc_filter['proto'] is not socket.IPPROTO_ICMP:
		filter_trans_hdr = "tcph" if tc_filter['proto'] is socket.IPPROTO_TCP else "udph"
		filter_port = tc_filter['port']

		# Bounds check to filter out small packets
		tc_prog = tc_prog.replace(
			'TRANS_HDR_BOUNDS_CHECK',
			f"if (data + sizeof(*eth) + sizeof(*iph) + sizeof(*{filter_trans_hdr}) > data_end) return TC_ACT_OK;")

		# Check if either source or dest port fits
		tc_prog = tc_prog.replace(
			'PORT_FILTER',
			f"if ({filter_trans_hdr}->source != htons({filter_port}) && {filter_trans_hdr}->dest != htons({filter_port})) return TC_ACT_UNSPEC;")
	else:
		# Without transport header filtering check bounds only till IP header
		tc_prog = tc_prog.replace(
			'TRANS_HDR_BOUNDS_CHECK',
			"if (data + sizeof(*eth) + sizeof(*iph) > data_end) return TC_ACT_OK;")
		tc_prog = tc_prog.replace('PORT_FILTER', "")

def tc_generate_and_load(tc_filter):
	tc_generate(tc_filter)

	b = BPF(text=tc_prog)
	bpf_obj = b.load_func("filter", BPF.SCHED_CLS)

	link = tc_filter['link']
	ipr = pyroute2.IPRoute()
	ipr.tc("add", "clsact", link)
	ipr.tc("add-filter", "bpf", link, ":1", fd=bpf_obj.fd, name=bpf_obj.name,
		   parent="ffff:fff2", direct_action=True)

	try:
		pass
		#b.trace_print()
	except KeyboardInterrupt:
		ipr.tc("del", "clsact", link)
