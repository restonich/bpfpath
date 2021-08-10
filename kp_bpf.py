#!/usr/bin/python

import ctypes as ct

from bcc import BPF

def kp_load(bpf_obj):
	bpf_obj.attach_kprobe(event="ip_rcv", fn_name="probe")
	bpf_obj.attach_kprobe(event="tcp_v4_rcv", fn_name="probe")
	# bpf_obj.attach_kprobe(event="deliver_skb", fn_name="probe")
	bpf_obj.attach_kprobe(event="ip_local_deliver", fn_name="probe")
	bpf_obj.attach_kprobe(event="ip_route_input_noref", fn_name="probe")
	# bpf_obj.attach_kprobe(event="skb_set_owner_r", fn_name="probe")
	bpf_obj.attach_kprobe(event="skb_copy_datagram_iter", fn_name="probe")





	bpf_obj.attach_kprobe(event="consume_skb", fn_name="probe")
	# bpf_obj.attach_kprobe(event="kfree_skb_reason", fn_name="probe")
	bpf_obj.attach_kprobe(event="__kfree_skb", fn_name="probe")
	bpf_obj.attach_kprobe(event="skb_release_data", fn_name="probe")
	bpf_obj.attach_kprobe(event="kfree_skbmem", fn_name="probe")




# ip_local_deliver_finish(struct net *net, struct sock *sk, struct sk_buff *skb)
# ip_rcv_finish(struct net *net, struct sock *sk, struct sk_buff *skb)

#tcp_v4_do_rcv(struct sock *sk, struct sk_buff *skb)
#tcp_rcv_established(struct sock *sk, struct sk_buff *skb)
#tcp_data_queue(struct sock *sk, struct sk_buff *skb)
#tcp_queue_rcv(struct sock *sk, struct sk_buff *skb)
#tcp_event_data_recv(struct sock *sk, struct sk_buff *skb)
#static inline void __skb_queue_tail(struct sk_buff_head *list,
#				   struct sk_buff *newsk)

#sock_recvmsg   no skb
#sock_recvmsg_nosec   no skb
#skb_queue_walk  define
#skb_copy_datagram_msg   inline

