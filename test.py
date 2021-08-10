#!/usr/bin/python

from bcc import BPF

# prog="""
# #undef __entry
# #define __entry args

# #undef __get_dynamic_array
# #define __get_dynamic_array(field)	\
# 		((void *)__entry + (__entry->data_loc_##field & 0xffff))


# #undef __get_str
# #define __get_str(field) ((char *)__get_dynamic_array(field))

# TRACEPOINT_PROBE(net, netif_receive_skb) {
#     // args is from /sys/kernel/debug/tracing/events/random/urandom_read/format
#     bpf_trace_printk("[%s] skb=%p len=%i\\n", __get_str(name), args->skbaddr, args->len);
#     return 0;
# }
# """

# BPF(text=prog).trace_print()

prog="""
#include <uapi/linux/ptrace.h>
#include <bcc/proto.h>

BPF_RINGBUF_OUTPUT(tracing_info, 4);

struct tracing_data {
	void *ip_ptr;
};

int func(struct pt_regs *ctx)
{
	struct tracing_data tr_data = {0};

	tr_data.ip_ptr = (void *)PT_REGS_IP(ctx);

	tracing_info.ringbuf_output(&tr_data, sizeof(tr_data), 0 /* flags */);
	return 0;
}
"""

b = BPF(text=prog)

def tracing_event(ctx, data, size):
	event = b["tracing_info"].event(data)

	fn = b.ksym(event.ip_ptr)
	print(f"[{event.ip_ptr}] fn: {fn}")

b.attach_kprobe(event="consume_skb", fn_name="func")
b.attach_kprobe(event="ip_rcv", fn_name="func")
b.attach_kprobe(event="__netif_receive_skb_core", fn_name="func")
b['tracing_info'].open_ring_buffer(tracing_event)

try:
	while True:
		b.ring_buffer_poll(10000)
except KeyboardInterrupt:
	exit
