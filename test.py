#!/usr/bin/python

from bcc import BPF

prog="""
#undef __entry
#define __entry args

#undef __get_dynamic_array
#define __get_dynamic_array(field)	\
		((void *)__entry + (__entry->data_loc_##field & 0xffff))


#undef __get_str
#define __get_str(field) ((char *)__get_dynamic_array(field))

TRACEPOINT_PROBE(net, netif_receive_skb) {
    // args is from /sys/kernel/debug/tracing/events/random/urandom_read/format
    bpf_trace_printk("[%s] skb=%p len=%i\\n", __get_str(name), args->skbaddr, args->len);
    return 0;
}
"""

BPF(text=prog).trace_print()
