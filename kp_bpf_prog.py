#!/usr/bin/python

import ctypes as ct

from bcc import BPF

kp_prog="""
#include <linux/sched.h>
#include <uapi/linux/ptrace.h>
#include <net/sock.h>
#include <bcc/proto.h>
#include <linux/skbuff.h>

#define SKB_FIN (-1llu)

#define FN_NAME_LEN 64
#ifndef FN_NAME_STR
# define FN_NAME_STR "unknown_fn"
#endif

BPF_TABLE("extern", u32, void*, skb_ptr, 1);

BPF_RINGBUF_OUTPUT(tracing_info, 128);

struct tracing_data {
	u64  tgid_pid;
	u64  gid_uid;
	char task_comm[TASK_COMM_LEN];

	char fn_name[FN_NAME_LEN];
	u64  timestamp;

	//void *skb;
};

static __always_inline struct tracing_data get_tracing_data()
{
	struct tracing_data tr_data = {
		.fn_name = FN_NAME_STR
	};

	tr_data.tgid_pid = bpf_get_current_pid_tgid();
	tr_data.gid_uid = bpf_get_current_uid_gid();
	bpf_get_current_comm(&tr_data.task_comm, TASK_COMM_LEN);

	tr_data.timestamp = bpf_ktime_get_ns();

	return tr_data;
}

int probe(struct pt_regs *ctx, struct sk_buff *skb)
{
	/* Check current pointer
	 * Key is always 0, skb_ptr array consists of only one element
	 * skb_val == 0       -- tracing just initiated
	 * skb_val == SKB_FIN -- tracing was concluded or not yet started
	 * other skb_val is the pointer to the traced packet
	 */
	u32 skb_key = 0;
	u64 **skb_val = NULL;
	skb_val = (u64 **)skb_ptr.lookup(&skb_key);
	/* Safety check, should never go here */
	if (skb_val  == NULL) return 0;
	/* tracing is concluded, don't run other kprobes */
	if (*skb_val == (u64 *)SKB_FIN) return 0;
	/* tracing just started, run other kprobes in case pointer will be added */
	if (*skb_val == 0) return 1;

	if ((struct sk_buff*)*skb_val != skb) return 1;

	struct tracing_data tr_data = get_tracing_data();
	//tr_data.skb = (void *)skb;
	tracing_info.ringbuf_output(&tr_data, sizeof(tr_data), BPF_RB_FORCE_WAKEUP /* flags */);

	//void *skb_fin = (void *)SKB_FIN;
	//skb_ptr.update(&skb_key, &skb_fin);

	return 1;
}
"""

TASK_COMM_LEN = 16    # linux/sched.h
FN_NAME_LEN   = 64
class tracing_data(ct.Structure):
    _fields_ = [("tgid_pid", ct.c_uint64),
				("gid_uid", ct.c_uint64),
				("task_comm", ct.c_char * TASK_COMM_LEN),
				("fn_name", ct.c_char * FN_NAME_LEN),
                ("timestamp", ct.c_uint64)]

def tracing_event(ctx, data, size):
	tr_data = ct.cast(data, ct.POINTER(tracing_data)).contents

	print(f"{tr_data.tgid_pid} {tr_data.gid_uid} {tr_data.task_comm} fn: {tr_data.fn_name.decode('utf-8')}  ts: {tr_data.timestamp}")

def kp_generate_and_load():
	bpfs = []

	b = BPF(text=kp_prog, cflags=['-DFN_NAME_STR="consume_skb"'])
	b.attach_kprobe(event="consume_skb", fn_name="probe")
	b['tracing_info'].open_ring_buffer(tracing_event)
	bpfs.append(b)

	b = BPF(text=kp_prog, cflags=['-DFN_NAME_STR="kfree_skb"'])
	b.attach_kprobe(event="kfree_skb", fn_name="probe")
	b['tracing_info'].open_ring_buffer(tracing_event)
	bpfs.append(b)
	
	b = BPF(text=kp_prog, cflags=['-DFN_NAME_STR="ip_local_deliver"'])
	b.attach_kprobe(event="ip_local_deliver", fn_name="probe")
	b['tracing_info'].open_ring_buffer(tracing_event)
	bpfs.append(b)
	
	b = BPF(text=kp_prog, cflags=['-DFN_NAME_STR="tcp_v4_rcv"'])
	b.attach_kprobe(event="tcp_v4_rcv", fn_name="probe")
	b['tracing_info'].open_ring_buffer(tracing_event)
	bpfs.append(b)

	b = BPF(text=kp_prog, cflags=['-DFN_NAME_STR="ip_rcv"'])
	b.attach_kprobe(event="ip_rcv", fn_name="probe")
	b['tracing_info'].open_ring_buffer(tracing_event)
	bpfs.append(b)

	return bpfs
