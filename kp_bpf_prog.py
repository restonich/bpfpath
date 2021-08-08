#!/usr/bin/python

from bcc import BPF

kp_prog="""
#define SKB_FIN (-1llu)

BPF_TABLE("extern", u32, void*, skb_ptr, 1);

int probe(void *ctx){
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
	if (*skb_val == SKB_FIN) return 0;
	/* tracing just started, run other kprobes in case pointer will be added */
	if (*skb_val == 0) return 1;

	bpf_trace_printk("skb: %llx", *skb_val);

	return 1;
}
"""

def kp_generate_and_load():
	
	b = BPF(text=kp_prog)
	b.attach_kprobe(event="ip_rcv", fn_name="probe")

	try:
		b.trace_print()
	except KeyboardInterrupt:
		pass
