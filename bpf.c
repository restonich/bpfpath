#include <uapi/linux/pkt_cls.h> 	/* TC_ACT_* */
#include <uapi/linux/if_ether.h> 	/* struct ethhdr */
#include <uapi/linux/ip.h> 			/* struct iphdr */
#include <uapi/linux/tcp.h> 		/* struct tcphdr */
#include <uapi/linux/udp.h> 		/* struct udphdr */
#include <linux/sched.h>			/* TASK_COMM_LEN */
#include <uapi/linux/ptrace.h>		/* PT_REGS_IP */
#include <linux/skbuff.h>
#include <linux/netdevice.h>

#define STOP_TRACE (void *)(-1llu)

BPF_ARRAY(skb_ptr, void*, 1);

BPF_RINGBUF_OUTPUT(tracing_info, 32);

#define TC_COMM "unknown_comm"

struct tracing_data {
	u64  tgid_pid;
	u64  gid_uid;
	char task_comm[TASK_COMM_LEN];

	void *ip_ptr;
	u64  timestamp;
};


static __always_inline struct tracing_data __filter_tracing_data()
{
	struct tracing_data tr_data = {0};

	memcpy(tr_data.task_comm, TC_COMM, TASK_COMM_LEN);
	tr_data.task_comm[TASK_COMM_LEN-1] = 0;

	/* Cannot get this info in TC program, so set to 0, process in userspace */
	tr_data.timestamp = bpf_ktime_get_ns();

	return tr_data;
}

int filter(struct __sk_buff *skb)
{
	/* Check current pointer
	 * Key is always 0, skb_ptr array consists of only one element
	 * skb_val == 0       	 -- tracing just initiated
	 * skb_val == STOP_TRACE -- tracing was concluded or not yet started
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

	/* Filtering routine. Strings get replaced with provided values in the main program
	 * Return TC_ACT_UNSPEC to allow other filters process this packet
	 * Return TC_ACT_OK to stop all TC actions and continue
	 * packet proces by networking stack
	 */
	/* Bounds check depends on wheter we check transport header */
	BOUNDS_CHECK
	/* Check IPv4, if not -- stop all filtering */
	if (eth->h_proto != htons(ETH_P_IP)) return TC_ACT_OK;
	/* Check IP proto */
	IP_PROTO_FILTER
	/* Check source IP */
	SRC_IP_FILTER
	/* Check destination IP */
	DST_IP_FILTER
	/* Check port, either source or destination */
	PORT_FILTER

	skb->mark = 1337;

	void *vall = (void*)skb;
	skb_ptr.update(&skb_key, &vall);

	struct tracing_data tr_data = __filter_tracing_data();
	tracing_info.ringbuf_output(&tr_data, sizeof(tr_data), 0);

	return TC_ACT_OK;
}

static __always_inline struct tracing_data __probe_tracing_data(struct pt_regs *ctx)
{
	struct tracing_data tr_data = {0};

	tr_data.tgid_pid = bpf_get_current_pid_tgid();
	tr_data.gid_uid = bpf_get_current_uid_gid();
	bpf_get_current_comm(&tr_data.task_comm, TASK_COMM_LEN);

	tr_data.ip_ptr = (void *)PT_REGS_IP(ctx);
	tr_data.timestamp = bpf_ktime_get_ns();

	return tr_data;
}

int probe(struct pt_regs *ctx, struct sk_buff *skb)
{
	/* Check current pointer
	 * Key is always 0, skb_ptr array consists of only one element
	 * skb_val == 0       -- tracing just initiated
	 * skb_val == STOP_TRACE -- tracing was concluded or not yet started
	 * other skb_val is the pointer to the traced packet
	 */
	u32 skb_key = 0;
	void **skb_val = NULL;
	skb_val = skb_ptr.lookup(&skb_key);
	/* Safety check, should never go here */
	if (skb_val  == NULL) return 0;
	/* tracing is concluded, don't run other kprobes */
	if (*skb_val == STOP_TRACE) return 0;
	/* tracing just started, run other kprobes in case pointer will be added */
	if (*skb_val == 0) return 1;

	// if ((struct sk_buff*)*skb_val != skb) return 1;
	
	if (skb->mark != 1337) return 0;

	struct tracing_data tr_data = __probe_tracing_data(ctx);
	tracing_info.ringbuf_output(&tr_data, sizeof(tr_data), 0);

	// int skb_iif;
	// int ifindex;
	// char name[16];
	// bpf_probe_read_kernel(&skb_iif, sizeof(int), &skb->skb_iif);
	// bpf_probe_read_kernel(&ifindex, sizeof(int), &skb->dev->ifindex);
	// bpf_probe_read_kernel(&name, 16, &skb->dev->name);
	// bpf_trace_printk("skb->skb_iif: %u", skb_iif);
	// bpf_trace_printk("skb->dev->ifindex: %u", ifindex);
	// bpf_trace_printk("skb->dev->name: %s", name);
	// u32 mark;
	// bpf_probe_read_kernel(&mark, sizeof(u32), &skb->mark);
	// bpf_trace_printk("skb->mark: %llx", mark);

	return 1;
}

int final_probe(struct pt_regs *ctx, struct sk_buff *skb)
{
	/* Check current pointer
	 * Key is always 0, skb_ptr array consists of only one element
	 * skb_val == 0       -- tracing just initiated
	 * skb_val == STOP_TRACE -- tracing was concluded or not yet started
	 * other skb_val is the pointer to the traced packet
	 */
	u32 skb_key = 0;
	void **skb_val = NULL;
	skb_val = skb_ptr.lookup(&skb_key);
	/* Safety check, should never go here */
	if (skb_val  == NULL) return 0;
	/* tracing is concluded, don't run other kprobes */
	if (*skb_val == STOP_TRACE) return 0;
	/* tracing just started, run other kprobes in case pointer will be added */
	if (*skb_val == 0) return 1;

	if ((struct sk_buff*)*skb_val != skb) return 1;

	struct tracing_data tr_data = __probe_tracing_data(ctx);
	tracing_info.ringbuf_output(&tr_data, sizeof(tr_data), 0);
	
	int skb_iif;
	int ifindex;
	char name[16];
	bpf_probe_read_kernel(&skb_iif, sizeof(int), &skb->skb_iif);
	bpf_probe_read_kernel(&ifindex, sizeof(int), &skb->dev->ifindex);
	bpf_probe_read_kernel(&name, 16, &skb->dev->name);
	bpf_trace_printk("skb->skb_iif: %u", skb_iif);
	bpf_trace_printk("skb->dev->ifindex: %u", ifindex);
	bpf_trace_printk("skb->dev->name: %s", name);
	u32 mark;
	bpf_probe_read_kernel(&mark, sizeof(u32), &skb->mark);
	bpf_trace_printk("skb->mark: %llx", mark);

	void *skb_stop = STOP_TRACE;
	skb_ptr.update(&skb_key, &skb_stop);
	return 1;
}
