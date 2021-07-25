#include <uapi/linux/if_ether.h>
#include <uapi/linux/ip.h>
#include <uapi/linux/bpf.h>

#define MAP_KEY_SIZE  4

#define SKB_VAL_SIZE  sizeof(void *)
#define SKB_VAL_AMT   1
#define PATH_VAL_SIZE sizeof(uint64_t)
#define PATH_VAL_AMT  128

#define FILTER_IP_PROTO IPPROTO_ICMP
#define FILTER_SRC_IP   0xAC1F000A /* 172.31.0.10 */

#define TC_NUM  0
#define TC_NAME "__netif_receive_skb_core"


BPF_ARRAY(skb_ptr, (void *), 1)

int filter(struct __sk_buff *skb)
{
	/* Check current pointer
	 * Key is always 0, skb_ptr array consists of only one element
	 * skb_val != 0 means that the packet is already traced
	 * or tracing is not yet initiated
	 */
	u32 skb_key = 0;
	void **skb_val = NULL;
	skb_val = skb_ptr.lookup(&skb_key)
	if (skb_val  == NULL) return TC_ACT_OK;
	if (*skb_val != 0)    return TC_ACT_OK;

	/* Get header pointers for filtering */
	void         *data = (void *)(long)skb->data;
	void     *data_end = (void *)(long)skb->data_end;
	struct ethhdr *eth = data;
	struct iphdr  *iph = data + sizeof(*eth);
	/* Bounds check */
	if (data + sizeof(*eth) + sizeof(*iph) > data_end) return TC_ACT_OK;

	/* Return TC_ACT_UNSPEC to allow other filters process this packet
	 * Return TC_ACT_OK to stop all TC actions and continue
	 * packet proces by networking stack
	 */
	
	// PROGRAMMABLE_BPF_FILTER
	//  /* Check IPv4 */
	// if (eth->h_proto != htons(ETH_P_IP)) return TC_ACT_UNSPEC;
	// /* Check IP protocol */
	// if (iph->protocol != FILTER_IP_PROTO) return TC_ACT_UNSPEC;
	// /* Check src IP address */
	// if (iph->saddr != htonl(FILTER_SRC_IP)) return TC_ACT_UNSPEC;

	/* That is probably wrong. This value should be stored properly */
	/* *skb_val = (void *)skb; */
	skb_ptr.update(&skb_key, &skb);

	u64 timestamp = bpf_ktime_get_ns();
	bpf_trace_printk("Timestamp: %li", timestamp);

	return TC_ACT_OK;
}
