#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <iproute2/bpf_elf.h>

#include "bpf_api.h"

#define MAP_KEY_SIZE  4

#define SKB_VAL_SIZE  sizeof(void *)
#define SKB_VAL_AMT   1
#define PATH_VAL_SIZE sizeof(uint64_t)
#define PATH_VAL_AMT  128

#define FILTER_IP_PROTO IPPROTO_ICMP
#define FILTER_SRC_IP   0xAC1F000A /* 172.31.0.10 */

#define TC_NUM  0
#define TC_NAME "__netif_receive_skb_core"

__section("maps")
struct bpf_elf_map skb_map = {
	.type 		= BPF_MAP_TYPE_ARRAY,
	.size_key 	= MAP_KEY_SIZE,
	.size_value 	= SKB_VAL_SIZE,
	.max_elem 	= SKB_VAL_AMT,
	.pinning 	= PIN_GLOBAL_NS
};

__section("maps")
struct bpf_elf_map path_map = {
	.type 		= BPF_MAP_TYPE_ARRAY,
	.size_key 	= MAP_KEY_SIZE,
	.size_value 	= PATH_VAL_SIZE,
	.max_elem 	= PATH_VAL_AMT,
	.pinning 	= PIN_GLOBAL_NS
};

__section("main")
int skb_filter(struct __sk_buff *skb)
{
	/* Check current pointer */
	uint32_t skb_key = 0;
	void   **skb_val = map_lookup_elem(&skb_map, &skb_key);
	if (skb_val  == NULL) return TC_ACT_OK;
	if (*skb_val != 0)    return TC_ACT_OK;

	void         *data = (void *)(long)skb->data;
	void     *data_end = (void *)(long)skb->data_end;
	struct ethhdr *eth = data;
	struct iphdr  *iph = data + sizeof(*eth);

	/* Bounds check */
	if (data + sizeof(*eth) + sizeof(*iph) > data_end) return TC_ACT_OK;
	/* Check network protocol */
	if (eth->h_proto != htons(ETH_P_IP)) return TC_ACT_OK;
	/* Check transport protocol */
	if (iph->protocol != FILTER_IP_PROTO) return TC_ACT_OK;
	/* Check src IP address */
	if (iph->saddr != htonl(FILTER_SRC_IP)) return TC_ACT_OK;

	/* That is probably wrong. This value should be stored properly */
	*skb_val = (void *)skb;

	uint32_t path_key = TC_NUM;
	uint64_t path_val = ktime_get_ns();
	int r = map_update_elem(&path_map, &path_key, &path_val, BPF_ANY);
	if (r < 0) {
		printt("timestamp not stored!\n");
		return TC_ACT_OK;
	}
	printt(TC_NAME ": %llu ns\n", path_val);

	return TC_ACT_OK;
}

__section("license")
char __license[] = "GPL";
