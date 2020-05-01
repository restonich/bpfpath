#include "bpf_api.h"

#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <iproute2/bpf_elf.h>

#define IP_SRC 0xAC1F000A /* 172.31.0.10 */

#define MAP_KEY_SIZE	 4
#define SKB_PTR_VAL_SIZE sizeof(void *)
#define SKB_PTR_VAL_AMT	 1
#define TSTAMP_VAL_SIZE	 sizeof(uint64_t)
#define TSTAMP_VAL_AMT	 256
#define PATH_VAL_SIZE	 sizeof(uint8_t)
#define PATH_VAL_AMT	 256

#define FUNC_NUM 0x0

__section("maps")
struct bpf_elf_map skb_ptr_map = {
	.type 		= BPF_MAP_TYPE_ARRAY,
	.size_key 	= MAP_KEY_SIZE,
	.size_value 	= SKB_PTR_VAL_SIZE,
	.max_elem 	= SKB_PTR_VAL_AMT,
	.pinning 	= PIN_GLOBAL_NS
};

__section("maps")
struct bpf_elf_map tstamp_map = {
	.type 		= BPF_MAP_TYPE_ARRAY,
	.size_key 	= MAP_KEY_SIZE,
	.size_value 	= TSTAMP_VAL_SIZE,
	.max_elem 	= TSTAMP_VAL_AMT,
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

/* copy of 'struct ethhdr' without __packed */
struct eth_hdr {
	unsigned char   h_dest[ETH_ALEN];
	unsigned char   h_source[ETH_ALEN];
	unsigned short  h_proto;
};

__section("main")
int icmp_check(struct __sk_buff *skb)
{
	void *data     = (void *)(long)skb->data;
	void *data_end = (void *)(long)skb->data_end;
	struct ethhdr *eth = data;
	struct iphdr  *iph = data + sizeof(*eth);
	uint32_t skb_ptr_key;
	void    *skb_ptr_val;
	void   **skb_ptr_cur;
	uint32_t tstamp_key;
	uint64_t tstamp_val;
	uint32_t path_key;
	uint8_t  path_value;
	int err;

	/* Bounds check */
	if (data + sizeof(*eth) + sizeof(*iph) > data_end) {
		return TC_ACT_OK;
	}

	/* Check if IP protocol */
	if (eth->h_proto != htons(ETH_P_IP)) {
		return TC_ACT_OK;
	}

	/* Check if ICMP protocol */
	if (iph->protocol != IPPROTO_ICMP) {
		return TC_ACT_OK;
	}

	/* Check if source address is IP_SRC */
	if (iph->saddr != htonl(IP_SRC)) {
		return TC_ACT_OK;
	}

	printt("--------SKB MATCH--------\n");

	skb_ptr_key = 0;
	skb_ptr_cur = map_lookup_elem(&skb_ptr_map, &skb_ptr_key);
	if (skb_ptr_cur == NULL) {
		printt("This should never happen.\n");
		return TC_ACT_OK;
	}

	if (*skb_ptr_cur != 0) {
		printt("skb_ptr already stored\n");
		return TC_ACT_OK;
	} 	

	/* That is a hack. This value needs to be stored properly */
	skb_ptr_val = (void *)skb;
	*skb_ptr_cur = skb_ptr_val;
	printt("skb_ptr: \t\t%lx\n", skb_ptr_val);

	/* tstamp upon arrival here */
	tstamp_key = FUNC_NUM;
	tstamp_val = ktime_get_ns();
	err = map_update_elem(&tstamp_map, &tstamp_key, &tstamp_val, BPF_ANY);
	if (err < 0) {
		printt("ts not stored!\n");
		return TC_ACT_OK;
	}
	printt("tstamp_val: \t\t%lx\n", tstamp_val);

	path_key = FUNC_NUM;
	path_value = 0x1;
	err = map_update_elem(&path_map, &path_key, &path_value, BPF_ANY);
	if (err < 0) {
		printt("function name not stored!\n");
		return TC_ACT_OK;
	}
	printt("path_key: \t\t%lx\n", path_key);

	return TC_ACT_OK;
}

__section("license")
char __license[] = "GPL";

