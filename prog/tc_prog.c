#include "bpf_api.h"

#include <linux/if_ether.h>
#include <linux/ip.h>
#include <iproute2/bpf_elf.h>

#define IP_P_ICMP 0x01
#define IP_SRC 0xAC1F000A /* 172.31.0.10 */

#define MAP_SIZE_KEY 4
#define FUNC_NAME_LEN 64

#define FUNC_NAME "__netif_receive_skb_core"

__section("maps")
struct bpf_elf_map skb_ptr_map = {
	.type 		= BPF_MAP_TYPE_ARRAY,
	.size_key 	= MAP_SIZE_KEY,
	.size_value 	= sizeof(void *),
	.pinning 	= PIN_GLOBAL_NS,
	.max_elem 	= 1
};

__section("maps")
struct bpf_elf_map ts_map = {
	.type 		= BPF_MAP_TYPE_ARRAY,
	.size_key 	= MAP_SIZE_KEY,
	.size_value 	= sizeof(uint64_t),
	.pinning 	= PIN_GLOBAL_NS,
	.max_elem 	= 2
};

__section("maps")
struct bpf_elf_map path_map = {
	.type 		= BPF_MAP_TYPE_ARRAY,
	.size_key 	= MAP_SIZE_KEY,
	.size_value 	= FUNC_NAME_LEN,
	.pinning 	= PIN_GLOBAL_NS,
	.max_elem 	= 2
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
	uint64_t ts = ktime_get_ns();
	void *data = (void *)(long)skb->data;
	void *data_end = (void *)(long)skb->data_end;
	struct ethhdr *eth = data;
	struct iphdr *iph = data + sizeof(*eth);

	printt("skb received\n");

	/* Bounds check */
	if (data + sizeof(*eth) + sizeof(*iph) > data_end) {
		return TC_ACT_OK;
	}
	printt("bounds good\n");

	/* Check if IP protocol */
	if (eth->h_proto != htons(ETH_P_IP)) {
		return TC_ACT_OK;
	}
	printt("IP protocol. eth->h_proto = %u\n", ntohs(eth->h_proto));

	/* Check if ICMP protocol */
	if (iph->protocol != IP_P_ICMP) {
		return TC_ACT_OK;
	}
	printt("ICMP protocol. iph->protocol = %u\n", iph->protocol);

	/* Check if source address is IP_SRC */
	if (iph->saddr != htonl(IP_SRC)) {
		return TC_ACT_OK;
	}
	printt("Valid source address. iph->saddr = %lu\n", ntohl(iph->saddr));

	uint32_t skb_path_key = 0;
	uint64_t *stored_val;
	uint64_t skb_head = (unsigned long)skb->head;
	stored_val = map_lookup_elem(&skb_ptr_map, &skb_path_key);
	if (stored_val != NULL) {
		if (*stored_val != 0) {
			printt("skb already stored; *stored_val = %lx\n", *stored_val);

			int r;
			skb_head = 0;
			r = map_update_elem(&skb_ptr_map, &skb_path_key, &skb_head, BPF_ANY);
			if (r < 0) {
				printt("skb not stored!\n");
				return TC_ACT_OK;
			}

			return TC_ACT_OK;
		} else {
			int r;

			r = map_update_elem(&skb_ptr_map, &skb_path_key, &skb_head, BPF_ANY);
			if (r < 0) {
				printt("skb not stored!\n");
				return TC_ACT_OK;
			}

			uint32_t ts_key = 0;
			r = map_update_elem(&ts_map, &ts_key, &ts, BPF_ANY);
			if (r < 0) {
				printt("ts not stored!\n");
				return TC_ACT_OK;
			}

			uint32_t path_key = 0;
			char path_value[FUNC_NAME_LEN] = FUNC_NAME;
			r = map_update_elem(&path_map, &path_key, &path_value, BPF_ANY);
			if (r < 0) {
				printt("function name not stored!\n");
				return TC_ACT_OK;
			}
			
			printt("skb stored: %lx\n", skb_head);
			printt("ts: %lx\n", ts);
			return TC_ACT_OK;
		}
	}

	printt("Bad key!\n");
	return TC_ACT_OK;
}

__section("license")
char __license[] = "GPL";

