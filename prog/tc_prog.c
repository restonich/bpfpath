#include "bpf_api.h"

#include <linux/if_ether.h>
#include <linux/ip.h>
#include <iproute2/bpf_elf.h>

#define IP_P_ICMP 0x01
#define IP_SRC 0xAC1F000A /* 172.31.0.10 */

struct bpf_elf_map __section("maps") skb_map = {
	.type 		= BPF_MAP_TYPE_ARRAY,
	.size_key 	= sizeof(uint32_t),
	.size_value 	= sizeof(uint64_t),
	.pinning 	= PIN_GLOBAL_NS,
	.max_elem 	= 1
};

struct bpf_elf_map __section("maps") timestamp_map = {
	.type 		= BPF_MAP_TYPE_ARRAY,
	.size_key 	= sizeof(uint32_t),
	.size_value 	= sizeof(uint64_t),
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
	uint64_t time = ktime_get_ns();
	void *data = (void *)(long)skb->data;
	void *data_end = (void *)(long)skb->data_end;
	struct eth_hdr *eth = data;
	struct iphdr *iph = data + sizeof(*eth);

	printt("skb received\n");

	/* Bounds check */
	if (data + sizeof(*eth) + sizeof(*iph) > data_end) {
		return TC_ACT_UNSPEC;
	}
	printt("bounds good\n");

	/* Check if IP protocol */
	if (eth->h_proto != htons(ETH_P_IP)) {
		return TC_ACT_UNSPEC;
	}
	printt("IP protocol. eth->h_proto = %u\n", ntohs(eth->h_proto));

	/* Check if ICMP protocol */
	if (iph->protocol != IP_P_ICMP) {
		return TC_ACT_UNSPEC;
	}
	printt("ICMP protocol. iph->protocol = %u\n", iph->protocol);

	/* Check if source address is IP_SRC */
	if (iph->saddr != htonl(IP_SRC)) {
		return TC_ACT_UNSPEC;
	}
	printt("Valid source address. iph->saddr = %lu\n", ntohl(iph->saddr));

	/* Search skb address value by key. This should be always found,
	 * as in BPF_MAP_TYPE_ARRAY all elements always exist.
	 */
	uint32_t skb_key = 0;
	uint64_t *stored_val;
	uint64_t skb_head = skb->head;
	stored_val = map_lookup_elem(&skb_map, &skb_key);
	if (stored_val != NULL) {
		if (*stored_val != 0) {
			printt("skb already stored; *stored_val = %lx\n", *stored_val);

			return TC_ACT_OK;
		} else {
			int r;

			r = map_update_elem(&skb_map, &skb_key, &skb_head, BPF_ANY);
			if (r < 0) {
				printt("skb not stored!\n");
				return TC_ACT_UNSPEC;
			}

			uint32_t time_key = 0;
			r = map_update_elem(&timestamp_map, &time_key, &time, BPF_ANY);
			if (r < 0) {
				printt("time not stored!\n");
				return TC_ACT_UNSPEC;
			}
			
			printt("skb stored\n");
			printt("time: %lx\n", time);
			return TC_ACT_OK;
		}
	}

	printt("Bad key!\n");
	return TC_ACT_UNSPEC;
}

char __license[] __section("license") = "GPL";

