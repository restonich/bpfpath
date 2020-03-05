#include "bpf_api.h"

#include <linux/if_ether.h>
#include <linux/ip.h>
#include <iproute2/bpf_elf.h>

struct bpf_elf_map __section("maps") skb_map = {
	.type 		= BPF_MAP_TYPE_ARRAY,
	.size_key 	= sizeof(uint32_t),
	.size_value 	= sizeof(uint64_t),
	.pinning 	= PIN_GLOBAL_NS,
	.max_elem 	= 3
};

__section("main")
int icmp_check(struct __sk_buff *skb)
{
	uint64_t head = skb->head;

	printt("########\n");
	printt("%lx\n", head);
	printt("%lx\n", skb->data);
	uint32_t key = 1;
	map_update_elem(&skb_map, &key, &head, BPF_ANY);

	return 0;
}

char __license[] __section("license") = "GPL";

