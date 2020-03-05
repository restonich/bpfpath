#include <stdint.h>
#include <linux/bpf.h>
#include <linux/pkt_cls.h>
#include <linux/filter.h>
#include <iproute2/bpf_elf.h>

#ifndef NULL
# define NULL ((void *)0)
#endif

#ifndef BPF_F_EGRESS
# define BPF_F_EGRESS 0
#endif

#ifndef __section
# define __section(NAME)						\
	__attribute__((section(NAME), used))
#endif

#ifndef BPF_FUNC
# define BPF_FUNC(NAME, ...)						\
	(* NAME)(__VA_ARGS__) = (void *) BPF_FUNC_##NAME
#endif

static void *BPF_FUNC(map_lookup_elem, void *map, const void *key);
static int BPF_FUNC(redirect, int ifindex, uint32_t flags);
static int BPF_FUNC(clone_redirect, struct __sk_buff *skb, int ifindex,
		    uint32_t flags);

#define BOND_KEY 0
#define VETH_KEY 1

struct bpf_elf_map __section("maps") ifindex_map = {
	.type 		= BPF_MAP_TYPE_ARRAY,
	.size_key 	= sizeof(uint32_t),
	.size_value 	= sizeof(uint32_t),
	.pinning 	= PIN_GLOBAL_NS,
	.max_elem 	= 2
};

__section("mirror")
int bpf_mirror(struct __sk_buff *skb)
{
	int key, *val, ifindex, r;

	key = VETH_KEY;
	val = map_lookup_elem(&ifindex_map, &key);
	if (val == NULL) {
		return TC_ACT_OK;
	}
	
	ifindex = *val;
	if (ifindex == 0) {
		return TC_ACT_OK;
	}

	r = clone_redirect(skb, ifindex, BPF_F_EGRESS);
	if (r < 0) {
		return TC_ACT_UNSPEC;
	}

	return TC_ACT_OK;
}

__section("redirect")
int bpf_redirect()
{
	int key, *val, ifindex;

	key = BOND_KEY;
	val = map_lookup_elem(&ifindex_map, &key);
	if (val == NULL) {
		return TC_ACT_OK;
	}
	
	ifindex = *val;
	if (ifindex == 0) {
		return TC_ACT_OK;
	}

	return redirect(ifindex, BPF_F_EGRESS);
}

char __license[] __section("license") = "GPL";

