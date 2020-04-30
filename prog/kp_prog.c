#include <linux/ptrace.h>
#include <linux/version.h>
#include "bpf_api.h"

#define _(P) ({typeof(P) val = 0; probe_read(&val, sizeof(val), &P); val;})

struct bpf_map_def skb_map __section("maps") = {
	.type 			= BPF_MAP_TYPE_ARRAY,
	.key_size 		= sizeof(uint32_t),
	.value_size 	= sizeof(void *),
	.max_entries 	= 1
};

__section("kprobe/kfree_skb")
int kprobe_test(struct pt_regs *ctx)
{
	void *skb;
	uint32_t key, r;

	/* non-portable! works for the given kernel only */
	skb = (void *) PT_REGS_PARM1(ctx);

	printt("skb: %lx\n", skb);

	key = 0;
	r = map_update_elem(&skb_map, &key, &skb, BPF_ANY);
	if (r < 0) {
		printt("skb not stored!\n");
		return 0;
	}
	
	return 0;
}

char __license[] __section("license") = "GPL";
uint32_t _version __section("version") = LINUX_VERSION_CODE;
