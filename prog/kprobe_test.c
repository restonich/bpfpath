#include <linux/ptrace.h>
#include <linux/version.h>
#include "bpf_api.h"

#define NULL (void *) 0
#define _(P) ({typeof(P) val = 0; probe_read(&val, sizeof(val), &P); val;})

struct bpf_map_def __section("maps") skb_map = {
	.type 		= BPF_MAP_TYPE_ARRAY,
	.key_size 	= sizeof(uint32_t),
	.value_size 	= sizeof(uint64_t),
	.max_entries 	= 1
};
struct bpf_map_def __section("maps") timestamp_map = {
	.type 		= BPF_MAP_TYPE_ARRAY,
	.key_size 	= sizeof(uint32_t),
	.value_size 	= sizeof(uint64_t),
	.max_entries 	= 2
};

/* static int __netif_receive_skb_core(struct sk_buff *skb, bool pfmemalloc,
 * 				    struct packet_type **ppt_prev)
 */
__section("kprobe/kfree_skb")
int kprobe_test(struct pt_regs *ctx)
{
	uint64_t time = ktime_get_ns();
	uint32_t key, r;
	uint64_t skb, *stored_skb, *stored_time;

	/* non-portable! works for the given kernel only */
	skb = (uint64_t) PT_REGS_PARM1(ctx);

	printt("####\n");
	printt("skb: %lx\n", skb);

	key = 0;
	stored_skb = map_lookup_elem(&skb_map, &key);
	if (stored_skb != NULL) {
		if (*stored_skb == skb) {
			printt("match!\n");
			key = 0;
			stored_time = map_lookup_elem(&timestamp_map, &key);
			if (*stored_time > time) {
				printt("stored time bad\n");
				return TC_ACT_UNSPEC;
			}

			uint64_t time_diff = time - *stored_time;
			printt("time in kernel: %lu ns\n", time_diff);

			key = 1;
			r = map_update_elem(&timestamp_map, &key, &time, BPF_ANY);
			if (r < 0) {
				printt("time not stored!\n");
				return TC_ACT_UNSPEC;
			}

			key = 0;
			skb = 0l;
			r = map_update_elem(&skb_map, &key, &skb, BPF_ANY);
			if (r < 0) {
				printt("skb not stored!\n");
				return TC_ACT_UNSPEC;
			}

			printt("done. ready for another tracing\n");

			return TC_ACT_OK;
		} else {
			return TC_ACT_OK;
		}
	}

	printt("bad key\n");
	return TC_ACT_UNSPEC;
}

uint32_t _version __section("version") = LINUX_VERSION_CODE;
char __license[] __section("license") = "GPL";

