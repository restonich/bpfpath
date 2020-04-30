#include <linux/ptrace.h>
#include <linux/version.h>
#include "bpf_api.h"

#define _(P) ({typeof(P) val = 0; probe_read(&val, sizeof(val), &P); val;})

#define MAP_SIZE_KEY 4
#define FUNC_NAME_LEN 64

#ifndef FUNC_NAME
# define FUNC_NAME "undefined_func"
#endif

__section("maps")
struct bpf_map_def skb_ptr_map = {
	.type	     = BPF_MAP_TYPE_ARRAY,
	.key_size    = MAP_SIZE_KEY,
	.value_size  = sizeof(void *),
	.max_entries = 1
};

__section("maps")
struct bpf_map_def ts_map = {
	.type	     = BPF_MAP_TYPE_ARRAY,
	.key_size    = MAP_SIZE_KEY,
	.value_size  = sizeof(uint64_t),
	.max_entries = 2
};

__section("maps")
struct bpf_map_def path_map = {
	.type	     = BPF_MAP_TYPE_ARRAY,
	.key_size    = MAP_SIZE_KEY,
	.value_size  = FUNC_NAME_LEN,
	.max_entries = 2
};

__section("kprobe/icmp_rcv")
int kp_program(struct pt_regs *ctx)
{
	void *skb, **skb_ptr;
	uint64_t ts = ktime_get_ns();
	uint32_t r;

	printt("--------KP_PROG--------\n");
	/* non-portable! works for the given kernel only */
	skb = (void *) PT_REGS_PARM1(ctx);
	printt("skb: \t\t%llx\n", skb);

	uint32_t skb_ptr_key = 0;
	skb_ptr = map_lookup_elem(&skb_ptr_map, &skb_ptr_key);
	if (skb_ptr != NULL) {
		if (*skb_ptr != 0) {
			printt("skb_ptr: \t\t%llx\n", *skb_ptr);
		} else {
			printt("skb_ptr: \t\t%llx\n", *skb_ptr);
			return 0;
		}
	} else {
		printt("skb_ptr is NULL\n");
		return 0;
	}
#if 1
	if (skb == *skb_ptr) {
		printt("MATCH!\n");

		uint64_t skb_ptr_value = 0;
		r = map_update_elem(&skb_ptr_map, &skb_ptr_key, &skb_ptr_value, BPF_ANY);
		if (r < 0) {
			printt("skb not stored!\n");
			return 0;
		}

		uint32_t ts_key = 1;
		r = map_update_elem(&ts_map, &ts_key, &ts, BPF_ANY);
		if (r < 0) {
			printt("ts not stored!\n");
			return 0;
		}
/*
		uint32_t path_key = 1;
		char path_value[FUNC_NAME_LEN] = FUNC_NAME;
		r = map_update_elem(&path_map, &path_key, &path_value, BPF_ANY);
		if (r < 0) {
			printt("function name not stored!\n");
			return 0;
		}
		*/
		
		printt("ts: %lx\n", ts);
		return 0;
	} else {
		printt("Nah\n");
	}
#endif

	return 0;
}

__section("license")
char __license[] = "GPL";

__section("version")
uint32_t _version = LINUX_VERSION_CODE;

