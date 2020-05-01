#include <linux/ptrace.h>
#include <linux/version.h>
#include "bpf_api.h"

#define MAP_KEY_SIZE	 4
#define SKB_PTR_VAL_SIZE sizeof(void *)
#define SKB_PTR_VAL_AMT	 1
#define TSTAMP_VAL_SIZE	 sizeof(uint64_t)
#define TSTAMP_VAL_AMT	 256
#define PATH_VAL_SIZE	 sizeof(uint8_t)
#define PATH_VAL_AMT	 256

#if 0
#define KP_SEC "kprobe/icmp_rcv"
#define KP_NUM 0x1
#endif

#define KP_SEC_UNDEF "kprobe/kfree_skb"
#define KP_NUM_UNDEF 0xff

#ifndef KP_SEC
# define KP_SEC KP_SEC_UNDEF
#endif

#ifndef KP_NUM
# define KP_NUM KP_NUM_UNDEF
#endif

__section("maps")
struct bpf_map_def skb_ptr_map = {
	.type	     = BPF_MAP_TYPE_ARRAY,
	.key_size    = MAP_KEY_SIZE,
	.value_size  = SKB_PTR_VAL_SIZE,
	.max_entries = SKB_PTR_VAL_AMT
};

__section("maps")
struct bpf_map_def tstamp_map = {
	.type	     = BPF_MAP_TYPE_ARRAY,
	.key_size    = MAP_KEY_SIZE,
	.value_size  = TSTAMP_VAL_SIZE,
	.max_entries = TSTAMP_VAL_AMT
};

__section("maps")
struct bpf_map_def path_map = {
	.type	     = BPF_MAP_TYPE_ARRAY,
	.key_size    = MAP_KEY_SIZE,
	.value_size  = PATH_VAL_SIZE,
	.max_entries = PATH_VAL_AMT
};

__section(KP_SEC)
int kp_program(struct pt_regs *ctx)
{
	void    *skb;
	uint32_t skb_ptr_key;
	void    *skb_ptr_val;
	void   **skb_ptr_cur;
	uint32_t tstamp_key;
	uint64_t tstamp_val;
	uint32_t path_key;
	uint8_t  path_value;
	int err;

	skb_ptr_key = 0;
	skb_ptr_cur = map_lookup_elem(&skb_ptr_map, &skb_ptr_key);
	if (skb_ptr_cur == NULL) {
		printt("This should never happen.\n");
		return 0;
	}

	/* non-portable! works for the given kernel only */
	skb = (void *) PT_REGS_PARM1(ctx);

	printt("--------KP_PROG--------\n");
	printt("skb: \t\t%llx\n", skb);
	printt("*skb_ptr_cur: \t%llx\n", *skb_ptr_cur);

	if (skb != *skb_ptr_cur) {
		printt("Nah\n");
	}

	printt("Match!\n");

	tstamp_key = KP_NUM;
	tstamp_val = ktime_get_ns();
	err = map_update_elem(&tstamp_map, &tstamp_key, &tstamp_val, BPF_ANY);
	if (err < 0) {
		printt("ts not stored!\n");
		return TC_ACT_OK;
	}
	printt("tstamp_val: \t\t%lx\n", tstamp_val);

	path_key = KP_NUM;
	path_value = 0x1;
	err = map_update_elem(&path_map, &path_key, &path_value, BPF_ANY);
	if (err < 0) {
		printt("function name not stored!\n");
		return TC_ACT_OK;
	}
	printt("path_key: \t\t%lx\n", path_key);
	
	/* This should be done in user space */
#if 1
	skb_ptr_val = 0;
	err = map_update_elem(&skb_ptr_map, &skb_ptr_key, &skb_ptr_val, BPF_ANY);
	if (err < 0) {
		printt("skb not stored!\n");
		return 0;
	}
#endif

	return 0;
}

__section("license")
char __license[] = "GPL";

__section("version")
uint32_t _version = LINUX_VERSION_CODE;

