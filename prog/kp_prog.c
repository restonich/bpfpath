#include "bpf/libbpf.h"
#include "bpf_api.h"

#define __STRINGIZE(A) #A
#define STRINGIZE(A) __STRINGIZE(A)

#define MAP_KEY_SIZE  4

#define SKB_VAL_SIZE  sizeof(void *)
#define SKB_VAL_AMT   1
#define PATH_VAL_SIZE sizeof(uint64_t)
#define PATH_VAL_AMT  128

#define SKB_FIN (-1llu)

#define KP_NUM_UNDEF  127
#define KP_NAME_UNDEF kfree_skb
#define KP_FIN_UNDEF  1

#ifndef KP_NUM
# define KP_NUM KP_NUM_UNDEF
#endif

#ifndef KP_NAME
# define KP_NAME KP_NAME_UNDEF
#endif

#ifndef KP_FIN
# define KP_FIN KP_FIN_UNDEF
#endif

#define KP_SEC "kprobe/" STRINGIZE(KP_NAME)

__section("maps")
struct bpf_map_def skb_map = {
	.type	     = BPF_MAP_TYPE_ARRAY,
	.key_size    = MAP_KEY_SIZE,
	.value_size  = SKB_VAL_SIZE,
	.max_entries = SKB_VAL_AMT
};

__section("maps")
struct bpf_map_def path_map = {
	.type	     = BPF_MAP_TYPE_ARRAY,
	.key_size    = MAP_KEY_SIZE,
	.value_size  = PATH_VAL_SIZE,
	.max_entries = PATH_VAL_AMT
};

__section(KP_SEC)
int skb_check(struct pt_regs *ctx)
{
	uint32_t skb_key = 0;
	void   **skb_val = map_lookup_elem(&skb_map, &skb_key);

	if (skb_val == NULL) return 0;
	if (*skb_val == 0 || *skb_val == (void *)SKB_FIN) return 0;

	/* non-portable! works for the given kernel only */
	void *skb = (void *)PT_REGS_PARM1(ctx);

	if (skb != *skb_val) return 0;

	uint32_t path_key = KP_NUM;
	uint64_t path_val = ktime_get_ns();
	int r = map_update_elem(&path_map, &path_key, &path_val, BPF_ANY);
	if (r < 0) {
		printt("timestamp not stored!\n");
		return 0;
	}
	printt(STRINGIZE(KP_NAME) ": %llu ns\n", path_val);
	
#if KP_FIN == 1
	*skb_val = (void *)SKB_FIN;
#endif

	return 0;
}

__section("license")
char __license[] = "GPL";

__section("version")
uint32_t _version = LINUX_VERSION_CODE;
