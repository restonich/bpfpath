#ifndef __BPF_API__
# define __BPF_API__

#include <linux/bpf.h>
#include <linux/pkt_cls.h>
#include <linux/filter.h>
#include <linux/ptrace.h>
#include <linux/version.h>

#include <stdint.h>
#include <asm/byteorder.h>

#ifndef __inline__
# define __inline__ __attribute__((always_inline))
#endif

#ifndef __section
# define __section(NAME) __attribute__((section(NAME), used))
#endif

#ifndef BPF_FUNC
# define BPF_FUNC(NAME, ...)				 \
	(* NAME)(__VA_ARGS__) = (void *) BPF_FUNC_##NAME
#endif

/* Map access/manipulation */
static void *BPF_FUNC(map_lookup_elem,
		      void *map, const void *key);
static int   BPF_FUNC(map_update_elem,
		      void *map, const void *key, const void *value, uint64_t flags);
static int   BPF_FUNC(map_delete_elem,
		      void *map, const void *key);

/* Timestamp access */
static uint64_t BPF_FUNC(ktime_get_ns);

/* Debugging */
static void BPF_FUNC(trace_printk,
		     const char *fmt, int fmt_size, ...);
#ifndef printt
# define printt(fmt, ...)					       \
	({							       \
		char ____fmt[] = fmt;				       \
		trace_printk(____fmt, sizeof(____fmt), ##__VA_ARGS__); \
	})
#endif

/* Packet redirection */
static int BPF_FUNC(redirect,
		    int ifindex, uint32_t flags);
static int BPF_FUNC(clone_redirect,
		    struct __sk_buff *skb, int ifindex, uint32_t flags);

/* Fetch registers values from kprobe programs. Works only on x86_64 */
#define PT_REGS_PARM1(x) ((x)->rdi)
#define PT_REGS_PARM2(x) ((x)->rsi)
#define PT_REGS_PARM3(x) ((x)->rdx)
#define PT_REGS_PARM4(x) ((x)->rcx)
#define PT_REGS_PARM5(x) ((x)->r8)
#define PT_REGS_RET(x)   ((x)->rsp)
#define PT_REGS_FP(x)    ((x)->rbp)
#define PT_REGS_RC(x)    ((x)->rax)
#define PT_REGS_SP(x)    ((x)->rsp)
#define PT_REGS_IP(x)    ((x)->rip)

/* LLVM built-ins, mem*() routines work for constant size */
#ifndef lock_xadd
# define lock_xadd(ptr, val) ((void) __sync_fetch_and_add(ptr, val))
#endif

#ifndef memset
# define memset(s, c, n) __builtin_memset((s), (c), (n))
#endif

#ifndef memcpy
# define memcpy(d, s, n) __builtin_memcpy((d), (s), (n))
#endif

#ifndef memmove
# define memmove(d, s, n) __builtin_memmove((d), (s), (n))
#endif

/* Misc macros */
#ifndef htons
# define htons(X) __constant_htons((X))
#endif

#ifndef ntohs
# define ntohs(X) __constant_ntohs((X))
#endif

#ifndef htonl
# define htonl(X) __constant_htonl((X))
#endif

#ifndef ntohl
# define ntohl(X) __constant_ntohl((X))
#endif

#ifndef NULL
# define NULL (void *) 0
#endif

#endif /* __BPF_API__ */
