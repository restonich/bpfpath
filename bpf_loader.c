#include <stdio.h>
#include <errno.h>
#include "bpf/libbpf.h"

#define CHECK(cond, tag, format...) ({		\
	int __check = !!(cond);			\
	if (__check) {				\
		printf("FAIL:%s ", tag);	\
		printf(format);			\
	} else {				\
		printf("PASS:%s\n", tag);	\
	}					\
	__check;				\
})

#define MAX_ERRNO 4095

#define IS_ERR_VALUE(x) (unsigned long)(void *)(x) >= (unsigned long)-MAX_ERRNO

static inline long PTR_ERR(const void *ptr)
{
	return (long) ptr;
}

static inline bool IS_ERR(const void *ptr)
{
	return IS_ERR_VALUE((unsigned long)ptr);
}

int main(int argc, const char **argv)
{
	struct bpf_object *obj;
	struct bpf_program *prog;
	struct bpf_map *map;
	struct bpf_link *link = NULL;
	char obj_file[64], prog_sec[64], map_name[64], kprobe_name[64];
	int prog_fd, map_fd, err;

	if (argc < 5) {
		printf("Usage: sudo ./bpf_loader OBJ SEC MAP KPROBE");
		return 0;
	}
	/* there are no parsing or checks performed, so input must be right
	 * parsing and testing would be performed by bpftool when I will (hopefully)
	 * pactch kprobe adding functionality to it
	 */
	strncpy(obj_file, argv[1], 64);
	strncpy(prog_sec, argv[2], 64);
	strncpy(map_name, argv[3], 64);
	strncpy(kprobe_name, argv[4], 64);

	/* load program */
	err = bpf_prog_load(obj_file, BPF_PROG_TYPE_KPROBE, &obj, &prog_fd);
	if (CHECK(err, "bpf_prog_load", "err %d errno %d\n", err, errno)) {
		return 0;
	}

	/* get prog struct */
	prog = bpf_object__find_program_by_title(obj, prog_sec);
	if (CHECK(!prog, "bpf_object__find_program_by_title", "prog not found!\n")) {
		goto cleanup;
	}

	/* get map struct and fd */
	map = bpf_object__find_map_by_name(obj, map_name);
	if (CHECK(!map, "bpf_object__find_map_by_name", "%s not found\n", map_name)) {
		goto cleanup;
	}

	map_fd = bpf_map__fd(map);
	if (CHECK(map_fd < 0, "bpf_map__fd", "err %d\n", map_fd)) {
		goto cleanup;
	}

	/* attach program to kprobe */
	link = bpf_program__attach_kprobe(prog, false /* retprobe */, KPROBE_FUNC);
	if (CHECK(IS_ERR(link), "bpf_program__attach_kprobe", "err %ld\n", PTR_ERR(link))) {
		link = NULL;
		goto cleanup;
	}

	/* terminate program on demand, since after this loader exists,
	 * kprobe and bpf prog will be destroyed
	 */
	printf("press enter to terminate...");
	getchar();
cleanup:
	bpf_link__destroy(link);
	bpf_object__close(obj);

	return 0;
}

