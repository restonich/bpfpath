#include <stdio.h>
#include <errno.h>

#include "bpf/bpf.h"
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
	char obj_file[64], kprobe_name[64], map_name[64];
	char prog_sec[64], map_path[64];
	int prog_fd, map_fd, err;

	struct bpf_object *obj;
	struct bpf_program *prog;
	struct bpf_map *map;
	struct bpf_link *link = NULL;

	if (argc < 4) {
		printf("Usage: sudo ./kpload OBJ_FILE KPROBE_NAME MAP_NAME\n");
		return 0;
	}
	/* there are no parsing or checks performed, so input must be right
	 * parsing and testing would be performed by bpftool when I will (hopefully)
	 * pactch kprobe adding functionality to it
	 */
	snprintf(obj_file,    64, "%s", argv[1]);
	snprintf(kprobe_name, 64, "%s", argv[2]);
	snprintf(map_name,    64, "%s", argv[3]);

	snprintf(prog_sec, 64, "kprobe/%s", kprobe_name);
	snprintf(map_path, 64, "/sys/fs/bpf/kp_maps/%s", map_name);

	map_fd = bpf_obj_get(map_path);
	if (map_fd < 0) {
		printf("Map \"%s\" not found! Check \"/sys/fs/bpf/kp_maps\" directory.\n", map_name);
		return 0;
	}

#if 0
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
	link = bpf_program__attach_kprobe(prog, false /* retprobe */, kprobe_name);
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

#endif
	return 0;
}

