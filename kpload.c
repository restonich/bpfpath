#include <stdio.h>
#include <errno.h>
#include <stdint.h>
#include <unistd.h>

#include <linux/bpf.h>

#include "bpf/bpf.h"
#include "bpf/libbpf.h"

#ifndef NULL
# define NULL ((void *)0)
#endif

#define SKB_PTR_MAP "skb_ptr_map"
#define TS_MAP      "ts_map"
#define PATH_MAP    "path_map"

#define KPROBE_TYPE 0 /* not retprobe */

int main(int argc, const char **argv)
{
	char obj_file[256], kprobe_name[256];
	char prog_sec[256], map_path[256], pin_file[256];
	int skb_ptr_map_fd = -1, ts_map_fd = -1, path_map_fd = -1;
	int err;

	enum bpf_prog_type prog_type;
	enum bpf_attach_type expected_attach_type;
	//uint32_t ifindex = 0;
	struct bpf_object *obj = NULL;
	struct bpf_program *prog = NULL;
	struct bpf_map *map = NULL;
	struct bpf_link *link = NULL;

	if (argc < 3) {
		printf("Usage: sudo ./kpload OBJ_FILE KPROBE_NAME\n");
		return 0;
	}

	snprintf(obj_file,    256, "%s", argv[1]);
	snprintf(kprobe_name, 256, "%s", argv[2]);

	memset(map_path, 0, 256);
	snprintf(map_path, 256, "/sys/fs/bpf/tc/globals/%s", SKB_PTR_MAP);
	skb_ptr_map_fd = bpf_obj_get(map_path);
	if (skb_ptr_map_fd < 0) {
		printf("Map \"%s\" not found! Check \"/sys/fs/bpf/tc/globals\" directory.\n", SKB_PTR_MAP);
		goto cleanup;
	}

	memset(map_path, 0, 256);
	snprintf(map_path, 256, "/sys/fs/bpf/tc/globals/%s", TS_MAP);
	ts_map_fd = bpf_obj_get(map_path);
	if (ts_map_fd < 0) {
		printf("Map \"%s\" not found! Check \"/sys/fs/bpf/tc/globals\" directory.\n", TS_MAP);
		goto cleanup;
	}

	memset(map_path, 0, 256);
	snprintf(map_path, 256, "/sys/fs/bpf/tc/globals/%s", PATH_MAP);
	path_map_fd = bpf_obj_get(map_path);
	if (path_map_fd < 0) {
		printf("Map \"%s\" not found! Check \"/sys/fs/bpf/tc/globals\" directory.\n", PATH_MAP);
		goto cleanup;
	}

	snprintf(prog_sec, 256, "kprobe/%s", kprobe_name);
	err = libbpf_prog_type_by_name(prog_sec, &prog_type, &expected_attach_type);
	if (err < 0) {
		printf("Failed to determine program type.\n");
		goto cleanup;
	}

	obj = bpf_object__open(obj_file);
	if (obj == NULL) {
		printf("Failed to open object file.\n");
		goto cleanup;
	}
#if 0
	bpf_object__for_each_program(prog, obj) {
		bpf_program__set_ifindex(prog, ifindex);
		bpf_program__set_type(prog, prog_type);
		bpf_program__set_expected_attach_type(prog, expected_attach_type);
	}
#endif

	bpf_object__for_each_map(map, obj) {
		const char *map_name = bpf_map__name(map);
		if (!strcmp(map_name, SKB_PTR_MAP)) {
			err = bpf_map__reuse_fd(map, skb_ptr_map_fd);
			if (err) {
				printf("Unable to reuse map \"%s\".\n", SKB_PTR_MAP);
				goto cleanup;
			}
		} else if (!strcmp(map_name, TS_MAP)) {
			err = bpf_map__reuse_fd(map, ts_map_fd);
			if (err) {
				printf("Unable to reuse map \"%s\".\n", TS_MAP);
				goto cleanup;
			}
		} else if (!strcmp(map_name, PATH_MAP)) {
			err = bpf_map__reuse_fd(map, path_map_fd);
			if (err) {
				printf("Unable to reuse map \"%s\".\n", PATH_MAP);
				goto cleanup;
			}
		} else {
			printf("Undefined map inside object file: %s\n", map_name);
		}
	}

	err = bpf_object__load(obj);
	if (err) {
		printf("Failed to load object file.\n");
		goto cleanup;
	}
	printf("check\n");

	prog = NULL;
	prog = bpf_program__next(NULL, obj);
	if (!prog) {
		printf("Object file doesn't contain any bpf program.\n");
		goto cleanup;
	}

	snprintf(pin_file, 256, "/sys/fs/bpf/kp_progs/%s_prog", kprobe_name);
	err = bpf_obj_pin(bpf_program__fd(prog), pin_file);
	if (err) {
		printf("Failed to pin program.\n");
		goto cleanup;
	}

	/* attach program to kprobe */
	link = bpf_program__attach_kprobe(prog, KPROBE_TYPE, kprobe_name);
	if (link == NULL) {
		printf("Failed to attach to kprobe.\n");
		goto cleanup;
	}

	/* terminate program on demand, since after this loader exists,
	 * kprobe and bpf prog will be destroyed
	 */
	printf("press enter to terminate...");
	getchar();
cleanup:
	bpf_object__close(obj);
	close(ts_map_fd);
	close(path_map_fd);
	bpf_link__destroy(link);
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

