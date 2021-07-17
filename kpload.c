#include <stdio.h>
#include <errno.h>
#include <stdint.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <linux/bpf.h>

#include "bpf/bpf.h"
#include "bpf/libbpf.h"

#define MAP_PIN_PATH "/sys/fs/bpf/tc/globals/"
#define SKB_MAP  "skb_map"
#define PATH_MAP "path_map"

#define KPROBE_TYPE 0 /* not retprobe */

int load_and_attach(const char *kp_name, int skb_map_fd, int path_map_fd,
		    struct bpf_object **obj_p, struct bpf_link **link_p)
{
	char kp_objs_path[256];
	struct bpf_object   *obj = NULL;
	struct bpf_link    *link = NULL;
	struct bpf_program *prog;
	struct bpf_map      *map;
	int r;

	snprintf(kp_objs_path, 256, "obj/%s_kp_prog.o", kp_name);
	obj = bpf_object__open(kp_objs_path);
	if (obj == NULL) {
		printf("Failed to open object file.\n");
		goto cleanup;
	}

	bpf_object__for_each_map(map, obj) {
		const char *map_name = bpf_map__name(map);

		if (!strcmp(map_name, SKB_MAP)) {
			r = bpf_map__reuse_fd(map, skb_map_fd);
			if (r) {
				printf("Unable to reuse map \"%s\".\n", SKB_MAP);
				goto cleanup;
			}
		} else if (!strcmp(map_name, PATH_MAP)) {
			r = bpf_map__reuse_fd(map, path_map_fd);
			if (r) {
				printf("Unable to reuse map \"%s\".\n", PATH_MAP);
				goto cleanup;
			}
		} else {
			printf("Undefined map inside object file: %s\n", map_name);
		}
	}

	r = bpf_object__load(obj);
	if (r) {
		printf("Failed to load object file.\n");
		goto cleanup;
	}

	prog = bpf_program__next(NULL, obj);
	if (!prog) {
		printf("Object file doesn't contain any bpf program.\n");
		goto cleanup;
	}

	link = bpf_program__attach_kprobe(prog, KPROBE_TYPE, kp_name);
	if (link == NULL) {
		printf("Failed to attach to kprobe.\n");
		goto cleanup;
	}

	*obj_p  = obj;
	*link_p = link;

	return 0;

cleanup:
	bpf_link__destroy(link);
	bpf_object__close(obj);

	return -1;
}

int main()
{
	FILE *kp_funcs = fopen("kp_funcs.list", "r");
	char kp_names[128][128], cur_name[128];
	int kp_amt;
	int kp_fin, r;

	kp_amt = 0;
	r = fscanf(kp_funcs, "%s %i\n", cur_name, &kp_fin);
	while(r != EOF) {
		if (kp_amt == 128) {
			printf("Too many kprobes!\n");
			fclose(kp_funcs);
			exit(EXIT_FAILURE);
		}

		cur_name[127] = 0;
		strcpy(kp_names[kp_amt], cur_name);

		r = fscanf(kp_funcs, "%s %i\n", cur_name, &kp_fin);
		++kp_amt;
	}
	fclose(kp_funcs);
	--kp_amt;

	int skb_map_fd = -1;
	int path_map_fd = -1;

	skb_map_fd = bpf_obj_get(MAP_PIN_PATH SKB_MAP);
	if (skb_map_fd < 0) {
		printf("Map \"%s\" not found! Check \"/sys/fs/bpf/tc/globals\" directory.\n", SKB_MAP);
		goto map_cleanup;
	}
	path_map_fd = bpf_obj_get(MAP_PIN_PATH PATH_MAP);
	if (path_map_fd < 0) {
		printf("Map \"%s\" not found! Check \"/sys/fs/bpf/tc/globals\" directory.\n", PATH_MAP);
		goto map_cleanup;
	}

	struct bpf_object *kp_objs[128];
	struct bpf_link *kp_links[128];
	for (int i = 0; i <= kp_amt; ++i) {
		kp_objs[i] = NULL;
		kp_links[i] = NULL;
		r = load_and_attach(kp_names[i], skb_map_fd, path_map_fd,
				    &kp_objs[i], &kp_links[i]);
		if (r) {
			goto prog_cleanup;
		}
	}
	
	/* terminate program on demand, since after this loader exists,
	 * kprobe and bpf prog will be destroyed
	 */
	printf("press enter to terminate...");
	getchar();

prog_cleanup:
	for (int i = 0; i <= kp_amt; ++i) {
		bpf_link__destroy(kp_links[i]);
		bpf_object__close(kp_objs[i]);
	}
map_cleanup:
	close(skb_map_fd);
	close(path_map_fd);

	return 0;
}
