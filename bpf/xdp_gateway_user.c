/*
 * bpfmaptest.c
 *
 *  Created on: Mar 31, 2020
 *      Author: ryan
 */
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>

#define BPF_CONNTRACK_OUTBOUND_MAP_PATH "/sys/fs/bpf/xdp_gateway_outbound"
#define BPF_CONNTRACK_RETURN_MAP_PATH "/sys/fs/bpf/xdp_gateway_return"

typedef struct xdp_gateway_bpf_map_info {
	char* bpf_pin_path;
	int map_fd;
} xdp_gateway_bpf_map_info;

void create_and_pin_bpf_maps(struct xdp_gateway_bpf_map_info *map_info) {
	for(int i=0; i<sizeof(xdp_gateway_bpf_map_info)/sizeof(map_info); i++) {
		printf("Creating map %s\n", map_info[i].bpf_pin_path);
	    int map_fd = bpf_create_map(BPF_MAP_TYPE_HASH, sizeof(0l), sizeof(0l), 2, 0);
		if (map_fd < 0) {
		    printf("failed to create map %s\n", map_info[i].bpf_pin_path);
		}
		else if(bpf_obj_pin(map_fd, map_info[i].bpf_pin_path) != 0) {
		    printf("failed to pin map %s\n", map_info[i].bpf_pin_path);
		}
	    map_info[i].map_fd = map_fd;
	}
}

int main(int argc, char **argv) {
	if(argc != 2) {
		printf("usage: %s <bpf obj>\n", argv[0]);
		return 1;
	}

	xdp_gateway_bpf_map_info outbound_map_info = {
		.bpf_pin_path = BPF_CONNTRACK_OUTBOUND_MAP_PATH,
	};
	xdp_gateway_bpf_map_info return_map_info = {
		.bpf_pin_path = BPF_CONNTRACK_RETURN_MAP_PATH
	} ;
	struct xdp_gateway_bpf_map_info bpf_map_list[] = {outbound_map_info, return_map_info};
	create_and_pin_bpf_maps(bpf_map_list);

	for(int i=0; i<sizeof(bpf_map_list)/sizeof(struct xdp_gateway_bpf_map_info); i++) {
		if (bpf_map_list[i].map_fd < 0) {
				printf("failed to create map\n");
				return 1;
		}
        if(access(bpf_map_list[i].bpf_pin_path, F_OK) != -1) {
				printf("successfully pinned map %s\n", bpf_map_list[i].bpf_pin_path);
		}
		else {
				printf("map pinning did not persist %s\n", bpf_map_list[i].bpf_pin_path);
		}
	}

	return 0;
}
