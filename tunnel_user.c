#include <arpa/inet.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

struct next_hop {
    __u32 ifindex;
    __be32 saddr;
    __be32 daddr;
    __u8 smac[6];
    __u8 dmac[6];
    __u8 direct;
};

int str2mac(const char *mac, uint8_t *values)
{
    if (6 == sscanf(mac, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx", &values[0], &values[1], &values[2], &values[3], &values[4], &values[5])) {
        return 1;
    } else {
        return 0;
    }
}

int main(int argc, char **argv)
{
    if (argc != 9) {
        printf("usage: ./tunnel_user map_path region saddr daddr ifindex dmac direct\n");
        return EXIT_FAILURE;
    }

    int map_fd = bpf_obj_get(argv[1]);
    if (map_fd < 0) {
        fprintf(stderr, "Error: cannot get map file descriptor: %s\n", strerror(errno));
        return EXIT_FAILURE;
    }

    __u16 key = atoi(argv[2]);
    struct next_hop value = {
        .ifindex = atoi(argv[3]),
        .saddr = inet_addr(argv[4]),
        .daddr = inet_addr(argv[5]),
        .direct = atoi(argv[8]),
    };

    str2mac(argv[6], value.smac);
    str2mac(argv[7], value.dmac);

    int ret = bpf_map_update_elem(map_fd, &key, &value, BPF_ANY);
    if (ret) {
        fprintf(stderr, "Error: cannot insert element into map: %s\n", strerror(errno));
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}
