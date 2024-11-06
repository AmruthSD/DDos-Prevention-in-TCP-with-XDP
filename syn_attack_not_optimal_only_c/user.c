#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>

#define LRU_MAP_PATH "/sys/fs/bpf/syn_lru_hash_map"

int main() {
    int map_fd;
    struct bpf_map_info map_info = {};
    __u32 map_info_len = sizeof(map_info);
    __u64 key, next_key;
    __u64 value;

    // Open the LRU map by name
    map_fd = bpf_obj_get(LRU_MAP_PATH);
    if (map_fd < 0) {
        perror("Failed to open LRU hash map");
        return 1;
    }

    printf("Reading entries from LRU map every 2 seconds...\n");
    while (1) {
        printf("\n\n");
        key = -1; // Start from the first key
        while (bpf_map_get_next_key(map_fd, &key, &next_key) == 0) {
            // Retrieve the value for each key
            if (bpf_map_lookup_elem(map_fd, &next_key, &value) == 0) {
                printf("Key: %llu, Value: %llu \n", next_key, value);
            }
            key = next_key;
        }
        sleep(5); // Read every 2 seconds
    }

    close(map_fd);
    return 0;
}

