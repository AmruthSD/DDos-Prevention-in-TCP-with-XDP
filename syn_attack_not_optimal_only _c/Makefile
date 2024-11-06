# Makefile

CC=clang
CFLAGS=-O2 -g -Wall -target bpf
LIBBPF_DIR=/usr/include/x86_64-linux-gnu 

IFACE=lo  

all: xdp_syn_kern.o user

xdp_syn_kern.o: xdp_syn_kern.c
	$(CC) $(CFLAGS) -I $(LIBBPF_DIR) -c xdp_syn_kern.c -o xdp_syn_kern.o

user: user.c
	$(CC) -o user user.c -lbpf

load: xdp_syn_kern.o
	sudo ip link set dev $(IFACE) xdp obj xdp_syn_kern.o section xdp
	sudo mkdir -p /sys/fs/bpf
	sudo mount -t bpf none /sys/fs/bpf
	sudo bpftool map pin name syn_lru_hash_map /sys/fs/bpf/syn_lru_hash_map

detach:
	sudo ip link set dev $(IFACE) xdp off
	sudo rm -f /sys/fs/bpf/syn_lru_hash_map

clean:
	rm -f xdp_syn_kern.o user
