# Makefile

CC=clang
CFLAGS=-O2 -g -Wall -target bpf
LIBBPF_DIR=/usr/include/x86_64-linux-gnu 

IFACE=lo  

all: xdp_rst_kern.o 

xdp_rst_kern.o: xdp_rst_kern.c
	$(CC) $(CFLAGS) -I $(LIBBPF_DIR) -c xdp_rst_kern.c -o xdp_rst_kern.o


load: xdp_rst_kern.o
	sudo ip link set dev $(IFACE) xdp obj xdp_rst_kern.o section xdp
	sudo mkdir -p /sys/fs/bpf
	sudo mount -t bpf none /sys/fs/bpf
#sudo bpftool map pin name port_rst /sys/fs/bpf/port_rst

detach:
	sudo ip link set dev $(IFACE) xdp off
	sudo rm -f /sys/fs/bpf/port_rst

clean:
	rm -f xdp_rst_kern.o 
