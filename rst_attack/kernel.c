#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/icmp.h>
#include <linux/ipv6.h>
#include <bcc/proto.h>
#include <linux/pkt_cls.h>

#define SIZEOFPORTS 65536
#define TIMEOUT  1000
#define THRESHOLD 100

struct port_node{
    __u64 port_time;
    __u32 rst_cnt;
    struct bpf_spin_lock semaphore;
};

BPF_ARRAY(port_rst,struct port_node,SIZEOFPORTS);

int xdp_tcp_rst(struct xdp_md *ctx) {
    int zero = 0,one = 1, two = 2;
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    struct ethhdr *eth = data;
    
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;
    
    struct tcphdr *tcp;

    if (eth->h_proto == __constant_htons(ETH_P_IP)) {
        
        struct iphdr *ip = (void *)(eth + 1);
        if ((void *)(ip + 1) > data_end){
            return XDP_PASS;
        }
        if (ip->protocol == IPPROTO_TCP) {
            tcp = (void *)((unsigned char *)ip + (ip->ihl * 4));
            if ((void *)(tcp + 1) > data_end){
                return XDP_PASS;
            }
        }
    } 
    else if (eth->h_proto == __constant_htons(ETH_P_IPV6)) {

        struct ipv6hdr *ipv6 = (void *)(eth + 1);
        if ((void *)(ipv6 + 1) > data_end){
            return XDP_PASS;
        }
        if (ipv6->nexthdr == IPPROTO_TCP){
            tcp = (void *)((unsigned char *)ipv6 + 1);
            if ((void *)(tcp + 1) > data_end){
                return XDP_PASS;
            }
        }
    }
    else{
        return XDP_PASS;
    }
    __u32 dest = tcp->dest; 

    if((void *)(tcp+1) > data_end){
        return XDP_PASS;
    }
    if(tcp->rst){
        struct port_node *node = port_rst.lookup(&dest);
        if(!node){
            return XDP_PASS;
        }
        __u64 curr_time = bpf_ktime_get_ns();
        bpf_spin_lock(&node->semaphore);
        if(node->port_time + TIMEOUT < curr_time){
            node->port_time = curr_time;
            node->rst_cnt = 1;
            bpf_spin_unlock(&node->semaphore);
            return XDP_PASS;
        }
        else{
            if(node->rst_cnt<THRESHOLD){
                node->rst_cnt++;
                bpf_spin_unlock(&node->semaphore);
                return XDP_PASS;
            }
            else{
                bpf_spin_unlock(&node->semaphore);
                return XDP_DROP;
            }
        }
        
    }
    return XDP_PASS;
}
