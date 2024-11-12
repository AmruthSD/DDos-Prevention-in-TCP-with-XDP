#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/icmp.h>
#include <linux/ipv6.h>
#include <linux/pkt_cls.h>
#include <bpf/bpf_helpers.h>
#include <linux/in.h>     // for IPPROTO_TCP, IPPROTO_IPV6 (for IPv4)
#include <linux/in6.h>    // for IPv6 headers


#define SIZEOFPORTS 65536
#define TIMEOUT  1000000000
#define THRESHOLD 10

struct port_node{
    __u64 port_time;
    __u32 rst_cnt;
    struct bpf_spin_lock semaphore;
};


struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, SIZEOFPORTS);      
    __type(key, __u32);            
    __type(value, struct port_node);          
} tcp_rst_port SEC(".maps");


SEC("xdp")
int xdp_tcp_rst(struct xdp_md *ctx) {
    __u32 zero = 0,one = 1, two = 2;
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
    if((void *)(tcp+1) > data_end){
        return XDP_PASS;
    }
    __u32 dest = tcp->dest; 
    if(tcp->rst){
        struct port_node *node = bpf_map_lookup_elem(&tcp_rst_port,&dest);
        if(!node){
            return XDP_PASS;
        }
        __u64 curr_time = bpf_ktime_get_ns();
        bpf_spin_lock(&node->semaphore);
        if(node->port_time + TIMEOUT < curr_time){
            node->port_time = curr_time;
            node->rst_cnt = 1;
            bpf_spin_unlock(&node->semaphore);
            bpf_printk("Passed");
            return XDP_PASS;
        }
        else{
            if(node->rst_cnt<THRESHOLD){
                node->rst_cnt++;
                bpf_spin_unlock(&node->semaphore);
                bpf_printk("Passed");
                return XDP_PASS;
            }
            else{
                bpf_spin_unlock(&node->semaphore);
                bpf_printk("Dropped");
                return XDP_DROP;
            }
        }
        
    }
    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
