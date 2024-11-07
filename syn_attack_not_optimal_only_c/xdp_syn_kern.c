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


#define limit 10
#define extra_time  1000000000

struct __u128 {
    __u64 hi; // Higher 64 bits for IPv6
    __u64 lo; // Lower 64 bits for IPv6
};

union ip_address {
    __u32 ipv4;           // 32-bit IPv4 address
    struct __u128 ipv6;   // 128-bit IPv6 address
};

struct node_index{
    __u32 index;
};

struct packet_id_key{
    union ip_address ipadd; // IPv4 or IPv6
    __u16 dest;
    __u16 source;
    __u8 ip_type;
};
struct Semp{
    struct bpf_spin_lock semaphore;
};

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 2);      
    __type(key, __u32);            
    __type(value, __u64);          
} syn_size_oldtime SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 1000);      
    __type(key, struct packet_id_key);            
    __type(value, __u64);          
} syn_lru_hash_map SEC(".maps");

SEC("xdp")
int xdp_tcp_syn(struct xdp_md *ctx) {
    __u32 zero = 0,one = 1;
    struct packet_id_key packet_key;
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    struct ethhdr *eth = data;
    
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;
    
    struct tcphdr *tcp;

    if (eth->h_proto == __constant_htons(ETH_P_IP)) {
        
        packet_key.ip_type = 1;
        struct iphdr *ip = (void *)(eth + 1);
        if ((void *)(ip + 1) > data_end){
            return XDP_PASS;
        }
        packet_key.ipadd.ipv4 = ip->saddr;
        if (ip->protocol == IPPROTO_TCP) {
            tcp = (void *)((unsigned char *)ip + (ip->ihl * 4));
            if ((void *)(tcp + 1) > data_end){
                return XDP_PASS;
            }
        }
    } 
    else if (eth->h_proto == __constant_htons(ETH_P_IPV6)) {
        
        packet_key.ip_type = 2;
        struct ipv6hdr *ipv6 = (void *)(eth + 1);
        if ((void *)(ipv6 + 1) > data_end){
            return XDP_PASS;
        }
        __builtin_memcpy(&packet_key.ipadd.ipv6, &ipv6->saddr, sizeof(struct in6_addr));
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
    packet_key.dest = tcp->dest;
    packet_key.source = tcp->source;
    __u64 *size_allowed,*old_time;
    size_allowed = bpf_map_lookup_elem(&syn_size_oldtime,&zero);
    old_time = bpf_map_lookup_elem(&syn_size_oldtime,&one);
    if(!size_allowed || !old_time){
        return XDP_PASS;
    }
    if(!(tcp->fin  ||
        tcp->psh || 
        tcp->urg || 
        tcp->ece || 
        tcp->cwr || 
        tcp->rst )){
        if (tcp->syn && !tcp->ack) {
            __u64 curr_time = bpf_ktime_get_ns();
            //check if time is greater than old time + extra
            if(*old_time + extra_time < curr_time){
                // if yes update old time and make size as 1
                *size_allowed = 1;
                *old_time = curr_time;
                bpf_map_update_elem(&syn_lru_hash_map,&packet_key,&curr_time,BPF_ANY);
                bpf_printk("Passed");
                return XDP_PASS;
            }
            else{
                // else check size == limit
                if(*size_allowed == limit){
                    // if yes DROP
                    bpf_printk("Dropped");
                    return XDP_DROP;
                }
                else{
                    //else update size and insert into hash and PASS
                    *size_allowed += 1;
                    bpf_map_update_elem(&syn_lru_hash_map,&packet_key,&curr_time,BPF_ANY);
                    bpf_printk("Passed");
                    return XDP_PASS;
                }
            }
        }
        if (tcp->syn && tcp->ack) {
            bpf_printk("TCP SYN-ACK packet detected!\n");
            return XDP_PASS;
        }
        if (!tcp->syn && tcp->ack) {
            //check if element is present
            __u64 *packet_time = bpf_map_lookup_elem(&syn_lru_hash_map,&packet_key);
            if(!packet_time){
                //  if yes check time is in range
                if(*packet_time < *old_time + extra_time){
                    //size =-1 remove from map and PASS
                    *size_allowed -= 1;
                    bpf_map_delete_elem(&syn_lru_hash_map,&packet_key);
                    return XDP_PASS;
                }
                else{
                    //PASS
                    return XDP_PASS;
                }
            }
            else{
                // PASS
                return XDP_PASS;
            }
        }
    }
    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
