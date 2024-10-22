#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/icmp.h>
#include <linux/ipv6.h>
#include <bcc/proto.h>
#include <linux/pkt_cls.h>

struct nodDe{
    __u32 data;
    __u32 prev;
    __u32 next;
    __u8 is_used;
    __u32 ipadd;
    __u16 dest;
    __u16 source;
};
struct Semp{
    struct bpf_spin_lock semaphore;
};

BPF_ARRAY(double_linked,struct nodDe,10);
BPF_ARRAY(head_tail,__u32,2);
BPF_ARRAY(semaphore_for_map,struct Semp,1);

int xdp_tcp_syn(struct xdp_md *ctx) {
    int zero = 0;
    struct Semp *s = semaphore_for_map.lookup(&zero);
    if(!s){ 
        bpf_trace_printk("Void sem");
        return XDP_PASS;
    }
    bpf_spin_lock(&s->semaphore);
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    struct ethhdr *eth = data;
    bpf_spin_unlock(&s->semaphore);
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
    
    if((void *)(tcp+1) > data_end){
        return XDP_PASS;
    }
    __u16 a=tcp->dest,b=tcp->source;
    bpf_trace_printk("%d %d",a,b);
    if(!(tcp->fin  ||
        tcp->psh || 
        tcp->urg || 
        tcp->ece || 
        tcp->cwr || 
        tcp->rst )){
        if (tcp->syn && !tcp->ack) {
            bpf_trace_printk("TCP SYN packet detected!\n");
            return XDP_PASS;
        }
        if (tcp->syn && tcp->ack) {
            bpf_trace_printk("TCP SYN-ACK packet detected!\n");
            return XDP_PASS;
        }
        if (!tcp->syn && tcp->ack) {
            bpf_trace_printk("TCP ACK packet detected!\n");
            return XDP_PASS;
        }
    }
    return XDP_PASS;
}
