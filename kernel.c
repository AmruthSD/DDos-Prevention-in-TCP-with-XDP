#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/icmp.h>
#include <linux/ipv6.h>
#include <bcc/proto.h>
#include <linux/pkt_cls.h>


#define extra_time  1000

struct __u128 {
    __u64 hi; // Higher 64 bits for IPv6
    __u64 lo; // Lower 64 bits for IPv6
};

union ip_address {
    __u32 ipv4;           // 32-bit IPv4 address
    struct __u128 ipv6;   // 128-bit IPv6 address
};

struct queue_node {
    __u32 data;
    __u32 prev;
    __u32 next;
    __u8 is_used;
    union ip_address ipadd; // IPv4 or IPv6
    __u16 dest;
    __u16 source;
    __u64 time_insert;
    __u8 ip_type; // 1 for IPv4, 2 for IPv6
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

BPF_ARRAY(double_linked,struct queue_node,10);
BPF_ARRAY(head_tail_size,__u32,3);
BPF_ARRAY(semaphore_for_map,struct Semp,1);
BPF_HASH(idx_from_ip_ports,struct packet_id_key,struct node_index,10);

int xdp_tcp_syn(struct xdp_md *ctx) {
    int zero = 0,one = 1, two = 2;
    struct packet_id_key packet_key;
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
    
    if((void *)(tcp+1) > data_end){
        return XDP_PASS;
    }
    packet_key.dest = tcp->dest;
    packet_key.source = tcp->source;
    /*
    __u16 a=tcp->dest,b=tcp->source;
    bpf_trace_printk("%d %d",a,b);
    */
    if(!(tcp->fin  ||
        tcp->psh || 
        tcp->urg || 
        tcp->ece || 
        tcp->cwr || 
        tcp->rst )){
        if (tcp->syn && !tcp->ack) {
            struct node_index *index = idx_from_ip_ports.lookup(&packet_key);
            //if the ip ports are already there then just drop
            if(index){
                return XDP_DROP;
            }

            //if head of queue is empty add the packet
            __u32 *head = head_tail_size.lookup(&zero);
            if(!head){
                return XDP_PASS;
            }
            struct queue_node *head_node = double_linked.lookup(head); 
            if(!head_node){
                return XDP_PASS;
            }
            if(head_node->is_used){
                __u64 curr_time = bpf_ktime_get_ns();
                if(head_node->time_insert + extra_time < curr_time){
                    return XDP_DROP;
                }
                else{
                    //remove the head from hash and then insert new packet to hash and then to tail
                    struct packet_id_key old_packet_key;
                    old_packet_key.ip_type = head_node->ip_type;
                    old_packet_key.source = head_node->source;
                    old_packet_key.dest = head_node->dest;
                    if(old_packet_key.ip_type==1){
                        old_packet_key.ipadd.ipv4 = head_node->ipadd.ipv4;
                    }
                    else{
                        __builtin_memcpy(&old_packet_key.ipadd.ipv6, &head_node->ipadd.ipv6, sizeof(struct in6_addr));
                    }
                    /*
                    __u32 res = bpf_map_delete_elem(&idx_from_ip_ports,&old_packet_key);
                    if(res==0){

                    }
                    else{

                    }*/
                    head_node->ip_type = packet_key.ip_type;
                    
                    if(head_node->ip_type==1){
                        head_node->ipadd.ipv4 = packet_key.ipadd.ipv4;
                    }
                    else{
                        __builtin_memcpy(&head_node->ipadd.ipv6, &packet_key.ipadd.ipv6, sizeof(struct in6_addr));
                    }
                    //head = head_node->next
                    head_node->next = 0;
                    //head_node->prev = tail;
                    //tail_node->next = head;
                    //tail = head_node
                }
            }
            else{
                //insert new packet into hash and insert to tail of queue 
            }

            bpf_trace_printk("TCP SYN packet detected!\n");
            return XDP_PASS;
        }
        if (tcp->syn && tcp->ack) {
            bpf_trace_printk("TCP SYN-ACK packet detected!\n");
            return XDP_PASS;
        }
        if (!tcp->syn && tcp->ack) {
            //if exists the ip port port then remove it and free the space in the queue
            //else pass
            bpf_trace_printk("TCP ACK packet detected!\n");
            return XDP_PASS;
        }
    }
    return XDP_PASS;
}
