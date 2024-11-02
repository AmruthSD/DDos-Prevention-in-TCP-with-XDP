#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/icmp.h>
#include <linux/ipv6.h>
#include <bcc/proto.h>
#include <linux/pkt_cls.h>

#define SIZEOFQUEUE 1000
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

BPF_ARRAY(double_linked,struct queue_node,SIZEOFQUEUE);
BPF_ARRAY(head_tail_size,__u32,3);
BPF_ARRAY(semaphore_for_map,struct Semp,1);
BPF_HASH(idx_from_ip_ports,struct packet_id_key,struct node_index,SIZEOFQUEUE);

int xdp_tcp_syn(struct xdp_md *ctx) {
    int zero = 0,one = 1, two = 2;
    struct packet_id_key packet_key;
    /*struct Semp *s = semaphore_for_map.lookup(&zero);
    if(!s){ 
        bpf_trace_printk("Void sem");
        return XDP_PASS;
    }
    bpf_spin_lock(&s->semaphore);
    bpf_spin_unlock(&s->semaphore);*/
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
                bpf_trace_printk("Dropping packet due to same index");
                return XDP_DROP; //actuall has to drop
                //return XDP_PASS;
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
                    bpf_trace_printk("Dropping due to too many packets");
                    return XDP_DROP; //actuall has to drop
                    //return XDP_PASS;
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
                    
                    //bpf_map_delete_elem(&idx_from_ip_ports,&old_packet_key);

                    head_node->ip_type = packet_key.ip_type;
                    head_node->time_insert = curr_time;
                    if(head_node->ip_type==1){
                        head_node->ipadd.ipv4 = packet_key.ipadd.ipv4;
                    }
                    else{
                        __builtin_memcpy(&head_node->ipadd.ipv6, &packet_key.ipadd.ipv6, sizeof(struct in6_addr));
                    }
                    head_node->source = packet_key.source;
                    head_node->dest = packet_key.dest;
                    //head = head_node->next
                    head_tail_size.update(&zero,&head_node->next);

                    head_node->next = 0;

                    //insert into hash map
                    idx_from_ip_ports.update(&packet_key,(void*)&head_node->data);

                    //head_node->prev = tail;
                    __u32 *tail = head_tail_size.lookup(&one);
                    if(!tail){
                        return XDP_PASS;
                    }

                    head_node->prev = *tail;

                    //tail_node->next = head;
                    struct queue_node *tail_node = double_linked.lookup(tail);
                    if(!tail_node){
                        return XDP_PASS;
                    }
                    tail_node->next = head_node->data;
                    double_linked.update(tail,tail_node);

                    //tail = head_node
                    head_tail_size.update(&one,&head_node->data);
                    double_linked.update(&head_node->data,head_node);

                    return XDP_PASS;
                }
            }
            else{
                
                //insert new packet into hash and insert to tail of queue 
                head_node->ip_type = packet_key.ip_type;
                    
                if(head_node->ip_type==1){
                    head_node->ipadd.ipv4 = packet_key.ipadd.ipv4;
                }
                else{
                    __builtin_memcpy(&head_node->ipadd.ipv6, &packet_key.ipadd.ipv6, sizeof(struct in6_addr));
                }
                head_node->source = packet_key.source;
                head_node->dest = packet_key.dest;
                head_node->time_insert = bpf_ktime_get_ns();
                head_node->is_used = 1;
                //head = head_node->next
                head_tail_size.update(&zero,&head_node->next);

                //insert into hash map
                idx_from_ip_ports.update(&packet_key,(void *)&head_node->data);

                //head_node->prev = tail;
                __u32 *tail = head_tail_size.lookup(&one);
                if(!tail){
                    return XDP_PASS;
                }
                head_node->prev = *tail;

                //tail_node->next = head;
                struct queue_node *tail_node = double_linked.lookup(tail),*next_node = double_linked.lookup((void*)&head_node->next);
                if(!(tail_node)){
                    return XDP_PASS;
                }
                if(!(next_node)){
                    return XDP_PASS;
                }
                tail_node->next = head_node->data;
                double_linked.update(&tail_node->data,tail_node);
                head_node->next = 0;
                next_node->prev = 0;
                //tail = head_node
                head_tail_size.update(&one,&head_node->data);
                double_linked.update(&head_node->data,head_node);
                double_linked.update(&next_node->data,next_node);

                return XDP_PASS;
            }

            bpf_trace_printk("TCP SYN packet detected!\n");
            return XDP_PASS;
        }
        if (tcp->syn && tcp->ack) {
            bpf_trace_printk("TCP SYN-ACK packet detected!\n");
            return XDP_PASS;
        }
        if (!tcp->syn && tcp->ack) {
            struct node_index *index = idx_from_ip_ports.lookup(&packet_key);
            if(!index){
                return XDP_PASS;
            }
            struct queue_node *curr_node = double_linked.lookup((void *)&index);
            struct queue_node *prev_node,*next_node;
            if(!(curr_node)){
                return XDP_PASS;
            }
                
            prev_node = double_linked.lookup(&curr_node->prev);
            next_node = double_linked.lookup(&curr_node->next);
            if(!(prev_node)){
                return XDP_PASS;
            }
            if(!(next_node)){
                return XDP_PASS;
            }
            //implement the remove from the hash
            //bpf_map_delete_elem(&idx_from_ip_ports,&packet_key);
            
            //connect queue
            prev_node->next = curr_node->next;
            next_node->prev = curr_node->prev;
            double_linked.update(&prev_node->data,prev_node);
            double_linked.update(&next_node->data,next_node);

            //add curr_node to the head 
            curr_node->is_used = 0;
            __u32 *head = head_tail_size.lookup(&zero);
            if(!head){
                return XDP_PASS;
            }
            struct queue_node *head_node = double_linked.lookup(head); 
            if(!head_node){
                return XDP_PASS;
            }
            head_node->prev = curr_node->data;
            curr_node->prev = 0;
            curr_node->next = head_node->data;
            double_linked.update(&head_node->data,head_node);
            head_tail_size.update(&zero,&curr_node->data);
            double_linked.update(&curr_node->data,curr_node);
            bpf_trace_printk("TCP ACK packet detected!\n");
            return XDP_PASS;
        }
    }
    return XDP_PASS;
}
