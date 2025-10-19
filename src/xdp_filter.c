#include <linux/types.h> 
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>   
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <stdint.h>

/*Non Standard ETH_TYPES*/
#define ETH_P_ECAT 0x88A4 // EtherCAT EtherType


/* FILTER TYPES */
#define IPV4_FILTER_TYPE_START 0
#define IPV4_FILTER_TYPE_END 1
#define ETHER_TYPE_FILTER 2
#define PORT_FILTER 3

struct iphdr {
    __u8  ihl:4;
    __u8  version:4;
    __u8  tos;
    __be16 tot_len;
    __be16 id;
    __be16 frag_off;
    __u8  ttl;
    __u8  protocol;
    __be16 check;
    __be32 saddr;
    __be32 daddr;
};

#define BLOCK_IP __builtin_bswap32(0xc0a8025b)
#define BLOCK_NET __builtin_bswap32(0xC0A80200) // Block 192.168.2.0 
#define BLOCK_MASK __builtin_bswap32(0xFFFFFF00) // 255.255.255.0 /24 CIDR Blocks 192.168.2.1 -> 192.168.2.255


// Filters out one ip range with subnet
int filter_ip_range(void* data,void* data_end, struct ethhdr* eth, unsigned int block_net, unsigned int block_mask) {
    if (bpf_ntohs(eth->h_proto) != ETH_P_IP)
        return 0;

    struct iphdr *ip = (struct iphdr *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return 0;
 
    return ((ip->saddr & block_mask) == block_net);
}

int filter_ip(void* data,void* data_end,struct ethhdr* eth) {
    if (bpf_ntohs(eth->h_proto) != ETH_P_IP)
        return 0;

    struct iphdr *ip = (struct iphdr *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return 0;

    return (ip->saddr == BLOCK_IP); // stored in host byte order
}

// ether type is expected to be in host byte order
inline int filter_eth_type(struct ethhdr* eth, unsigned short ether_type) {
    return bpf_ntohs(eth->h_proto) == ether_type;
}

SEC("xdp")
int xtreme_filter(struct xdp_md *ctx) {
  void *data_end = (void *)(long)ctx->data_end;
  void *data = (void *)(long)ctx->data;
  struct ethhdr *eth = data;
  
  if ((void *)(eth + 1) > data_end)
    return XDP_PASS;
  
  
    #ifdef WHITELIST_IP
        if( !filter_ip_range(data,data_end,eth,BLOCK_NET,BLOCK_MASK) ) {
            return XDP_DROP; 
        }
    #endif
    
    #ifndef WHITELIST_IP        
        if( filter_ip_range(data,data_end,eth,BLOCK_NET,BLOCK_MASK) ) {
            return XDP_DROP;   
        }
    #endif

  return XDP_PASS; 
}

char _license[] SEC("license") = "GPL";