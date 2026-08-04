#ifdef __linux__
#include <uapi/linux/bpf.h>
#include <linux/in.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#else
#include <stdint.h>
typedef uint8_t u8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef uint64_t u64;
typedef uint16_t __be16;
typedef uint32_t __be32;
typedef uint16_t __sum16;
typedef uint32_t __u32;
typedef uint8_t __u8;

#define XDP_PASS 2
#define XDP_DROP 1
#define ETH_P_IP 0x0800

struct xdp_md {
    __u32 data;
    __u32 data_end;
    __u32 data_meta;
    __u32 ingress_ifindex;
    __u32 rx_queue_index;
    __u32 egress_ifindex;
};

struct ethhdr {
    unsigned char h_dest[6];
    unsigned char h_source[6];
    __be16 h_proto;
};

struct iphdr {
    __u8 ihl:4, version:4;
    __u8 tos;
    __be16 tot_len;
    __be16 id;
    __be16 frag_off;
    __u8 ttl;
    __u8 protocol;
    __sum16 check;
    __be32 saddr;
    __be32 daddr;
};

#define BPF_HASH(name, key_type, val_type) \
    struct { \
        val_type* (*lookup)(key_type*); \
    } name
#define BPF_ARRAY(name, val_type, size) \
    struct { \
        val_type* (*lookup)(u32*); \
    } name

static inline u16 bpf_htons(u16 val) { return val; }
#endif

// BPF Map definitions
BPF_HASH(blacklist_map, u32, u32);
BPF_ARRAY(drop_count_map, u64, 1);
BPF_ARRAY(active_port_map, u32, 1);
BPF_ARRAY(honeypot_port_map, u32, 1);

static inline int process_ip(struct xdp_md *ctx) {
    void *data = (void *)(unsigned long long)ctx->data;
    void *data_end = (void *)(unsigned long long)ctx->data_end;
    
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;
        
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;
        
    struct iphdr *ip = data + sizeof(struct ethhdr);
    if ((void *)(ip + 1) > data_end)
        return XDP_PASS;
        
    u32 src_ip = ip->saddr;
    
    // Check if IP is in blacklist
    u32 *is_banned = blacklist_map.lookup(&src_ip);
    if (is_banned && *is_banned == 1) {
        // Increment drop counter
        u32 key = 0;
        u64 *drop_count = drop_count_map.lookup(&key);
        if (drop_count) {
            __sync_fetch_and_add(drop_count, 1);
        }
        return XDP_DROP;
    }
    
    return XDP_PASS;
}

int xdp_spectre_prog(struct xdp_md *ctx) {
    return process_ip(ctx);
}
