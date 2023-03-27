#ifndef COMMON_H
#define COMMON_H

#define DEBUG(x, ...) bpf_printk(x, ##__VA_ARGS__)

#define MAGIC    0x1234
#define SRC_PORT 20000
#define DST_PORT 30000

#define NS1_REGION 0x0001
#define NS2_REGION 0x0002
#define NS3_REGION 0x0003
#define NS4_REGION 0x0004

struct encaphdr {
    struct iphdr ip;
    struct udphdr udp;
    __u16 magic;
    __u16 src_region;
    __u16 dst_region;
};

struct next_hop {
    __u32 ifindex;
    __be32 saddr;
    __be32 daddr;
    __u8 smac[6];
    __u8 dmac[6];
    __u8 direct;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u16);
    __type(value, struct next_hop);
    __uint(max_entries, 1024);
} route_table SEC(".maps");

static __always_inline struct next_hop *find_next_hop(__u16 dst_region)
{
    return bpf_map_lookup_elem(&route_table, &dst_region);
}

static __always_inline __u16 csum_diff(__u16 oldsum, __u16 olddata,
                                       __u16 newdata)
{
    __u32 sum = (__u32)oldsum + ~olddata + newdata;
    return (sum >> 16) + (sum & 0xffff);
}

static __always_inline __u16 csum_tcpudp_magic(__be32 saddr, __be32 daddr,
                                               __u16 len, __u8 proto,
                                               __u32 csum)
{
    __u32 sum;

    sum = (__u32)saddr + (__u32)daddr + ((len + proto) << 8);
    sum = (sum & 0xffff) + (sum >> 16);
    sum = csum + sum;
    return (__u16)(~csum_diff(~sum, 0, 0));
}

static __always_inline __u16 csum_udp(struct udphdr *udp, __be32 saddr,
                                      __be32 daddr)
{
    __u16 udp_len = bpf_ntohs(udp->len);
    __u32 csum = 0;

    csum = csum_diff(0, udp_len, csum_diff(0, saddr >> 16, saddr & 0xffff));
    csum = csum_diff(csum, daddr >> 16, daddr & 0xffff);
    csum += bpf_ntohs(udp->dest);
    csum += bpf_ntohs(udp->source);
    csum += udp_len;
    csum += IPPROTO_UDP;

    return csum_tcpudp_magic(saddr, daddr, udp_len, IPPROTO_UDP, csum);
}

static __always_inline __u32 csum_partial(const void *ptr, int len, __u32 csum)
{
    __u64 offset = 0;

// #pragma unroll
//     while (len > 0) {
//         __u64 data;
//         __builtin_memcpy(&data, ptr + offset, sizeof(data));
//         csum += data;
//         len -= sizeof(data);
//         offset += sizeof(data);
//     }

//     if (len == 1) {
//         __u8 last_byte;
//         __builtin_memcpy(&last_byte, ptr + offset, sizeof(last_byte));
//         csum += (__u16)last_byte;
//     } else if (len == 2) {
//         __u16 last_bytes;
//         __builtin_memcpy(&last_bytes, ptr + offset, sizeof(last_bytes));
//         csum += (__u32)last_bytes;
//     }

    return csum;
}

static __always_inline __u16 csum_tcp(struct tcphdr *tcp, __be32 saddr, __be32 daddr)
{
    __u32 tcp_length = bpf_ntohs(tcp->doff) * 4;
    __u16 proto = IPPROTO_TCP;
    __u32 sum = 0;

    sum += (__u32)saddr;
    sum += (__u32)daddr;
    sum += ((__u16)bpf_htons(proto) << 8);
    sum += tcp_length;

    sum += csum_partial(tcp, tcp_length, 0);
    return csum_tcpudp_magic(saddr, daddr, tcp_length, proto, sum);
}

static __always_inline void set_ipv4_csum(struct iphdr *iph)
{
    __u16 *iph16 = (__u16 *)iph;
    __u32 csum;
    int i;

    iph->check = 0;

#pragma clang loop unroll(full)
    for (i = 0, csum = 0; i < sizeof(struct iphdr) >> 1; i++)
        csum += *iph16++;

    iph->check = ~((csum & 0xffff) + (csum >> 16));
}

static __always_inline void set_tcp_csum(struct tcphdr *tcp, const struct iphdr *ip)
{
    tcp->check = 0;
    tcp->check = csum_tcp(tcp, ip->saddr, ip->daddr);
}

static __always_inline void set_udp_csum(struct udphdr *udp, const struct iphdr *ip)
{
    udp->check = 0;
    udp->check = csum_udp(udp, ip->saddr, ip->daddr);
}

static __always_inline void swap_src_dst_mac(struct ethhdr *eth)
{
    __u8 tmp[ETH_ALEN];
    __builtin_memcpy(tmp, eth->h_source, ETH_ALEN);
    __builtin_memcpy(eth->h_source, eth->h_dest, ETH_ALEN);
    __builtin_memcpy(eth->h_dest, tmp, ETH_ALEN);
}

static __always_inline void swap_src_dst_ipv4(struct iphdr *iph)
{
    __be32 tmp = iph->saddr;
    iph->saddr = iph->daddr;
    iph->daddr = tmp;
}

static __always_inline void swap_src_dst_port(struct udphdr *udp)
{
    __be16 tmp = udp->source;

    udp->source = udp->dest;
    udp->dest = tmp;
}

#endif