#include <linux/bpf.h>

#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <linux/icmp.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/if_vlan.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/pkt_cls.h>
#include <linux/tcp.h>
#include <linux/udp.h>

#include "common.h"

struct l4hdr {
    __be16 source;
    __be16 dest;
};

struct l4_conntrack_tuple {
    __be32 laddr;
    __be32 faddr;
    __be16 lport;
    __be16 fport;
    __u8 protocol;
    __u8 aligned0;
    __u16 aligned1;
};

struct l4_conntrack_info {
    __be32 saddr;
    __be32 src_region;
    __be16 sport;
    __be16 aligned;
};

struct icmp_conntrack_tuple {
    __be32 laddr;
    __be32 faddr;
    __u16 id;
    __u8 code;
    __u8 type;
};

struct icmp_conntrack_info {
    __be32 saddr;
    __be32 src_region;
};

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, struct l4_conntrack_tuple);
    __type(value, struct l4_conntrack_info);
    __uint(max_entries, 1024);
} l4_conntrack_table SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, struct icmp_conntrack_tuple);
    __type(value, struct icmp_conntrack_info);
    __uint(max_entries, 1024);
} icmp_conntrack_table SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __be32);
    __type(value, __u8);
    __uint(max_entries, 256);
} local_ip_table SEC(".maps");

static __always_inline void set_l4_conntrack_info(__u16 src_region, struct iphdr *ip, struct l4hdr *l4,
                                                  __be16 lport, __u8 protocol, const struct next_hop *hop)
{
    struct l4_conntrack_tuple tuple = {
        .laddr = hop->saddr,
        .faddr = ip->daddr,
        .lport = lport,
        .fport = l4->dest,
        .protocol = protocol,
        .aligned0 = 0,
        .aligned1 = 0,
    };

    struct l4_conntrack_info info = {
        .saddr = ip->saddr,
        .src_region = src_region,
        .sport = l4->source,
        .aligned = 0,
    };

    bpf_map_update_elem(&l4_conntrack_table, &tuple, &info, BPF_ANY);
}

static __always_inline struct l4_conntrack_info *get_l4_conntrack_info(struct iphdr *ip, struct l4hdr *l4, __u8 protocol)
{
    struct l4_conntrack_tuple tuple = {
        .laddr = ip->daddr,
        .faddr = ip->saddr,
        .lport = l4->dest,
        .fport = l4->source,
        .protocol = protocol,
        .aligned0 = 0,
        .aligned1 = 0,
    };

    return bpf_map_lookup_elem(&l4_conntrack_table, &tuple);
}

static __always_inline void set_icmp_conntrack_info(__u16 src_region, struct iphdr *ip, struct icmphdr *icmp,
                                                    const struct next_hop *hop)
{
    struct icmp_conntrack_tuple tuple = {
        .laddr = hop->saddr,
        .faddr = ip->daddr,
        .code = icmp->code,
        .id = icmp->un.echo.id,
        .type = ICMP_ECHOREPLY,
    };

    struct icmp_conntrack_info info = {
        .saddr = ip->saddr,
        .src_region = src_region,
    };

    bpf_map_update_elem(&icmp_conntrack_table, &tuple, &info, BPF_ANY);
}

static __always_inline struct icmp_conntrack_info *get_icmp_conntrack_info(struct iphdr *ip, struct icmphdr *icmp)
{
    struct icmp_conntrack_tuple tuple = {
        .laddr = ip->daddr,
        .faddr = ip->saddr,
        .code = icmp->code,
        .id = icmp->un.echo.id,
        .type = icmp->type,
    };

    return bpf_map_lookup_elem(&icmp_conntrack_table, &tuple);
}

static __always_inline __be16 assign_udp_port(struct iphdr *ip, struct udphdr *udp, const struct next_hop *hop)
{
    return bpf_htons(50000);
}

static __always_inline __be16 assign_tcp_port(struct iphdr *ip, struct tcphdr *tcp, const struct next_hop *hop)
{
    return bpf_htons(50000);
}

static __always_inline int forward(struct xdp_md *xdp, struct ethhdr *eth, struct iphdr *ip,
                                   const struct next_hop *hop)
{
    struct udphdr *udp = (struct udphdr *)(ip + 1);

    __builtin_memcpy(eth->h_source, hop->smac, ETH_ALEN);
    __builtin_memcpy(eth->h_dest, hop->dmac, ETH_ALEN);

    ip->saddr = hop->saddr;
    ip->daddr = hop->daddr;
    set_ipv4_csum(ip);
    set_udp_csum(udp, ip);

    return xdp->ingress_ifindex == hop->ifindex ? XDP_TX : bpf_redirect(hop->ifindex, 0);
}

static __always_inline int decap(struct xdp_md *xdp, struct encaphdr *encap, const struct next_hop *hop)
{
    void *data_end;
    struct ethhdr *eth;
    struct iphdr *ip;
    struct tcphdr *tcp;
    struct udphdr *udp;
    struct icmphdr *icmp;
    __u16 src_region = bpf_ntohs(encap->src_region);
    __be16 lport;

    if (bpf_xdp_adjust_head(xdp, sizeof(struct encaphdr)))
        return XDP_DROP;

    eth = (void *)(long)xdp->data;
    data_end = (void *)(long)xdp->data_end;
    if ((void *)(eth + 1) > data_end)
        return XDP_DROP;

    ip = (struct iphdr *)(eth + 1);
    if ((void *)(ip + 1) > data_end) {
        return XDP_DROP;
    }

    eth->h_proto = bpf_htons(ETH_P_IP);

    // hard code (only support NS1)
    if (ip->daddr == 1677724170) {
        __builtin_memcpy(eth->h_source, hop->dmac, ETH_ALEN);
        __builtin_memcpy(eth->h_dest, hop->smac, ETH_ALEN);
        return XDP_PASS;
    }

    switch (ip->protocol) {
    case IPPROTO_TCP:
        tcp = (struct tcphdr *)(ip + 1);
        if ((void *)(tcp + 1) > data_end)
            return XDP_DROP;

        lport = assign_tcp_port(ip, tcp, hop);
        set_l4_conntrack_info(src_region, ip, (struct l4hdr *)tcp, lport, IPPROTO_TCP, hop);
        tcp->source = lport;
        tcp->check = 34;
        break;

    case IPPROTO_UDP:
        udp = (struct udphdr *)(ip + 1);
        if ((void *)(udp + 1) > data_end)
            return XDP_DROP;

        lport = assign_udp_port(ip, udp, hop);
        set_l4_conntrack_info(src_region, ip, (struct l4hdr *)udp, lport, IPPROTO_UDP, hop);
        udp->source = lport;
        csum_udp(udp, hop->saddr, ip->daddr);
        break;

    case IPPROTO_ICMP:
        icmp = (struct icmphdr *)(ip + 1);
        if ((void *)(icmp + 1) > data_end)
            return XDP_DROP;

        set_icmp_conntrack_info(src_region, ip, icmp, hop);
        break;
    }

    __builtin_memcpy(eth->h_source, hop->smac, ETH_ALEN);
    __builtin_memcpy(eth->h_dest, hop->dmac, ETH_ALEN);

    ip->saddr = hop->saddr;
    set_ipv4_csum(ip);

    return xdp->ingress_ifindex == hop->ifindex ? XDP_TX : bpf_redirect(hop->ifindex, 0);
}

static __always_inline int l3_encap(struct xdp_md *xdp, struct next_hop *hop, __be32 saddr, __u16 src_region)
{
    void *data;
    void *data_end;
    struct ethhdr *new_eth;
    struct ethhdr *old_eth;
    struct encaphdr *encap;
    struct iphdr *ip;

    if (bpf_xdp_adjust_head(xdp, -(int)sizeof(struct encaphdr)))
        return -1;

    data = (void *)(long)xdp->data;
    data_end = (void *)(long)xdp->data_end;
    new_eth = (struct ethhdr *)data;
    if ((void *)(new_eth + 1) > data_end)
        return -1;

    old_eth = (struct ethhdr *)(data + sizeof(struct encaphdr));
    if ((void *)(old_eth + 1) > data_end)
        return -1;

    encap = (struct encaphdr *)(data + sizeof(struct ethhdr));
    if ((void *)(encap + 1) > data_end)
        return -1;

    ip = (struct iphdr *)(encap + 1);
    if ((void *)(ip + 1) > data_end)
        return -1;

    __builtin_memcpy(new_eth->h_source, hop->smac, ETH_ALEN);
    __builtin_memcpy(new_eth->h_dest, hop->dmac, ETH_ALEN);
    new_eth->h_proto = bpf_htons(ETH_P_IP);

    __builtin_memcpy(encap, ip, sizeof(struct iphdr));
    encap->ip.protocol = IPPROTO_UDP;
    encap->ip.tot_len = bpf_htons(sizeof(struct encaphdr) + bpf_ntohs(ip->tot_len));
    encap->ip.saddr = hop->saddr;
    encap->ip.daddr = hop->daddr;
    encap->ip.ihl = sizeof(struct iphdr) >> 2;
    set_ipv4_csum(&encap->ip);

    ip->daddr = saddr;
    set_ipv4_csum(ip);

    encap->udp.source = bpf_htons(SRC_PORT);
    encap->udp.dest = bpf_htons(DST_PORT);
    encap->udp.len = bpf_htons(bpf_ntohs(ip->tot_len) + sizeof(struct encaphdr) - sizeof(struct iphdr));
    encap->magic = bpf_htons(MAGIC);
    encap->src_region = 0;
    encap->dst_region = bpf_htons(src_region);
    set_udp_csum(&encap->udp, &encap->ip);

    return 0;
}

static __always_inline int udp_encap(struct xdp_md *xdp, __be16 sport)
{
    void *data = (void *)(long)xdp->data;
    void *data_end = (void *)(long)xdp->data_end;
    struct iphdr *ip;
    struct udphdr *udp;

    ip = (struct iphdr *)(data + sizeof(struct ethhdr) + sizeof(struct encaphdr));
    if ((void *)(ip + 1) > data_end)
        return -1;

    udp = (struct udphdr *)(ip + 1);
    if ((void *)(udp + 1) > data_end)
        return -1;

    udp->dest = sport;
    set_udp_csum(udp, ip);

    return 0;
}

static __always_inline int tcp_encap(struct xdp_md *xdp, __be16 sport)
{
    void *data = (void *)(long)xdp->data;
    void *data_end = (void *)(long)xdp->data_end;
    struct iphdr *ip;
    struct tcphdr *tcp;

    ip = (struct iphdr *)(data + sizeof(struct ethhdr) + sizeof(struct encaphdr));
    if ((void *)(ip + 1) > data_end)
        return -1;

    tcp = (struct tcphdr *)(ip + 1);
    if ((void *)(tcp + 1) > data_end)
        return -1;

    tcp->dest = sport;
    // set_tcp_csum(tcp, ip);

    return 0;
}

static __always_inline int tcp_input(struct xdp_md *xdp, struct ethhdr *eth, struct iphdr *ip,
                                     struct tcphdr *tcp, void *data_end)
{
    struct encaphdr *encap;
    struct next_hop *hop;
    struct l4_conntrack_info *info;

    info = get_l4_conntrack_info(ip, (struct l4hdr *)tcp, IPPROTO_TCP);
    if (!info) {
        return XDP_PASS;
    }

    hop = find_next_hop(info->src_region);
    if (!hop) {
        DEBUG("[tcp_input] find_next_hop failed, dst_region = %x", info->src_region);
        return XDP_DROP;
    }

    if (l3_encap(xdp, hop, info->saddr, info->src_region))
        return XDP_DROP;

    if (tcp_encap(xdp, info->sport))
        return XDP_DROP;

    return xdp->ingress_ifindex == hop->ifindex ? XDP_TX : bpf_redirect(hop->ifindex, 0);
}

static __always_inline int udp_input(struct xdp_md *xdp, struct ethhdr *eth, struct iphdr *ip,
                                     struct udphdr *udp, void *data_end)
{
    struct encaphdr *encap;
    struct next_hop *hop;
    struct l4_conntrack_info *info;
    int is_encapsulated = 1;

    do {
        if (bpf_ntohs(udp->source) != SRC_PORT ||
            bpf_ntohs(udp->dest) != DST_PORT) {
            is_encapsulated = 0;
            break;
        }

        encap = (struct encaphdr *)ip;
        if ((void *)(encap + 1) > data_end) {
            return XDP_DROP;
        }

        if (encap->magic != bpf_htons(MAGIC)) {
            is_encapsulated = 0;
            break;
        }
    } while (0);

    if (is_encapsulated) {
        hop = find_next_hop(bpf_ntohs(encap->dst_region));
        if (!hop) {
            DEBUG("[xdp_rx_tunnel] find_next_hop failed, dst_region = %x, ifindex = %d", bpf_ntohs(encap->dst_region), xdp->ingress_ifindex);
            return XDP_DROP;
        }

        if (hop->direct) {
            return decap(xdp, encap, hop);
        } else {
            return forward(xdp, eth, ip, hop);
        }
    }

    info = get_l4_conntrack_info(ip, (struct l4hdr *)udp, IPPROTO_UDP);
    if (!info) {
        return XDP_PASS;
    }

    hop = find_next_hop(info->src_region);
    if (!hop) {
        DEBUG("[udp_input] find_next_hop failed, dst_region = %x", info->src_region);
        return XDP_DROP;
    }

    if (l3_encap(xdp, hop, info->saddr, info->src_region))
        return XDP_DROP;

    if (udp_encap(xdp, info->sport))
        return XDP_DROP;

    return xdp->ingress_ifindex == hop->ifindex ? XDP_TX : bpf_redirect(hop->ifindex, 0);
}

static __always_inline int icmp_input(struct xdp_md *xdp, struct iphdr *ip, struct icmphdr *icmp)
{
    void *data;
    void *data_end;
    struct icmp_conntrack_info *info;
    struct ethhdr *new_eth;
    struct ethhdr *old_eth;
    struct encaphdr *encap;
    struct next_hop *hop;

    info = get_icmp_conntrack_info(ip, icmp);
    if (!info)
        return XDP_PASS;

    hop = find_next_hop(info->src_region);
    if (!hop) {
        DEBUG("[icmp_input] find_next_hop failed, dst_region = %x", info->src_region);
        return XDP_DROP;
    }

    if (l3_encap(xdp, hop, info->saddr, info->src_region))
        return XDP_DROP;

    return xdp->ingress_ifindex == hop->ifindex ? XDP_TX : bpf_redirect(hop->ifindex, 0);
}

SEC("xdp_rx")
int xdp_rx_tunnel(struct xdp_md *xdp)
{
    void *data_end = (void *)(long)xdp->data_end;
    void *data = (void *)(long)xdp->data;
    struct ethhdr *eth = (struct ethhdr *)(data);
    struct encaphdr *encap;
    struct iphdr *ip;
    struct tcphdr *tcp;
    struct udphdr *udp;
    struct icmphdr *icmp;
    struct next_hop *hop;
    int drop;

    if ((void *)(eth + 1) > data_end)
        return XDP_DROP;

    if (eth->h_proto != bpf_htons(ETH_P_IP)) {
        return XDP_PASS;
    }

    ip = (struct iphdr *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return XDP_DROP;

    switch (ip->protocol) {
    case IPPROTO_TCP:
        tcp = (struct tcphdr *)(ip + 1);
        if ((void *)(tcp + 1) > data_end)
            return XDP_DROP;

        return tcp_input(xdp, eth, ip, tcp, data_end);

    case IPPROTO_UDP:
        udp = (struct udphdr *)(ip + 1);
        if ((void *)(udp + 1) > data_end)
            return XDP_DROP;

        return udp_input(xdp, eth, ip, udp, data_end);

    case IPPROTO_ICMP:
        icmp = (struct icmphdr *)(ip + 1);
        if ((void *)(icmp + 1) > data_end)
            return XDP_DROP;

        return icmp_input(xdp, ip, icmp);
    }
    return XDP_PASS;
}

static char _license[] SEC("license") = "GPL";
