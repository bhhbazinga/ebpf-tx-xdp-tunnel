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

SEC("tc_tx")
int tc_tx_tunnel(struct __sk_buff *skb)
{
    void *data_end = (void *)(long)skb->data_end;
    void *data = (void *)(long)skb->data;
    struct iphdr *inner_ip;
    struct encaphdr encap;
    struct next_hop *hop;
    __u16 payload_len;

    struct ethhdr *eth = (struct ethhdr *)(data);
    if ((void *)(eth + 1) > data_end)
        return TC_ACT_SHOT;

    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return TC_ACT_OK;

    inner_ip = (struct iphdr *)(eth + 1);
    if ((void *)(inner_ip + 1) > data_end)
        return TC_ACT_SHOT;

    if (inner_ip->protocol != IPPROTO_TCP &&
        inner_ip->protocol != IPPROTO_UDP &&
        inner_ip->protocol != IPPROTO_ICMP)
        return TC_ACT_OK;

    hop = find_next_hop(NS4_REGION);
    if (!hop) {
        DEBUG("[tc_tx_tunnel] find_next_hop failed, dst_region = %x", NS4_REGION);
        return TC_ACT_SHOT;
    }

    payload_len = bpf_ntohs(inner_ip->tot_len);

    __builtin_memset(&encap, 0, sizeof(struct encaphdr));

    if (bpf_skb_load_bytes(skb, ETH_HLEN, &encap, sizeof(struct iphdr)))
        return TC_ACT_SHOT;

    if (bpf_skb_adjust_room(skb, sizeof(struct encaphdr), BPF_ADJ_ROOM_MAC,
                            BPF_F_ADJ_ROOM_FIXED_GSO |
                                BPF_F_ADJ_ROOM_ENCAP_L3_IPV4 |
                                BPF_F_ADJ_ROOM_ENCAP_L4_UDP))
        return TC_ACT_SHOT;

    encap.ip.protocol = IPPROTO_UDP;
    encap.ip.tot_len = bpf_htons(sizeof(struct encaphdr) + payload_len);
    encap.ip.daddr = hop->daddr;
    encap.ip.ihl = sizeof(struct iphdr) >> 2;
    set_ipv4_csum(&encap.ip);

    encap.udp.source = bpf_htons(SRC_PORT);
    encap.udp.dest = bpf_htons(DST_PORT);
    encap.udp.len = bpf_htons(payload_len + sizeof(struct encaphdr) - sizeof(struct iphdr));
    encap.magic = bpf_htons(MAGIC);
    encap.src_region = bpf_htons(NS1_REGION);
    encap.dst_region = bpf_htons(NS4_REGION);
    set_udp_csum(&encap.udp, &encap.ip);

    if (bpf_skb_store_bytes(skb, ETH_HLEN, &encap, sizeof(struct encaphdr),
                            BPF_F_INVALIDATE_HASH))
        return TC_ACT_SHOT;

    return TC_ACT_OK;
}

static char _license[] SEC("license") = "GPL";
