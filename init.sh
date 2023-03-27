#!/bin/bash
set -v

make

sudo ip netns del ns1
sudo ip netns del ns2
sudo ip netns del ns3
sudo ip netns del ns4
sudo ip netns del ns-router
sudo ip link del veth0

sudo ip route del 10.10.0.0/24 via 10.0.0.1
sudo ip route del 10.20.0.0/24 via 10.0.0.1
sudo ip route del 10.30.0.0/24 via 10.0.0.1
sudo ip route del 10.31.0.0/24 via 10.0.0.1
sudo ip route del 10.40.0.0/24 via 10.0.0.1

sudo rm /sys/fs/bpf/ns1_route_table_in_tc
sudo rm /sys/fs/bpf/ns1_route_table_in_xdp
sudo rm /sys/fs/bpf/ns2_route_table
sudo rm /sys/fs/bpf/ns3_route_table

sudo ip netns add ns1
sudo ip netns add ns2
sudo ip netns add ns3
sudo ip netns add ns4
sudo ip netns add ns-router

sudo ip link add veth0 type veth peer name ns0-router0
sudo ip link set ns0-router0 netns ns-router

sudo ip link add ns1-veth0 type veth peer name ns1-router0
sudo ip link set ns1-veth0 netns ns1
sudo ip link set ns1-router0 netns ns-router

sudo ip link add ns2-veth0 type veth peer name ns2-router0
sudo ip link set ns2-veth0 netns ns2
sudo ip link set ns2-router0 netns ns-router

sudo ip link add ns3-veth0 type veth peer name ns3-router0
sudo ip link set ns3-veth0 netns ns3
sudo ip link set ns3-router0 netns ns-router

sudo ip link add ns3-veth1 type veth peer name ns3-router1
sudo ip link set ns3-veth1 netns ns3
sudo ip link set ns3-router1 netns ns-router

sudo ip link add ns4-veth0 type veth peer name ns4-router0
sudo ip link set ns4-veth0 netns ns4
sudo ip link set ns4-router0 netns ns-router

sudo ip addr add 10.0.0.100/24 dev veth0
sudo ip -n ns1 addr add 10.10.0.100/24 dev ns1-veth0
sudo ip -n ns2 addr add 10.20.0.100/24 dev ns2-veth0
sudo ip -n ns3 addr add 10.30.0.100/24 dev ns3-veth0
sudo ip -n ns3 addr add 10.31.0.100/24 dev ns3-veth1
sudo ip -n ns4 addr add 10.40.0.100/24 dev ns4-veth0

sudo ip -n ns-router addr add 10.0.0.1/24 dev ns0-router0
sudo ip -n ns-router addr add 10.10.0.1/24 dev ns1-router0
sudo ip -n ns-router addr add 10.20.0.1/24 dev ns2-router0
sudo ip -n ns-router addr add 10.30.0.1/24 dev ns3-router0
sudo ip -n ns-router addr add 10.31.0.1/24 dev ns3-router1
sudo ip -n ns-router addr add 10.40.0.1/24 dev ns4-router0

sudo ip link set veth0 up
sudo ip -n ns1 link set ns1-veth0 up
sudo ip -n ns2 link set ns2-veth0 up
sudo ip -n ns3 link set ns3-veth0 up
sudo ip -n ns3 link set ns3-veth1 up
sudo ip -n ns4 link set ns4-veth0 up
sudo ip -n ns1 link set lo up
sudo ip -n ns2 link set lo up
sudo ip -n ns3 link set lo up
sudo ip -n ns4 link set lo up
sudo ip -n ns-router link set ns0-router0 up
sudo ip -n ns-router link set ns1-router0 up
sudo ip -n ns-router link set ns2-router0 up
sudo ip -n ns-router link set ns3-router0 up
sudo ip -n ns-router link set ns3-router1 up
sudo ip -n ns-router link set ns4-router0 up

sudo ip route add 10.10.0.0/24 via 10.0.0.1
sudo ip route add 10.20.0.0/24 via 10.0.0.1
sudo ip route add 10.30.0.0/24 via 10.0.0.1
sudo ip route add 10.31.0.0/24 via 10.0.0.1
sudo ip route add 10.40.0.0/24 via 10.0.0.1

sudo ip -n ns1 route add default via 10.10.0.1
sudo ip -n ns2 route add default via 10.20.0.1
sudo ip -n ns3 rule add from 10.30.0.100/32 lookup 30
sudo ip -n ns3 rule add from 10.31.0.100/32 lookup 31
sudo ip -n ns3 route add default via 10.30.0.1 table 30
sudo ip -n ns3 route add default via 10.31.0.1 table 31
sudo ip -n ns4 route add default via 10.40.0.1
sudo ip -n ns-router route add default via 10.0.0.100

sudo ip netns exec ns1 tc qdisc add dev ns1-veth0 clsact
sudo ip netns exec ns1 tc filter add dev ns1-veth0 egress bpf direct-action obj ./tc_tunnel_kern.o sec tc_tx
# sudo ip -n ns1 link set dev ns1-veth0 xdpgeneric off
sudo ip -n ns1 link set dev ns1-veth0 xdpgeneric obj ./xdp_tunnel_kern.o sec xdp_rx
# sudo ip -n ns2 link set dev ns2-veth0 xdpgeneric off
sudo ip -n ns2 link set dev ns2-veth0 xdpgeneric obj ./xdp_tunnel_kern.o sec xdp_rx
# sudo ip -n ns3 link set dev ns3-veth0 xdpgeneric off

sudo ip -n ns3 link set dev ns3-veth0 xdpgeneric obj ./xdp_tunnel_kern.o sec xdp_rx
LAST_PROG_ID=$(sudo bpftool prog | grep 'xdp_rx_tunnel' | tail -1 | awk '{print $1}' | sed 's/://')
sudo ip netns exec ns3 bpftool net attach xdpgeneric id $LAST_PROG_ID dev ns3-veth1

NS1_MAP_IN_TC=$(sudo bpftool map | grep 'route_table' | head -1 | tail -1 | awk '{print $1}' | sed 's/://')
NS1_MAP_IN_XDP=$(sudo bpftool map | grep 'route_table' | head -2 | tail -1 | awk '{print $1}' | sed 's/://')
NS2_MAP=$(sudo bpftool map | grep 'route_table' | head -3 | tail -1 | awk '{print $1}' | sed 's/://')
NS3_MAP=$(sudo bpftool map | grep 'route_table' | tail -1 | awk '{print $1}' | sed 's/://')

NS1_IFINDEX=$(sudo ip netns exec ns1 ip a l | grep 'ns1-veth0' | grep 'mtu' | awk '{print $1}' | sed 's/://')
NS2_IFINDEX=$(sudo ip netns exec ns2 ip a l | grep 'ns2-veth0' | grep 'mtu' | awk '{print $1}' | sed 's/://')
NS3_IFINDEX0=$(sudo ip netns exec ns3 ip a l | grep 'ns3-veth0' | grep 'mtu' | awk '{print $1}' | sed 's/://')
NS3_IFINDEX1=$(sudo ip netns exec ns3 ip a l | grep 'ns3-veth1' | grep 'mtu' | awk '{print $1}' | sed 's/://')

NS1_IFINDEX_MAC=$(sudo ip -n ns1 link show ns1-veth0 | grep 'link' | awk '{print $2}')
NS2_IFINDEX_MAC=$(sudo ip -n ns2 link show ns2-veth0 | grep 'link' | awk '{print $2}')
NS3_IFINDEX0_MAC=$(sudo ip -n ns3 link show ns3-veth0 | grep 'link' | awk '{print $2}')
NS3_IFINDEX1_MAC=$(sudo ip -n ns3 link show ns3-veth1 | grep 'link' | awk '{print $2}')

NS1_ROUTER0_MAC=$(sudo ip -n ns-router link show ns1-router0 | grep 'link' | awk '{print $2}')
NS2_ROUTER0_MAC=$(sudo ip -n ns-router link show ns2-router0 | grep 'link' | awk '{print $2}')
NS3_ROUTER0_MAC=$(sudo ip -n ns-router link show ns3-router0 | grep 'link' | awk '{print $2}')
NS3_ROUTER1_MAC=$(sudo ip -n ns-router link show ns3-router1 | grep 'link' | awk '{print $2}')

sudo mkdir -p /sys/fs/bpf
sudo bpftool map pin id $NS1_MAP_IN_TC /sys/fs/bpf/ns1_route_table_in_tc
sudo bpftool map pin id $NS1_MAP_IN_XDP /sys/fs/bpf/ns1_route_table_in_xdp
sudo bpftool map pin id $NS2_MAP /sys/fs/bpf/ns2_route_table
sudo bpftool map pin id $NS3_MAP /sys/fs/bpf/ns3_route_table

sudo ./tunnel_user /sys/fs/bpf/ns1_route_table_in_tc 4 $NS1_IFINDEX 10.10.0.100 10.20.0.100 $NS1_IFINDEX_MAC $NS1_ROUTER0_MAC 0
sudo ./tunnel_user /sys/fs/bpf/ns1_route_table_in_xdp 4 $NS1_IFINDEX 10.10.0.100 10.20.0.100 $NS1_IFINDEX_MAC $NS1_ROUTER0_MAC 0
sudo ./tunnel_user /sys/fs/bpf/ns1_route_table_in_tc 1 $NS1_IFINDEX 10.10.0.100 0 $NS1_IFINDEX_MAC $NS1_ROUTER0_MAC 1
sudo ./tunnel_user /sys/fs/bpf/ns1_route_table_in_xdp 1 $NS1_IFINDEX 10.10.0.100 0 $NS1_IFINDEX_MAC $NS1_ROUTER0_MAC 1

sudo ./tunnel_user /sys/fs/bpf/ns2_route_table 1 $NS2_IFINDEX 10.20.0.100 10.10.0.100 $NS2_IFINDEX_MAC $NS2_ROUTER0_MAC 0
sudo ./tunnel_user /sys/fs/bpf/ns2_route_table 4 $NS2_IFINDEX 10.20.0.100 10.30.0.100 $NS2_IFINDEX_MAC $NS2_ROUTER0_MAC 0 

sudo ./tunnel_user /sys/fs/bpf/ns3_route_table 1 $NS3_IFINDEX0 10.30.0.100 10.20.0.100 $NS3_IFINDEX0_MAC $NS3_ROUTER0_MAC 0
sudo ./tunnel_user /sys/fs/bpf/ns3_route_table 4 $NS3_IFINDEX1 10.31.0.100 0 $NS3_IFINDEX1_MAC $NS3_ROUTER1_MAC 1
