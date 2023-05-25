/*

Copyright (C) 2023 The Kindling Authors.

This file is dual licensed under either the MIT or GPL 2. See MIT.txt
or GPL2.txt for full copies of the license.

*/
#ifndef __SOCKET_HELPERS_H
#define __SOCKET_HELPERS_H

#include <uapi/linux/bpf.h>
#include <uapi/linux/in.h>
#include <uapi/linux/if.h>
#include <uapi/linux/if_ether.h>
#include <uapi/linux/ip.h>
#include <uapi/linux/ipv6.h>
#include <uapi/linux/tcp.h>
#include <uapi/linux/if_tunnel.h>

#include "bpf_helpers.h"
#include "types.h"

#define IP_MF 0x2000
#define IP_OFFSET 0x1FFF
#define IP_HOST 0x7F000001
#define VXLAN_HLEN 8

static __always_inline int get_proto_ports_offset(__u8 proto)
{
	switch(proto)
	{
	case IPPROTO_TCP:
	case IPPROTO_UDP:
	case IPPROTO_DCCP:
	case IPPROTO_ESP:
	case IPPROTO_SCTP:
	case IPPROTO_UDPLITE:
		return 0;
	case IPPROTO_AH:
		return 4;
	default:
		return 0;
	}
}

static __always_inline int is_ip_fragment(struct iphdr *iph)
{
	return __constant_htons(_READ(iph->frag_off)) & (IP_MF | IP_OFFSET);
}

/*
	To distinguish packets that is from a container network interface or a physical network interface, 
	we use is_overlay field. Currently, we only focus on 'UDP+VXLAN'(by Flannel) and 'IPIP'(by Calico).
*/

static __always_inline void parse_ip(struct iphdr *iph, __u8 *ip_proto, struct bpf_flow_keys *flow)
{
	if(unlikely(is_ip_fragment(iph)))
		*ip_proto = 0;
	else
		*ip_proto = _READ(iph->protocol);

	if(*ip_proto != IPPROTO_GRE)
	{
		flow->src = __constant_htonl(_READ(iph->saddr));
		flow->dst = __constant_htonl(_READ(iph->daddr));
	}
}


static __always_inline void reverse_tuple(struct tcp_tuple *tp)
{
	// swap port
	tp->sport = tp->sport ^ tp->dport;
	tp->dport = tp->sport ^ tp->dport;
	tp->sport = tp->sport ^ tp->dport;
	// swap ip
	tp->saddr = tp->saddr ^ tp->daddr;
	tp->daddr = tp->saddr ^ tp->daddr;
	tp->saddr = tp->saddr ^ tp->daddr;
}

static __always_inline struct tcp_tuple new_tuple(struct bpf_flow_keys *flow)
{
	struct tcp_tuple cur_tuple = {};
	memset(&cur_tuple, 0, sizeof(cur_tuple)); // Because of memory alignment, it is best to initialize all spaces with memset (to prevent the compiler from causing bpf verifier error when the space is not filled)
	cur_tuple.sport = flow->port16[1];
	cur_tuple.dport = flow->port16[0];
	cur_tuple.saddr = flow->src;
	cur_tuple.daddr = flow->dst;
	cur_tuple.ifindex = flow->ifindex;
	return cur_tuple;
}

static __always_inline bool parse_tcp(struct tcphdr *tcph, __u8 *ip_proto, struct bpf_flow_keys *flow, u64 *interface_type)
{
	int poff = get_proto_ports_offset(*ip_proto);
	if(poff >= 0)
	{
		flow->port16[0] = __constant_htons(_READ(tcph->source));
		flow->port16[1] = __constant_htons(_READ(tcph->dest));
	}

	if(flow->port16[0] == 22 || flow->port16[1] == 22) return false;//filter out SSH protocol
	flow->seq = __constant_htonl(_READ(tcph->seq));
	flow->ack_seq = __constant_htonl(_READ(tcph->ack_seq));
	bpf_probe_read(&flow->flag, sizeof(flow->flag), (void *)tcph + 12);
	flow->flag = __constant_htons(flow->flag);
	flow->window = __constant_htons(_READ(tcph->window));

	
	return true;
}

static __always_inline bool parse_udp(struct udphdr *udph, __u8 *ip_proto, struct bpf_flow_keys *flow, u64 *interface_type)
{
	// parse UDP header
	__u16 source = __constant_htons(_READ(udph->source));
	__u16 dest = __constant_htons(_READ(udph->dest));
	__u16 len = __constant_htons(_READ(udph->len));
	__u16 check = __constant_htons(_READ(udph->check));

	if(dest == 4789 || dest == 8472) //VXLAN port
	{
		struct iphdr *iph = (struct iphdr *)((__u64)udph + sizeof(*udph) + VXLAN_HLEN + ETH_HLEN);

		parse_ip(iph, ip_proto, flow);

		if(*ip_proto != IPPROTO_TCP) return false;

		struct tcphdr *tcph = (struct tcphdr *)((__u64)iph + sizeof(*iph));

		if(parse_tcp(tcph, &ip_proto, flow, interface_type)){
			return true;
		}
	}
	return false;
}

static __always_inline void reset_skb(void **head, void **data, __u16 *network_header)
{
	*network_header = (unsigned char *)(*data) - (unsigned char *)(*head);
}

static __always_inline bool flow_dissector(struct sk_buff *skb, struct bpf_flow_keys *flow, u64 interface_type, u16 direction_type)
{
	void *head = _READ(skb->head);
	void *pkt_data = _READ(skb->data);
	u32 data_len = _READ(skb->len);
	void *data_end = (void *)(data_len + (long)pkt_data);

	__u16 mac_offset = _READ(skb->mac_header);
	struct ethhdr *eth = (struct skbhdr *)((__u64)head + (__u64)mac_offset);
	struct iphdr *iph;
	__u16 ip_offset = _READ(skb->network_header);
	if(direction_type == 0){ //reset_skb when netif_receive_skb
		reset_skb(&head, &pkt_data, &ip_offset);
	}

	__u8 ip_proto;
	__u16 proto = _READ(eth->h_proto);
	proto = htons(proto);

	if(likely(proto == ETH_P_IP))
	{
		iph = (struct iphdr *)((__u64)head + (__u64)ip_offset);
		if (unlikely((__u64)iph + 1 > (__u64)data_end)) {
			return false;
		}
		parse_ip(iph, &ip_proto, flow); 
	}
	else
	{
		return false;
	}
		

	if(flow->src == IP_HOST || flow->dst == IP_HOST)
		return false; // host ip filter

	bool is_ipip = false;

	switch(ip_proto)
	{
	case IPPROTO_IPIP:
	{
		iph = (struct iphdr *)((__u64)iph + sizeof(*iph));
		if ((__u64)iph + 1 > (__u64)data_end) {
			return false;
		}
		parse_ip(iph, &ip_proto, flow);
		is_ipip = true;
		break;
	}
	default:
		break;
	}

	/*
		Note: We think it is from calico network when we capture a packet with IPIP proto.
		So be careful in userspace when we get a packet from the physical interface!
		TODO. It may be a bug if a packet with IPIP proto come but not from calico network.
	*/

	if(interface_type == PHYSICAL_INTERFACE && ip_proto != IPPROTO_UDP && !is_ipip) return false;

	switch(ip_proto)
	{
	case IPPROTO_UDP:
	{
		struct udphdr *udph = (struct udphdr *)((__u64)iph + sizeof(*iph));

		if ((__u64)udph + 1 > (__u64)data_end) {
			return false;
		}
		if(!parse_udp(udph, &ip_proto, flow, &interface_type)){ //return fasle if not from Flannel+VXLAN network
			return false;
		}
		break;
	}
	case IPPROTO_TCP:
	{
		struct tcphdr *tcph = (struct tcphdr *)((__u64)iph + sizeof(*iph));
		if ((__u64)tcph + 1 > (__u64)data_end) {
			return false;
		}
		if(!parse_tcp(tcph, &ip_proto, flow, &interface_type)){
			return false;
		}
		break;
	}
	default:
		break;
	}

	flow->ip_proto = ip_proto;

	return true;
}

#endif