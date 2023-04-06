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

static __always_inline int get_proto_ports_offset(__u64 proto)
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

static __always_inline void parse_ip(struct iphdr *iph, __u64 *ip_proto, struct bpf_flow_keys *flow)
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

static __always_inline void init_buffer_pointer(u64 **head, u64 **tail, int head_key, int tail_key)
{
	*head = bpf_map_lookup_elem(&tcp_buffer_pointer, &head_key);
	*tail = bpf_map_lookup_elem(&tcp_buffer_pointer, &tail_key);
}
static __always_inline void parse_tcp_handshake(struct sysdig_bpf_settings *settings, struct bpf_flow_keys *flow, u64 *cur_time)
{
	bool SYN = flow->flag & (1 << 1);
	bool ACK = flow->flag & (1 << 4);

	struct tcp_tuple cur_tuple = new_tuple(flow);

	int cpu = bpf_get_smp_processor_id();

	u64 *head, *tail;
	int head_key = TCP_HANDSHAKE_BUFFER_HEAD, tail_key = TCP_HANDSHAKE_BUFFER_TAIL;
	init_buffer_pointer(&head, &tail, head_key, tail_key);

	if(likely(SYN == 0 && ACK == 1))
	{
		struct tcp_handshake_rtt *s_rtt = bpf_map_lookup_elem(&tcp_handshake_map, &cur_tuple);
		// the third handshake
		if(likely(s_rtt))
		{
			bpf_printk("third: insert to handshake buffer: synrtt: %llu, ackrtt: %llu, timestamp: %llu\n", s_rtt->synrtt, s_rtt->ackrtt, *cur_time);
			tail = bpf_map_lookup_elem(&tcp_buffer_pointer, &tail_key);
			if(likely(tail))
			{
				struct tcp_handshake_buffer_elem cur_elem = {};
				cur_elem.tp = cur_tuple;
				cur_elem.synrtt = s_rtt->ackrtt - s_rtt->synrtt; // synrtt = second - first
				cur_elem.ackrtt = *cur_time - s_rtt->ackrtt;	 // ackrtt = third - second
				cur_elem.timestamp = *cur_time;
				// clear map
				bpf_map_delete_elem(&tcp_handshake_map, &cur_tuple);
				bpf_map_update_elem(&tcp_handshake_buffer, tail, &cur_elem, BPF_ANY);
				if(likely(*tail < MAX_BUFFER_LEN - 1))
				{
					__sync_fetch_and_add(tail, 1); // tail++
				}
				else
				{
					*tail = 0; // reset tail
				}
			}
			else
			{
				bpf_printk("handshake buffer error, the tail pointer not found in the third handshake.\n");
			}
		}
		else
		{
			bpf_printk("handshake map error, the second handshake not found.\n");
		}
	}
	else if(SYN == 1)
	{
		if(ACK == 0)
		{ // the first handshake
			struct tcp_handshake_rtt f_rtt = {};
			f_rtt.synrtt = *cur_time;
			bpf_map_update_elem(&tcp_handshake_map, &cur_tuple, &f_rtt, BPF_ANY);
			bpf_printk("first: cur_time: %llu, cpuid = %d\n", *cur_time, cpu);
		}
		else
		{ // the second handshake
			reverse_tuple(&cur_tuple);
			struct tcp_handshake_rtt *f_rtt = bpf_map_lookup_elem(&tcp_handshake_map, &cur_tuple);
			if(f_rtt)
			{
				f_rtt->ackrtt = *cur_time; // update to the second handshake timestamp
				bpf_printk("second: cur_time: %llu, cpuid = %d\n", *cur_time, cpu);
			}
			else // only drop if not match
			{
				bpf_printk("handshake map error, the first handshake not found.\n");
				bpf_map_delete_elem(&tcp_handshake_map, &cur_tuple);
			}
		}
	}
}

static __always_inline void parse_tcp_datainfo(struct sysdig_bpf_settings *settings, struct bpf_flow_keys *flow, u64 *cur_time)
{
	bool SYN = flow->flag & (1 << 1);
	bool ACK = flow->flag & (1 << 4);
	bool FIN = flow->flag & 1;

	struct tcp_tuple cur_tuple = new_tuple(flow);

	struct tcp_datainfo_last *last_package = bpf_map_lookup_elem(&tcp_datainfo_map, &cur_tuple);
	if(likely(last_package))
	{
		__sync_fetch_and_add(&last_package->package_counts, 1);
	}
	else
	{
		struct tcp_datainfo_last last = {};
		last.package_counts = 1;
		bpf_map_update_elem(&tcp_datainfo_map, &cur_tuple, &last, BPF_ANY);
		last_package = bpf_map_lookup_elem(&tcp_datainfo_map, &cur_tuple);
	}

	if(likely(SYN == 0 && ACK == 1))
	{
		if(likely(FIN == 0))
		{
			reverse_tuple(&cur_tuple);
			struct tcp_datainfo_last *last_rcv_pkg = bpf_map_lookup_elem(&tcp_datainfo_map, &cur_tuple);
			if(likely(last_package && last_rcv_pkg && last_rcv_pkg->last_fin == 0))
			{
				reverse_tuple(&cur_tuple);
				u64 *head, *tail;
				int head_key = TCP_DATAINFO_BUFFER_HEAD, tail_key = TCP_DATAINFO_BUFFER_TAIL;
				init_buffer_pointer(&head, &tail, head_key, tail_key);
				struct tcp_datainfo info = {};
				info.tp = cur_tuple;
				info.seq = flow->seq;
				info.ack_seq = flow->ack_seq;
				info.package_counts = last_package->package_counts;
				info.timestamp = *cur_time;
				if(likely(tail))
				{
					bpf_map_update_elem(&tcp_datainfo_buffer, tail, &info, BPF_ANY);
					if(likely(*tail < MAX_BUFFER_LEN - 1))
					{
						__sync_fetch_and_add(tail, 1); // tail++
					}
					else
					{
						*tail = 0; // reset tail
					}
				}
			}
			else if(last_package && last_rcv_pkg && last_rcv_pkg->last_fin == 1 && last_package->last_fin == 1)
			{
				// If two FIN flags are encountered, clean up the map
				bpf_map_delete_elem(&tcp_datainfo_map, &cur_tuple);
				reverse_tuple(&cur_tuple);
				bpf_map_delete_elem(&tcp_datainfo_map, &cur_tuple);
			}
		}
		else
		{
			if(last_package)
			{
				last_package->last_fin = 1;
			}
		}
	}
}

static __always_inline void send_tcp_rawdata(struct sysdig_bpf_settings *settings, struct bpf_flow_keys *flow, u64 *cur_time){
	struct tcp_tuple cur_tuple = new_tuple(flow);
	u64 *head, *tail;
	int head_key = TCP_RAWDATA_BUFFER_HEAD, tail_key = TCP_RAWDATA_BUFFER_TAIL;
	init_buffer_pointer(&head, &tail, head_key, tail_key);
	struct tcp_raw_data raw_tcp = {};
	raw_tcp.tp = cur_tuple;
	raw_tcp.seq = flow->seq;
	raw_tcp.ack_seq = flow->ack_seq;
	raw_tcp.timestamp = *cur_time;
	raw_tcp.flag = flow->flag;
	if(likely(tail))
	{
		bpf_map_update_elem(&tcp_rawdata_buffer, tail, &raw_tcp, BPF_ANY);
		if(likely(*tail < MAX_BUFFER_LEN - 1))
		{
			__sync_fetch_and_add(tail, 1); // tail++
		}
		else
		{
			*tail = 0; // reset tail
		}
	}

}

static __always_inline void parse_tcp(struct tcphdr *tcph, __u64 *ip_proto, struct bpf_flow_keys *flow, u64 *cur_time, u64 *interface_type)
{
	flow->seq = __constant_htonl(_READ(tcph->seq));
	flow->ack_seq = __constant_htonl(_READ(tcph->ack_seq));
	bpf_probe_read(&flow->flag, sizeof(flow->flag), (void *)tcph + 12);
	flow->flag = __constant_htons(flow->flag);

	int poff = get_proto_ports_offset(*ip_proto);
	if(poff >= 0)
	{
		flow->port16[0] = __constant_htons(_READ(tcph->source));
		flow->port16[1] = __constant_htons(_READ(tcph->dest));
	}

	struct sysdig_bpf_settings *settings = get_bpf_settings();
	if(!settings || !settings->capture_enabled)
		return;

	if(*interface_type == CONTAINER_INTERFACE)
	{
		parse_tcp_handshake(settings, flow, cur_time);
		parse_tcp_datainfo(settings, flow, cur_time);
	}
	send_tcp_rawdata(settings, flow, cur_time);
	
	return;
}

static __always_inline void parse_udp(struct udphdr *udph, __u64 *ip_proto, struct bpf_flow_keys *flow, u64 *cur_time, u64 *interface_type)
{
	// parse UDP header
	__u16 source = __constant_htons(_READ(udph->source));
	__u16 dest = __constant_htons(_READ(udph->dest));
	__u16 len = __constant_htons(_READ(udph->len));
	__u16 check = __constant_htons(_READ(udph->check));

	// char fmt1[] = "enter parse udp...dest = %d, vxlan_port = %d\n";
	// bpf_trace_printk(fmt1, sizeof(fmt1), dest, vxlan_port);

	if(dest == 4789 || dest == 8472) //VXLAN port
	{
		// char fmt[] = "get VXLAN protocol...dest = %d, vxlan_port = %d\n";
		// bpf_trace_printk(fmt, sizeof(fmt), dest, vxlan_port);

		// char fmt_ipo[] = "get out--src_ip = %u, out--dst_ip = %u\n";
		// bpf_trace_printk(fmt_ipo, sizeof(fmt_ipo), flow->src, flow->dst);
		struct iphdr *iph = (struct iphdr *)((__u64)udph + VXLAN_HLEN + ETH_HLEN);

		parse_ip(iph, &ip_proto, flow);

		parse_tcp(iph, &ip_proto, flow, cur_time, interface_type);
		
		// char fmt_ip[] = "get in--src_ip = %u, in--dst_ip = %u\n\n";
		// bpf_trace_printk(fmt_ip, sizeof(fmt_ip), flow->src, flow->dst);
	}
}

static __always_inline bool flow_dissector(struct sk_buff *skb, struct bpf_flow_keys *flow, u64 *cur_time, u64 interface_type)
{
	void *head = _READ(skb->head);
	void *pkt_data = _READ(skb->data);
	u32 data_len = _READ(skb->len);
	void *data_end = (void *)(data_len + (long)pkt_data);
	__u16 mac_offset = _READ(skb->mac_header);
	struct ethhdr *eth = (struct skbhdr *)((__u64)head + (__u64)mac_offset);
	struct iphdr *iph;

	__u64 nhoff = ETH_HLEN;
	__u64 ip_proto;
	__u16 proto = _READ(eth->h_proto);
	proto = htons(proto);

	if(likely(proto == ETH_P_IP))
	{
		__u16 ip_offset = _READ(skb->network_header);
		iph = (struct iphdr *)((__u64)head + (__u64)ip_offset);
		parse_ip(iph, &ip_proto, flow); 
	}
	else
		return false;

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

	// if(interface_type == PHYSICAL_INTERFACE && ip_proto != IPPROTO_UDP && !is_ipip) return false;
	switch(ip_proto)
	{
	case IPPROTO_UDP:
	{
		struct udphdr *udph = (struct udphdr *)((__u64)iph + sizeof(*iph));
		if ((__u64)udph + 1 > (__u64)data_end) {
			return false;
		}
		parse_udp(udph, &ip_proto, flow, cur_time, &interface_type);
		break;
	}
	case IPPROTO_TCP:
	{
		struct tcphdr *tcph = (struct tcphdr *)((__u64)iph + sizeof(*iph));
		if ((__u64)tcph + 1 > (__u64)data_end) {
			return false;
		}
		parse_tcp(tcph, &ip_proto, flow, cur_time, &interface_type);
		break;
	}
	default:
		break;
	}

	flow->ip_proto = ip_proto;

	// char log1[] = "ifindex = %u, srcip = %u, dstip = %u\n";
	// char log2[] = "seq = %u, sport = %d, dport = %d\n";
	// char log3[]="SYN = %d, ACK = %d, FIN = %d\n";
	// char log4[]="flow->ip_proto: %d, curtime = %llu\n";
	// char log5[] = "skb_addr = %lld\n";
	// bool SYN = flow->flag & (1 << 1);
	// bool FIN = flow->flag & 1;
	// bool ACK = flow->flag & (1 << 4);
	// bpf_trace_printk(log1, sizeof(log1), flow->ifindex, flow->src, flow->dst);
	// bpf_trace_printk(log2, sizeof(log2), flow->seq, flow->port16[0], flow->port16[1]);
	// bpf_trace_printk(log3, sizeof(log3), SYN, ACK, FIN);
	// bpf_trace_printk(log4, sizeof(log4), flow->ip_proto, *cur_time);
	// bpf_trace_printk(log5, sizeof(log5), skb);

	return true;
}

#endif