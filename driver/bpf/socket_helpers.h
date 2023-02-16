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

static __always_inline int ip_is_fragment(struct __sk_buff *ctx, __u64 nhoff)
{
	return load_half(ctx, nhoff + offsetof(struct iphdr, frag_off)) & (IP_MF | IP_OFFSET);
}

static __always_inline __u32 ipv6_addr_hash(struct __sk_buff *ctx, __u64 off)
{
	__u64 w0 = load_word(ctx, off);
	__u64 w1 = load_word(ctx, off + 4);
	__u64 w2 = load_word(ctx, off + 8);
	__u64 w3 = load_word(ctx, off + 12);

	return (__u32)(w0 ^ w1 ^ w2 ^ w3);
}

static __always_inline __u64 parse_ip(struct __sk_buff *skb, __u64 nhoff, __u64 *ip_proto,
				      struct bpf_flow_keys *flow)
{
	__u64 verlen;

	if(unlikely(ip_is_fragment(skb, nhoff))) //判断是否进行了ip分片
		*ip_proto = 0;
	else
		*ip_proto = load_byte(skb, nhoff + offsetof(struct iphdr, protocol));

	if(*ip_proto != IPPROTO_GRE)
	{
		flow->src = load_word(skb, nhoff + offsetof(struct iphdr, saddr));
		flow->dst = load_word(skb, nhoff + offsetof(struct iphdr, daddr));
	}

	verlen = load_byte(skb, nhoff + 0 /*offsetof(struct iphdr, ihl)*/);
	if(likely(verlen == 0x45))
		nhoff += 20;
	else
		nhoff += (verlen & 0xF) << 2;

	return nhoff; //返回ip数据报报文内容的偏移位置
}

static __always_inline __u64 parse_ipv6(struct __sk_buff *skb, __u64 nhoff, __u64 *ip_proto,
					struct bpf_flow_keys *flow)
{
	*ip_proto = load_byte(skb,
			      nhoff + offsetof(struct ipv6hdr, nexthdr));
	flow->src = ipv6_addr_hash(skb,
				   nhoff + offsetof(struct ipv6hdr, saddr));
	flow->dst = ipv6_addr_hash(skb,
				   nhoff + offsetof(struct ipv6hdr, daddr));
	nhoff += sizeof(struct ipv6hdr);

	return nhoff;
}

static __always_inline void reverse_tuple(struct tcp_tuple *tp)
{
	//swap port
	tp->sport = tp->sport ^ tp->dport;
	tp->dport = tp->sport ^ tp->dport;
	tp->sport = tp->sport ^ tp->dport;
	//swap ip
	tp->saddr = tp->saddr ^ tp->daddr;
	tp->daddr = tp->saddr ^ tp->daddr;
	tp->saddr = tp->saddr ^ tp->daddr;
}

static __always_inline struct tcp_tuple new_tuple(struct bpf_flow_keys *flow)
{
	struct tcp_tuple cur_tuple = {};
	memset(&cur_tuple, 0, sizeof(cur_tuple)); //由于内存对齐的原因，最好使用memset初始化所有空间（防止编译器填充空间不确定引发bpf verifier error）
	cur_tuple.sport = flow->port16[1];
	cur_tuple.dport = flow->port16[0];
	cur_tuple.saddr = flow->src;
	cur_tuple.daddr = flow->dst;
	return cur_tuple;
}

static __always_inline void init_buffer_pointer(u64 **head, u64 **tail, int head_key, int tail_key)
{
	*head = bpf_map_lookup_elem(&tcp_buffer_pointer, &head_key);
	*tail = bpf_map_lookup_elem(&tcp_buffer_pointer, &tail_key);
	if(!(*head) || !(*tail)) //初始化buffer pointer
	{
		u64 val = 0;
		const char m[] = "init head and tail.\n";
		bpf_trace_printk(m, sizeof(m));
		bpf_map_update_elem(&tcp_buffer_pointer, &head_key, &val, BPF_ANY);
		bpf_map_update_elem(&tcp_buffer_pointer, &tail_key, &val, BPF_ANY);
		*head = bpf_map_lookup_elem(&tcp_buffer_pointer, &head_key);
		*tail = bpf_map_lookup_elem(&tcp_buffer_pointer, &tail_key);
	}
}
static __always_inline void parse_tcp_handshake(struct sysdig_bpf_settings *settings, struct bpf_flow_keys *flow)
{
	bool SYN = flow->flag & (1 << 1);
	bool ACK = flow->flag & (1 << 4);

	struct tcp_tuple cur_tuple = new_tuple(flow);

	u64 cur_time = bpf_ktime_get_ns() + settings->boot_time;

	int cpu = bpf_get_smp_processor_id();

	u64 *head, *tail;
	int head_key = TCP_HANDSHAKE_BUFFER_HEAD, tail_key = TCP_HANDSHAKE_BUFFER_TAIL;
	init_buffer_pointer(&head, &tail, head_key, tail_key);

	if(SYN == 0 && ACK == 1)
	{
		struct tcp_handshake_rtt *s_rtt = bpf_map_lookup_elem(&tcp_handshake_map, &cur_tuple);
		//第三次握手
		if(s_rtt)
		{
			//s_rtt->synrtt = s_rtt->ackrtt - s_rtt->synrtt; //synrtt = 第二次握手时间戳-第一次握手时间戳
			//s_rtt->ackrtt = cur_time - s_rtt->ackrtt;      //ackrtt = 第三次握手时间戳 - 第二次握手时间戳
			const char log[] = "third: insert to handshake buffer: synrtt: %llu, ackrtt: %llu, timestamp: %llu\n";
			bpf_trace_printk(log, sizeof(log), s_rtt->synrtt, s_rtt->ackrtt, cur_time);
			u64 *tail = bpf_map_lookup_elem(&tcp_buffer_pointer, &tail_key);
			if(tail)
			{
				//三次握手数据均已处理完成，清除map
				// bpf_map_delete_elem(&tcp_handshake_map, &cur_tuple);
				struct tcp_handshake_buffer_elem cur_elem = {}; //填充数据
				cur_elem.tp = cur_tuple;
				cur_elem.synrtt = s_rtt->ackrtt - s_rtt->synrtt;
				cur_elem.ackrtt = cur_time - s_rtt->ackrtt;
				cur_elem.timestamp = cur_time;
				//三次握手数据均已处理完成，清除map
				bpf_map_delete_elem(&tcp_handshake_map, &cur_tuple);
				bpf_map_update_elem(&tcp_handshake_buffer, tail, &cur_elem, BPF_ANY);
				__sync_fetch_and_add(tail, 1); //数据填充完成，tail++
			}
			else
			{
				const char error[] = "handshake buffer error, the tail pointer not found in the third handshake.\n";
				bpf_trace_printk(error, sizeof(error));
			}
		}
		else
		{
			const char error[] = "handshake map error, the second handshake not found.\n";
			bpf_trace_printk(error, sizeof(error));
		}
	}
	else if(SYN == 1)
	{
		if(ACK == 0)
		{ //第一次握手
			struct tcp_handshake_rtt f_rtt = {};
			f_rtt.synrtt = cur_time;
			bpf_map_update_elem(&tcp_handshake_map, &cur_tuple, &f_rtt, BPF_ANY);

			const char tlog[] = "first: cur_time: %llu, cpuid = %d\n";
			bpf_trace_printk(tlog, sizeof(tlog), cur_time, cpu);
		}
		else
		{ //第二次握手
			reverse_tuple(&cur_tuple);
			struct tcp_handshake_rtt *f_rtt = bpf_map_lookup_elem(&tcp_handshake_map, &cur_tuple);
			if(f_rtt)
			{
				f_rtt->ackrtt = cur_time; //更新为第二次握手时间
				const char tlog[] = "second: cur_time: %llu, cpuid = %d\n";
				bpf_trace_printk(tlog, sizeof(tlog), cur_time, cpu);
			}
			else //对于没匹配到第一次握手的数据包直接丢弃
			{
				const char error[] = "handshake map error, the first handshake not found.\n";
				bpf_trace_printk(error, sizeof(error));
				bpf_map_delete_elem(&tcp_handshake_map, &cur_tuple);
			}
		}
	}
}

static __always_inline void parse_tcp_datainfo(struct sysdig_bpf_settings *settings, struct bpf_flow_keys *flow)
{
	bool SYN = flow->flag & (1 << 1);
	bool ACK = flow->flag & (1 << 4);
	bool FIN = flow->flag & 1;

	struct tcp_tuple cur_tuple = new_tuple(flow);

	struct tcp_datainfo_last *last_package = bpf_map_lookup_elem(&tcp_datainfo_map, &cur_tuple);
	if(last_package)
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

	if(SYN == 0 && ACK == 1)
	{
		if(FIN == 0)
		{
			reverse_tuple(&cur_tuple);
			struct tcp_datainfo_last *last_rcv_pkg = bpf_map_lookup_elem(&tcp_datainfo_map, &cur_tuple);
			if(last_package && last_rcv_pkg && last_rcv_pkg->last_fin == 0)
			{
				reverse_tuple(&cur_tuple);
				u64 *head, *tail;
				int head_key = TCP_DATAINFO_BUFFER_HEAD, tail_key = TCP_DATAINFO_BUFFER_TAIL;
				init_buffer_pointer(&head, &tail, head_key, tail_key);
				struct tcp_datainfo info = {};
				//memset(&info, 0, sizeof(info));
				info.tp = cur_tuple;
				info.seq = flow->seq;
				info.ack_seq = flow->ack_seq;
				info.package_counts = last_package->package_counts;
				info.timestamp = bpf_ktime_get_ns() + settings->boot_time;
				if(tail)
				{
					bpf_map_update_elem(&tcp_datainfo_buffer, tail, &info, BPF_ANY);
					__sync_fetch_and_add(tail, 1); //数据填充完成，tail++
				}
			}
			else if(last_package && last_rcv_pkg && last_rcv_pkg->last_fin == 1 && last_package->last_fin == 1)
			{
				//遇到两个FIN标志，则清理map
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

static __always_inline __u64 parse_tcp(struct __sk_buff *skb, __u64 nhoff, __u64 *ip_proto, struct bpf_flow_keys *flow)
{
	__u32 seq = load_word(skb, nhoff + offsetof(struct tcphdr, seq));
	__u32 ack_seq = load_word(skb, nhoff + offsetof(struct tcphdr, ack_seq));
	__u16 flag = load_half(skb, nhoff + 12 /*offsetof(struct tcphdr, 12)*/);
	flow->seq = seq;
	flow->ack_seq = ack_seq;
	flow->flag = flag;

	int poff = get_proto_ports_offset(ip_proto);
	if(poff >= 0)
	{
		nhoff += poff;
		flow->ports = load_word(skb, nhoff);
		//__u8 tmp = load_byte(skb, nhoff);
		//const char tmp_fmt[] = "testBigLittleEndian: %d --- %d\n";
		//bpf_trace_printk(tmp_fmt, sizeof(tmp_fmt), (__u8)(flow->ports), tmp);
	}

	struct sysdig_bpf_settings *settings = get_bpf_settings();
	if (!settings || !settings->capture_enabled)
		return nhoff;

	parse_tcp_handshake(settings, flow); //处理握手包信息

	//parse_tcp_datainfo(settings, flow); //处理tcp其他信息

	// const char fmt_str[] = "src: %d, srcport: %d, dst: %d";
	// bpf_trace_printk(fmt_str, sizeof(fmt_str), flow->src, flow->port16[1], flow->dst);
	// const char fmt_str2[] = "dstport: %d, SYN: %d, ACK: %d\n";
	// bool SYN = flow->flag&(0x0040);
	// bool ACK = flow->flag&(0x0008);
	// bpf_trace_printk(fmt_str2, sizeof(fmt_str2), flow->port16[0], SYN, ACK);
	//update_stats(skb, flow);
	return nhoff;
}

static __always_inline bool flow_dissector(struct __sk_buff *skb, struct bpf_flow_keys *flow)
{
	__u64 nhoff = ETH_HLEN;
	__u64 ip_proto;
	__u64 proto = load_half(skb, 12);
	int poff;

	if(proto == ETH_P_8021AD)
	{ //处理ETH VLAN协议
		proto = load_half(skb, nhoff + offsetof(struct my_vlan_hdr,
							h_vlan_encapsulated_proto));
		nhoff += sizeof(struct my_vlan_hdr); //nhoff最终指向ip数据报头
	}

	if(proto == ETH_P_8021Q)
	{
		proto = load_half(skb, nhoff + offsetof(struct my_vlan_hdr,
							h_vlan_encapsulated_proto));
		nhoff += sizeof(struct my_vlan_hdr);
	}

	if(likely(proto == ETH_P_IP))			       //处理ip数据报头
		nhoff = parse_ip(skb, nhoff, &ip_proto, flow); //nhoff指向ip数据报文
	else if(proto == ETH_P_IPV6)
		nhoff = parse_ipv6(skb, nhoff, &ip_proto, flow);
	else
		return false;

	switch(ip_proto)
	{
	case IPPROTO_TCP:
	{
		nhoff = parse_tcp(skb, nhoff, &ip_proto, flow);
		break;
	}
	default:
		break;
	}

	flow->ip_proto = ip_proto;
	poff = get_proto_ports_offset(ip_proto);
	if(poff >= 0)
	{
		nhoff += poff;
		flow->ports = load_word(skb, nhoff);
	}

	flow->thoff = (__u16)nhoff;
	//bpf_trace_printk("protocol: %d\n", flow->ip_proto);
	return true;
}

struct pair
{
	long packets;
	long bytes;
};

#endif