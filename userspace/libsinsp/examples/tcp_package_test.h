#ifndef TCP_PACKAGE_TEST_H
#define TCP_PACKAGE_TEST_H
#include <iostream>
#include <iomanip>
#include <getopt.h>
#include <signal.h>
#include <unistd.h>
#include <sinsp.h>
#include <ifaddrs.h>
#include <netdb.h>

struct agg_triple_key
{
	uint16_t dport;
	uint32_t saddr;
	uint32_t daddr;
	bool operator<(const agg_triple_key &e) const
	{
		return dport < e.dport;
	}
};

struct agg_handshake_rtt_value
{
	uint64_t data_counts;
	int64_t synrtt_delta;
	int64_t ackrtt_delta;
	uint64_t start_time;
	uint64_t end_time;
};

class tcp_analyer_base {
    unordered_map<uint32_t, bool> host_map;
public:
    void init_host_map();
    bool is_host_ip(uint32_t ip_int);
    void ipv4_int_to_str(int ip, char ip_str[]);
    tcp_tuple get_reverse_tuple(tcp_tuple *tp);
};

class tcp_handshake_analyzer: public tcp_analyer_base {
    map<agg_triple_key, agg_handshake_rtt_value> handshake_agg_map;
    map<agg_triple_key, agg_handshake_rtt_value>::iterator map_ptr;
public:
	tcp_handshake_analyzer();
    void aggregate_handshake_info(tcp_handshake_buffer_elem *results, int *reslen);
};

struct agg_iptuple_key
{
	uint32_t saddr;
	uint32_t daddr;
	agg_iptuple_key(uint32_t s, uint32_t d):
		saddr(s), daddr(d) {}
};

struct agg_tcp_ack
{
	uint64_t data_counts;
	int64_t acktime_delta;
	uint64_t start_time;
	uint64_t end_time;
	agg_tcp_ack(uint64_t t):
		start_time(t), end_time(t), data_counts(0), acktime_delta(0) {}
};

struct tcp_tuple_hash
{
	size_t operator()(const tcp_tuple &tp) const
	{
		return hash<uint32_t>()(tp.saddr + tp.daddr + tp.sport + tp.dport);
	}
};

struct tcp_tuple_equal
{
	size_t operator()(const tcp_tuple &a, const tcp_tuple &b) const
	{
		return a.saddr == b.saddr && a.sport == b.sport && a.daddr == b.daddr && a.dport == b.dport;
	}
};

struct agg_iptuple_key_hash
{
	size_t operator()(const agg_iptuple_key &tp) const
	{
		return hash<uint32_t>()(tp.saddr) ^ hash<uint32_t>()(tp.daddr);
	}
};

struct agg_iptuple_key_equal
{
	size_t operator()(const agg_iptuple_key &a, const agg_iptuple_key &b) const
	{
		return a.saddr == b.saddr && a.daddr == b.daddr;
	}
};

struct packets_total
{
    uint64_t total_counts;
    int direction_type; //1: send, 0: received
};

class tcp_packets_analyzer: public tcp_analyer_base {
    /*
        for get_total_tcp_packets() function.
        count the number of tcp packets.
        quadruples_total_map(src,dst,sport,dport) --- aggregate ---> iptuples_total_map(src, dst)
    */
    unordered_map<tcp_tuple, uint64_t, tcp_tuple_hash, tcp_tuple_equal> quadruples_total_map;
	unordered_map<agg_iptuple_key, packets_total, agg_iptuple_key_hash, agg_iptuple_key_equal> iptuples_total_map;
    /*
        for get_tcp_ack_delay() function. 
        to match and caculate the ack delay.
    */
    unordered_map<agg_iptuple_key, agg_tcp_ack, agg_iptuple_key_hash, agg_iptuple_key_equal> ack_delay_map;
    unordered_map<agg_iptuple_key, agg_tcp_ack, agg_iptuple_key_hash, agg_iptuple_key_equal>::iterator dmap_ptr;
    unordered_map<tcp_tuple, queue<tcp_datainfo *>, tcp_tuple_hash, tcp_tuple_equal> ack_match_queue_map;
	unordered_map<tcp_tuple, queue<tcp_datainfo *>, tcp_tuple_hash, tcp_tuple_equal>::iterator qmap_ptr;
public:
	tcp_packets_analyzer();
    void get_total_tcp_packets(tcp_datainfo *results, int *reslen);
    void get_tcp_ack_delay(tcp_datainfo *results, int *reslen);
};

#endif