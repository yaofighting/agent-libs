#include "tcp_package_test.h"

void tcp_analyer_base::init_host_map()
{
    struct ifaddrs *ifaddr, *ifa;
	int family, s;
	char host[NI_MAXHOST];

	if(getifaddrs(&ifaddr) == -1)
	{
		perror("getifaddrs");
		return;
	}

	for(ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next)
	{
		if(ifa->ifa_addr == NULL)
			continue;

		family = ifa->ifa_addr->sa_family;

		if(!strcmp(ifa->ifa_name, "lo"))
			continue;
		if(family == AF_INET || family == AF_INET6)
		{
			s = getnameinfo(ifa->ifa_addr, (family == AF_INET) ? sizeof(struct sockaddr_in) : sizeof(struct sockaddr_in6), host, NI_MAXHOST, NULL, 0, NI_NUMERICHOST);
			string str_ip = host;
			uint32_t ip = ipv4string_to_int(str_ip);
			host_map[ip] = true;
		}
	}
	freeifaddrs(ifaddr);
}

bool tcp_analyer_base::is_host_ip(uint32_t ip_int)
{
    return host_map[ip_int];
}

void tcp_analyer_base::ipv4_int_to_str(int ip, char ip_str[])
{
    int a = ip / (1 << 24) % (1 << 8);
	int b = ip / (1 << 16) % (1 << 8);
	int c = ip / (1 << 8) % (1 << 8);
	int d = ip % (1 << 8);
	sprintf(ip_str, "%d.%d.%d.%d", a, b, c, d);
}

tcp_tuple tcp_analyer_base::get_reverse_tuple(tcp_tuple *tp)
{
	tcp_tuple rtp;
	rtp.saddr = tp->daddr;
	rtp.daddr = tp->saddr;
	rtp.sport = tp->dport;
	rtp.dport = tp->sport;
	return rtp;
}

tcp_handshake_analyzer::tcp_handshake_analyzer()
{
    init_host_map();
}

void tcp_handshake_analyzer::aggregate_handshake_info(tcp_handshake_buffer_elem *results, int *reslen)
{
	//cout << "the total number of tcp handshake data: " << *reslen << endl;
	for(int i = 0; i < *reslen; i++)
	{
		agg_triple_key k = {results[i].tp.dport, results[i].tp.saddr, results[i].tp.daddr};
		map_ptr = handshake_agg_map.find(k);
		if(map_ptr == handshake_agg_map.end())
		{
			agg_handshake_rtt_value val = {1, results[i].synrtt, results[i].ackrtt, results[i].timestamp, results[i].timestamp};
			handshake_agg_map[k] = val;
		}
		else
		{
			map_ptr->second.data_counts++;
			map_ptr->second.synrtt_delta += results[i].synrtt;
			map_ptr->second.ackrtt_delta += results[i].ackrtt;
			map_ptr->second.end_time = results[i].timestamp;
		}
	}
	char sip_str[20], dip_str[20];
	for(auto &e : handshake_agg_map)
	{
        ipv4_int_to_str(e.first.saddr, sip_str);
        ipv4_int_to_str(e.first.daddr, dip_str);
		if(is_host_ip(e.first.saddr))
		{
			e.second.ackrtt_delta = -1; //If host a client, ackrtt is invalid
		}
		else
		{
			e.second.synrtt_delta = -1; //If host a server, synrtt is invalid
		}
		// cout << "src_ip: " << sip_str << "  dst_ip: " <<  dip_str << "  dst_port: " << e.first.dport
		//     << "  data_counts: " << e.second.data_counts << "  synrtt_delta: " << e.second.synrtt_delta << "  ackrtt_delta: " << e.second.ackrtt_delta
		//     << "  start_time: " << e.second.start_time << "  end_time: " << e.second.end_time << endl;
	}
}

tcp_packets_analyzer::tcp_packets_analyzer()
{
    init_host_map();
}

void tcp_packets_analyzer::get_total_tcp_packets(tcp_datainfo *results, int *reslen)
{
	for(int i = 0; i < *reslen; i++)
	{
		quadruples_total_map[results[i].tp] = quadruples_total_map[results[i].tp] > results[i].package_counts ? quadruples_total_map[results[i].tp] : results[i].package_counts;
	}
	for(auto &e : quadruples_total_map)
	{
		agg_iptuple_key agg_key = agg_iptuple_key{e.first.saddr, e.first.daddr};
        if(iptuples_total_map.find(agg_key) == iptuples_total_map.end())
        {
            packets_total agg_val = packets_total{e.second, 0};
            if(is_host_ip(e.first.saddr))
            {
                agg_val.direction_type = 1;
            }
		    iptuples_total_map[agg_key] = agg_val;
        }
        else
        {
            iptuples_total_map[agg_key].total_counts += e.second;
        }
	}
	char sip_str[20], dip_str[20];
	for(auto &e : iptuples_total_map)
	{
		ipv4_int_to_str(e.first.saddr, sip_str);
    	ipv4_int_to_str(e.first.daddr, dip_str);
		// cout << "src_ip: " << sip_str << "  dst_ip: " << dip_str
		//      << " packet_counts: " << e.second.total_counts << " directionType: " << e.second.direction_type << endl;
	}
}
void tcp_packets_analyzer::get_tcp_ack_delay(tcp_datainfo *results, int *reslen)
{
	int i;
	//cout << "the total number of tcp data: " << *reslen << endl;
	for(i = 0; i < *reslen; i++)
	{
		if(!is_host_ip(results[i].tp.saddr))
		{
			ack_match_queue_map[results[i].tp].push(&results[i]);
			continue; //only calculate src(host) ---> dst
		}

		tcp_tuple rtp = get_reverse_tuple(&results[i].tp);
		qmap_ptr = ack_match_queue_map.find(rtp);
		if(qmap_ptr != ack_match_queue_map.end())
		{
			tcp_datainfo *cur = qmap_ptr->second.front();
			tcp_datainfo *pre = NULL;
			while(!qmap_ptr->second.empty() && cur->seq <= results[i].ack_seq && cur->ack_seq <= results[i].seq)
			{
				pre = cur;
				qmap_ptr->second.pop();
				cur = qmap_ptr->second.front();
			}
			if(pre)
			{
				agg_iptuple_key agg_key = agg_iptuple_key{results[i].tp.saddr, results[i].tp.daddr};
				if(ack_delay_map.find(agg_key) == ack_delay_map.end())
				{
					ack_delay_map.emplace(piecewise_construct, forward_as_tuple(agg_key), forward_as_tuple(results[i].timestamp)); //construct in place
				}
				dmap_ptr = ack_delay_map.find(agg_key);
				dmap_ptr->second.acktime_delta += results[i].timestamp - pre->timestamp;
				dmap_ptr->second.data_counts++;
				dmap_ptr->second.end_time = results[i].timestamp;
			}
		}
	}

	char sip_str[20], dip_str[20];
	for(auto &e : ack_delay_map)
	{
        ipv4_int_to_str(e.first.saddr, sip_str);
        ipv4_int_to_str(e.first.daddr, dip_str);
		// cout << "src_ip: " << sip_str << "  dst_ip: " << dip_str
		//      << "  data_counts: " << e.second.data_counts << "  acktime_delta: " << e.second.acktime_delta
		//      << "  start_time: " << e.second.start_time << "  end_time: " << e.second.end_time << endl;
	}
}