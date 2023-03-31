#include "tcp_package_test.h"

#define PROC_NET_ROUTE "/proc/net/route"
void tcp_analyer_base::init_virtual_interface_ip()
{
	char line[512] = {};
	FILE *fp = NULL;
    fp = fopen(PROC_NET_ROUTE, "r");
    if(fp == NULL) return;

    bool first_line = true;
    char *delimiters = " \t";
    char *token;

    while(fgets(line, sizeof(line), fp))
    {
        char *scratch;
        if(first_line) //skip the first line
        {
            first_line = false;
            continue;
        }

        // interface
        token = strtok_r(line, delimiters, &scratch);
        if(token && strncmp(token, "veth", 4) == 0 || strncmp(token, "cali",4) == 0)
        {
			uint32_t ifindex = if_nametoindex(token);
			// Destination
        	token = strtok_r(NULL, delimiters, &scratch);
        	if(token)
        	{
				char *end;
        		uint32_t ip = strtoul(token, &end, 16);
        		ip = ntohl(ip);
				host_map[ip] = ifindex;
        	}
        }
    }
	fclose(fp);
}

void tcp_analyer_base::init_host_ip()
{
    struct ifaddrs *ifaddr, *ifa;
	struct ifreq ifr;
	int family, s, ifcount = 0, pifcount = 0;
	char host[NI_MAXHOST];
	int container_interface[1024];
	int physical_interface[1024];

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

		if(!strcmp(ifa->ifa_name, "lo")) //filter out localhost/127.0.0.1
			continue;

		if(!strncmp(ifa->ifa_name, "veth", 4) || !strncmp(ifa->ifa_name, "cali", 4))
		{
			container_interface[ifcount++] = if_nametoindex(ifa->ifa_name);
		}

		if(!strncmp(ifa->ifa_name, "en", 2) || !strncmp(ifa->ifa_name, "eth", 3))
		{
			physical_interface[pifcount++] = if_nametoindex(ifa->ifa_name);
		}

		if(family == AF_INET)
		{
			s = getnameinfo(ifa->ifa_addr, sizeof(struct sockaddr_in), host, NI_MAXHOST, NULL, 0, NI_NUMERICHOST);
			string str_ip = host;
			uint32_t ip = ipv4string_to_int(str_ip);
			host_map[ip] = if_nametoindex(ifa->ifa_name);
		}
	}
	container_interface[ifcount] = -1;
	physical_interface[pifcount] = -1;
	//init container network interface map
	inspector->init_focus_network_interface(container_interface, CONTAINER_INTERFACE);
	//init physical network interface map
	inspector->init_focus_network_interface(physical_interface, PHYSICAL_INTERFACE);
	//init virtual interface info (ip, ifindex)
	init_virtual_interface_ip();
	freeifaddrs(ifaddr);
}

uint32_t tcp_analyer_base::get_interface_by_ip(uint32_t ip_int)
{
    return host_map[ip_int];
}

void tcp_analyer_base::ipv4_int_to_str(uint32_t ip, char ip_str[])
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
	rtp.ifindex = tp->ifindex;
	return rtp;
}

tcp_handshake_analyzer::tcp_handshake_analyzer(sinsp *inspector)
{
	this->inspector = inspector;
    init_host_ip();
}

void tcp_handshake_analyzer::aggregate_handshake_info(tcp_handshake_buffer_elem *results, int *reslen)
{
	//cout << "the total number of tcp handshake data: " << *reslen << endl;
	for(int i = 0; i < *reslen; i++)
	{
		if(results[i].timestamp == 0) continue;
		//agg_tcp_key k = {results[i].tp.sport, results[i].tp.dport, results[i].tp.saddr, results[i].tp.daddr, results[i].tp.ifindex};
		map_ptr = handshake_agg_map.find(results[i].tp);
		if(map_ptr == handshake_agg_map.end())
		{
			agg_handshake_rtt_value val = {1, results[i].synrtt, results[i].ackrtt, results[i].timestamp, results[i].timestamp};
			handshake_agg_map[results[i].tp] = val;
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
		if(get_interface_by_ip(e.first.saddr) == e.first.ifindex)
		{
			e.second.ackrtt_delta = -1; //If host a client, ackrtt is invalid
		}
		else if(get_interface_by_ip(e.first.daddr) == e.first.ifindex)
		{
			e.second.synrtt_delta = -1; //If host a server, synrtt is invalid
		}
		// cout << "src_ip: " << sip_str << "  dst_ip: " <<  dip_str << "  src_port: " << e.first.sport << "  dst_port: " << e.first.dport
		//     << "  data_counts: " << e.second.data_counts << "  synrtt_delta: " << e.second.synrtt_delta << "  ackrtt_delta: " << e.second.ackrtt_delta
		//     << "  start_time: " << e.second.start_time << "  end_time: " << e.second.end_time << "  ifindex: " << e.first.ifindex << endl;
	}
}

tcp_packets_analyzer::tcp_packets_analyzer(sinsp *inspector)
{
	this->inspector = inspector;
    init_host_ip();
}

void tcp_packets_analyzer::get_total_tcp_packets(tcp_datainfo *results, int *reslen)
{
	for(int i = 0; i < *reslen; i++)
	{
		if(results[i].timestamp == 0) continue;
		if(quadruples_total_map.find(results[i].tp) == quadruples_total_map.end())
		{
			packets_total pt = packets_total{results[i].package_counts, 0};
			if(get_interface_by_ip(results[i].tp.saddr) == results[i].tp.ifindex)
			{
				pt.direction_type = 1;
			}
			quadruples_total_map[results[i].tp] = pt;
		}
		else
		{
			quadruples_total_map[results[i].tp].total_counts = quadruples_total_map[results[i].tp].total_counts > results[i].package_counts ? quadruples_total_map[results[i].tp].total_counts : results[i].package_counts;
		}
	}
	char sip_str[20], dip_str[20];
	for(auto &e : quadruples_total_map)
	{
		ipv4_int_to_str(e.first.saddr, sip_str);
    	ipv4_int_to_str(e.first.daddr, dip_str);
		// cout << "src_ip: " << sip_str << "  sport: " << e.first.sport << "  dst_ip: " << dip_str << "  dport: " << e.first.dport
		//      << "  ifindex: " << e.first.ifindex << "  packet_counts: " << e.second.total_counts << "  directionType: " << e.second.direction_type << endl;
	}
}
void tcp_packets_analyzer::get_tcp_ack_delay(tcp_datainfo *results, int *reslen)
{
	int i;
	//cout << "the total number of tcp data: " << *reslen << endl;
	for(i = 0; i < *reslen; i++)
	{
		if(results[i].timestamp == 0) continue;
		if(get_interface_by_ip(results[i].tp.saddr) != results[i].tp.ifindex)
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
				//agg_tcp_key agg_key = agg_iptuple_key{results[i].tp.saddr, results[i].tp.daddr};
				if(ack_delay_map.find(results[i].tp) == ack_delay_map.end())
				{
					ack_delay_map.emplace(piecewise_construct, forward_as_tuple(results[i].tp), forward_as_tuple(results[i].timestamp)); //construct in place
				}
				dmap_ptr = ack_delay_map.find(results[i].tp);
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
		// cout << "src_ip: " << sip_str << "  sport: " << e.first.sport << "  dst_ip: " << dip_str << "  dport: " << e.first.dport
		//      << "  data_counts: " << e.second.data_counts << "  acktime_delta: " << e.second.acktime_delta
		//      << "  start_time: " << e.second.start_time << "  end_time: " << e.second.end_time << endl;
	}
}