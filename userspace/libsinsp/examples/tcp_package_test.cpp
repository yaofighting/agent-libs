#include "tcp_package_test.h"

char * ipv4_int_to_str(int ip, char ip_str[]) {
	int a = ip / (1 << 24) % (1 << 8);
	int b = ip / (1 << 16) % (1 << 8);
	int c = ip / (1 << 8) % (1 << 8);
	int d = ip % (1 << 8);
	sprintf(ip_str, "%d.%d.%d.%d",a,b,c,d);
    return ip_str;
}

bool is_host_ip(char *ip)
{
    struct ifaddrs *ifaddr, *ifa;
    int family, s;
    char host[NI_MAXHOST];

    if (getifaddrs(&ifaddr) == -1) 
    {
        perror("getifaddrs");
        return NULL;
    }

    for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) 
    {
        if (ifa->ifa_addr == NULL)
            continue;

        family = ifa->ifa_addr->sa_family;

        if (!strcmp(ifa->ifa_name, "lo"))
            continue;
        if (family == AF_INET || family == AF_INET6) 
        {
            s = getnameinfo(ifa->ifa_addr, (family == AF_INET) ? sizeof(struct sockaddr_in) : sizeof(struct sockaddr_in6), host, NI_MAXHOST, NULL, 0, NI_NUMERICHOST);
            if(strcmp(host, ip) == 0) return true;
            //printf("ip: %s\n", host);
        }
    }
    freeifaddrs(ifaddr);
    return false;
}


void test_tcp_handshake_agg(tcp_handshake_buffer_elem *results, int *reslen)
{
    map<agg_tcp_key, agg_tcp_value> mp;
    map<agg_tcp_key, agg_tcp_value>::iterator it;
    int i;
    cout << "the total number of tcp handshake data: " << *reslen << endl;
    for(i = 0;i < *reslen;i++)
    {
        agg_tcp_key k = {results[i].tp.dport, results[i].tp.saddr, results[i].tp.daddr};
        it = mp.find(k);
        if(it == mp.end())
        {
            agg_tcp_value val = {1, results[i].synrtt, results[i].ackrtt, results[i].timestamp, results[i].timestamp};
            mp[k] = val;
        }   
        else
        {
            it->second.data_counts++;
            it->second.synrtt_delta += results[i].synrtt;
            it->second.ackrtt_delta += results[i].ackrtt;
            it->second.end_time = results[i].timestamp;
        }
    }
    char ip_str[20];
    for(auto &e: mp)
    {
        ipv4_int_to_str(e.first.src_ip, ip_str);
        if(is_host_ip(ip_str))
        {
            e.second.ackrtt_delta = -1; //If host a client, ackrtt is invalid
        }
        else
        {
            e.second.synrtt_delta = -1; //If host a server, synrtt is invalid
        }
        // cout << "src_ip: " << ip_str << "  dst_ip: " <<  ipv4_int_to_str(e.first.dst_ip, ip_str) << "  dst_port: " << e.first.dst_port
        //     << "  data_counts: " << e.second.data_counts << "  synrtt_delta: " << e.second.synrtt_delta << "  ackrtt_delta: " << e.second.ackrtt_delta
        //     << "  start_time: " << e.second.start_time << "  end_time: " << e.second.end_time << endl;
    }
}

tcp_tuple get_reverse_tuple(tcp_tuple *tp)
{
    tcp_tuple rtp;
    rtp.saddr = tp->daddr;
    rtp.daddr = tp->saddr;
    rtp.sport = tp->dport;
    rtp.dport = tp->sport;
    return rtp;
}

bool ip_filter(uint32_t ip)
{
    char ip_str[20];
    ipv4_int_to_str(ip, ip_str);
    return is_host_ip(ip_str);
}

unordered_map<agg_tcp_ip_key, agg_tcp_ack, tcp_ip_key_hash, tcp_ip_key_equal> agg_res;
unordered_map<agg_tcp_ip_key, agg_tcp_ack, tcp_ip_key_hash, tcp_ip_key_equal>::iterator agg_it;
void get_tcp_ack_delay(tcp_datainfo *results, int *reslen)
{
    unordered_map<tcp_tuple, queue<tcp_datainfo *>, tcp_tuple_hash, tcp_tuple_equal> vis;
    unordered_map<tcp_tuple, queue<tcp_datainfo *>, tcp_tuple_hash, tcp_tuple_equal>::iterator it;

    int i;
    cout << "the total number of tcp data: " << *reslen << endl;
    for(i = 0;i < *reslen;i++)
    {
        vis[results[i].tp].push(&results[i]);
        if(!ip_filter(results[i].tp.saddr)) continue; //only calculate src(host) ---> dst
        agg_tcp_ip_key agg_key = agg_tcp_ip_key{results[i].tp.saddr, results[i].tp.daddr};
        if(agg_res.find(agg_key) == agg_res.end())
        {
            agg_res.emplace(piecewise_construct, forward_as_tuple(agg_key), forward_as_tuple(results[i].timestamp)); //construct in place
        }

        tcp_tuple rtp = get_reverse_tuple(&results[i].tp);
        it = vis.find(rtp);
        if(it != vis.end())
        {   
            tcp_datainfo * cur = it->second.front();
            tcp_datainfo * pre = NULL;
            while(!it->second.empty() && cur->seq <= results[i].ack_seq && cur->ack_seq <= results[i].seq)
            {
                pre = cur;
                it->second.pop();
                cur = it->second.front();
            }
            if(pre)
            {
                agg_it = agg_res.find(agg_key);
                agg_it->second.acktime_delta += results[i].timestamp - pre->timestamp;
                agg_it->second.data_counts++;
                agg_it->second.end_time = results[i].timestamp;
            }
        }
    }

    char ip_str[20];
    for(auto &e: agg_res){
        cout << "src_ip: " << ipv4_int_to_str(e.first.saddr, ip_str) << "  dst_ip: " <<  ipv4_int_to_str(e.first.daddr, ip_str) 
            << "  data_counts: " << e.second.data_counts << "  acktime_delta: " << e.second.acktime_delta 
            << "  start_time: " << e.second.start_time << "  end_time: " << e.second.end_time << endl;
    }

}
void get_total_tcp_packets(tcp_datainfo *results, int *reslen){
    unordered_map<tcp_tuple, uint64_t, tcp_tuple_hash, tcp_tuple_equal> cnt_map;
    unordered_map<agg_tcp_ip_key, uint64_t, tcp_ip_key_hash, tcp_ip_key_equal> agg_pkg_total;
    for(int i = 0;i < *reslen;i++)
    {
        cnt_map[results[i].tp] = cnt_map[results[i].tp] > results[i].package_counts ? cnt_map[results[i].tp] : results[i].package_counts;
    }
    for(auto &e: cnt_map)
    {
        agg_tcp_ip_key agg_key = agg_tcp_ip_key{e.first.saddr, e.first.daddr};
        agg_pkg_total[agg_key] += e.second;
    }
    for(auto &e: agg_pkg_total)
    {
        char ip_str[20];
        if(!ip_filter(e.first.saddr)) continue; //only calculate src(host) ---> dst
        cout << "src_ip: " << ipv4_int_to_str(e.first.saddr, ip_str) << "  dst_ip: " <<  ipv4_int_to_str(e.first.daddr, ip_str)
            << " packet_counts: " << e.second << endl;
    }
}