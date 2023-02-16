/*
Copyright (C) 2021 The Falco Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

#include <iostream>
#include <iomanip>
#include <getopt.h>
#include <signal.h>
#include <unistd.h>
#include <sinsp.h>
#include <ifaddrs.h>
#include <netdb.h>
#include "util.h"

using namespace std;

static bool g_interrupted;
static const uint8_t g_backoff_timeout_secs = 2; 

static void sigint_handler(int signum)
{
    g_interrupted = true;
}

static void usage()
{
    string usage = R"(Usage: sinsp-example [options]

Options:
  -h, --help                    Print this page
  -f <filter>                   Filter string for events (see https://falco.org/docs/rules/supported-fields/ for supported fields)
)";
    cout << usage << endl;
}

//
// Sample filters:
//   "evt.category=process or evt.category=net"
//   "evt.dir=< and (evt.category=net or (evt.type=execveat or evt.type=execve or evt.type=clone or evt.type=fork or evt.type=vfork))"
// 

struct agg_tcp_key {
	uint16_t dst_port;
	uint32_t src_ip;
	uint32_t dst_ip;
    bool operator <(const agg_tcp_key& e)const{
        return dst_port < e.dst_port;
    }
};

struct agg_tcp_value{
	uint64_t data_counts;
	int64_t synrtt_delta;
	int64_t ackrtt_delta;
    uint64_t start_time;
	uint64_t end_time;
};

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
    cout << "the total number of elems: " << *reslen << endl;
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
            e.second.ackrtt_delta = -1; //如果自己是客户端，那么ackrtt值无效
        }
        else
        {
            e.second.synrtt_delta = -1; //如果自己是服务端，那么synrtt无效
        }
        cout << "src_ip: " << ip_str << "  dst_ip: " <<  ipv4_int_to_str(e.first.dst_ip, ip_str) << "  dst_port: " << e.first.dst_port
            << "  data_counts: " << e.second.data_counts << "  synrtt_delta: " << e.second.synrtt_delta << "  ackrtt_delta: " << e.second.ackrtt_delta
            << "  start_time: " << e.second.start_time << "  end_time: " << e.second.end_time << endl;
    }
}
int main(int argc, char **argv)
{
    sinsp inspector;

    // Parse configuration options.
    static struct option long_options[] = {
            {"help",      no_argument, 0, 'h'},
            {0,   0,         0,  0}
    };

    int op;
    int long_index = 0;
    string filter_string;
    while((op = getopt_long(argc, argv,
                            "hr:s:f:",
                            long_options, &long_index)) != -1)
    {
        switch(op)
        {
            case 'h':
                usage();
                return EXIT_SUCCESS;
            case 'f':
                filter_string = optarg;
                break;
            default:
                break;
        }
    }

    signal(SIGINT, sigint_handler);
    signal(SIGPIPE, sigint_handler);

    inspector.open();

    if(!filter_string.empty())
    {
        try
        {
            inspector.set_filter(filter_string);
        }
        catch(const sinsp_exception &e) {
            cerr << "[ERROR] Unable to set filter: " << e.what() << endl;
        }
    }


    //for(int i = 0;i < 3;i++) {
        tcp_handshake_buffer_elem *elem = new tcp_handshake_buffer_elem[500000];
        int len;
        sleep(1);
        int32_t ret = inspector.get_tcp_handshake_rtt(elem, &len);
        int tmp = 0;
        test_tcp_handshake_agg(elem, &len);
    //}

    while(!g_interrupted)
    {
        sinsp_evt* ev = NULL;
        int32_t res = inspector.next(&ev);

        if(SCAP_TIMEOUT == res)
        {
            continue;
        }
        else if(res != SCAP_SUCCESS)
        {
            cout << "[ERROR] " << inspector.getlasterr() << endl;
            sleep(g_backoff_timeout_secs);
	        continue;
        }

        sinsp_threadinfo* thread = ev->get_thread_info();
        if(thread)
        {
            string cmdline;
            sinsp_threadinfo::populate_cmdline(cmdline, thread);

            if(thread->is_main_thread())
            {
                string date_time;
                sinsp_utils::ts_to_iso_8601(ev->get_ts(), &date_time);

                bool is_host_proc = thread->m_container_id.empty();
                cout << "[" << date_time << "]:["  
			              << (is_host_proc ? "HOST" : thread->m_container_id) << "]:";

                cout << "[CAT=";

                if(ev->get_category() == EC_PROCESS)
                {
                    cout << "PROCESS]:";
                }
                else if(ev->get_category() == EC_NET)
                {
                    cout << get_event_category(ev->get_category()) << "]:";
                    sinsp_fdinfo_t* fd_info = ev->get_fd_info();

                    // event subcategory should contain SC_NET if ipv4/ipv6
                    if(nullptr != fd_info && (fd_info->get_l4proto() != SCAP_L4_UNKNOWN && fd_info->get_l4proto() != SCAP_L4_NA))
                    {
                        cout << "[" << fd_info->tostring() << "]:";
                    }
                }
                else if(ev->get_category() == EC_IO_READ || ev->get_category() == EC_IO_WRITE)
                {
                    cout << get_event_category(ev->get_category()) << "]:";
                    
                    sinsp_fdinfo_t* fd_info = ev->get_fd_info();
                    if(nullptr != fd_info && (fd_info->get_l4proto() != SCAP_L4_UNKNOWN && fd_info->get_l4proto() != SCAP_L4_NA))
                    {
                        cout << "[" << fd_info->tostring() << "]:";
                    }
                }
                else
                {
                    cout << get_event_category(ev->get_category()) << "]:";
                }

                sinsp_threadinfo *p_thr = thread->get_parent_thread();
                int64_t parent_pid;
                if(nullptr != p_thr)
                {
                    parent_pid = p_thr->m_pid;
                }

                cout << "[PPID=" << parent_pid << "]:"
                          << "[PID=" << thread->m_pid << "]:"
                          << "[TYPE=" << get_event_type(ev->get_type()) << "]:"
                          << "[EXE=" << thread->get_exepath() << "]:"
                          << "[CMD=" << cmdline << "]"
                          << endl;
            }
        }
        else
        {
            cout << "[EVENT]:[" << get_event_category(ev->get_category()) << "]:"
                      << ev->get_name() << endl;
        }
    }

    return 0;
}
