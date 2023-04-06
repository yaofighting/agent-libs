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
#include "tcp_package_test.h"

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

const int max_len = 500000;
tcp_handshake_buffer_elem *elem = new tcp_handshake_buffer_elem[max_len];
tcp_datainfo *tcp_data = new tcp_datainfo[max_len];
tcp_raw_data *tcp_raw = new tcp_raw_data[max_len];
void test_tcp_packets_analyzer(sinsp *inspector)
{
    int len = 0;
    tcp_handshake_analyzer hds_analyzer(inspector);
    // tcp_packets_analyzer tp_analyzer(inspector);
    // int32_t ret = inspector->get_tcp_handshake_rtt(elem, &len, max_len);
    // hds_analyzer.aggregate_handshake_info(elem, &len);  
        
    // int32_t ret2 = inspector->get_tcp_datainfo(tcp_data, &len, max_len);
    // tp_analyzer.get_total_tcp_packets(tcp_data, &len);
    // tp_analyzer.get_tcp_ack_delay(tcp_data, &len);

    // int32_t ret3 = inspector->get_tcp_raw_data(tcp_raw, &len, max_len);
    // printf("total number of tcp raw data = %d\n", len);
    // for(int i = 0;i < len; i++){
    //     bool SYN = tcp_raw[i].flag & (1 << 1);
    //     bool ACK = tcp_raw[i].flag & (1 << 4)
    //     printf("get tcp raw data---src = %u, dst = %u, sport = %u, dport = %u, ifindex = %d, SYN = %d, ACK = %d, seq = %u, ack_seq = %u, time = %llu\n",
    //     tcp_raw[i].tp.saddr, tcp_raw[i].tp.daddr, tcp_raw[i].tp.sport, tcp_raw[i].tp.dport, tcp_raw[i].tp.ifindex, SYN, ACK,
    //     tcp_raw[i].seq, tcp_raw[i].ack_seq, tcp_raw[i].timestamp);
    // }
    
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

    // for(int i=0;i<5;i++){
        test_tcp_packets_analyzer(&inspector);
    //     cout << endl << "------------------------" << endl;
    //     sleep(1);
    // }

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
