#define BL_MAX_FILE_TABLE_SIZE 256
#define BL_MAX_PROG_TABLE_SIZE 1024
#define BL_STARTUP_TIME_NS (30LL * 1000000000)

//
// This class stores the set of files that a program accesses
//
class blfiletable
{
public:
	blfiletable()
	{
		m_is_r_full = false;
		m_is_rw_full = false;
		m_is_c_full = false;
		m_is_other_full = false;
		m_is_uncategorized_full = false;
	}

	void clear()
	{
		m_is_r_full = false;
		m_is_rw_full = false;
		m_is_c_full = false;
		m_is_other_full = false;
		m_is_other_full = false;
		m_r.clear();
		m_rw.clear();
		m_c.clear();
		m_other.clear();
		m_uncategorized.clear();
	}

	inline void add(string& name, uint32_t openflags, bool uncategorized)
	{
		if(openflags & PPM_O_WRONLY)
		{
			if(!m_is_rw_full)
			{
				m_rw.insert(name);
				if(m_rw.size() >= BL_MAX_FILE_TABLE_SIZE)
				{
					m_is_rw_full = true;
				}

				if(m_uncategorized.size() != 0)
				{
					auto it = m_uncategorized.find(name);
				
					if(it != m_uncategorized.end())
					{
						m_uncategorized.erase(it);
					}
				}
			}
		}
		else if(openflags & PPM_O_RDONLY)
		{
			if(!m_is_r_full)
			{
				m_r.insert(name);
				if(m_r.size() >= BL_MAX_FILE_TABLE_SIZE)
				{
					m_is_r_full = true;
				}

				if(m_uncategorized.size() != 0)
				{
					auto it = m_uncategorized.find(name);
				
					if(it != m_uncategorized.end())
					{
						m_uncategorized.erase(it);
					}
				}
			}
		}
		else
		{
			if(uncategorized)
			{
				if(!m_is_uncategorized_full)
				{
					m_uncategorized.insert(name);
					if(m_uncategorized.size() >= BL_MAX_FILE_TABLE_SIZE)
					{
						m_is_uncategorized_full = true;
					}
				}
			}
			else
			{
				if(!m_is_other_full)
				{
					m_other.insert(name);
					if(m_other.size() >= BL_MAX_FILE_TABLE_SIZE)
					{
						m_is_other_full = true;
					}

					if(m_uncategorized.size() != 0)
					{
						auto it = m_uncategorized.find(name);
				
						if(it != m_uncategorized.end())
						{
							m_uncategorized.erase(it);
						}
					}
				}
			}
		}
	}

	//
	// Convert a filename into a directory by filtering out the last part and 
	// then add it
	//
	inline void add_dir(string& filename, uint32_t openflags, bool uncategorized)
	{
		size_t pos = filename.rfind('/');
		if(pos != string::npos)
		{
			if(pos < filename.size() - 1)
			{
				string ts(filename, 0, pos + 1);
				add(ts, openflags, uncategorized);
			}
		}
		else
		{
			string ts("/");
			add(ts, openflags, uncategorized);
		}
	}

#ifdef HAS_ANALYZER
	void serialize_protobuf(draiosproto::falco_subcategory_container* cat)
	{
		if(m_r.size() != 0)
		{
			draiosproto::falco_subcategory* sr = cat->add_subcats();
			sr->set_name("r");
			sr->set_full(m_is_r_full);

			for(auto it : m_r)
			{
				sr->add_d(it);
			}
		}

		if(m_rw.size() != 0)
		{
			draiosproto::falco_subcategory* srw = cat->add_subcats();
			srw->set_name("rw");
			srw->set_full(m_is_r_full);

			for(auto it : m_rw)
			{
				srw->add_d(it);
			}
		}

		if(m_other.size() != 0)
		{
			draiosproto::falco_subcategory* sother = cat->add_subcats();
			sother->set_name("other");
			sother->set_full(m_is_other_full);

			for(auto it : m_other)
			{
				sother->add_d(it);
			}
		}

		if(m_uncategorized.size() != 0)
		{
			draiosproto::falco_subcategory* suncategorized = cat->add_subcats();
			suncategorized->set_name("uncategorized");
			suncategorized->set_full(m_is_uncategorized_full);

			for(auto it : m_uncategorized)
			{
				suncategorized->add_d(it);
			}
		}
	}
#endif

	void serialize_json(Json::Value& element)
	{
		Json::Value echild;

		if(m_r.size() != 0)
		{
			for(auto it : m_r)
			{
				echild[it] = 1;
			}
			element["r"]["d"] = echild;
			element["r"]["full"] = m_is_r_full;
			echild.clear();
		}

		if(m_rw.size() != 0)
		{
			for(auto it : m_rw)
			{
				echild[it] = 1;
			}
			element["rw"]["d"] = echild;
			element["rw"]["full"] = m_is_rw_full;
			echild.clear();
		}

		if(m_other.size() != 0)
		{
			for(auto it : m_other)
			{
				echild[it] = 1;
			}
			element["other"]["d"] = echild;
			element["other"]["full"] = m_is_other_full;
			echild.clear();
		}

		if(m_uncategorized.size() != 0)
		{
			for(auto it : m_uncategorized)
			{
				echild[it] = 1;
			}
			element["uncategorized"]["d"] = echild;
			element["uncategorized"]["full"] = m_is_uncategorized_full;
			echild.clear();
		}
	}

	bool has_data()
	{
		return (m_r.size() != 0) ||
			(m_rw.size() != 0) ||
			(m_c.size() != 0) ||
			(m_other.size() != 0) ||
			(m_uncategorized.size() != 0);
	}

	set<string> m_r;	// entries opened for reading only
	set<string> m_rw;	// entries opened for read and write
	set<string> m_c;	// entries opened with the create flag
	set<string> m_other; // entries that have only flags different from read or write
	set<string> m_uncategorized; // entries not categorized yet, likely because they come from scanning proc, where we don't extract open flags yet
	bool m_is_r_full;
	bool m_is_rw_full;
	bool m_is_c_full;
	bool m_is_other_full;
	bool m_is_uncategorized_full;
};

//
// This class manages two blfiletable tables, one for the process startup phase and one
// for regular long term activity
//
class blfiletable_split
{
public:
	void clear()
	{
		m_startup_table.clear();
		m_regular_table.clear();
	}

	inline void add(string& name, uint32_t openflags, bool uncategorized, uint64_t time_from_clone)
	{
		if(time_from_clone < BL_STARTUP_TIME_NS)
		{
			m_startup_table.add(name, openflags, uncategorized);
		}
		else
		{
			m_regular_table.add(name, openflags, uncategorized);
		}
	}

	inline void add_dir(string& filename, uint32_t openflags, bool uncategorized, uint64_t time_from_clone)
	{
		if(time_from_clone < BL_STARTUP_TIME_NS)
		{
			m_startup_table.add_dir(filename, openflags, uncategorized);
		}
		else
		{
			m_regular_table.add_dir(filename, openflags, uncategorized);
		}
	}

#ifdef HAS_ANALYZER
	void serialize_protobuf(draiosproto::falco_category* cat)
	{
		if(m_startup_table.has_data())
		{
			draiosproto::falco_subcategory_container* sc = cat->add_startup_subcats();
			m_startup_table.serialize_protobuf(sc);
		}

		if(m_regular_table.has_data())
		{
			draiosproto::falco_subcategory_container* sc = cat->add_regular_subcats();
			m_regular_table.serialize_protobuf(sc);
		}
	}
#endif

	void serialize_json(Json::Value& element)
	{
		Json::Value vsi;
		m_startup_table.serialize_json(vsi);
		if(!vsi.empty())
		{
			element["startup"] = vsi;
		}

		Json::Value vsl;
		m_regular_table.serialize_json(vsl);
		if(!vsl.empty())
		{
			element["regular"] = vsl;
		}
	}

	bool has_data()
	{
		return m_startup_table.has_data() || m_regular_table.has_data();
	}

	blfiletable m_startup_table;
	blfiletable m_regular_table;
};

//
// This class stores the set of programs that a process executes
//
class blprogtable
{
public:
	blprogtable()
	{
		m_is_p_full = false;
	}

	void clear()
	{
		m_is_p_full = false;
		m_p.clear();
	}

	inline void add(string& name)
	{
		if(!m_is_p_full)
		{
			m_p.insert(name);
			if(m_p.size() >= BL_MAX_FILE_TABLE_SIZE)
			{
				m_is_p_full = true;
			}
		}
	}

#ifdef HAS_ANALYZER
	void serialize_protobuf(draiosproto::falco_subcategory_container* cat)
	{
		if(m_p.size() != 0)
		{
			draiosproto::falco_subcategory* sp = cat->add_subcats();
			sp->set_name("p");
			sp->set_full(m_is_p_full);

			for(auto it : m_p)
			{
				sp->add_d(it);
			}
		}
	}
#endif

	void serialize_json(Json::Value& element)
	{
		Json::Value echild;

		if(m_p.size() != 0)
		{
			for(auto it : m_p)
			{
				echild[it] = 1;
			}
			element["p"]["d"] = echild;
			element["p"]["full"] = m_is_p_full;
			echild.clear();
		}
	}

	bool has_data()
	{
		return (m_p.size() != 0);
	}

	set<string> m_p;
	bool m_is_p_full;
};

//
// This class manages two blprogtable tables, one for the process startup phase and one
// for regular long term activity
//
class blprogtable_split
{
public:
	void clear()
	{
		m_startup_table.clear();
		m_regular_table.clear();
	}

	inline void add(string& name, uint64_t time_from_clone)
	{
		if(time_from_clone < BL_STARTUP_TIME_NS)
		{
			m_startup_table.add(name);
		}
		else
		{
			m_regular_table.add(name);
		}
	}

#ifdef HAS_ANALYZER
	void serialize_protobuf(draiosproto::falco_category* cat)
	{
		if(m_startup_table.has_data())
		{
			draiosproto::falco_subcategory_container* sc = cat->add_startup_subcats();
			m_startup_table.serialize_protobuf(sc);
		}

		if(m_regular_table.has_data())
		{
			draiosproto::falco_subcategory_container* sc = cat->add_regular_subcats();
			m_regular_table.serialize_protobuf(sc);
		}
	}
#endif

	void serialize_json(Json::Value& element)
	{
		Json::Value vsi;
		m_startup_table.serialize_json(vsi);
		if(!vsi.empty())
		{
			element["startup"] = vsi;
		}

		Json::Value vsl;
		m_regular_table.serialize_json(vsl);
		if(!vsl.empty())
		{
			element["regular"] = vsl;
		}
	}

	bool has_data()
	{
		return m_startup_table.has_data() || m_regular_table.has_data();
	}

	blprogtable m_startup_table;
	blprogtable m_regular_table;
};

//
// This class keeps track of the ports that a program uses
//
class blporttable
{
public:
	blporttable()
	{
		m_is_l_tcp_full = false;
		m_is_r_tcp_full = false;
		m_is_l_udp_full = false;
		m_is_r_udp_full = false;
	}

	void clear()
	{
		m_is_l_tcp_full = false;
		m_is_r_tcp_full = false;
		m_l_tcp.clear();
		m_r_tcp.clear();
		m_is_l_udp_full = false;
		m_is_r_udp_full = false;
		m_l_udp.clear();
		m_r_udp.clear();
	}

	inline void add_l_tcp(uint16_t port)
	{
		if(!m_is_l_tcp_full)
		{
			m_l_tcp.insert(port);
			if(m_l_tcp.size() >= BL_MAX_FILE_TABLE_SIZE)
			{
				m_is_l_tcp_full = true;
			}
		}
	}

	inline void add_r_tcp(uint16_t port)
	{
		if(!m_is_r_tcp_full)
		{
			m_r_tcp.insert(port);
			if(m_r_tcp.size() >= BL_MAX_FILE_TABLE_SIZE)
			{
				m_is_r_tcp_full = true;
			}
		}
	}

	inline void add_l_udp(uint16_t port)
	{
		if(!m_is_l_udp_full)
		{
			m_l_udp.insert(port);
			if(m_l_udp.size() >= BL_MAX_FILE_TABLE_SIZE)
			{
				m_is_l_udp_full = true;
			}
		}
	}

	inline void add_r_udp(uint16_t port)
	{
		if(!m_is_r_udp_full)
		{
			m_r_udp.insert(port);
			if(m_r_udp.size() >= BL_MAX_FILE_TABLE_SIZE)
			{
				m_is_r_udp_full = true;
			}
		}
	}

	inline void add(blporttable& other)
	{
		if(!m_is_r_tcp_full)
		{
			for(auto it : other.m_r_tcp)
			{
				add_r_tcp(it);
			}
		}

		if(!m_is_l_tcp_full)
		{
			for(auto it : other.m_l_tcp)
			{
				add_l_tcp(it);
			}
		}

		if(!m_is_r_udp_full)
		{
			for(auto it : other.m_r_udp)
			{
				add_r_udp(it);
			}
		}

		if(!m_is_l_udp_full)
		{
			for(auto it : other.m_l_udp)
			{
				add_l_udp(it);
			}
		}
	}

#ifdef HAS_ANALYZER
	void serialize_protobuf(draiosproto::falco_subcategory_container* cat)
	{
		if(m_l_tcp.size() != 0)
		{
			draiosproto::falco_subcategory* sl_tcp = cat->add_subcats();
			sl_tcp->set_name("l_tcp");
			sl_tcp->set_full(m_is_l_tcp_full);

			for(auto it : m_l_tcp)
			{
				sl_tcp->add_d(to_string(it));
			}
		}

		if(m_r_tcp.size() != 0)
		{
			draiosproto::falco_subcategory* sr_tcp = cat->add_subcats();
			sr_tcp->set_name("r_tcp");
			sr_tcp->set_full(m_is_r_tcp_full);

			for(auto it : m_r_tcp)
			{
				sr_tcp->add_d(to_string(it));
			}
		}

		if(m_l_udp.size() != 0)
		{
			draiosproto::falco_subcategory* sl_udp = cat->add_subcats();
			sl_udp->set_name("l_udp");
			sl_udp->set_full(m_is_l_udp_full);

			for(auto it : m_l_udp)
			{
				sl_udp->add_d(to_string(it));
			}
		}

		if(m_r_udp.size() != 0)
		{
			draiosproto::falco_subcategory* sr_udp = cat->add_subcats();
			sr_udp->set_name("r_udp");
			sr_udp->set_full(m_is_r_udp_full);

			for(auto it : m_r_udp)
			{
				sr_udp->add_d(to_string(it));
			}
		}
	}
#endif

	void serialize_json(Json::Value& element)
	{
		Json::Value echild;

		if(m_l_tcp.size() != 0)
		{
			for(auto it : m_l_tcp)
			{
				echild[to_string(it)] = 1;
			}
			element["l_tcp"]["d"] = echild;
			element["l_tcp"]["full"] = m_is_l_tcp_full;
			echild.clear();
		}

		if(m_r_tcp.size() != 0)
		{
			for(auto it : m_r_tcp)
			{
				echild[to_string(it)] = 1;
			}
			element["r_tcp"]["d"] = echild;
			element["r_tcp"]["full"] = m_is_r_tcp_full;
			echild.clear();
		}

		if(m_l_udp.size() != 0)
		{
			for(auto it : m_l_udp)
			{
				echild[to_string(it)] = 1;
			}
			element["l_udp"]["d"] = echild;
			element["l_udp"]["full"] = m_is_l_udp_full;
			echild.clear();
		}

		if(m_r_udp.size() != 0)
		{
			for(auto it : m_r_udp)
			{
				echild[to_string(it)] = 1;
			}
			element["r_udp"]["d"] = echild;
			element["r_udp"]["full"] = m_is_r_udp_full;
			echild.clear();
		}
	}

	bool has_data()
	{
		return (m_l_tcp.size() != 0) ||
			(m_r_tcp.size() != 0) ||
			(m_l_udp.size() != 0) ||
			(m_r_udp.size() != 0);
	}

	set<uint16_t> m_l_tcp;	// local TCP server ports
	set<uint16_t> m_r_tcp;	// remote TCP server ports
	set<uint16_t> m_l_udp;	// local TCP server ports
	set<uint16_t> m_r_udp;	// remote TCP server ports
	bool m_is_l_tcp_full;
	bool m_is_r_tcp_full;
	bool m_is_l_udp_full;
	bool m_is_r_udp_full;
};

//
// This class manages two blporttable tables, one for the process startup phase and one
// for regular long term activity
//
class blporttable_split
{
public:
	void clear()
	{
		m_startup_table.clear();
		m_regular_table.clear();
	}

	inline void add_l_tcp(uint16_t port, uint64_t time_from_clone)
	{
		if(time_from_clone < BL_STARTUP_TIME_NS)
		{
			m_startup_table.add_l_tcp(port);
		}
		else
		{
			m_regular_table.add_l_tcp(port);
		}
	}

	inline void add_r_tcp(uint16_t port, uint64_t time_from_clone)
	{
		if(time_from_clone < BL_STARTUP_TIME_NS)
		{
			m_startup_table.add_r_tcp(port);
		}
		else
		{
			m_regular_table.add_r_tcp(port);
		}
	}

	inline void add_l_udp(uint16_t port, uint64_t time_from_clone)
	{
		if(time_from_clone < BL_STARTUP_TIME_NS)
		{
			m_startup_table.add_l_udp(port);
		}
		else
		{
			m_regular_table.add_l_udp(port);
		}
	}

	inline void add_r_udp(uint16_t port, uint64_t time_from_clone)
	{
		if(time_from_clone < BL_STARTUP_TIME_NS)
		{
			m_startup_table.add_r_udp(port);
		}
		else
		{
			m_regular_table.add_r_udp(port);
		}
	}

#ifdef HAS_ANALYZER
	void serialize_protobuf(draiosproto::falco_category* cat)
	{
		if(m_startup_table.has_data())
		{
			draiosproto::falco_subcategory_container* sc = cat->add_startup_subcats();
			m_startup_table.serialize_protobuf(sc);
		}

		if(m_regular_table.has_data())
		{
			draiosproto::falco_subcategory_container* sc = cat->add_regular_subcats();
			m_regular_table.serialize_protobuf(sc);
		}
	}
#endif

	void serialize_json(Json::Value& element)
	{
		Json::Value vsi;
		m_startup_table.serialize_json(vsi);
		if(!vsi.empty())
		{
			element["startup"] = vsi;
		}

		Json::Value vsl;
		m_regular_table.serialize_json(vsl);
		if(!vsl.empty())
		{
			element["regular"] = vsl;
		}
	}

	bool has_data()
	{
		return m_startup_table.has_data() || m_regular_table.has_data();
	}

	blporttable m_startup_table;
	blporttable m_regular_table;
};

//
// This class keeps track of the ports that a program uses
//
class bl_ip_endpoint_table
{
public:
	bl_ip_endpoint_table()
	{
		m_is_c_tcp_full = false;
		m_is_s_tcp_full = false;
		m_is_udp_full = false;
	}

	void clear()
	{
		m_is_c_tcp_full = false;
		m_is_s_tcp_full = false;
		m_c_tcp.clear();
		m_s_tcp.clear();
		m_is_udp_full = false;
		m_udp.clear();
	}

	inline void add_c_tcp(uint32_t ip)
	{
		if(!m_is_c_tcp_full)
		{
			m_c_tcp.insert(ip);
			if(m_c_tcp.size() >= BL_MAX_FILE_TABLE_SIZE)
			{
				m_is_c_tcp_full = true;
			}
		}
	}

	inline void add_s_tcp(uint32_t ip)
	{
		if(!m_is_s_tcp_full)
		{
			m_s_tcp.insert(ip);
			if(m_s_tcp.size() >= BL_MAX_FILE_TABLE_SIZE)
			{
				m_is_s_tcp_full = true;
			}
		}
	}

	inline void add_udp(uint32_t ip)
	{
		if(!m_is_udp_full)
		{
			m_udp.insert(ip);
			if(m_udp.size() >= BL_MAX_FILE_TABLE_SIZE)
			{
				m_is_udp_full = true;
			}
		}
	}

	inline void add(bl_ip_endpoint_table& other)
	{
		if(!m_is_c_tcp_full)
		{
			for(auto it : other.m_c_tcp)
			{
				add_c_tcp(it);
			}
		}

		if(!m_is_s_tcp_full)
		{
			for(auto it : other.m_s_tcp)
			{
				add_s_tcp(it);
			}
		}

		if(!m_is_udp_full)
		{
			for(auto it : other.m_udp)
			{
				add_udp(it);
			}
		}
	}

	static uint32_t c_subnet(uint32_t ip)
	{
		return ip & 0x00FFFFFF;
	}

#ifdef HAS_ANALYZER
	void serialize_protobuf(draiosproto::falco_subcategory_container* cat)
	{
		char addrbuff[32];

		if(m_c_tcp.size() != 0)
		{
			draiosproto::falco_subcategory* sc_tcp = cat->add_subcats();
			sc_tcp->set_name("c_tcp");
			sc_tcp->set_full(m_is_c_tcp_full);

			for(auto it : m_c_tcp)
			{
				sc_tcp->add_d(inet_ntop(AF_INET, &it, addrbuff, sizeof(addrbuff)));
			}
		}

		if(m_s_tcp.size() != 0)
		{
			draiosproto::falco_subcategory* ss_tcp = cat->add_subcats();
			ss_tcp->set_name("s_tcp");
			ss_tcp->set_full(m_is_s_tcp_full);

			for(auto it : m_s_tcp)
			{
				ss_tcp->add_d(inet_ntop(AF_INET, &it, addrbuff, sizeof(addrbuff)));
			}
		}

		if(m_udp.size() != 0)
		{
			draiosproto::falco_subcategory* sudp = cat->add_subcats();
			sudp->set_name("udp");
			sudp->set_full(m_is_udp_full);

			for(auto it : m_udp)
			{
				sudp->add_d(inet_ntop(AF_INET, &it, addrbuff, sizeof(addrbuff)));
			}
		}

	}
#endif

	void serialize_json(Json::Value& element)
	{
		Json::Value echild;
		char addrbuff[32];

		if(m_c_tcp.size() != 0)
		{
			for(auto it : m_c_tcp)
			{
				echild[inet_ntop(AF_INET, &it, addrbuff, sizeof(addrbuff))] = 1;
			}
			element["c_tcp"]["d"] = echild;
			element["c_tcp"]["full"] = m_is_c_tcp_full;
			echild.clear();
		}

		if(m_s_tcp.size() != 0)
		{
			for(auto it : m_s_tcp)
			{
				echild[inet_ntop(AF_INET, &it, addrbuff, sizeof(addrbuff))] = 1;
			}
			element["s_tcp"]["d"] = echild;
			element["s_tcp"]["full"] = m_is_s_tcp_full;
			echild.clear();
		}

		if(m_udp.size() != 0)
		{
			for(auto it : m_udp)
			{
				echild[inet_ntop(AF_INET, &it, addrbuff, sizeof(addrbuff))] = 1;
			}
			element["udp"]["d"] = echild;
			element["udp"]["full"] = m_is_udp_full;
			echild.clear();
		}
	}

	bool has_data()
	{
		return (m_c_tcp.size() != 0) ||
			(m_s_tcp.size() != 0) ||
			(m_udp.size() != 0);
	}

	set<uint32_t> m_c_tcp;	// TCP client endpoints
	set<uint32_t> m_s_tcp;	// TCP server endpoints
	set<uint32_t> m_udp;	// UDP endpoints
	bool m_is_c_tcp_full;
	bool m_is_s_tcp_full;
	bool m_is_udp_full;
};

//
// This class manages two bl_ip_endpoint_table tables, one for the process startup phase and one
// for regular long term activity
//
class bl_ip_endpoint_table_split
{
public:
	void clear()
	{
		m_startup_table.clear();
		m_regular_table.clear();
	}

	inline void add_c_tcp(uint32_t ip, uint64_t time_from_clone)
	{
		if(time_from_clone < BL_STARTUP_TIME_NS)
		{
			m_startup_table.add_c_tcp(ip);
		}
		else
		{
			m_regular_table.add_c_tcp(ip);
		}
	}

	inline void add_s_tcp(uint32_t ip, uint64_t time_from_clone)
	{
		if(time_from_clone < BL_STARTUP_TIME_NS)
		{
			m_startup_table.add_s_tcp(ip);
		}
		else
		{
			m_regular_table.add_s_tcp(ip);
		}
	}

	inline void add_udp(uint32_t ip, uint64_t time_from_clone)
	{
		if(time_from_clone < BL_STARTUP_TIME_NS)
		{
			m_startup_table.add_udp(ip);
		}
		else
		{
			m_regular_table.add_udp(ip);
		}
	}

#ifdef HAS_ANALYZER
	void serialize_protobuf(draiosproto::falco_category* cat)
	{
		if(m_startup_table.has_data())
		{
			draiosproto::falco_subcategory_container* sc = cat->add_startup_subcats();
			m_startup_table.serialize_protobuf(sc);
		}

		if(m_regular_table.has_data())
		{
			draiosproto::falco_subcategory_container* sc = cat->add_regular_subcats();
			m_regular_table.serialize_protobuf(sc);
		}
	}
#endif

	void serialize_json(Json::Value& element)
	{
		Json::Value vsi;
		m_startup_table.serialize_json(vsi);
		if(!vsi.empty())
		{
			element["startup"] = vsi;
		}

		Json::Value vsl;
		m_regular_table.serialize_json(vsl);
		if(!vsl.empty())
		{
			element["regular"] = vsl;
		}
	}

	bool has_data()
	{
		return m_startup_table.has_data() || m_regular_table.has_data();
	}

	bl_ip_endpoint_table m_startup_table;
	bl_ip_endpoint_table m_regular_table;
};

//
// Program State
//
class blprogram
{
public:
	blprogram()
	{
	}

	blprogram(string& comm)
	{
		m_comm = comm;
	}

	string m_comm; // Command name (e.g. "top")
	string m_exe; // argv[0] (e.g. "sshd: user@pts/4")
	vector<uint64_t> m_pids; // Command line arguments (e.g. "-d1")
	//string m_parent_comm; // Parent command name (e.g. "top")
	//vector<string> m_args; // Command line arguments (e.g. "-d1")
	//vector<string> m_env; // Environment variables
	string m_container_id; // heuristic-based container id
	uint32_t m_user_id; // user id
	blfiletable_split m_files;
	blfiletable_split m_dirs;
	blprogtable_split m_executed_programs;
	blporttable_split m_server_ports;
	blporttable_split m_bound_ports;
	bl_ip_endpoint_table_split m_ip_endpoints;
	bl_ip_endpoint_table_split m_c_subnet_endpoints;
};

//
// Container Information
//
class blcontainer
{
public:
	blcontainer(string name, string image_name, string image_id)
	{
		m_name = name;
		m_image_name = image_name;
		m_image_id = image_id;
	}

	blcontainer()
	{
	}

	string m_name;
	string m_image_name;
	string m_image_id;
};

//
// The baseliner class
//
class sisnp_baseliner
{
public:
	void init(sinsp* inspector);
	void load_tables(uint64_t time);
	void clear_tables();
	void register_callbacks(sinsp_fd_listener* listener);
	void serialize_json(string filename);
#ifdef HAS_ANALYZER
	void serialize_protobuf(draiosproto::falco_baseline* pbentry);
	void emit_as_protobuf(uint64_t time, draiosproto::falco_baseline* pbentry);
#else
	void emit_as_json(uint64_t time);
#endif

	void on_file_open(sinsp_evt *evt, string& name, uint32_t openflags);
	void on_new_proc(sinsp_evt *evt, sinsp_threadinfo* tinfo);
	void on_connect(sinsp_evt *evt);
	void on_accept(sinsp_evt *evt, sinsp_fdinfo_t* fdinfo);
	void on_bind(sinsp_evt *evt);
	void on_new_container(const sinsp_container_info& container_info);

private:
	void init_programs(uint64_t time);
	void init_containers();

	sinsp* m_inspector;
	sinsp_network_interfaces* m_ifaddr_list;
	unordered_map<size_t, blprogram> m_progtable;
	unordered_map<string, blcontainer> m_container_table;
#ifndef HAS_ANALYZER
	string m_hostname;
	uint64_t m_hostid;
#endif	
};
