//
// Why isn't this parser written using antlr or some other parser generator?
// Essentially, after dealing with that stuff multiple times in the past, and fighting for a day
// to configure everything with crappy documentation and code that doesn't compile,
// I decided that I agree with this http://mortoray.com/2012/07/20/why-i-dont-use-a-parser-generator/
// and that I'm going with a manually written parser. The grammar is simple enough that it's not
// going to take more time. On the other hand I will avoid a crappy dependency that breaks my 
// code at every new release, and I will have a cleaner and easier to understand code base.
//

#include "sinsp.h"
#include "sinsp_int.h"

#ifdef HAS_FILTERING
#include "filterchecks.h"
#include "filter.h"

extern sinsp_evttables g_infotables;

///////////////////////////////////////////////////////////////////////////////
// sinsp_filter_check implementation
///////////////////////////////////////////////////////////////////////////////
sinsp_filter_check::sinsp_filter_check()
{
	m_boolop = BO_NONE;
	m_cmpop = CO_NONE;
	m_inspector = NULL;
}

void sinsp_filter_check::set_inspector(sinsp* inspector)
{
	m_inspector = inspector;
}

///////////////////////////////////////////////////////////////////////////////
// sinsp_filter_check_fd implementation
///////////////////////////////////////////////////////////////////////////////
bool sinsp_filter_check_fd::recognize_operand(string operand)
{
	if(operand.substr(0, string("fd").length()) == "fd")
	{
		return true;
	}
	else
	{
		return false;
	}
}

void sinsp_filter_check_fd::parse_operand1(string val)
{
	m_type = TYPE_NONE;

	if(val.substr(0, string("fd").length()) == "fd")
	{
		vector<string> components = sinsp_split(val, '.');

		if(components.size() == 1)
		{
			m_type = TYPE_FDNUM;
			return;
		}
		else if(components.size() == 2)
		{
			if(components[1] == "name")
			{
				m_type = TYPE_FDNAME;
				return;
			}
			else if(components[1] == "type")
			{
				m_type = TYPE_FDTYPE;
				return;
			}
			else if(components[1] == "ip")
			{
				m_type = TYPE_IP;
				return;
			}
			else if(components[1] == "clientip")
			{
				m_type = TYPE_CLIENTIP;
				return;
			}
			else if(components[1] == "serverip")
			{
				m_type = TYPE_SERVERIP;
				return;
			}
			else if(components[1] == "port")
			{
				m_type = TYPE_PORT;
				return;
			}
			else if(components[1] == "clientport")
			{
				m_type = TYPE_CLIENTPORT;
				return;
			}
			else if(components[1] == "serverport")
			{
				m_type = TYPE_SERVERPORT;
				return;
			}
		}
	}

	throw sinsp_exception("filter error: unrecognized field " + val);
}

void sinsp_filter_check_fd::parse_operand2(string val)
{
	switch(m_type)
	{
	case TYPE_FDNUM:
		m_fd = sinsp_numparser::parsed64(val);
		break;
	case TYPE_FDNAME:
		m_fdname = val;
		break;
	case TYPE_FDTYPE:
		if(val == "file")
		{
			m_fd_type = FDT_FILE;
			return;
		}
		else if(val == "socket")
		{
			m_fd_type = FDT_SOCK;
			return;
		}
		else if(val == "ipv4socket")
		{
			m_fd_type = FDT_IPV4_SOCK;
			return;
		}
		else if(val == "ipv6socket")
		{
			m_fd_type = FDT_IPV6_SOCK;
			return;
		}
		else if(val == "unixsocket")
		{
			m_fd_type = FDT_UNIX_SOCK;
			return;
		}
		else if(val == "pipe")
		{
			m_fd_type = FDT_PIPE;
			return;
		}
		else if(val == "event")
		{
			m_fd_type = FDT_EVENT;
			return;
		}
		else if(val == "signalfd")
		{
			m_fd_type = FDT_SIGNALFD;
			return;
		}
		else if(val == "eventpoll")
		{
			m_fd_type = FDT_EVENTPOLL;
			return;
		}
		else if(val == "inotify")
		{
			m_fd_type = FDT_INOTIFY;
			return;
		}
		else if(val == "timerfd")
		{
			m_fd_type = FDT_TIMERFD;
			return;
		}
		else
		{
			throw sinsp_exception("filter error: unsupported fd type " + val);
		}
		break;
	case TYPE_IP:
	case TYPE_CLIENTIP:
	case TYPE_SERVERIP:
		{
			if(inet_pton(AF_INET, val.c_str(), &m_ip) != 1)
			{
				throw sinsp_exception("filter error: malformed IP address " + val);
			}
		}
		break;
	case TYPE_PORT:
	case TYPE_CLIENTPORT:
	case TYPE_SERVERPORT:
		m_port = sinsp_numparser::parseu32(val);
		break;
	default:
		ASSERT(false);
	}
}

bool sinsp_filter_check_fd::check_fdtype(sinsp_fdinfo* fdinfo)
{
	scap_fd_type evt_type = fdinfo->m_type;

	switch(m_fd_type)
	{
	case FDT_FILE:
		if(evt_type == SCAP_FD_FILE || evt_type == SCAP_FD_DIRECTORY)
		{
			return true;
		}
		break;
	case FDT_SOCK:
		if(evt_type == SCAP_FD_IPV4_SOCK || evt_type == SCAP_FD_IPV6_SOCK ||
			 evt_type == SCAP_FD_IPV4_SERVSOCK || evt_type == SCAP_FD_IPV6_SERVSOCK || evt_type == SCAP_FD_UNIX_SOCK)
		{
			return true;
		}
		break;
	case FDT_IPV4_SOCK:
		if(evt_type == SCAP_FD_IPV4_SOCK || evt_type == SCAP_FD_IPV4_SERVSOCK)
		{
			return true;
		}
		break;
	case FDT_IPV6_SOCK:
		if(evt_type == SCAP_FD_IPV6_SOCK || evt_type == SCAP_FD_IPV6_SERVSOCK)
		{
			return true;
		}
		break;
	case FDT_UNIX_SOCK:
		if(evt_type == SCAP_FD_UNIX_SOCK)
		{
			return true;
		}
		break;
	case FDT_PIPE:
		if(evt_type == SCAP_FD_FIFO)
		{
			return true;
		}
		break;
	case FDT_EVENT:
		if(evt_type == SCAP_FD_EVENT)
		{
			return true;
		}
		break;
	case FDT_SIGNALFD:
		if(evt_type == SCAP_FD_SIGNALFD)
		{
			return true;
		}
		break;
	case FDT_EVENTPOLL:
		if(evt_type == SCAP_FD_EVENTPOLL)
		{
			return true;
		}
		break;
	case FDT_INOTIFY:
		if(evt_type == SCAP_FD_INOTIFY)
		{
			return true;
		}
		break;
	case FDT_TIMERFD:
		if(evt_type == SCAP_FD_TIMERFD)
		{
			return true;
		}
		break;
	default:
		ASSERT(false);
	}

	return false;
}

bool sinsp_filter_check_fd::run(sinsp_evt *evt)
{
	ASSERT(evt);
	sinsp_threadinfo* tinfo;
	sinsp_fdinfo* fdinfo;
	ppm_event_flags eflags = evt->get_flags();

	//
	// Make sure this is an event that creates or consumes an fd
	//
	if(eflags & (EF_CREATES_FD | EF_USES_FD | EF_DESTROYS_FD))
	{
		//
		// This is an fd-related event, get the thread info and the fd info
		//
		tinfo = evt->get_thread_info();
		if(tinfo == NULL)
		{
			return false;
		}

		fdinfo = evt->get_fd_info();

		if(fdinfo == NULL && tinfo->m_lastevent_fd != -1)
		{
			fdinfo = tinfo->get_fd(tinfo->m_lastevent_fd);
		}
	}
	else
	{
		return false;
	}

	switch(m_type)
	{
	case TYPE_FDNUM:
		if(flt_compare(m_cmpop, PT_PID, &tinfo->m_lastevent_fd, &m_fd) == true)
		{
			return true;
		}

		break;
	case TYPE_FDNAME:
		if(fdinfo != NULL && flt_compare(m_cmpop, 
			PT_CHARBUF, 
			(void*)fdinfo->m_name.c_str(), (void*)m_fdname.c_str()) == true)
		{
			return true;
		}

		break;
	case TYPE_FDTYPE:
		if(fdinfo != NULL)
		{
			return check_fdtype(fdinfo);
		}

		break;
	case TYPE_IP:
		if(fdinfo != NULL)
		{
			scap_fd_type evt_type = fdinfo->m_type;

			if(evt_type == SCAP_FD_IPV4_SOCK)
			{
				if(fdinfo->m_info.m_ipv4info.m_fields.m_sip == m_ip ||
					fdinfo->m_info.m_ipv4info.m_fields.m_dip == m_ip)
				{
					return true;
				}
			}
			else if(evt_type == SCAP_FD_IPV4_SERVSOCK)
			{
				if(fdinfo->m_info.m_ipv4serverinfo.m_ip == m_ip)
				{
					return true;
				}
			}
		}

		break;
	case TYPE_CLIENTIP:
		if(fdinfo != NULL)
		{
			scap_fd_type evt_type = fdinfo->m_type;

			if(evt_type == SCAP_FD_IPV4_SOCK)
			{
				if(fdinfo->m_info.m_ipv4info.m_fields.m_sip == m_ip)
				{
					return true;
				}
			}
		}

		break;
	case TYPE_SERVERIP:
		if(fdinfo != NULL)
		{
			scap_fd_type evt_type = fdinfo->m_type;

			if(evt_type == SCAP_FD_IPV4_SOCK)
			{
				if(fdinfo->m_info.m_ipv4info.m_fields.m_dip == m_ip)
				{
					return true;
				}
			}
			else if(evt_type == SCAP_FD_IPV4_SERVSOCK)
			{
				if(fdinfo->m_info.m_ipv4serverinfo.m_ip == m_ip)
				{
					return true;
				}
			}
		}

		break;
	case TYPE_PORT:
		if(fdinfo != NULL)
		{
			scap_fd_type evt_type = fdinfo->m_type;

			if(evt_type == SCAP_FD_IPV4_SOCK)
			{
				if(fdinfo->m_info.m_ipv4info.m_fields.m_sport == m_port ||
					fdinfo->m_info.m_ipv4info.m_fields.m_dport == m_port)
				{
					return true;
				}
			}
			else if(evt_type == SCAP_FD_IPV4_SERVSOCK)
			{
				if(fdinfo->m_info.m_ipv4serverinfo.m_port == m_port)
				{
					return true;
				}
			}
			else if(evt_type == SCAP_FD_IPV6_SOCK)
			{
				if(fdinfo->m_info.m_ipv6info.m_fields.m_sport == m_port ||
					fdinfo->m_info.m_ipv6info.m_fields.m_dport == m_port)
				{
					return true;
				}
			}
			else if(evt_type == SCAP_FD_IPV6_SERVSOCK)
			{
				if(fdinfo->m_info.m_ipv6serverinfo.m_port == m_port)
				{
					return true;
				}
			}
		}
	case TYPE_CLIENTPORT:
		if(fdinfo != NULL)
		{
			scap_fd_type evt_type = fdinfo->m_type;

			if(evt_type == SCAP_FD_IPV4_SOCK)
			{
				if(fdinfo->m_info.m_ipv4info.m_fields.m_sport)
				{
					return true;
				}
			}
			else if(evt_type == SCAP_FD_IPV6_SOCK)
			{
				if(fdinfo->m_info.m_ipv6info.m_fields.m_sport == m_port)
				{
					return true;
				}
			}
		}
	case TYPE_SERVERPORT:
		if(fdinfo != NULL)
		{
			scap_fd_type evt_type = fdinfo->m_type;

			if(evt_type == SCAP_FD_IPV4_SOCK)
			{
				if(fdinfo->m_info.m_ipv4info.m_fields.m_dport == m_port)
				{
					return true;
				}
			}
			else if(evt_type == SCAP_FD_IPV4_SERVSOCK)
			{
				if(fdinfo->m_info.m_ipv4serverinfo.m_port == m_port)
				{
					return true;
				}
			}
			else if(evt_type == SCAP_FD_IPV6_SOCK)
			{
				if(fdinfo->m_info.m_ipv6info.m_fields.m_dport == m_port)
				{
					return true;
				}
			}
			else if(evt_type == SCAP_FD_IPV6_SERVSOCK)
			{
				if(fdinfo->m_info.m_ipv6serverinfo.m_port == m_port)
				{
					return true;
				}
			}
		}

		break;

	default:
		ASSERT(false);
	}

	return false;
}

///////////////////////////////////////////////////////////////////////////////
// sinsp_filter_check_thread implementation
///////////////////////////////////////////////////////////////////////////////
bool sinsp_filter_check_thread::recognize_operand(string operand)
{
	if(operand.substr(0, string("thread").length()) == "thread")
	{
		return true;
	}
	else
	{
		return false;
	}
}

void sinsp_filter_check_thread::parse_operand1(string val)
{
	m_type = TYPE_NONE;

	vector<string> components = sinsp_split(val, '.');

	if(components.size() == 2)
	{
		if(components[1] == "tid")
		{
			m_type = TYPE_TID;
			return;
		}
		else if(components[1] == "pid")
		{
			m_type = TYPE_PID;
			return;
		}
		else if(components[1] == "comm")
		{
			m_type = TYPE_COMM;
			return;
		}
		else if(components[1] == "exe")
		{
			m_type = TYPE_EXE;
			return;
		}
		else if(components[1].substr(0, sizeof("arg") - 1) == "arg")
		{
			m_type = TYPE_ARGS;
			return;
		}
		else if(components[1] == "cwd")
		{
			m_type = TYPE_CWD;
			return;
		}
		else if(components[1] == "nchilds")
		{
			m_type = TYPE_NCHILDS;
			return;
		}
		else if(components[1] == "ismainthread")
		{
			m_type = TYPE_ISMAINTHREAD;
			return;
		}
	}

	throw sinsp_exception("filter error: unrecognized field " + val);
}

void sinsp_filter_check_thread::parse_operand2(string val)
{
	switch(m_type)
	{
	case TYPE_TID:
	case TYPE_PID:
		m_xid = sinsp_numparser::parsed64(val);
		break;
	case TYPE_COMM:
	case TYPE_EXE:
	case TYPE_CWD:
		m_str = val;
		break;
	case TYPE_NCHILDS:
		m_nchilds = sinsp_numparser::parseu64(val);
		break;
	case TYPE_ISMAINTHREAD:
		if(val == "true")
		{
			m_ismainthread = true;
		}
		else if(val == "false")
		{
			m_ismainthread = false;
		}
		else
		{
			throw sinsp_exception("filter error: unrecognized ismainthread value " + val);
		}

		break;
	default:
		ASSERT(false);
	}
}

bool sinsp_filter_check_thread::run(sinsp_evt *evt)
{
	sinsp_threadinfo* tinfo = evt->get_thread_info();

	if(tinfo == NULL)
	{
		return false;
	}

	switch(m_type)
	{
	case TYPE_TID:
		if(flt_compare(m_cmpop, PT_PID, &tinfo->m_tid, &m_xid) == true)
		{
			return true;
		}
		break;
	case TYPE_PID:
		if(flt_compare(m_cmpop, PT_PID, &tinfo->m_pid, &m_xid) == true)
		{
			return true;
		}
		break;
	case TYPE_COMM:
		if(flt_compare(m_cmpop, PT_CHARBUF, 
			(void*)tinfo->get_comm().c_str(), (void*)m_str.c_str()) == true)
		{
			return true;
		}
		break;
	case TYPE_EXE:
		if(flt_compare(m_cmpop, PT_CHARBUF, 
			(void*)tinfo->get_exe().c_str(), (void*)m_str.c_str()) == true)
		{
			return true;
		}
		break;
	case TYPE_ARGS:
		ASSERT(false);
		throw sinsp_exception("filter error: thread.args filter not implemented yet");
		return false;
	case TYPE_CWD:
		if(flt_compare(m_cmpop, PT_CHARBUF, 
			(void*)tinfo->get_cwd().c_str(), (void*)m_str.c_str()) == true)
		{
			return true;
		}
		break;
	case TYPE_ISMAINTHREAD:
		if(tinfo->is_main_thread() == m_ismainthread)
		{
			return true;
		}
		break;
	default:
		ASSERT(false);
		break;
	}

	return false;
}

///////////////////////////////////////////////////////////////////////////////
// sinsp_filter_check_event implementation
///////////////////////////////////////////////////////////////////////////////
bool sinsp_filter_check_event::recognize_operand(string operand)
{
	if(operand.substr(0, string("evt").length()) == "evt")
	{
		return true;
	}
	else
	{
		return false;
	}
}

void sinsp_filter_check_event::parse_operand1(string val)
{
	m_type = TYPE_NONE;

	vector<string> components = sinsp_split(val, '.');

	if(components.size() >= 2)
	{
		if(components[1] == "ts")
		{
			m_type = TYPE_TS;
			return;
		}
		else if(components[1] == "name")
		{
			m_type = TYPE_NAME;
			return;
		}
		else if(components[1] == "num")
		{
			m_type = TYPE_NUMBER;
			return;
		}
		else if(components[1] == "cpu")
		{
			m_type = TYPE_CPU;
			return;
		}
		else if(components[1] == "args")
		{
			if(components.size() != 3)
			{
				throw sinsp_exception("filter error: unrecognized argument field " + val);
			}

			m_type = TYPE_ARGS;

			m_argname = components[2];

			return;
		}
	}

	throw sinsp_exception("filter error: unrecognized field " + val);
}

void sinsp_filter_check_event::parse_operand2(string val)
{
	switch(m_type)
	{
	case TYPE_TS:
	case TYPE_NUMBER:
		m_u64val = sinsp_numparser::parseu64(val);
		break;
	case TYPE_CPU:
		m_cpuid = (uint16_t)sinsp_numparser::parseu32(val);
		break;
	case TYPE_NAME:
		if(m_cmpop == CO_CONTAINS)
		{
			m_strval = val;
			m_evttype = PPM_EVENT_MAX;
		}
		else
		{
			try
			{
				m_type = (check_type)sinsp_numparser::parseu32(val);
			}
			catch(...)
			{
				//
				// Search for the event in the table of decoded events
				//
				for(uint32_t j = 0; j < PPM_EVENT_MAX; j++)
				{
					if(val == g_infotables.m_event_info[j].name)
					{
						m_evttype = PPME_MAKE_ENTER(j);
						return;
					}
				}

				//
				// Event not found in the table. It might be an event that we don't support
				// yet, so save it as string and give it a try
				//
				m_strval = val;
				m_evttype = PPM_EVENT_MAX;
			}
		}

		break;
	case TYPE_ARGS:
		{
			try
			{
				if(val[0] == '-')
				{
					m_d64val = sinsp_numparser::parsed64(val);
					m_arg_type = PT_INT64;
					return;
				}
				else
				{
					m_u64val = sinsp_numparser::parseu64(val);
					m_arg_type = PT_UINT64;
					return;
				}
			}
			catch(...)
			{
			}

			m_strval = val;
			m_arg_type = PT_CHARBUF;
		}
		break;
	default:
		ASSERT(false);
	}
}

bool sinsp_filter_check_event::run(sinsp_evt *evt)
{
	sinsp_threadinfo* tinfo = evt->get_thread_info();

	if(tinfo == NULL)
	{
		return false;
	}

	switch(m_type)
	{
	case TYPE_TS:
		if(flt_compare(m_cmpop, PT_UINT64, &evt->m_pevt->ts, &m_u64val) == true)
		{
			return true;
		}
		break;
	case TYPE_NAME:
		{
			uint16_t enter_type;
			char* evname;

			if(evt->m_pevt->type == PPME_GENERIC_E || evt->m_pevt->type == PPME_GENERIC_X)
			{
				sinsp_evt_param *parinfo = evt->get_param(0);
				ASSERT(parinfo->m_len == sizeof(uint16_t));
				uint16_t evid = *(uint16_t *)parinfo->m_val;

				evname = g_infotables.m_syscall_info_table[evid].name;
				enter_type = PPM_EVENT_MAX;
			}
			else
			{
				evname = (char*)evt->get_name();
				enter_type = PPME_MAKE_ENTER(evt->m_pevt->type);
			}

			if(m_evttype == PPM_EVENT_MAX)
			{
				if(flt_compare(m_cmpop, PT_CHARBUF, 
					evname, (char*)m_strval.c_str()) == true)
				{
					return true;
				}
			}
			else
			{
				if(flt_compare(m_cmpop, PT_UINT16, 
					&enter_type, &m_evttype) == true)
				{
					return true;
				}
			}
		}
		break;
	case TYPE_NUMBER:
		if(flt_compare(m_cmpop, PT_UINT64, &evt->m_evtnum, &m_u64val) == true)
		{
			return true;
		}
		break;
	case TYPE_CPU:
		{
			int16_t cpuid = evt->get_cpuid();

			if(flt_compare(m_cmpop, PT_UINT64, &cpuid, &m_u64val) == true)
			{
				return true;
			}
		}
		break;
	case TYPE_ARGS:
		{
			const char* resolved_argstr;
			const char* argstr = evt->get_param_value_str(m_argname.c_str(), 
				&resolved_argstr);

			switch(m_arg_type)
			{
			case PT_CHARBUF:
				if(argstr && flt_compare(m_cmpop, PT_CHARBUF, (void*)argstr, (void*)m_strval.c_str()) == true)
				{
					return true;
				}

				break;
			case PT_UINT64:
				{
					uint64_t dval;
					if(resolved_argstr && !sinsp_numparser::tryparseu64(resolved_argstr, &dval))
					{
						if(argstr && !sinsp_numparser::tryparseu64(argstr, &dval))
						{
							throw sinsp_exception("filter error: field " + m_argname + " is not a number");
						}
					}

					if(flt_compare(m_cmpop, PT_INT64, &dval, &m_u64val) == true)
					{
						return true;
					}
				}
				break;
			case PT_INT64:
				{
					int64_t dval;
					if(resolved_argstr && !sinsp_numparser::tryparsed64(resolved_argstr, &dval))
					{
						if(argstr && !sinsp_numparser::tryparsed64(argstr, &dval))
						{
							throw sinsp_exception("filter error: field " + m_argname + " is not a number");
						}
					}

					if(flt_compare(m_cmpop, PT_INT64, &dval, &m_d64val) == true)
					{
						return true;
					}
				}
				break;
			default:
				ASSERT(false);
				break;
			}
		}
		break;
	default:
		ASSERT(false);
		break;
	}

	return false;
}

///////////////////////////////////////////////////////////////////////////////
// sinsp_filter_check_user implementation
///////////////////////////////////////////////////////////////////////////////
bool sinsp_filter_check_user::recognize_operand(string operand)
{
	if(operand.substr(0, string("user").length()) == "user")
	{
		return true;
	}
	else
	{
		return false;
	}
}

void sinsp_filter_check_user::parse_operand1(string val)
{
	m_type = TYPE_NONE;

	vector<string> components = sinsp_split(val, '.');

	if(components.size() == 2)
	{
		if(components[1] == "uid")
		{
			m_type = TYPE_UID;
			return;
		}
		else if(components[1] == "name")
		{
			m_type = TYPE_NAME;
			return;
		}
		else if(components[1] == "homedir")
		{
			m_type = TYPE_HOMEDIR;
			return;
		}
		else if(components[1] == "shell")
		{
			m_type = TYPE_SHELL;
			return;
		}
	}

	throw sinsp_exception("filter error: unrecognized field " + val);
}

void sinsp_filter_check_user::parse_operand2(string val)
{
	switch(m_type)
	{
	case TYPE_UID:
		m_uid = sinsp_numparser::parsed32(val);
		break;
	case TYPE_NAME:
	case TYPE_HOMEDIR:
	case TYPE_SHELL:
		m_strval = val;
		break;
	default:
		ASSERT(false);
	}
}

bool sinsp_filter_check_user::run(sinsp_evt *evt)
{
	sinsp_threadinfo* tinfo = evt->get_thread_info();
	scap_userinfo* uinfo;

	if(tinfo == NULL)
	{
		return false;
	}

	if(m_type != TYPE_UID)
	{
		unordered_map<uint32_t, scap_userinfo*>::iterator it;

		ASSERT(m_inspector != NULL);
		unordered_map<uint32_t, scap_userinfo*>* userlist = 
			(unordered_map<uint32_t, scap_userinfo*>*)m_inspector->get_userlist();
		ASSERT(userlist->size() != 0);

		it = userlist->find(tinfo->m_uid);
		if(it == userlist->end())
		{
			ASSERT(false);
			return false;
		}

		uinfo = it->second;
		ASSERT(uinfo != NULL);
	}

	switch(m_type)
	{
	case TYPE_UID:
		if(flt_compare(m_cmpop, PT_PID, &tinfo->m_uid, &m_uid) == true)
		{
			return true;
		}
		break;
	case TYPE_NAME:
		if(flt_compare(m_cmpop, PT_CHARBUF, uinfo->name, (char*)m_strval.c_str()) == true)
		{
			return true;
		}
		break;
	case TYPE_HOMEDIR:
		if(flt_compare(m_cmpop, PT_CHARBUF, uinfo->homedir, (char*)m_strval.c_str()) == true)
		{
			return true;
		}
		break;
	case TYPE_SHELL:
		if(flt_compare(m_cmpop, PT_CHARBUF, uinfo->shell, (char*)m_strval.c_str()) == true)
		{
			return true;
		}
		break;
	default:
		ASSERT(false);
		break;
	}

	return false;
}

///////////////////////////////////////////////////////////////////////////////
// sinsp_filter_check_group implementation
///////////////////////////////////////////////////////////////////////////////
bool sinsp_filter_check_group::recognize_operand(string operand)
{
	if(operand.substr(0, string("group").length()) == "group")
	{
		return true;
	}
	else
	{
		return false;
	}
}

void sinsp_filter_check_group::parse_operand1(string val)
{
	m_type = TYPE_NONE;

	vector<string> components = sinsp_split(val, '.');

	if(components.size() == 2)
	{
		if(components[1] == "gid")
		{
			m_type = TYPE_GID;
			return;
		}
		else if(components[1] == "name")
		{
			m_type = TYPE_NAME;
			return;
		}
	}

	throw sinsp_exception("filter error: unrecognized field " + val);
}

void sinsp_filter_check_group::parse_operand2(string val)
{
	switch(m_type)
	{
	case TYPE_GID:
		m_gid = sinsp_numparser::parsed32(val);
		break;
	case TYPE_NAME:
		m_name = val;
		break;
	default:
		ASSERT(false);
	}
}

bool sinsp_filter_check_group::run(sinsp_evt *evt)
{
	sinsp_threadinfo* tinfo = evt->get_thread_info();

	if(tinfo == NULL)
	{
		return false;
	}

	switch(m_type)
	{
	case TYPE_GID:
		if(flt_compare(m_cmpop, PT_PID, &tinfo->m_gid, &m_gid) == true)
		{
			return true;
		}
		break;
	case TYPE_NAME:
		{
			unordered_map<uint32_t, scap_groupinfo*>::iterator it;

			ASSERT(m_inspector != NULL);
			unordered_map<uint32_t, scap_groupinfo*>* grouplist = 
				(unordered_map<uint32_t, scap_groupinfo*>*)m_inspector->get_grouplist();
			ASSERT(grouplist->size() != 0);

			it = grouplist->find(tinfo->m_gid);
			if(it == grouplist->end())
			{
				ASSERT(false);
				return false;
			}

			scap_groupinfo* ginfo = it->second;
			ASSERT(ginfo != NULL);

			if(flt_compare(m_cmpop, PT_CHARBUF, ginfo->name, (char*)m_name.c_str()) == true)
			{
				return true;
			}
		}
		break;
	default:
		ASSERT(false);
		break;
	}

	return false;
}

#endif // HAS_FILTERING
