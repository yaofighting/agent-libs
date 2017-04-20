#pragma once

#include <memory>
#include <chrono>
#include <iostream>

class sinsp_evttables;

///////////////////////////////////////////////////////////////////////////////
// Hashing support for stl pairs
///////////////////////////////////////////////////////////////////////////////
template <class T>
inline void hash_combine(std::size_t & seed, const T & v)
{
  std::hash<T> hasher;
  seed ^= hasher(v) + 0x9e3779b9 + (seed << 6) + (seed >> 2);
}

namespace std
{
  template<typename S, typename T> struct hash<pair<S, T>>
  {
    inline size_t operator()(const pair<S, T> & v) const
    {
      size_t seed = 0;
      ::hash_combine(seed, v.first);
      ::hash_combine(seed, v.second);
      return seed;
    }
  };
}

///////////////////////////////////////////////////////////////////////////////
// Hashing support for ipv4tuple
// XXX for the moment, this has not been optimized for performance
///////////////////////////////////////////////////////////////////////////////
struct ip4t_hash
{
	size_t operator()(ipv4tuple t) const
	{
		size_t seed = 0;

		std::hash<uint64_t> hasher64;
		std::hash<uint32_t> hasher32;
		std::hash<uint8_t> hasher8;

		seed ^= hasher64(*(uint64_t*)t.m_all) + 0x9e3779b9 + (seed << 6) + (seed >> 2);
		seed ^= hasher32(*(uint32_t*)(t.m_all + 8)) + 0x9e3779b9 + (seed << 6) + (seed >> 2);
		seed ^= hasher8(*(uint8_t*)(t.m_all + 12)) + 0x9e3779b9 + (seed << 6) + (seed >> 2);

		return seed;
	}
};

struct ip4t_cmp
{
	bool operator () (ipv4tuple t1, ipv4tuple t2) const
	{
		return (memcmp(t1.m_all, t2.m_all, sizeof(t1.m_all)) == 0);
	}
};

///////////////////////////////////////////////////////////////////////////////
// Hashing support for unix_tuple
// not yet optimized
///////////////////////////////////////////////////////////////////////////////
struct unixt_hash
{
	size_t operator()(unix_tuple t) const
	{
		size_t seed = 0;

		std::hash<uint64_t> hasher64;

		seed ^= hasher64(*(uint64_t*)t.m_all) + 0x9e3779b9 + (seed << 6) + (seed >> 2);
		seed ^= hasher64(*(uint64_t*)(t.m_all + 8)) + 0x9e3779b9 + (seed << 6) + (seed >> 2);

		return seed;
	}
};

struct unixt_cmp
{
	bool operator () (unix_tuple t1, unix_tuple t2) const
	{
		return (memcmp(t1.m_all, t2.m_all, sizeof(t1.m_all)) == 0);
	}
};

inline bool sinsp_strcmpi(char* buf1, char* buf2, size_t count)
{
	size_t j = count;

	while(--j)
	{
		//
		// Note: '| 0x20' converts to lowercase
		//
		if(((*buf1) | 0x20) != ((*buf2) | 0x20))
		{
			return false;
		}

		buf1++;
		buf2++;
	}

	return true;
}

inline void debug_print_binary_buf(char* buf, uint64_t bufsize)
{
	for (unsigned int j=0; j< bufsize; ++j)
	{
		if(buf[j] >= 'A' && buf[j] <= 'z' )
		{
			printf("\x1B[31m%c\x1B[0m",buf[j]);
		}
		else
		{
			printf("%02x",(uint8_t)buf[j]);
		}
	}
}

inline string truncate_str(const string& s, uint32_t max_size)
{
	if (s.size() <= max_size)
	{
		return s;
	}
	else
	{
		string truncated(s, 0, max_size-3);
		truncated += "...";
		return truncated;
	}
}

#ifndef _WIN32
template<typename T, typename... Ts>
unique_ptr<T> make_unique(Ts&&... params)
{
	return unique_ptr<T>(new T(forward<Ts>(params)...));
}
#endif // _WIN32

// Use it as private superclass to make an object non copyable
class noncopyable
{
public:
	noncopyable(const noncopyable&) = delete;
	noncopyable& operator=(const noncopyable&) = delete;
protected:
	noncopyable() = default;
};

#ifdef SIMULATE_DROP_MODE
bool should_drop(sinsp_evt *evt);
#endif

// Use raw setns syscall for versions of glibc that don't include it (namely glibc-2.12)
#if __GLIBC__ == 2 && __GLIBC_MINOR__ < 14
//#define _GNU_SOURCE
#include <unistd.h>
#include <sys/syscall.h>
#if defined(__NR_setns) && !defined(SYS_setns)
#define SYS_setns __NR_setns
#endif
#ifdef SYS_setns
inline int setns(int fd, int nstype)
{
	return syscall(SYS_setns, fd, nstype);
}
#endif
#endif

/**
 * This class allows you to count time used by some function in an easy way
 * you can use it in two ways:
 *
 * 1. scoped
 *
 * {
 *   stopwatch watch("My block of code");
 *   ...
 * }
 *
 * 2. or by manually calling start() and stop()
 *
 * {
 *   stopwatch watch;
 *   watch.start("1st part");
 *   ...
 *   watch.stop();
 *   watch.start("2nd part"):
 *   ...
 *   watch.stop();
 * }
 */
class stopwatch
{
public:
	stopwatch() {}

	stopwatch(string&& name):
			m_name(name),
			m_starttime(chrono::system_clock::now()),
			m_started(true)
	{
	}

	~stopwatch()
	{
		if(m_started)
		{
			stop();
		}
	}

	void start(string&& name)
	{
		m_name = name;
		m_starttime = chrono::system_clock::now();
		m_started = true;
	}

	void stop()
	{
		m_endtime = chrono::system_clock::now();
		auto d = chrono::duration_cast<chrono::microseconds>(m_endtime - m_starttime);
		std::cerr << m_name << " took " << d.count() << " us" << std::endl;
		m_started = false;
	}


private:
	string m_name;
	chrono::system_clock::time_point m_starttime;
	chrono::system_clock::time_point m_endtime;
	bool m_started;
};

/**
 * Often we need to run something on an interval
 * usually we need to store last_run_ts compare to now
 * and run it
 * This micro-class makes this easier
 */
class run_on_interval
{
public:
	inline run_on_interval(uint64_t interval);

	template<typename Callable>
	inline void run(const Callable& c, uint64_t now = sinsp_utils::get_current_time_ns());
	uint64_t interval() const { return m_interval; }
	void interval(uint64_t i) { m_interval = i; }
private:
	uint64_t m_last_run_ns;
	uint64_t m_interval;
};

run_on_interval::run_on_interval(uint64_t interval):
		m_last_run_ns(0),
		m_interval(interval)
{
}

template<typename Callable>
void run_on_interval::run(const Callable& c, uint64_t now)
{
	if(now - m_last_run_ns > m_interval)
	{
		c();
		m_last_run_ns = now;
	}
}

void send_subprocess_heartbeat();

class nsenter
{
public:
	nsenter(int pid, const string& type);
	virtual ~nsenter();

private:
	int open_ns_fd(int pid, const string& type);
	static unordered_map<string, int> m_home_ns;
	string m_type;
};
