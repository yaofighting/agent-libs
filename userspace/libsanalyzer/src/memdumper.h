#pragma once

#include <unistd.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>

#include <atomic>

#include "Poco/Mutex.h"
#include "Poco/ScopedLock.h"

#include "analyzer_utils.h"
#include "capture.h"
#include "sinsp_int.h"

/**
 * @brief A wrapper over Poco::Mutex with RAII unlocking
 *
 * Compared to Poco::ScopedLock, it offers manual locking together with
 * unlocking on destruction (Poco::ScopedLock locks the mutex immediately
 * when it's created)
 */
class lazy_scoped_lock
{
public:
	lazy_scoped_lock(Poco::Mutex* mutex): m_mutex(mutex), m_locked(false) {}

	/**
	 * @brief lock the mutex
	 *
	 * It will be unlocked automatically when the `lazy_scoped_lock`
	 * goes out of scope
	 */
	void lock()
	{
		ASSERT(!m_locked);
		m_mutex->lock();
		m_locked = true;
	}

	/**
	 * @brief unlock the mutex
	 */
	void unlock()
	{
		ASSERT(m_locked);
		m_mutex->unlock();
		m_locked = false;
	}

	~lazy_scoped_lock()
	{
		if(m_locked)
		{
			unlock();
		}
	}

private:
	Poco::Mutex* m_mutex;
	bool m_locked;
};

class sinsp_memory_dumper_state
{
public:
	sinsp_memory_dumper_state(sinsp* inspector, uint64_t bufsize, const std::string& shm_name)
		: m_inspector(inspector),
		m_shm_name(shm_name),
		m_bufsize(bufsize),
		m_begin_ts(0),
		m_end_ts(0)
	{
	}

	~sinsp_memory_dumper_state()
	{
		close();

		if(shm_unlink(m_shm_name.c_str()) != 0)
		{
			glogf(sinsp_logger::SEV_CRITICAL, "unable to remove the shared memory region %s: %s",
			      m_shm_name.c_str(),
			      strerror(errno));
		}
	}

	void close()
	{
		m_dumper = NULL;
	}

	bool open(std::string &errstr)
	{
		shm_unlink(m_shm_name.c_str());

		int shm_fd = shm_open(m_shm_name.c_str(), O_RDWR | O_CREAT | O_EXCL, S_IRWXU);
		if(shm_fd == -1)
		{
			errstr = std::string("could not reset shared memory segment: ") + strerror(errno);
			return false;
		}

		try
		{
			m_dumper = make_unique<sinsp_dumper>(m_inspector);

			// NOTE: Compression is intentionally disabled. In
			// addition to being a better tradeoff of cpu time vs
			// space savings, the file offsets used in
			// inspector.get_bytes_read()/m_dumper->written_bytes()
			// only match up when using pass-through uncompressed
			// files. Otherwise, you have to perform an lseek
			// system call every time you check the offsets.
			m_dumper->fdopen(shm_fd, false, true);
		}
		catch(const sinsp_exception& e)
		{
			int en = errno;
			glogf(sinsp_logger::SEV_ERROR,
			      "Exception when attempting to open shared memory segment: %s : %s",
			      e.what(),
			      strerror(en));
			errstr = "capture memory buffer too small to store process information. Current size: " +
				std::to_string(m_bufsize);
			return false;
		}

		m_begin_ts = m_end_ts = 0;

		return true;
	}

	bool is_open()
	{
		return (m_dumper && m_dumper->is_open());
	}

	// Returns the number of bytes written.
	inline uint64_t flush()
	{
		Poco::ScopedLock<Poco::FastMutex> lck(m_dumper_mtx);
		m_dumper->flush();

		return m_dumper->written_bytes();
	}

	inline void dump(sinsp_evt *evt)
	{
		Poco::ScopedLock<Poco::FastMutex> lck(m_dumper_mtx);

		if(m_begin_ts == 0)
		{
			m_begin_ts = evt->get_ts();
		}

		m_end_ts = evt->get_ts();

		m_dumper->dump(evt);
	}

	sinsp *m_inspector;
        std::string m_shm_name;
	std::unique_ptr<sinsp_dumper> m_dumper;
	uint64_t m_bufsize;

	// Reflects the timerange covered by events in this memory state.
	uint64_t m_begin_ts;
	uint64_t m_end_ts;

	// Mutex that protects access to this state's dumper
	Poco::FastMutex m_dumper_mtx;
};

class sinsp_memory_dumper_job
{
public:
	enum state
	{
		ST_INPROGRESS = 0,
		ST_DONE_OK = 1,
		ST_DONE_ERROR = 2,
		ST_STOPPPED = 3,
	};

	sinsp_memory_dumper_job()
	{
		m_start_time = 0;
		m_end_time = 0;
		m_state = ST_INPROGRESS;
		m_filter = NULL;
	}

	~sinsp_memory_dumper_job()
	{
		if(m_filter)
		{
			delete m_filter;
		}
	}

	inline bool is_done()
	{
		return m_state != ST_INPROGRESS;
	}

	void stop()
	{
		m_state = ST_STOPPPED;
	}

	uint64_t m_start_time;
	uint64_t m_end_time;
	std::string m_filterstr;
	std::string m_filename;
	bool m_delete_file_when_done;
	state m_state;
	std::string m_lasterr;
	std::unique_ptr<capture> m_capture;
	sinsp_filter* m_filter;
};

class sinsp_memory_dumper
{
public:
	sinsp_memory_dumper(sinsp* inspector);
	~sinsp_memory_dumper();
	void init(uint64_t bufsize, uint64_t max_disk_size, uint64_t max_init_attempts, bool autodisable, uint64_t capture_headers_percentage_threshold, uint64_t time_between_switch_states_ms, uint64_t re_enable_interval_minutes);
	void close();

	// Write a file on disk that contains the result of applying
	// the filter to the events in the memory buffer. If track_job
	// is true, also create internal state to track this memory
	// dumper job going forward.
	// Returns an object containing details on what occurred.
	// The caller should delete this object.
	//
	// If membuf_mtx is non-NULL, lock the mutex before the job has
	// fully read the memory buffer, to guarantee that
	// process_event will stop adding new events to the
	// buffer. The caller will unlock the mutex when the job has
	// been added to the list of jobs.

	std::unique_ptr<sinsp_memory_dumper_job> add_job(uint64_t ts,
	                                 const std::string& filename,
	                                 const std::string& filter,
	                                 uint64_t delta_time_past_ns,
	                                 uint64_t delta_time_future_ns,
	                                 lazy_scoped_lock* membuf_mtx,
	                                 bool delete_file_when_done);

	inline void process_event(sinsp_evt *evt)
	{
		//
		// Capture is disabled if there was not enough memory to dump the thread table.
		//
		if(m_disabled)
		{
			// try to re-enable the memdumper every memdumper.autodisable.re_enable_interval_minutes
			if(m_disabled_by_autodisable &&
			   ((evt->get_ts() - m_last_autodisable_ns) > m_re_enable_interval_ns))
			{
				m_disabled = false;
				m_disabled_by_autodisable = false;
				glogf(sinsp_logger::SEV_INFO,
				      "sinsp_memory_dumper: re-enable memdumper after autodisable occurred");
			}
			else
			{
				return;
			}
		}

		m_processed_events_between_switch_states++;

		// If a delayed state switch is needed, see if it is
		// ready and if so switch states. Otherwise, skip the
		// event.
		if(m_delayed_switch_states_needed)
		{
			if(m_delayed_switch_states_ready)
			{
				switch_states(evt->get_ts());

				// If after switching, memdump is
				// disabled, just return.
				if(m_disabled)
				{
					return;
				}
			}
			else
			{
				m_delayed_switch_states_missed_events++;
				return;
			}
		}

		try
		{
			(*m_active_state)->dump(evt);

			if(m_autodisable)
			{
				if(m_processed_events_between_switch_states == 1)
				{
					m_dump_buffer_headers_size = (*m_active_state)->m_dumper->next_write_position();
				}
			}

			// If we've written at least m_bsize bytes to the active state, switch states.
			if((*m_active_state)->m_dumper->next_write_position() >= (*m_active_state)->m_bufsize)
			{
				m_processed_events_between_switch_states = 0;

				switch_states(evt->get_ts());

				// If after switching, memdump is
				// disabled, just return.
				if(m_disabled)
				{
					return;
				}
			}
		}
		catch(const sinsp_exception& e)
		{
			ASSERT(evt != NULL);
			switch_states(evt->get_ts());

			// If after switching, memdump is
			// disabled, just return.
			if(m_disabled)
			{
				return;
			}

			{
				Poco::ScopedLock<Poco::FastMutex> lck((*m_active_state)->m_dumper_mtx);
				(*m_active_state)->m_dumper->dump(evt);
			}
		}
	}

	inline bool is_enabled()
	{
		return !m_disabled;
	}

private:
	void check_autodisable(uint64_t evt_ts_ns, uint64_t sys_ts_ns);
	void switch_states(uint64_t ts);
	bool read_membuf_using_inspector(sinsp &inspector, const std::shared_ptr<sinsp_memory_dumper_state> &state,
	                                 unique_ptr<sinsp_memory_dumper_job>& job);
	void apply_job_filter(const std::shared_ptr<sinsp_memory_dumper_state> &state,
	                      unique_ptr<sinsp_memory_dumper_job>& job,
	                      lazy_scoped_lock* membuf_mtx);

	typedef std::list<std::shared_ptr<sinsp_memory_dumper_state>> memdump_state;

	scap_threadinfo* m_scap_proclist;
	sinsp* m_inspector;

	memdump_state m_states;
	memdump_state::iterator m_active_state;
	memdump_state::const_reverse_iterator m_reader_state;
	std::atomic<bool> m_reader_active;
	uint32_t m_file_id;
	FILE* m_f;
	FILE* m_cf;
	bool m_disabled;
	bool m_disabled_by_autodisable;
	uint64_t m_last_autodisable_ns;
	uint32_t m_switches_to_go;
	uint32_t m_cur_dump_size;
	uint32_t m_max_disk_size;
	uint64_t m_bsize;
	bool m_autodisable;
	uint64_t m_capture_headers_percentage_threshold;
	uint64_t m_min_time_between_switch_states_ns;
	uint64_t m_re_enable_interval_ns;

	std::atomic<bool> m_delayed_switch_states_needed;
	std::atomic<bool> m_delayed_switch_states_ready;
	uint64_t m_delayed_switch_states_missed_events;

	uint64_t m_processed_events_between_switch_states;
	uint64_t m_autodisable_threshold_reached_count;
	uint64_t m_dump_buffer_headers_size;
	uint64_t m_last_switch_state_ns;

	// Mutex that protects access to the list of states
	Poco::FastMutex m_state_mtx;

	char m_errbuf[256];
};
