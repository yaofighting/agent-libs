#pragma once

class sinsp_procfs_parser
{
public:
	sinsp_procfs_parser(const scap_machine_info* machine_info);

	uint32_t get_global_cpu_load(OUT uint64_t* global_total_jiffies = NULL);

	void get_cpus_load(OUT vector<uint32_t>* loads);
	
	//
	// must call get_total_cpu_load to update the system time before calling this
	//
	uint32_t get_process_cpu_load(uint64_t pid, uint64_t* old_proc_jiffies, uint64_t delta_global_total_jiffies);

	int64_t get_process_resident_memory_kb(uint64_t pid);

private:
//	uint64_t m_last_read_time;
	const scap_machine_info* m_machine_info;
	vector<uint64_t> m_old_total_jiffies;
	vector<uint64_t> m_old_work_jiffies;
	uint64_t m_old_global_total_jiffies;
	uint64_t m_old_global_work_jiffies;
};
