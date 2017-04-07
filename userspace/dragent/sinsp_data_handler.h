#pragma once

#include "main.h"
#include "protocol.h"
#include "draios.pb.h"

class dragent_configuration;

class sinsp_data_handler : public analyzer_callback_interface
{
public:
	sinsp_data_handler(dragent_configuration* configuration,
			   protocol_queue* queue);

	void sinsp_analyzer_data_ready(uint64_t ts_ns, uint64_t nevts, draiosproto::metrics* metrics, uint32_t sampling_ratio, double analyzer_cpu_pct, double flush_cpu_pct, uint64_t analyzer_flush_duration_ns);

	uint64_t get_last_loop_ns() const
	{
		return m_last_loop_ns;
	}

private:
	dragent_configuration* m_configuration;
	protocol_queue* m_queue;
	volatile uint64_t m_last_loop_ns;
};
