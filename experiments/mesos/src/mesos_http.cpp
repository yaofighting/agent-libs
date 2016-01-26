//
// mesos_http.cpp
//

#ifdef HAS_CAPTURE

#include "mesos_http.h"
#include "curl/curl.h"
#include "curl/easy.h"
#include "curl/curlbuild.h"
#define BUFFERSIZE 512 // b64 needs this macro
#include "b64/encode.h"
#include "sinsp.h"
#include "sinsp_int.h"
#include "mesos.h"
#include <sstream>
#include <stdexcept>
#include <unistd.h>

mesos_http::mesos_http(mesos& m, const uri& url):
	m_curl(curl_easy_init()),
	m_mesos(m),
	m_url(url),
	m_connected(true),
	m_watch_socket(-1)
{
	if(!m_curl)
	{
		throw sinsp_exception("CURL initialization failed.");
	}

	curl_version_info_data* data = curl_version_info(CURLVERSION_NOW);
	if((m_url.get_scheme() == "https") && !(data->features | CURL_VERSION_SSL))
	{
		cleanup();
		throw sinsp_exception("HTTPS NOT supported");
	}
}

mesos_http::~mesos_http()
{
	cleanup();
}

void mesos_http::cleanup()
{
	if(m_curl)
	{
		curl_easy_cleanup(m_curl);
		m_curl = 0;
	}
}

size_t mesos_http::write_data(void *ptr, size_t size, size_t nmemb, void *cb)
{
	std::string data(reinterpret_cast<const char*>(ptr), static_cast<size_t>(size * nmemb));
	*reinterpret_cast<std::ostream*>(cb) << data << std::flush;
	return size * nmemb;
}

CURLcode mesos_http::get_data(const std::string& url, std::ostream& os)
{
	g_logger.log(std::string("Retrieving data from ") + url, sinsp_logger::SEV_DEBUG);
	curl_easy_setopt(m_curl, CURLOPT_URL, url.c_str());
	curl_easy_setopt(m_curl, CURLOPT_FOLLOWLOCATION, 1L);

	if(m_url.get_scheme() == "https")
	{
		check_error(curl_easy_setopt(m_curl, CURLOPT_SSL_VERIFYPEER , 0));
	}

	curl_easy_setopt(m_curl, CURLOPT_NOSIGNAL, 1); //Prevent "longjmp causes uninitialized stack frame" bug
	curl_easy_setopt(m_curl, CURLOPT_ACCEPT_ENCODING, "deflate");
	curl_easy_setopt(m_curl, CURLOPT_WRITEFUNCTION, &mesos_http::write_data);
	
	curl_easy_setopt(m_curl, CURLOPT_WRITEDATA, &os);
	return curl_easy_perform(m_curl);
}

bool mesos_http::get_all_data(parse_func_t parse)
{
	std::ostringstream os;
	CURLcode res = get_data(m_url.to_string(), os);

	if(res != CURLE_OK)
	{
		g_logger.log(curl_easy_strerror(res), sinsp_logger::SEV_ERROR);
		m_connected = false;
	}
	else
	{
		(m_mesos.*parse)(os.str());
		m_connected = true;
	}

	return res == CURLE_OK;
}

int mesos_http::wait(/*curl_socket_t sockfd,*/ int for_recv, long timeout_ms)
{
	curl_socket_t sockfd = get_watch_socket(timeout_ms);

	struct timeval tv;
	fd_set infd, outfd, errfd;
	int res;

	tv.tv_sec = timeout_ms / 1000;
	tv.tv_usec = (timeout_ms % 1000) * 1000;

	FD_ZERO(&infd);
	FD_ZERO(&outfd);
	FD_ZERO(&errfd);

	FD_SET(sockfd, &errfd);

	if(for_recv)
	{
		FD_SET(sockfd, &infd);
	}
	else
	{
		FD_SET(sockfd, &outfd);
	}

	res = select(sockfd + 1, &infd, &outfd, &errfd, &tv);
	return res;
}

int mesos_http::get_watch_socket(long timeout_ms)
{
	if(m_watch_socket < 0)
	{
		long sockextr;
		size_t iolen;
		std::string url = get_url().to_string();

		check_error(curl_easy_setopt(get_curl(), CURLOPT_URL, url.c_str()));
		check_error(curl_easy_setopt(get_curl(), CURLOPT_CONNECT_ONLY, 1L));

		check_error(curl_easy_perform(get_curl()));

		check_error(curl_easy_getinfo(get_curl(), CURLINFO_LASTSOCKET, &sockextr));
		m_watch_socket = sockextr;

		if(!wait(/*m_watch_socket,*/ 0, timeout_ms))
		{
			cleanup();
			throw sinsp_exception("Error: timeout.");
		}

		std::ostringstream request;
		std::string host_and_port = get_url().get_host();
		int port = get_url().get_port();
		if(port)
		{
			host_and_port.append(1, ':').append(std::to_string(port));
		}
		request << "GET " << get_url().get_path() << " HTTP/1.1\r\nHost: " << host_and_port << "\r\nAccept: text/event-stream\r\n";
		if(!get_credentials().empty())
		{
			std::istringstream is(get_credentials());
			std::ostringstream os;
			base64::encoder().encode(is, os);
			request << "Authorization: Basic " << os.str() << "\r\n";
		}
		request << "\r\n";
		check_error(curl_easy_send(get_curl(), request.str().c_str(), request.str().size(), &iolen));
		ASSERT (request.str().size() == iolen);
		if(!wait(/*m_watch_socket,*/ 1, timeout_ms))
		{
			cleanup();
			throw sinsp_exception("Error: timeout.");
		}

		g_logger.log(std::string("Collecting data from ") + url, sinsp_logger::SEV_DEBUG);
	}

	return m_watch_socket;
}

bool mesos_http::on_data()
{
	throw sinsp_exception("Mesos HTTP does not implement watch handlers.");
}

void mesos_http::on_error(const std::string& /*err*/, bool /*disconnect*/)
{
	throw sinsp_exception("Mesos HTTP does not implement watch handlers.");
}

void mesos_http::check_error(CURLcode res)
{
	if(CURLE_OK != res && CURLE_AGAIN != res)
	{
		std::ostringstream os;
		os << "Error: " << curl_easy_strerror(res);
		throw sinsp_exception(os.str());
	}
}

std::string mesos_http::make_uri(const std::string& path)
{
	uri url = get_url();
	std::string target_uri = url.get_scheme();
	target_uri.append("://");
	std::string user = url.get_user();
	if(!user.empty())
	{
		target_uri.append(user).append(1, ':').append(url.get_password()).append(1, '@');
	}
	target_uri.append(url.get_host());
	int port = url.get_port();
	if(port)
	{
		target_uri.append(1, ':').append(std::to_string(port));
	}
	target_uri.append(path);
	return target_uri;
}

Json::Value mesos_http::get_task_labels(const std::string& task_id)
{
	std::ostringstream os;
	CURLcode res = get_data(make_uri("/master/tasks"), os);

	Json::Value labels;
	if(res != CURLE_OK)
	{
		g_logger.log(curl_easy_strerror(res), sinsp_logger::SEV_ERROR);
		return labels;
	}

	try
	{
		Json::Value root;
		Json::Reader reader;
		if(reader.parse(os.str(), root, false))
		{
			Json::Value tasks = root["tasks"];
			if(!tasks.isNull())
			{
				for(const auto& task : tasks)
				{
					Json::Value id = task["id"];
					if(!id.isNull() && id.isString() && id.asString() == task_id)
					{
						Json::Value statuses = task["statuses"];
						if(!statuses.isNull())
						{
							double tstamp = 0.0;
							for(const auto& status : statuses)
							{
								// only task with most recent status
								// "TASK_RUNNING" considered
								Json::Value ts = status["timestamp"];
								if(!ts.isNull() && ts.isNumeric() && ts.asDouble() > tstamp)
								{
									Json::Value st = status["state"];
									if(!st.isNull() && st.isString())
									{
										if(st.asString() == "TASK_RUNNING")
										{
											labels = task["labels"];
											tstamp = ts.asDouble();
										}
										else
										{
											labels.clear();
										}
									}
								}
							}
							if(!labels.empty()) // currently running task found
							{
								return labels;
							}
						}
					}
				}
			}
		}
		else
		{
			g_logger.log("Error parsing tasks.\nJSON:\n---\n" + os.str() + "\n---", sinsp_logger::SEV_ERROR);
		}
	}
	catch(std::exception& ex)
	{
		g_logger.log(std::string("Error parsing tasks:") + ex.what(), sinsp_logger::SEV_ERROR);
	}

	return labels;
}

#endif // HAS_CAPTURE
