//
// kubernetes.cpp
//


#include "kubernetes.h"
#include "draios.pb.h"
#include "google/protobuf/text_format.h"
#include <strstream>
#include <utility>


using Poco::Net::HTTPClientSession;
using Poco::Net::HTTPRequest;
using Poco::Net::HTTPResponse;
using Poco::Net::HTTPMessage;
using Poco::StreamCopier;
using Poco::SharedPtr;
using Poco::URI;
using Poco::Path;
using Poco::format;
using Poco::Exception;
using namespace draiosproto;


const kubernetes::component_map kubernetes::m_components =
{
	{ K8S_NODES, "nodes" },
	{ K8S_NAMESPACES, "namespaces" },
	{ K8S_PODS, "pods" },
	{ K8S_REPLICATIONCONTROLLERS, "replicationcontrollers" },
	{ K8S_SERVICES, "services" }
};


kubernetes::kubernetes(URI uri, const std::string& api) :
	m_uri(uri.toString() + api),
	m_credentials(0),
	m_session(0)
{
	m_uri.normalize();

	std::string username;
	std::string password;
	Poco::Net::HTTPCredentials::extractCredentials(m_uri, username, password);

	m_credentials = new Poco::Net::HTTPCredentials(username, password);
	if (!m_credentials)
	{
		throw Poco::NullPointerException("HTTP credentials.");
	}
	
	m_session = new HTTPClientSession(m_uri.getHost(), m_uri.getPort());
	if (!m_session)
	{
		throw Poco::NullPointerException("HTTP session.");
	}
}

kubernetes::~kubernetes()
{
	delete m_session;
	delete m_credentials;
}

const draiosproto::k8s_state& kubernetes::get_proto()
{
	std::string path(m_uri.getPathAndQuery());
	for (auto component : m_components)
	{
		path = m_uri.toString() + component.second;
		HTTPRequest request(HTTPRequest::HTTP_GET, path, HTTPMessage::HTTP_1_1);
		HTTPResponse response;
		if (!send_request(*m_session, request, response, component))
		{
			m_credentials->authenticate(request, response);
			if (!send_request(*m_session, request, response, component))
			{
				throw Poco::InvalidAccessException("Invalid username/password.");
			}
		}
	}
	make_protobuf();
	return m_k8s_state;
}

bool kubernetes::send_request(HTTPClientSession& session, HTTPRequest& request, HTTPResponse& response, const component_map::value_type& component)
{
	session.sendRequest(request);
	std::istream& rs = session.receiveResponse(response);
	if (response.getStatus() != Poco::Net::HTTPResponse::HTTP_UNAUTHORIZED)
	{
		std::ostringstream os;
		StreamCopier::copyStream(rs, os);
		parse_json(os.str(), component);
		return true;
	}
	else
	{
		Poco::NullOutputStream null;
		StreamCopier::copyStream(rs, null);
		return false;
	}
}

void kubernetes::add_object_entry(Component component, const std::string& name, k8s_pair_s&& p)
{
	switch (component)
	{
	case K8S_NODES:
		if (name == "labels")
		{
			m_state.nodes.back().m_labels.emplace_back(std::forward<k8s_pair_s>(p));
			return;
		}
		break;

	case K8S_NAMESPACES:
		if (name == "labels")
		{
			m_state.nss.back().m_labels.emplace_back(std::forward<k8s_pair_s>(p));
			return;
		}
		break;

	case K8S_PODS:
		if (name == "labels")
		{
			m_state.pods.back().m_labels.emplace_back(std::forward<k8s_pair_s>(p));
			return;
		}
		break;
	// only controllers and services can have selectors
	case K8S_REPLICATIONCONTROLLERS:
		if (name == "labels")
		{
			m_state.rcs.back().m_labels.emplace_back(std::forward<k8s_pair_s>(p));
			return;
		}
		else if (name == "selector")
		{
			m_state.rcs.back().m_selectors.emplace_back(std::forward<k8s_pair_s>(p));
			return;
		}
		break;

	case K8S_SERVICES:
		if (name == "labels")
		{
			m_state.services.back().m_labels.emplace_back(std::forward<k8s_pair_s>(p));
			return;
		}
		else if (name == "selector")
		{
			m_state.services.back().m_selectors.emplace_back(std::forward<k8s_pair_s>(p));
			return;
		}
		break;
	}

	throw Poco::InvalidAccessException(
		Poco::format("Unknown component [%d] or object name [%s]",
			static_cast<int>(component), name));
}

// extracts labels or selectors
void kubernetes::extract_object(Component component, const Json::Value& object, const std::string& name)
{
	if (!object.isNull())
	{
		Json::Value entries = object[name];
		if (!object.isNull())
		{
			Json::Value::Members members = entries.getMemberNames();
			for (auto member : members)
			{
				Json::Value val = entries[member];
				if (!val.isNull())
				{
					add_object_entry(component, name, k8s_pair_s(member, val.asString()));
				}
			}
		}
	}
}

void kubernetes::extract_nodes_addresses(const Json::Value& status)
{
	if (!status.isNull())
	{
		Json::Value addresses = status["addresses"];
		if (!addresses.isNull())
		{
			for (auto address : addresses)
			{
				if (address.isObject())
				{
					Json::Value::Members addr_list = address.getMemberNames();
					for (auto entry : addr_list)
					{
						if (entry == "address")
						{
							Json::Value ip = address[entry];
							if (!ip.isNull())
							{
								m_state.nodes.back().host_ips.emplace_back(ip.asString());
							}
						}
					}
				}
			}
		}
	}
}

void kubernetes::extract_pods_data(const Json::Value& item)
{
	extract_pod_containers(item);

	Json::Value spec = item["spec"];
	if (!spec.isNull())
	{
		Json::Value node_name = spec["nodeName"];
		if (!node_name.isNull())
		{
			m_state.pods.back().node_name = node_name.asString();
		}
		Json::Value status = item["status"];
		if (!status.isNull())
		{
			Json::Value host_ip = status["hostIP"];
			if (!host_ip.isNull())
			{
				m_state.pods.back().host_ip = host_ip.asString();
			}
			Json::Value pod_ip = status["podIP"];
			if (!pod_ip.isNull())
			{
				m_state.pods.back().internal_ip = pod_ip.asString();
			}
		}
	}
}

void kubernetes::extract_pod_containers(const Json::Value& item)
{
	Json::Value spec = item["status"];
	if (!spec.isNull())
	{
		Json::Value containers = spec["containerStatuses"];
		if (!containers.isNull())
		{
			for (auto container : containers)
			{
				Json::Value container_id = container["containerID"];
				if (!container_id.isNull())
				{
					m_state.pods.back().container_ids.emplace_back(container_id.asString());
				}
			}
		}
	}
}

void kubernetes::add_common_single_value(Component component, const std::string& name, const std::string& uid, const std::string& ns)
{
	switch (component)
	{
	case K8S_NODES:
		m_state.nodes.emplace_back(k8s_node_s(name, uid, ns));
		break;

	case K8S_NAMESPACES:
		m_state.nss.emplace_back(k8s_ns_s(name, uid, ns));
		break;

	case K8S_PODS:
		m_state.pods.emplace_back(k8s_pod_s(name, uid, ns));
		break;

	case K8S_REPLICATIONCONTROLLERS:
		m_state.rcs.emplace_back(k8s_rc_s(name, uid, ns));
		break;

	case K8S_SERVICES:
		m_state.services.emplace_back(k8s_service_s(name, uid, ns));
		break;

	default:
		throw Poco::InvalidAccessException(
			Poco::format("Unknown component: %d", static_cast<int>(component)));
	}
}

void kubernetes::extract_data(const Json::Value& items, Component component)
{
	if (items.isArray())
	{
		for (auto item : items)
		{
			Json::Value obj = item["metadata"];
			if (obj.isObject())
			{
				Json::Value ns = obj["namespace"];
				std::string nspace;
				if (!ns.isNull())
				{
					nspace = ns.asString();
				}
				add_common_single_value(component, obj["name"].asString(), obj["uid"].asString(), nspace);


				Json::Value metadata = item["metadata"];
				if (!metadata.isNull())
				{
					extract_object(component, metadata, "labels");
				}

				Json::Value spec = item["spec"];
				if (!metadata.isNull())
				{
					extract_object(component, spec, "selector");
				}

				if (component == K8S_NODES)
				{
					extract_nodes_addresses(item["status"]);
				}
				else if (component == K8S_PODS)
				{
					extract_pods_data(item);
				}
			}
		}
	}
}

void kubernetes::make_protobuf()
{
	for (auto ns : m_state.nss)
	{
		populate_component(ns, m_k8s_state.add_namespaces(), K8S_NAMESPACES);
	}

	for (auto node : m_state.nodes)
	{
		k8s_node* nodes = m_k8s_state.add_nodes();
		populate_component(node, nodes, K8S_NODES);
		auto host_ips = nodes->mutable_host_ips();
		for (auto host_ip : node.host_ips)
		{
			auto host_ips = nodes->add_host_ips();
			host_ips->assign(host_ip.begin(), host_ip.end());
		}
	}
	for (auto pod : m_state.pods)
	{
		k8s_pod* pods = m_k8s_state.add_pods();
		populate_component(pod, pods, K8S_PODS);
		auto container_ids = pods->mutable_container_ids();
		for (auto container_id : pod.container_ids)
		{
			auto container_ids = pods->add_container_ids();
			container_ids->assign(container_id.begin(), container_id.end());
		}
		pods->set_node_name(pod.node_name);
		pods->set_host_ip(pod.host_ip);
		pods->set_internal_ip(pod.internal_ip);
	}
	for (auto rc : m_state.rcs)
	{
		populate_component(rc, m_k8s_state.add_controllers(), K8S_REPLICATIONCONTROLLERS);
	}
	for (auto service : m_state.services)
	{
		populate_component(service, m_k8s_state.add_services(), K8S_SERVICES);
	}
}

void kubernetes::parse_json(const std::string& json, const component_map::value_type& component)
{
	Json::Value root;
	Json::Reader reader;
	bool success = reader.parse(json, root, false);
	Json::Value items = root["items"];
	extract_data(items, component.first);
	//std::cout << std::endl << root.toStyledString() << std::endl;
}
