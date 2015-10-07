//
// k8s_component.cpp
//

#include "k8s_component.h"
#include <sstream>

//
// component
//

const k8s_component::component_map k8s_component::list =
{
	{ k8s_component::K8S_NODES, "nodes" },
	{ k8s_component::K8S_NAMESPACES, "namespaces" },
	{ k8s_component::K8S_PODS, "pods" },
	{ k8s_component::K8S_REPLICATIONCONTROLLERS, "replicationcontrollers" },
	{ k8s_component::K8S_SERVICES, "services" }
};

k8s_component::k8s_component(const std::string& name, const std::string& uid, const std::string& ns) : 
	m_name(name), m_uid(uid), m_ns(ns)
{
}

k8s_pair_list k8s_component::extract_object(const Json::Value& object, const std::string& name)
{
	k8s_pair_list entry_list;
	if (!object.isNull())
	{
		Json::Value entries = object[name];
		if (!entries.isNull())
		{
			Json::Value::Members members = entries.getMemberNames();
			for (auto& member : members)
			{
				Json::Value val = entries[member];
				if (!val.isNull())
				{
					entry_list.emplace_back(k8s_pair_s(member, val.asString()));
				}
			}
		}
	}
	return entry_list;
}

std::vector<std::string> k8s_component::extract_pod_containers(const Json::Value& item)
{
	std::vector<std::string> container_list;
	Json::Value status = item["status"];
	if (!status.isNull())
	{
		Json::Value containers = status["containerStatuses"];
		if (!containers.isNull())
		{
			for (auto& container : containers)
			{
				Json::Value container_id = container["containerID"];
				if (!container_id.isNull())
				{
					container_list.emplace_back(container_id.asString());
				}
			}
		}
	}
	return container_list;
}

void k8s_component::extract_pod_data(const Json::Value& item, k8s_pod_s& pod)
{
	Json::Value spec = item["spec"];
	if (!spec.isNull())
	{
		Json::Value node_name = spec["nodeName"];
		if (!node_name.isNull())
		{
			const std::string& nn = node_name.asString();
			if (!nn.empty())
			{
				pod.set_node_name(nn);
			}
		}
		Json::Value status = item["status"];
		if (!status.isNull())
		{
			Json::Value host_ip = status["hostIP"];
			if (!host_ip.isNull())
			{
				const std::string& hip = host_ip.asString();
				if (!hip.empty())
				{
					pod.set_host_ip(hip);
				}
			}
			Json::Value pod_ip = status["podIP"];
			if (!pod_ip.isNull())
			{
				const std::string& pip = pod_ip.asString();
				if (!pip.empty())
				{
					pod.set_internal_ip(pip);
				}
			}
		}
	}
}

std::vector<std::string> k8s_component::extract_nodes_addresses(const Json::Value& status)
{
	std::vector<std::string> addr_list;
	if (!status.isNull())
	{
		Json::Value addresses = status["addresses"];
		if (!addresses.isNull() && addresses.isArray())
		{
			for (auto& address : addresses)
			{
				if (address.isObject())
				{
					Json::Value::Members addr_list = address.getMemberNames();
					for (auto& entry : addr_list)
					{
						if (entry == "address")
						{
							Json::Value ip = address[entry];
							if (!ip.isNull())
							{
								addr_list.emplace_back(std::move(ip.asString()));
							}
						}
					}
				}
			}
		}
	}
	return addr_list;
}

void k8s_component::extract_services_data(const Json::Value& spec, k8s_service_s& service)
{
	if (!spec.isNull())
	{
		Json::Value cluster_ip = spec["clusterIP"];
		if (!cluster_ip.isNull())
		{
			service.set_cluster_ip(cluster_ip.asString());
		}

		k8s_service_s::port_list pl;
		Json::Value ports = spec["ports"];
		if (!ports.isNull() && ports.isArray())
		{
			for (auto& port : ports)
			{
				k8s_service_s::net_port p;
				Json::Value json_port = port["port"];
				if (!json_port.isNull())
				{
					p.m_port = json_port.asUInt();
				}

				Json::Value json_protocol = port["protocol"];
				if (!json_protocol.isNull())
				{
					p.m_protocol = json_protocol.asString();
				}

				Json::Value json_target_port = port["targetPort"];
				if (!json_target_port.isNull())
				{
					p.m_target_port = json_target_port.asUInt();
				}

				Json::Value json_node_port = port["nodePort"];
				if (!json_node_port.isNull())
				{
					p.m_node_port = json_node_port.asUInt();
				}

				if (p.m_port && p.m_target_port)
				{
					pl.push_back(p);
				}
				else
				{
					// log warning
				}
			}
		}

		if (pl.size())
		{
			service.set_port_list(std::move(pl));
		}
	}
}

//
// namespace
//
k8s_ns_s::k8s_ns_s(const std::string& name, const std::string& uid, const std::string& ns) :
	k8s_component(name, uid, ns)
{
}


//
// node
//

k8s_node_s::k8s_node_s(const std::string& name, const std::string& uid, const std::string& ns) :
	k8s_component(name, uid, ns)
{
}


//
// pod 
//

k8s_pod_s::k8s_pod_s(const std::string& name, const std::string& uid, const std::string& ns) :
	k8s_component(name, uid, ns)
{
}


//
// replication controller
//
k8s_rc_s::k8s_rc_s(const std::string& name, const std::string& uid, const std::string& ns) : 
	k8s_component(name, uid, ns)
{
}


//
// service
//
k8s_service_s::k8s_service_s(const std::string& name, const std::string& uid, const std::string& ns) : 
	k8s_component(name, uid, ns)
{
}


//
// state
//

k8s_state_s::k8s_state_s()
{
}

void k8s_state_s::replace_items(k8s_component::type t, const std::string& name, const std::vector<k8s_pair_s>&& items)
{
	switch (t)
	{
	case k8s_component::K8S_NODES:
		if (name == "labels")
		{
			m_nodes.back().m_labels = std::move(items);
			return;
		}
		break;

	case k8s_component::K8S_NAMESPACES:
		if (name == "labels")
		{
			m_namespaces.back().m_labels = std::move(items);
			return;
		}
		break;

	case k8s_component::K8S_PODS:
		if (name == "labels")
		{
			m_pods.back().m_labels = std::move(items);
			return;
		}
		break;
	// only controllers and services can have selectors
	case k8s_component::K8S_REPLICATIONCONTROLLERS:
		if (name == "labels")
		{
			m_controllers.back().m_labels = std::move(items);
			return;
		}
		else if (name == "selector")
		{
			m_controllers.back().m_selectors = std::move(items);
			return;
		}
		break;

	case k8s_component::K8S_SERVICES:
		if (name == "labels")
		{
			m_services.back().m_labels = std::move(items);
			return;
		}
		else if (name == "selector")
		{
			m_services.back().m_selectors = std::move(items);
			return;
		}
		break;
	}

	std::ostringstream os;
	os << "Unknown component type " << static_cast<int>(t) <<
		" or object name " << name;
	throw std::invalid_argument(os.str().c_str());
}

k8s_component& k8s_state_s::add_common_single_value(k8s_component::type component, const std::string& name, const std::string& uid, const std::string& ns)
{
	switch (component)
	{
		case k8s_component::K8S_NODES:
			return get_component<nodes, k8s_node_s>(m_nodes, name, uid, ns);

		case k8s_component::K8S_NAMESPACES:
			return get_component<namespaces, k8s_ns_s>(m_namespaces, name, uid, ns);

		case k8s_component::K8S_PODS:
			return get_component<pods, k8s_pod_s>(m_pods, name, uid, ns);

		case k8s_component::K8S_REPLICATIONCONTROLLERS:
			return get_component<controllers, k8s_rc_s>(m_controllers, name, uid, ns);

		case k8s_component::K8S_SERVICES:
			return get_component<services, k8s_service_s>(m_services, name, uid, ns);
	}

	std::ostringstream os;
	os << "Unknown component: " << component;
	throw std::invalid_argument(os.str());
}

k8s_node_s* k8s_state_s::get_node(const std::string& uid)
{
	for (auto& node : m_nodes)
	{
		if (node.get_uid() == uid)
		{
			return &node;
		}
	}

	return nullptr;
}

