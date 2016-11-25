
#ifndef MANAGEMENT_H
#define MANAGEMENT_H

#include <list>
#include <map>

#include <cybermon/socket.h>

class interface_info {
  public:
    std::string interface;
    std::string filter;
    float delay;
};

// Sender status
class sender_info {
  public:
    std::string hostname;
    unsigned short port;
    std::string type;
    std::string description;
};

class management {

  public:
    virtual ~management() = default;

    // Modifies interface capture
    virtual void add_interface(const std::string& iface,
			       const std::string& filter,
			       float delay) = 0;

    // Modifies interface capture
    virtual void remove_interface(const std::string& iface,
				  const std::string& filter,
				  float delay) = 0;

    virtual void get_interfaces(std::list<interface_info>& ii) = 0;

    // Modifies the target map to include a mapping from address to target.
    virtual void add_target(const tcpip::address& addr, 
			    unsigned int mask,
			    const std::string& liid) = 0;

    // Removes a target mapping.
    virtual void remove_target(const tcpip::address& addr,
			       unsigned int mask) = 0;

    // Fetch current target list.
    virtual void 
	get_targets(std::map<int, 
		    std::map<tcpip::ip4_address, std::string> >& t4,
		    std::map<int,
		    std::map<tcpip::ip6_address, std::string> >& t6) = 0;

    // Adds an endpoint
    virtual void add_endpoint(const std::string& host, unsigned int port,
			      const std::string& type) = 0;

    // Removes an endpoint
    virtual void remove_endpoint(const std::string& host, unsigned int port,
				 const std::string& type) = 0;

    // Fetch current target list.
    virtual void get_endpoints(std::list<sender_info>& info) = 0;

    // Add parameter.
    virtual void add_parameter(const std::string& key, const std::string& val)
	= 0;

    // Remove parameter.
    virtual void remove_parameter(const std::string& key) = 0;

    // Get all parameters.
    virtual void get_parameters(std::map<std::string,std::string>& params) = 0;

};

#endif

