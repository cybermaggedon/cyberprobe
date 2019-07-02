
#ifndef DELIVERY_H
#define DELIVERY_H

#include "sender.h"
#include "parameters.h"
#include "management.h"
#include "capture.h"
#include "packet_consumer.h"
#include "address_map.h"
#include <cybermon/pdu.h>

#include <map>
#include <list>
#include <algorithm>
#include <memory>
#include <mutex>

// Defines an endpoint.
class ep {

    std::string key;

public:
    std::string hostname;	// Hostname
    unsigned int port;		// Port number.
    std::string type;		// Type, one of: etsi, nhis.
    std::string transport;	// Transport, one of: tcp, tls.
    std::map<std::string, std::string> params;

    ep(const std::string& host, unsigned int port,
       const std::string& type, const std::string& transport,
       const std::map<std::string, std::string>& params) {
	this->hostname = host;
	this->port = port;
	this->type = type;
	this->transport = transport;
	this->params = params;
	make_key();
    }

    void make_key() {
	std::ostringstream buf;
	buf << hostname << ":" << port << ":" << type << ":" << transport;
	for(std::map<std::string, std::string>::iterator it = params.begin();
	    it != params.end();
	    it++)
	    buf << ":" << it->first << "=" << it->second;
	key = buf.str();
    }

    bool operator<(const ep& e) const {

	return (key < e.key);

    }

};

// Results of a match, returned by ipv4_match and ipv6_match.
class match {
public:
    std::shared_ptr<std::string> liid;
    std::shared_ptr<std::string> network;
};

// Internal ipv4_match and ipv6_match state.
class match_state {

public:

    match_state(const std::string& l, const std::string& n) :
        liid(l), network(n) {}
    match_state() {}
    
    // On a match, these values are the input to 'mangling'.
    std::string liid;
    std::string network;

    // Caching hits for templated values - the output of 'mangling'.
    std::map<tcpip::ip4_address, match> mangled;   // IPv4
    std::map<tcpip::ip6_address, match> mangled6;  // IPv6

};

// Defines an interface.
class intf {
public:
    std::string interface;
    std::string filter;
    float delay;

    bool operator<(const intf& i) const {

	if (interface < i.interface)
	    return true;
	else if (interface > i.interface) return false;

	if (filter < i.filter)
	    return true;
	else if (filter > i.filter) return false;

	if (delay < i.delay)
	    return true;
	else
	    return false;

    }

};

// Information extracted from the link layer.
class link_info {
public:
    link_info() : vlan(0), ipv(0) {}
    std::vector<unsigned char> mac;
    uint16_t vlan;
    uint8_t ipv;
};

// Delivery manager class.  You feed it IP packets, and it works out what to
// do with the IP packets.  The 'delivery' class owns the NHIS connections
// to the recipient endpoints, and also a target map, which maps IP addresses
// to LIIDs.  IP packets are only delivered if they contain an address which
// hits in the target map.
//
// Note an IP address can only can be mapped to a single LIID.

class delivery : public parameters, public management, public packet_consumer {
private:

    // Targets : an IP address to LIID mapping.
    std::mutex targets_lock;

    address_map<tcpip::ip4_address, match_state> targets;
    address_map<tcpip::ip6_address, match_state> targets6;

    // Endpoints
    std::mutex senders_lock;
    std::map<ep, sender*> senders;

    // Interfaces
    std::mutex interfaces_lock;
    std::map<intf, capture_dev*> interfaces;

    // Parameters and lock
    std::mutex parameters_lock;
    std::map<std::string, std::string> parameters;

    // Short-hand
    typedef std::vector<unsigned char>::const_iterator const_iterator;

    // Link-layer processing.  Alters start/end parameters and returns
    // IP version.
    void identify_link(const_iterator& start,      /* Start of packet */
		       const_iterator& end,	   /* End of packet */
		       int linktype,		   /* PCAP linktype */
		       link_info& link);

    // IPv4 header to LIID
    bool ipv4_match(const_iterator& start,	   /* Start of packet */
		    const_iterator& end,           /* End of packet */
		    const match*& hit,
		    tcpip::ip4_address& match,
                    cybermon::direction& direc,
		    const link_info&);

    // IPv6 header to LIID
    bool ipv6_match(const_iterator& start,	   /* Start of packet */
		    const_iterator& end,           /* End of packet */
		    const match*& hit,
		    tcpip::ip6_address& match,
                    cybermon::direction& direc,
		    const link_info&);

    // Expand liid/network template
    static void expand_template(const std::string& in,
				std::string& out,
				const tcpip::address& addr,
				const tcpip::address& subnet,
				const link_info& link);

public:

    // Modifies interface capture
    virtual void add_interface(const std::string& iface,
			       const std::string& filter,
			       float delay);

    // Modifies interface capture
    virtual void remove_interface(const std::string& iface,
				  const std::string& filter,
				  float delay);

    // Returns the interfaces list.
    virtual void get_interfaces(std::list<interface_info>& ii);

    // Fetch a parameter.
    std::string get_parameter(const std::string& key,
			      const std::string& dflt) {

	parameters_lock.lock();
	if (parameters.find(key) != parameters.end()) {
	    std::string ret = parameters[key];
	    parameters_lock.unlock();
	    return ret;
	} else {
	    parameters_lock.unlock();
	    return dflt;
	}

    }

    // Constructor: Specify the hostname and port number of the NHIS
    // recipient endpoint.
    delivery() {}

    // Destructor.
    virtual ~delivery() {}

    // Allows caller to provide an IP packet for delivery.
    virtual void receive_packet(timeval tv,
				const std::vector<unsigned char>& packet,
				int datalink);

    // Modifies the target map to include a mapping from address to target.
    void add_target(const tcpip::address& addr,
		    unsigned int mask,
		    const std::string& liid,
		    const std::string& network);

    // Removes a target mapping.
    void remove_target(const tcpip::address& addr,
		       unsigned int mask);

    // Fetch current target list.
    virtual void get_targets(std::map<int,
			     std::map<tcpip::ip4_address, std::string> >& t4,
			     std::map<int,
			     std::map<tcpip::ip6_address, std::string> >& t6);

    // Adds an endpoint
    virtual void add_endpoint(const std::string& host,
			      unsigned int port,
			      const std::string& type,
			      const std::string& transp,
			      const std::map<std::string, std::string>& params);

    // Removes an endpoint
    virtual void remove_endpoint(const std::string& host,
				 unsigned int port,
				 const std::string& type,
				 const std::string& transp,
				 const std::map<std::string, std::string>& p);

    // Fetch current target list.
    virtual void get_endpoints(std::list<sender_info>& info);

    // Add a parameter
    virtual void add_parameter(const std::string& key, const std::string& val) {
	parameters_lock.lock();
	parameters[key] = val;
	parameters_lock.unlock();
    }

    // Remove a parameter
    virtual void remove_parameter(const std::string& key) {
	parameters_lock.lock();
	parameters.erase(key);
	parameters_lock.unlock();
    }

    // Get all parameters.
    virtual void get_parameters(std::map<std::string,std::string>& params) {
	parameters_lock.lock();
	params = parameters;
	parameters_lock.unlock();
    }


};

#endif

