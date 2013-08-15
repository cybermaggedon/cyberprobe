
#ifndef DELIVERY_H
#define DELIVERY_H

#include "sender.h"
#include "parameters.h"
#include "management.h"
#include "capture.h"
#include "packet_consumer.h"

#include <map>
#include <list>
#include <algorithm>

// Defines an endpoint.
class ep {
  public:
    std::string hostname;
    unsigned int port;
    std::string type;

    bool operator<(const ep& e) const {

	if (hostname < e.hostname)
	    return true;
	else
	    if (hostname > e.hostname)
		return false;

	// hostname == e.hostname
	if (port < e.port)
	    return true;
	else
	    if (port > e.port)
		return false;

	if (type < e.type) 
	    return true;
	else
	    return false;

    }

};

// Defines an interface.
class intf {
  public:
    std::string interface;
    std::string filter;
    int delay;

    // FIXME: I haven't checked this works?!?!?!
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

// Delivery manager class.  You feed it IP packets, and it works out what to
// do with the IP packets.  The 'delivery' class owns the NHIS connections
// to the recipient endpoints, and also a target map, which maps IP addresses
// to LIIDs.  IP packets are only delivered if they contain an address which
// hits in the target map.
//
// Note an IP address can only can be mapped to a single LIID.

class delivery : public parameters, public management, public packet_consumer {
  private:
    
    // Lock for senders and targets maps.
    //threads::mutex lock;

    // Targets : an IP address to LIID mapping.
    threads::mutex targets_lock;
    std::map<tcpip::ip4_address, std::string> targets;   // IPv4
    std::map<tcpip::ip6_address, std::string> targets6;  // IPv6

    // Endpoints
    threads::mutex senders_lock;
    std::map<ep, sender*> senders;

    // Interfaces
    threads::mutex interfaces_lock;
    std::map<intf, capture_dev*> interfaces;

    // Parameters and lock
    threads::mutex parameters_lock;
    std::map<std::string, std::string> parameters;

    // Short-hand
    typedef std::vector<unsigned char>::const_iterator const_iterator;

    // Link-layer processing.  Alters start/end parameters and returns
    // IP version.
    void identify_link(const_iterator& start,      /* Start of packet */
		       const_iterator& end,	   /* End of packet */
		       int linktype,		   /* PCAP linktype */
		       int& ipv);		   /* IP version (return) */

    // IPv4 header to LIID
    bool ipv4_match(const_iterator& start,	   /* Start of packet */
		    const_iterator& end,           /* End of packet */
		    std::string& liid,
		    tcpip::ip4_address& match);

    // IPv6 header to LIID
    bool ipv6_match(const_iterator& start,	   /* Start of packet */
		    const_iterator& end,           /* End of packet */
		    std::string& liid,
		    tcpip::ip6_address& match);

  public:

    // Modifies interface capture
    virtual void add_interface(const std::string& iface,
			       const std::string& filter,
			       int delay);

    // Modifies interface capture
    virtual void remove_interface(const std::string& iface,
				  const std::string& filter,
				  int delay);
    
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
    virtual void receive_packet(const std::vector<unsigned char>& packet, 
				int datalink);

    // Modifies the target map to include a mapping from address to target.
    void add_target(const tcpip::address& addr, 
		    const std::string& liid);

    // Removes a target mapping.
    void remove_target(const tcpip::address& addr);

    // Fetch current target list.
    virtual void get_targets(std::map<tcpip::ip4_address, std::string>& t4,
			     std::map<tcpip::ip6_address, std::string>& t6);

    // Adds an endpoint
    virtual void add_endpoint(const std::string& host, unsigned int port,
			      const std::string& type);

    // Removes an endpoint
    virtual void remove_endpoint(const std::string& host, unsigned int port,
				 const std::string& type);

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

