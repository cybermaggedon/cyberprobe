
#ifndef DELIVERY_H
#define DELIVERY_H

#include "sender.h"
#include "parameters.h"
#include "targeting.h"

#include <map>
#include <list>
#include <algorithm>

// Delivery manager class.  You feed it IP packets, and it works out what to
// do with the IP packets.  The 'delivery' class owns the NHIS connections
// to the recipient endpoints, and also a target map, which maps IP addresses
// to LIIDs.  IP packets are only delivered if they contain an address which
// hits in the target map.
//
// Note an IP address can only can be mapped to a single LIID.

class delivery : public parameters, public targeting {
  private:
    
    // Lock for senders and targets maps.
    threads::mutex lock;

    // Targets : an IP address to LIID mapping.
    std::map<tcpip::ip4_address, std::string> targets;

    // Targets : an IP address to LIID mapping.
    std::map<tcpip::ip6_address, std::string> targets6;

    // Endpoints
    std::list<sender*> senders;

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

    // Parameter stuff.  No parameters defined yet.
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
    virtual void deliver(const std::vector<unsigned char>& packet, 
			 int datalink);

    // Modifies the target map to include a mapping from address to target.
    void add_target(const tcpip::address& addr, 
		    const std::string& liid) {
	lock.lock();
	if (addr.universe == addr.ipv4) {
	    const tcpip::ip4_address& a =
		reinterpret_cast<const tcpip::ip4_address&>(addr);
	    targets[a] = liid;
	} else {
	    const tcpip::ip6_address& a =
		reinterpret_cast<const tcpip::ip6_address&>(addr);
	    targets6[a] = liid;
	}
	lock.unlock();
    }

    // Removes a target mapping.
    void remove_target(const tcpip::address& addr) {
	lock.lock();
	if (addr.universe == addr.ipv4) {
	    const tcpip::ip4_address& a =
		reinterpret_cast<const tcpip::ip4_address&>(addr);
	    targets.erase(a);
	} else {
	    const tcpip::ip6_address& a =
		reinterpret_cast<const tcpip::ip6_address&>(addr);
	    targets6.erase(a);
	}
	lock.unlock();
    }

    // Fetch current target list.
    virtual void get_targets(std::map<tcpip::ip4_address, std::string>& t4,
			     std::map<tcpip::ip6_address, std::string>& t6) {
	t4 = targets;
	t6 = targets6;
    }

    // Adds an endpoint
    void add_endpoint(sender* s) {
	lock.lock();
	senders.push_back(s);
	lock.unlock();
    }

    // Removes an endpoint
    void remove_endpoint(sender* s) {
	lock.lock();
	senders.remove(s);
	lock.unlock();
    }

    // Fetch current target list.
    virtual void get_endpoints(std::list<sender_info>& info) {
	lock.lock();

	info.clear();
	for(std::list<sender*>::iterator it = senders.begin();
	    it != senders.end();
	    it++) {
	    sender_info inf;
	    (*it)->get_info(inf);
	    info.push_back(inf);
	}

	lock.unlock();
    }

    // Add a parameter
    void add_parameter(const std::string& key, const std::string& val) {
	parameters_lock.lock();
	parameters[key] = val;
	parameters_lock.unlock();
    }

    // Remove a parameter
    void remove_parameter(const std::string& key, const std::string& val) {
	parameters_lock.lock();
	parameters.erase(key);
	parameters_lock.unlock();
    }

};

#endif

