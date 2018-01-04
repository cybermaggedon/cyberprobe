
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

// Defines an interface.
class intf {
  public:
    std::string interface;
    std::string filter;
    float delay;

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
    std::map<int, std::map<tcpip::ip4_address, std::string> > targets;   // IPv4
    std::map<int, std::map<tcpip::ip6_address, std::string> > targets6;  // IPv6
    std::map<std::string, std::string> networks;

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
    virtual void receive_packet(const std::vector<unsigned char>& packet, 
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

