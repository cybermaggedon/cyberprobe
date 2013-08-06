
#ifndef TARGETING_H
#define TARGETING_H

#include "sender.h"

class targeting {

  public:

    // Constructor.
    targeting() {}

    // Destructor.
    virtual ~targeting() {}

    // Modifies the target map to include a mapping from address to target.
    virtual void add_target(const tcpip::address& addr, 
			    const std::string& liid) = 0;

    // Removes a target mapping.
    virtual void remove_target(const tcpip::address& addr) = 0;

    // Fetch current target list.
    virtual void get_targets(std::map<tcpip::ip4_address, std::string>& t4,
			     std::map<tcpip::ip6_address, std::string>& t6) = 0;

    // Adds an endpoint
    virtual void add_endpoint(sender* s) = 0;

    // Removes an endpoint
    virtual void remove_endpoint(sender* s) = 0;

    // Fetch current target list.
    virtual void get_endpoints(std::list<sender_info>& info) = 0;

};

#endif

