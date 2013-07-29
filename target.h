
////////////////////////////////////////////////////////////////////////////
//
// TARGET RESOURCE
//
////////////////////////////////////////////////////////////////////////////

#ifndef TARGET_H
#define TARGET_H

#include "resource.h"

// A target specification: Maps an IP address to a LIID.
class target_spec : public specification {
public:

    // Type is 'target'.
    virtual std::string get_type() const { return "target"; }

    // LIID.
    std::string liid;

    // IP addresses
    tcpip::ip4_address addr;
    tcpip::ip6_address addr6;

    enum { IPv4, IPv6} universe;

    // Constructors.
    target_spec() { universe = IPv4; }

    // Set IPv4 address match.
    void set_ipv4(const std::string& liid, const tcpip::ip4_address& addr) {
	this->liid = liid; this->addr = addr; universe = IPv4;
    }

    // Set IPv6 address match.
    void set_ipv6(const std::string& liid, const tcpip::ip6_address& addr) {
	this->liid = liid; this->addr6 = addr; universe = IPv6;
    }

    // Hash is form ipaddr:liid.
    virtual std::string get_hash() const { 
	std::ostringstream buf;
	
	if (universe == IPv4)
	    buf << "IPv4:" << addr;
	else
	    buf << "IPv6:" << addr6;

	buf << ":" << liid;
	return buf.str();
    }

};

// Target resource.  The target resources are just instantiated as
// changes to the target map in the delivery engine.
class target : public resource {
private:

    // Spec.
    const target_spec& spec;

    // Delivery engine reference.
    delivery& deliv;

public:

    // Constructor.
    target(const target_spec& spec, delivery& d) : 
	spec(spec), deliv(d) { }

    // Start method, change the delivery engine mapping.
    virtual void start() { 

	std::string txt;
	if (spec.universe == target_spec::IPv4) {
	    deliv.add_target(spec.addr, spec.liid);
	    spec.addr.to_string(txt);
	} else {
	    deliv.add_target(spec.addr6, spec.liid);
	    spec.addr6.to_string(txt);
	}

	std::cerr << "Added target " << txt << " -> " << spec.liid << "." 
		  << std::endl;

    }

    // Stop method, remove the mapping.
    virtual void stop() { 

	std::string txt;
	if (spec.universe == target_spec::IPv4) {
	    deliv.remove_target(spec.addr);
	    spec.addr.to_string(txt);
	} else {
	    deliv.remove_target(spec.addr6);
	    spec.addr6.to_string(txt);
	}

	std::cerr << "Removed target " << txt
		  << " -> " 
		  << spec.liid << "." << std::endl;
    }

};

#endif

