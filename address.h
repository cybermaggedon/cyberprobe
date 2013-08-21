
////////////////////////////////////////////////////////////////////////////
//
// A class for representing a wide variety of addresses.
//
////////////////////////////////////////////////////////////////////////////

#ifndef ADDRESS_H
#define ADDRESS_H

#include <vector>
#include <iostream>

#include "pdu.h"
#include "socket.h"
#include "exception.h"

namespace analyser {

    // Protocol type.
    enum protocol {
	NO_PROTOCOL,		// No protocol.  This is the default when no
	                        // address information has been assigned.
	                        // A kind of 'null'.
	IP4,			// IPv4.
	IP6,			// IPv6.
	TCP,			// TCP.
	UDP,			// UDP
	ICMP,			// ICMP.
	HTTP,                   // HTTP.
	DNS,

	// Unknown stuff
	UNRECOGNISED
    };
    
    // The purpose served by the address.
    enum purpose {
	ROOT,                   // Root context
	NOT_SPECIFIED,		// Not specified.
	LINK,			// Link layer address.
	NETWORK,		// Network layer address.
	TRANSPORT,		// Transport address.
	SERVICE,		// Service address.
	APPLICATION,		// Application-layer address.
	CONTROL			// Control address.
    };

    // Address class, represents all kinds of addresses.
    class address {
      public:

	// The protocol's purpose.
	purpose layer;
	
	// Protocol.
	protocol proto;		

	// Address.
	std::vector<unsigned char> addr;

	// Constructor.
	address() {
	    addr.resize(0);
	    proto = NO_PROTOCOL;
	    layer = NOT_SPECIFIED;
	}

	// Assign to the address.
	void assign(const std::vector<unsigned char>& a, purpose pu,
		    protocol pr) {
	    layer = pu; proto = pr;
	    addr.assign(a.begin(), a.end());
	}

	// Assign to the address.
	void assign(pdu_iter s, pdu_iter e, purpose pu, 
		    protocol pr) {
	    layer = pu; proto = pr;
	    addr.assign(s, e);
	}
	
	// Describe the address in human-readable on an output-stream.
	void describe(std::ostream& out) const;

	// Less-than operator.
	bool operator<(const address& a) const {
	    if (layer < a.layer)
		return true;
	    else
		if (layer == a.layer)
		    if (proto < a.proto)
			return true;
		    else
			if (proto == a.proto)
			    if (addr < a.addr)
				return true;
	    return false;
	}

	// Equality operator.
	bool operator==(const address& a) const {
	    return layer == a.layer &&
	    proto == a.proto &&
	    addr == a.addr;
	}

	// Get the 'value' of the address in different formats.
	uint16_t get_16b() {
	    if (addr.size() != 2)
		throw exception("Address is not 16-bit");
	    return (addr[0] << 8) + addr[1];
	}

	std::string to_ip4_string() const {

	    if (addr.size() != 4)
		throw exception("Address is not 4 bytes.");

	    if (proto != IP4)
		throw exception("Address is not IPv4 protocol.");

	    tcpip::ip4_address x;
	    std::string s;

	    x.addr.assign(addr.begin(), addr.end());
	    x.to_string(s);

	    return s;

	}

	std::string to_ip6_string() const {

	    if (addr.size() != 16)
		throw exception("Address is not 16 bytes.");

	    if (proto != IP6)
		throw exception("Address is not IPv6 protocol.");

	    tcpip::ip6_address x;
	    std::string s;

	    x.addr.assign(addr.begin(), addr.end());
	    x.to_string(s);

	    return s;

	}

    };

};

std::ostream& operator<<(std::ostream& o, const tcpip::address& addr);

#endif

