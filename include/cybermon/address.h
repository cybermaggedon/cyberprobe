
////////////////////////////////////////////////////////////////////////////
//
// A class for representing a wide variety of addresses.
//
////////////////////////////////////////////////////////////////////////////

#ifndef CYBERMON_ADDRESS_H
#define CYBERMON_ADDRESS_H

#include <vector>
#include <iostream>

#include <cybermon/pdu.h>
#include <cybermon/socket.h>
#include <cybermon/exception.h>

namespace cybermon {

    // Protocol type.
    enum protocol {
        NO_PROTOCOL,            // No protocol.  This is the default when no
                                // address information has been assigned.
                                // A kind of 'null'.
        IP4,                    // IPv4.
        IP6,                    // IPv6.
        TCP,                    // TCP.
        UDP,                    // UDP.  'Address' is DNS id.
        ICMP,                   // ICMP.
        HTTP,                   // HTTP.
        DNS,
        SMTP,
        FTP,
        NTP,
        IMAP,
        IMAP_SSL,
        POP3,
        POP3_SSL,
        RTP,
        RTP_SSL,
        SIP,
        SIP_SSL,
        SMTP_AUTH,
        GRE,
        ESP,
        WLAN,
        TLS,

        // Unknown stuff
        UNRECOGNISED
    };
    
    // The purpose served by the address.
    enum purpose {
        ROOT,                   // Root context
        NOT_SPECIFIED,          // Not specified.
        LINK,                   // Link layer address.
        NETWORK,                // Network layer address.
        TRANSPORT,              // Transport address.
        SERVICE,                // Service address.
        APPLICATION,            // Application-layer address.
        CONTROL                 // Control address.
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
	void set(const std::vector<unsigned char>& a, purpose pu,
		 protocol pr) {
	    layer = pu; proto = pr;
	    addr.assign(a.begin(), a.end());
	}

	void get(std::vector<unsigned char>& a, purpose& pu, 
		 protocol& pr) const {
	    a = addr; pu = layer; pr = proto;
	}

	void get(std::string& type, std::string& address) const;

	pdu_iter begin() const { return addr.begin(); }
	pdu_iter end() const { return addr.begin(); }

	// Assign to the address.
	void set(pdu_iter s, pdu_iter e, purpose pu, protocol pr) {
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
		if (layer == a.layer) {
		    if (proto < a.proto)
			return true;
		    else
			if (proto == a.proto)
			    if (addr < a.addr)
                                return true;
		}
	    return false;
	}

	// Equality operator.
	bool operator==(const address& a) const {
	    return layer == a.layer &&
                proto == a.proto &&
                addr == a.addr;
	}

	// Get the 'value' of the address in different formats.
	uint16_t get_uint16() {
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

	void from_ip4_string(const std::string& a) {
	    tcpip::ip4_address x(a);
	    set(x.addr, NETWORK, IP4);
	}

	void from_ip6_string(const std::string& a) {
	    tcpip::ip6_address x(a);
	    set(x.addr, NETWORK, IP6);
	}

	void from_ip_string(const std::string& a) {

	    try {
		from_ip4_string(a);
		return;
	    } catch (...) {}

	    try {
		from_ip6_string(a);
		return;
	    } catch (...) {}

	    throw exception("Not an IP address");

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

	std::string to_ip_string() const {
	    std::string s;

	    try {
		return to_ip4_string();
	    } catch (...) {}

	    try {
		return to_ip6_string();
	    } catch (...) {}

	    throw exception("Not an IP address");

	}

    };

};

std::ostream& operator<<(std::ostream& o, const tcpip::address& addr);

#endif

