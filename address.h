
#ifndef ADDRESS_H
#define ADDRESS_H

#include <vector>
#include <iostream>

#include "pdu.h"

namespace analyser {

    enum protocol {
	NO_PROTOCOL, IP4, IP6, TCP, UDP, ICMP
    };
    
    enum purpose {
	NOT_SPECIFIED, LINK, NETWORK, TRANSPORT, SERVICE, APPLICATION,
	CONTROL
    };

    class address {
      public:
	purpose layer;
	protocol proto;
	std::vector<unsigned char> addr;
	address() {
	    addr.resize(0);
	    proto = NO_PROTOCOL;
	    layer = NOT_SPECIFIED;
	}
	void assign(const std::vector<unsigned char>& a, purpose pu,
		    protocol pr) {
	    layer = pu; proto = pr;
	    addr.assign(a.begin(), a.end());
	}
	void assign(const pdu_iter& s, const pdu_iter& e, purpose pu, 
		    protocol pr) {
	    layer = pu; proto = pr;
	    addr.assign(s, e);
	}
	void describe(std::ostream& out);
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
	bool operator==(const address& a) const {
	    return layer == a.layer &&
	    proto == a.proto &&
	    addr == a.addr;
	}
    };

};

#endif

