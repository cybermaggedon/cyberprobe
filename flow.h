
#ifndef FLOW_H
#define FLOW_H

#include "address.h"

namespace cybermon {

    class flow {
      public:
	address src;
	address dest;

	flow() {}

	flow(const tcpip::ip4_address& s, 
	     const tcpip::ip4_address& d) {
	    src.assign(s.addr, NETWORK, IP4);
	    dest.assign(d.addr, NETWORK, IP4);
	}

	flow(const address& s, const address& d) {
	    src = s; dest = d;
	}

	bool operator<(const flow& a) const {
	    if (src < a.src)
		return true;
	    else if (src == a.src)
		if (dest < a.dest)
		    return true;
	    return false;
	}
    };

};

#endif

