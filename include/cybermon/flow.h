
#ifndef CYBERMON_FLOW_H
#define CYBERMON_FLOW_H

#include <cybermon/address.h>

namespace cybermon {

    class flow_address {
      public:
	address src;
	address dest;

	flow_address() {}

	flow_address(const address& s, const address& d) {
	    src = s; dest = d;
	}

	bool operator<(const flow_address& a) const {
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

