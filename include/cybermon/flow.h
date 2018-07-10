
#ifndef CYBERMON_FLOW_H
#define CYBERMON_FLOW_H

#include <cybermon/address.h>

namespace cybermon {

    class flow_address {
      public:
	address src;
	address dest;
        direction direc;

	flow_address() {}

	flow_address(const address& s, const address& d, direction dir) {
	    src = s; dest = d;
            direc = dir;
	}

	bool operator<(const flow_address& a) const {
	    if (src < a.src)
		return true;
	    else if (src == a.src)
                if (dest < a.dest)
		    return true;
//                else if (dest == a.dest)
//                    if (direc < a.direc)
//                        return true;
	    return false;
	}
    };

};

#endif

