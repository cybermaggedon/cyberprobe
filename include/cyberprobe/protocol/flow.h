
#ifndef CYBERPROBE_PROTOCOL_FLOW_H
#define CYBERPROBE_PROTOCOL_FLOW_H

#include <cyberprobe/protocol/pdu.h>
#include <cyberprobe/protocol/address.h>

namespace cyberprobe {

namespace protocol {

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
// FIXME: ?!
//                else if (dest == a.dest)
//                    if (direc < a.direc)
//                        return true;
	    return false;
	}
    };

};

};

#endif

