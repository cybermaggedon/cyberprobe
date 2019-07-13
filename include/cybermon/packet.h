
#ifndef CYBERMON_PACKET_H
#define CYBERMON_PACKET_H

#include <string>
#include <vector>

#include "socket.h"

// Virtual packet handling interface
class packet_processor {
public:

    // IP packet.
    virtual void operator()(const std::string& device,
			    const std::vector<unsigned char>::iterator&,
			    const std::vector<unsigned char>::iterator&) = 0;

    // Gets called if target IP address is known.
    virtual void target_up(const std::string& decvice,
			   const tcpip::address& addr) = 0;

    virtual void target_down(const std::string& device) = 0;

};

#endif

