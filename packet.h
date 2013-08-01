
#ifndef PACKET_H
#define PACKET_H

#include <string>
#include <vector>

#include "socket.h"

// Virtual packet handling interface
class packet_processor {
  public:

    // IP packet.
    virtual void operator()(const std::string& liid,
			    const std::vector<unsigned char>::iterator&,
			    const std::vector<unsigned char>::iterator&) = 0;

    // Gets called if target IP address is known.
    virtual void discovered(const std::string& liid,
			    const tcpip::address& addr) = 0;

};

#endif

