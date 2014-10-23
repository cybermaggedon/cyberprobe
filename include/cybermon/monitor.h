
#ifndef CYBERMON_PACKET_H
#define CYBERMON_PACKET_H

#include <string>
#include <vector>

#include "socket.h"

// Monitor function, handles packets.
class monitor {
  public:

    // IP packet.
    virtual void operator()(const std::string& liid,
			    const std::vector<unsigned char>::iterator&,
			    const std::vector<unsigned char>::iterator&) = 0;

    // Gets called if initiator's connection is seen.
    virtual void target_up(const std::string& liid,
			   const tcpip::address& addr) = 0;

    // Gets called if initiator's disconnection is seen.
    virtual void target_down(const std::string& liid) = 0;

};

#endif

