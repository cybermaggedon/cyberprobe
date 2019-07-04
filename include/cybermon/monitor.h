
#ifndef CYBERMON_PACKET_H
#define CYBERMON_PACKET_H

#include <string>
#include <vector>

#include <cybermon/pdu.h>
#include "socket.h"

namespace cybermon {

    // Monitor function, handles packets.
    class monitor {
    public:
        virtual ~monitor() {}
        
        // IP packet.
        virtual void operator()(const std::string& liid,
                                const std::string& network,
                                std::vector<unsigned char>::const_iterator,
                                std::vector<unsigned char>::const_iterator,
                                const struct timeval& tv,
                                cybermon::direction dir) = 0;
        
        // Gets called if initiator's connection is seen.
        virtual void target_up(const std::string& liid,
                               const std::string& network,
                               const tcpip::address& addr,
                               const struct timeval& tv) = 0;
        
        // Gets called if initiator's disconnection is seen.
        virtual void target_down(const std::string& liid,
                                 const std::string& network,
                                 const struct timeval& tv) = 0;

    };

};

#endif

