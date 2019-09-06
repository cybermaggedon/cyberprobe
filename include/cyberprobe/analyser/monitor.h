
#ifndef CYBERPROBE_ANALYSER_MONITOR_H
#define CYBERPROBE_ANALYSER_MONITOR_H

#include <string>
#include <vector>

#include <cyberprobe/protocol/pdu.h>
#include <cyberprobe/network/socket.h>

namespace cyberprobe {

namespace analyser {

    // Monitor function, handles packets.
    class monitor {
    public:
        virtual ~monitor() {}
        
        // IP packet.
        virtual void operator()(const std::string& device,
                                const std::string& network,
                                cyberprobe::protocol::pdu_slice) = 0;
        
        // Gets called if initiator's connection is seen.
        virtual void target_up(const std::string& device,
                               const std::string& network,
                               const tcpip::address& addr,
                               const struct timeval& tv) = 0;
        
        // Gets called if initiator's disconnection is seen.
        virtual void target_down(const std::string& device,
                                 const std::string& network,
                                 const struct timeval& tv) = 0;

    };

};

};

#endif

