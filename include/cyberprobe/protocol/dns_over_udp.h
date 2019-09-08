
////////////////////////////////////////////////////////////////////////////
//
// DNS over UDP processing
//
////////////////////////////////////////////////////////////////////////////

#ifndef CYBERMON_DNS_OVER_UDP_H
#define CYBERMON_DNS_OVER_UDP_H

#include <cyberprobe/protocol/context.h>
#include <cyberprobe/protocol/manager.h>
#include <cyberprobe/protocol/pdu.h>

namespace cyberprobe {

namespace protocol {

    class dns_over_udp
    {
    public:


        // DNS over UDP processing function.
        static void process(manager&, context_ptr c, const pdu_slice& s);
    };

}
}

#endif

