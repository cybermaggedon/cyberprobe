
////////////////////////////////////////////////////////////////////////////
//
// SIP SSL processing
//
////////////////////////////////////////////////////////////////////////////

#ifndef CYBERMON_SIP_SSL_H
#define CYBERMON_SIP_SSL_H

#include <cyberprobe/protocol/context.h>
#include <cyberprobe/analyser/manager.h>
#include <cyberprobe/protocol/pdu.h>


namespace cyberprobe {
namespace protocol {
    
    class sip_ssl {
        using manager = cyberprobe::analyser::manager;
    public:
        static void process(manager& mgr, context_ptr c, const pdu_slice& sl);
    };

}
}

#endif

