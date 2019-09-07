
////////////////////////////////////////////////////////////////////////////
//
// RTP SSL processing
//
////////////////////////////////////////////////////////////////////////////

#ifndef CYBERMON_RTP_SSL_H
#define CYBERMON_RTP_SSL_H

#include <cyberprobe/protocol/context.h>
#include <cyberprobe/protocol/manager.h>
#include <cyberprobe/protocol/pdu.h>


namespace cyberprobe {
namespace protocol {
    
    class rtp_ssl
    {
    public:
        static void process(manager& mgr, context_ptr c, const pdu_slice& sl);
    };

}
}

#endif

