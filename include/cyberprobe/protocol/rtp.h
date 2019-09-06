
////////////////////////////////////////////////////////////////////////////
//
// RTP processing
//
////////////////////////////////////////////////////////////////////////////

#ifndef CYBERMON_RTP_H
#define CYBERMON_RTP_H

#include <cyberprobe/protocol/context.h>
#include <cyberprobe/analyser/manager.h>
#include <cyberprobe/protocol/pdu.h>


namespace cyberprobe {
namespace protocol {
    
    class rtp
    {
        using manager = cyberprobe::analyser::manager;
    public:
        static void process(manager& mgr, context_ptr c, const pdu_slice& sl);
    };

}
}

#endif

