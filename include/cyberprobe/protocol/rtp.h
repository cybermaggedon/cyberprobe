
////////////////////////////////////////////////////////////////////////////
//
// RTP processing
//
////////////////////////////////////////////////////////////////////////////

#ifndef CYBERMON_RTP_H
#define CYBERMON_RTP_H

#include <cyberprobe/protocol/context.h>
#include <cyberprobe/protocol/manager.h>
#include <cyberprobe/protocol/pdu.h>


namespace cyberprobe {
namespace protocol {
    
    class rtp
    {
    public:
        static void process(manager& mgr, context_ptr c, const pdu_slice& sl);
    };

}
}

#endif

