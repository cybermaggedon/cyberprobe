
////////////////////////////////////////////////////////////////////////////
//
// SIP processing
//
////////////////////////////////////////////////////////////////////////////

#ifndef CYBERMON_SIP_H
#define CYBERMON_SIP_H

#include <cyberprobe/protocol/context.h>
#include <cyberprobe/protocol/manager.h>
#include <cyberprobe/protocol/pdu.h>


namespace cyberprobe {
namespace protocol {
    
    class sip
    {
    public:
        static void process(manager& mgr, context_ptr c, const pdu_slice& sl);
    };

}
}

#endif

