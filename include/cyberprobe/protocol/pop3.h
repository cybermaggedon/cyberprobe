
////////////////////////////////////////////////////////////////////////////
//
// POP3 processing
//
////////////////////////////////////////////////////////////////////////////

#ifndef CYBERMON_POP3_H
#define CYBERMON_POP3_H

#include <cyberprobe/protocol/context.h>
#include <cyberprobe/protocol/manager.h>
#include <cyberprobe/protocol/pdu.h>


namespace cyberprobe {
namespace protocol {
    
    class pop3
    {
    public:
        // POP3 processing.
        static void process(manager& mgr, context_ptr c, const pdu_slice& sl);
    };

}

}

#endif

