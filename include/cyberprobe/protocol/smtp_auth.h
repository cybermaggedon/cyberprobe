
////////////////////////////////////////////////////////////////////////////
//
// SMTP Authentication processing
//
////////////////////////////////////////////////////////////////////////////

#ifndef CYBERMON_SMTP_AUTH_H
#define CYBERMON_SMTP_AUTH_H

#include <cyberprobe/protocol/context.h>
#include <cyberprobe/analyser/manager.h>
#include <cyberprobe/protocol/pdu.h>


namespace cyberprobe {
namespace protocol {
    
    class smtp_auth {
        using manager = cyberprobe::analyser::manager;
    public:
        // SMTP_AUTH processing.
        static void process(manager& mgr, context_ptr c, const pdu_slice& sl);
    };

}
}

#endif

