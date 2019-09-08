
////////////////////////////////////////////////////////////////////////////
//
// POP3 SSL processing
//
////////////////////////////////////////////////////////////////////////////

#ifndef CYBERMON_POP3_SSL_H
#define CYBERMON_POP3_SSL_H

#include <cyberprobe/protocol/context.h>
#include <cyberprobe/protocol/manager.h>
#include <cyberprobe/protocol/pdu.h>


namespace cyberprobe {
namespace protocol {
    
    class pop3_ssl
    {
    public:
        // POP3_SSL processing.
        static void process(manager& mgr, context_ptr c, const pdu_slice& sl);
    };

}
}

#endif

