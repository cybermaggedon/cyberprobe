
////////////////////////////////////////////////////////////////////////////
//
// IMAP SSL processing
//
////////////////////////////////////////////////////////////////////////////

#ifndef CYBERMON_IMAP_SSL_H
#define CYBERMON_IMAP_SSL_H

#include <cyberprobe/protocol/context.h>
#include <cyberprobe/protocol/manager.h>
#include <cyberprobe/protocol/pdu.h>


namespace cyberprobe {
namespace protocol {
    
    class imap_ssl
    {
    public:

        // IMAP_SSL processing.
        static void process(manager& mgr, context_ptr c, const pdu_slice& s);
    };

}
}

#endif

