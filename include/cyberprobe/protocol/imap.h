
////////////////////////////////////////////////////////////////////////////
//
// IMAP processing
//
////////////////////////////////////////////////////////////////////////////

#ifndef CYBERMON_IMAP_H
#define CYBERMON_IMAP_H

#include <cyberprobe/protocol/context.h>
#include <cyberprobe/analyser/manager.h>
#include <cyberprobe/protocol/pdu.h>


namespace cyberprobe {
namespace protocol {

    class imap
    {
        using manager = cyberprobe::analyser::manager;
    public:
        // IMAP processing.
        static void process(manager& mgr, context_ptr c, const pdu_slice& s);
    };

}
}

#endif

