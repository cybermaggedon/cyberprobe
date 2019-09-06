
#ifndef CYBERMON_PROTOCOL_H
#define CYBERMON_PROTOCOL_H

#include <cyberprobe/analyser/manager.h>
#include <cyberprobe/protocol/context.h>
#include <cyberprobe/protocol/pdu.h>

namespace cyberprobe {

    using manager = cyberprobe::analyser::manager;
    using context_ptr = cyberprobe::protocol::context_ptr;
    using pdu_slice = cyberprobe::protocol::pdu_slice;

    // FIXME: Is coupling to manager needed?
    typedef void (*process_fn)(manager&, context_ptr c, const pdu_slice& sl);

};

#endif

