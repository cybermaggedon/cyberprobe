
#ifndef CYBERMON_PROTOCOL_H
#define CYBERMON_PROTOCOL_H

#include <cyberprobe/protocol/manager.h>
#include <cyberprobe/protocol/context.h>
#include <cyberprobe/protocol/pdu.h>

namespace cyberprobe {

namespace protocol {

    typedef void (*process_fn)(manager&, context_ptr c, const pdu_slice& sl);

}

}

#endif

