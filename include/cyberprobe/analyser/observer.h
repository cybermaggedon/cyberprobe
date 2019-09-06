
#ifndef CYBERMON_OBSERVER_H
#define CYBERMON_OBSERVER_H

#include <cyberprobe/protocol/context.h>
#include <cyberprobe/protocol/dns_protocol.h>
#include <cyberprobe/protocol/ntp_protocol.h>
#include <cyberprobe/protocol/tls_handshake_protocol.h>
#include <cyberprobe/event/event.h>

#include <vector>
#include <memory>

namespace cyberprobe {

    // Observer interface.  The observer interface is called when various
    // reportable events occur.
    class observer {
    public:

	virtual void handle(std::shared_ptr<event::event>) = 0;
	
    };

};

#endif
