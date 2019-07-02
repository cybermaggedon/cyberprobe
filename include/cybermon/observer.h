
#ifndef CYBERMON_OBSERVER_H
#define CYBERMON_OBSERVER_H

#include <cybermon/context.h>
#include <cybermon/dns_protocol.h>
#include <cybermon/ntp_protocol.h>
#include <cybermon/tls_handshake_protocol.h>
#include <cybermon/event.h>

#include <vector>
#include <memory>

namespace cybermon {

    // Observer interface.  The observer interface is called when various
    // reportable events occur.
    class observer {
    public:

	virtual void handle(std::shared_ptr<event::event>) = 0;
	
    };

};

#endif
