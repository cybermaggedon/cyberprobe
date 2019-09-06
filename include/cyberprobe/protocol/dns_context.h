
////////////////////////////////////////////////////////////////////////////
//
// DNS Context
//
////////////////////////////////////////////////////////////////////////////

#ifndef CYBERMON_DNS_CONTEXT_H
#define CYBERMON_DNS_CONTEXT_H

#include <stdint.h>

#include <set>

#include <cyberprobe/protocol/context.h>
#include <cyberprobe/analyser/manager.h>
#include <cyberprobe/util/serial.h>
#include <cyberprobe/analyser/protocol.h>
#include <cyberprobe/protocol/dns_protocol.h>

namespace cyberprobe {

namespace protocol {

    // A DNS context.
    class dns_context : public context
    {
    public:
    
        // Constructor.
        dns_context(manager& m) : context(m) {}

        // Constructor, describing flow address and parent pointer.
        dns_context(manager& m, const flow_address& a, context_ptr p)
            :  context(m)
            {
                addr = a;
                parent = p; 
            }

        // Type is "dns".
        virtual std::string get_type() { return "dns"; }

        typedef std::shared_ptr<dns_context> ptr;

        static context_ptr create(manager& m, const flow_address& f, 
                                  context_ptr par) {
            context_ptr cp = context_ptr(new dns_context(m, f, par));
            return cp;
        }

        // Given a flow address, returns the child context.
        static ptr get_or_create(context_ptr base, const flow_address& f)
            {
                context_ptr cp = context::get_or_create(base, f, dns_context::create);

                ptr sp = std::dynamic_pointer_cast<dns_context>(cp);
                return sp;
            }

    };

} // End namespace

}

#endif

