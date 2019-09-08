
////////////////////////////////////////////////////////////////////////////
//
// RTP Context
//
////////////////////////////////////////////////////////////////////////////

#ifndef CYBERMON_RTP_CONTEXT_H
#define CYBERMON_RTP_CONTEXT_H

#include <cyberprobe/protocol/context.h>
#include <cyberprobe/protocol/manager.h>


namespace cyberprobe {
namespace protocol {
    
    class rtp_context : public context
    {
    public:

        // Constructor.
        rtp_context(manager& m) : context(m) {}

        // Constructor, when specifying flow address and parent context.
        rtp_context(manager& m, const flow_address& a, context_ptr p)
            : context(m)
            { 
                addr = a;
                parent = p; 
            }

        // Type is "rtp".
        virtual std::string get_type()
            {
                return "rtp";
            }

        typedef std::shared_ptr<rtp_context> ptr;

        static context_ptr create(manager& m, const flow_address& f, context_ptr par)
            { 
                context_ptr cp = context_ptr(new rtp_context(m, f, par));
                return cp;
            }

        // Given a flow address, returns the child context.
        static ptr get_or_create(context_ptr base, const flow_address& f)
            {
                context_ptr cp = context::get_or_create(base, f, rtp_context::create);
                ptr sp = std::dynamic_pointer_cast<rtp_context>(cp);
                return sp;
            }
    };

}
}

#endif

