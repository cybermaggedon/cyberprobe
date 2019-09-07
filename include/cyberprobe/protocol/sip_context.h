
////////////////////////////////////////////////////////////////////////////
//
// SIP Context
//
////////////////////////////////////////////////////////////////////////////

#ifndef CYBERMON_SIP_CONTEXT_H
#define CYBERMON_SIP_CONTEXT_H

#include <cyberprobe/protocol/context.h>
#include <cyberprobe/protocol/manager.h>

#include <memory>


namespace cyberprobe {
namespace protocol {
    
    class sip_context : public context
    {
    public:

        // Constructor.
        sip_context(manager& m);

        // Constructor, when specifying flow address and parent context.
        sip_context(manager& m, const flow_address& a, context_ptr p);

        virtual std::string get_type();

        typedef std::shared_ptr<sip_context> ptr;

        static context_ptr create(manager& m, const flow_address& f, context_ptr par);

        // Given a flow address, returns the child context.
        static ptr get_or_create(context_ptr base, const flow_address& f);

        void parse(std::string);

        std::string method;
        std::string from;
        std::string to;
        uint16_t audio_port;
        uint16_t video_port;
    };

}
}

#endif

