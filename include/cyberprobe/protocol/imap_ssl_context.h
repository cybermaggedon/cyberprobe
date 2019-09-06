
////////////////////////////////////////////////////////////////////////////
//
// IMAP SSL Context
//
////////////////////////////////////////////////////////////////////////////

#ifndef CYBERMON_IMAP_SSL_CONTEXT_H
#define CYBERMON_IMAP_SSL_CONTEXT_H

#include <cyberprobe/protocol/context.h>
#include <cyberprobe/analyser/manager.h>


namespace cyberprobe {
namespace protocol {
    
    class imap_ssl_context : public context
    {
    public:

        // Constructor.
        imap_ssl_context(manager& m) : context(m) {}

        // Constructor, when specifying flow address and parent context.
        imap_ssl_context(manager& m, const flow_address& a, context_ptr p)
            : context(m)
            { 
                addr = a;
                parent = p; 
            }

        // Type is "imap_ssl".
        virtual std::string get_type()
            {
                return "imap_ssl";
            }

        typedef std::shared_ptr<imap_ssl_context> ptr;

        static context_ptr create(manager& m, const flow_address& f, context_ptr par)
            { 
                context_ptr cp = context_ptr(new imap_ssl_context(m, f, par));
                return cp;
            }

        // Given a flow address, returns the child context.
        static ptr get_or_create(context_ptr base, const flow_address& f)
            {
                context_ptr cp = context::get_or_create(base, f, imap_ssl_context::create);
                ptr sp = std::dynamic_pointer_cast<imap_ssl_context>(cp);
                return sp;
            }
    };

}
}

#endif

