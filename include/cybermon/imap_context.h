
////////////////////////////////////////////////////////////////////////////
//
// IMAP Context
//
////////////////////////////////////////////////////////////////////////////

#ifndef CYBERMON_IMAP_CONTEXT_H
#define CYBERMON_IMAP_CONTEXT_H

#include <cybermon/context.h>
#include <cybermon/manager.h>


namespace cybermon
{
    
    class imap_context : public context
    {
    public:

        // Constructor.
        imap_context(manager& m) : context(m) {}

        // Constructor, when specifying flow address and parent context.
        imap_context(manager& m, const flow_address& a, context_ptr p)
            : context(m)
            { 
                addr = a;
                parent = p; 
            }

        // Type is "imap".
        virtual std::string get_type()
            {
                return "imap";
            }

        typedef std::shared_ptr<imap_context> ptr;

        static context_ptr create(manager& m, const flow_address& f, context_ptr par)
            { 
                context_ptr cp = context_ptr(new imap_context(m, f, par));
                return cp;
            }

        // Given a flow address, returns the child context.
        static ptr get_or_create(context_ptr base, const flow_address& f)
            {
                context_ptr cp = context::get_or_create(base, f, imap_context::create);
                ptr sp = std::dynamic_pointer_cast<imap_context>(cp);
                return sp;
            }
    };

}; // End namespace

#endif

