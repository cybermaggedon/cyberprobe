
////////////////////////////////////////////////////////////////////////////
//
// POP3 SSL Context
//
////////////////////////////////////////////////////////////////////////////

#ifndef CYBERMON_POP3_SSL_CONTEXT_H
#define CYBERMON_POP3_SSL_CONTEXT_H

#include <cybermon/context.h>
#include <cybermon/manager.h>


namespace cybermon
{
class pop3_ssl_context : public context
{
    public:

    // Construcotr.
    pop3_ssl_context(manager& m) : context(m) {}

    // Constructor, when specifying flow address and parent context.
    pop3_ssl_context(manager& m, const flow_address& a, context_ptr p)
        : context(m)
    { 
        addr = a;
        parent = p; 
    }

    // Type is "pop3_ssl".
    virtual std::string get_type()
    {
        return "pop3_ssl";
    }

    typedef boost::shared_ptr<pop3_ssl_context> ptr;

    static context_ptr create(manager& m, const flow_address& f, context_ptr par)
    { 
        context_ptr cp = context_ptr(new pop3_ssl_context(m, f, par));
        return cp;
    }

    // Given a flow address, returns the child context.
    static ptr get_or_create(context_ptr base, const flow_address& f)
    {
        context_ptr cp = context::get_or_create(base, f, pop3_ssl_context::create);
        ptr sp = boost::dynamic_pointer_cast<pop3_ssl_context>(cp);
        return sp;
    }
};

}; // End namespace

#endif

