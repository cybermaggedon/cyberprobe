
////////////////////////////////////////////////////////////////////////////
//
// SMTP_AUTH processing
//
////////////////////////////////////////////////////////////////////////////

#ifndef CYBERMON_SMTP_AUTH_H
#define CYBERMON_SMTP_AUTH_H

#include <cybermon/context.h>
#include <cybermon/manager.h>

namespace cybermon
{
    
// An SMTP_AUTH context.
class smtp_auth_context : public context
{
  public:

    // Constructor.
    smtp_auth_context(manager& m) : context(m) {}

    // Constructor, when specifying flow address and parent context.
    smtp_auth_context(manager& m, const flow_address& a, context_ptr p)
        : context(m)
    { 
        addr = a;
        parent = p; 
    }

    // Type is "smtp_auth".
    virtual std::string get_type()
    {
        return "smtp_auth";
    }

    typedef boost::shared_ptr<smtp_auth_context> ptr;

    static context_ptr create(manager& m, const flow_address& f, context_ptr par)
    { 
        context_ptr cp = context_ptr(new smtp_auth_context(m, f, par));
        return cp;
    }

    // Given a flow address, returns the child context.
    static ptr get_or_create(context_ptr base, const flow_address& f)
    {
        context_ptr cp = context::get_or_create(base, f, smtp_auth_context::create);
        ptr sp = boost::dynamic_pointer_cast<smtp_auth_context>(cp);
        return sp;
    }
};

    
class smtp_auth
{
  public:

    // SMTP_AUTH processing.
    static void process(manager& mgr, context_ptr c, pdu_iter s, pdu_iter e);
};

}; // End namespace

#endif

