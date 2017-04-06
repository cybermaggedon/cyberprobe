
////////////////////////////////////////////////////////////////////////////
//
// SIP Context
//
////////////////////////////////////////////////////////////////////////////

#ifndef CYBERMON_SIP_CONTEXT_H
#define CYBERMON_SIP_CONTEXT_H

#include <cybermon/context.h>
#include <cybermon/manager.h>


namespace cybermon
{
    
class sip_context : public context
{
  public:

    // Constructor.
    sip_context(manager& m) : context(m) {}

    // Constructor, when specifying flow address and parent context.
    sip_context(manager& m, const flow_address& a, context_ptr p)
        : context(m)
    { 
        addr = a;
        parent = p; 
    }

    // Type is "sip".
    virtual std::string get_type()
    {
        return "sip";
    }

    typedef boost::shared_ptr<sip_context> ptr;

    static context_ptr create(manager& m, const flow_address& f, context_ptr par)
    { 
        context_ptr cp = context_ptr(new sip_context(m, f, par));
        return cp;
    }

    // Given a flow address, returns the child context.
    static ptr get_or_create(context_ptr base, const flow_address& f)
    {
        context_ptr cp = context::get_or_create(base, f, sip_context::create);
        ptr sp = boost::dynamic_pointer_cast<sip_context>(cp);
        return sp;
    }
};

}; // End namespace

#endif

