
////////////////////////////////////////////////////////////////////////////
//
// POP3 processing
//
////////////////////////////////////////////////////////////////////////////

#ifndef CYBERMON_POP3_H
#define CYBERMON_POP3_H

#include <cybermon/context.h>
#include <cybermon/manager.h>

namespace cybermon
{
    
// A POP3 context.
class pop3_context : public context
{
  public:

    // Construcotr.
    pop3_context(manager& m) : context(m) {}

    // Constructor, when specifying flow address and parent context.
    pop3_context(manager& m, const flow_address& a, context_ptr p)
        : context(m)
    { 
        addr = a;
        parent = p; 
    }

    // Type is "pop3".
    virtual std::string get_type()
    {
        return "pop3";
    }

    typedef boost::shared_ptr<pop3_context> ptr;

    static context_ptr create(manager& m, const flow_address& f, context_ptr par)
    { 
        context_ptr cp = context_ptr(new pop3_context(m, f, par));
        return cp;
    }

    // Given a flow address, returns the child context.
    static ptr get_or_create(context_ptr base, const flow_address& f)
    {
        context_ptr cp = context::get_or_create(base, f, pop3_context::create);
        ptr sp = boost::dynamic_pointer_cast<pop3_context>(cp);
        return sp;
    }
};

    
class pop3
{
  public:

    // POP3 processing.
    static void process(manager& mgr, context_ptr c, pdu_iter s, pdu_iter e);
};

}; // End namespace

#endif

