
#ifndef ICMP_H
#define ICMP_H

#include "context.h"
#include "observer.h"

namespace cybermon {
    
    // ICMP context.  No address information, just flagging the presence of
    // ICMP.
    class icmp_context : public context {
    public:
        icmp_context(manager& m) : context(m) {}
        icmp_context(manager& m, const flow& a, context_ptr p) : context(m) {
	    addr = a; parent = p; 
	}
	virtual std::string get_type() { return "udp"; }
 
	typedef boost::shared_ptr<icmp_context> ptr;

	static context_ptr create(manager& m, const flow& f, context_ptr par) {
	    context_ptr cp = context_ptr(new icmp_context(m, f, par));
	    return cp;
	}

	// Given a flow address, returns the child context.
	static ptr get_or_create(context_ptr base, const flow& f) {
	    context_ptr cp = context::get_or_create(base, f, 
						    icmp_context::create);
	    ptr sp = boost::dynamic_pointer_cast<icmp_context>(cp);
	    return sp;
	}

   };
    
    class icmp {

    public:
	
	// ICMP processing function.
	static void process(manager& mgr, context_ptr c, pdu_iter s, 
			    pdu_iter e);

    };

};

#endif

