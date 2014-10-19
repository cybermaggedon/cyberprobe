
////////////////////////////////////////////////////////////////////////////
//
// UDP processing
//
////////////////////////////////////////////////////////////////////////////

#ifndef UDP_H
#define UDP_H

#include "context.h"
#include "manager.h"

namespace cybermon {
    
    // A UDP context.
    class udp_context : public context {
      public:
	
	// Construcotr.
        udp_context(manager& m) : context(m) {}

	// Constructor, when specifying flow address and parent context.
        udp_context(manager& m, const flow_address& a, context_ptr p) : 
	context(m) { 
	    addr = a; parent = p; 
	}

	// Type is "udp".
	virtual std::string get_type() { return "udp"; }

	typedef boost::shared_ptr<udp_context> ptr;

	static context_ptr create(manager& m, const flow_address& f, 
				  context_ptr par) {
	    context_ptr cp = context_ptr(new udp_context(m, f, par));
	    return cp;
	}

	// Given a flow address, returns the child context.
	static ptr get_or_create(context_ptr base, const flow_address& f) {
	    context_ptr cp = context::get_or_create(base, f, 
						    udp_context::create);
	    ptr sp = boost::dynamic_pointer_cast<udp_context>(cp);
	    return sp;
	}

    };
    
    class udp {

      public:
	
	// UDP processing.
	static void process(manager& mgr, context_ptr c, pdu_iter s, 
			    pdu_iter e);

    };

};

#endif

