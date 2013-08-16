
#ifndef ICMP_H
#define ICMP_H

#include "context.h"
#include "observer.h"

namespace analyser {
    
    // ICMP context.  No address information, just flagging the presence of
    // ICMP.
    class icmp_context : public context {
    public:
        icmp_context(manager& m) : context(m) {}
        icmp_context(manager& m, const flow& a, context_ptr p) : context(m) {
	    addr = a; parent = p; 
	}
	virtual std::string get_type() { return "udp"; }
    };
    
    class icmp {

    public:
	
	// ICMP processing function.
	static void process(manager& mgr, context_ptr c, pdu_iter s, 
			    pdu_iter e);

    };

};

#endif

