
////////////////////////////////////////////////////////////////////////////
//
// UDP processing
//
////////////////////////////////////////////////////////////////////////////

#ifndef UDP_H
#define UDP_H

#include "context.h"
#include "analyser.h"

namespace analyser {
    
    // A UDP context.
    class udp_context : public context {
      public:
	
	// Construcotr.
        udp_context(watcher& w) : context(w) {}

	// Constructor, when specifying flow address and parent context.
        udp_context(watcher& w, const flow& a, context_ptr p) : context(w) { 
	    addr = a; parent = p; 
	}

	// Type is "udp".
	virtual std::string get_type() { return "udp"; }
    };
    
    class udp {

      public:
	
	// UDP processing.
	static void process(engine& eng, context_ptr c, pdu_iter s, pdu_iter e);

    };

};

#endif

