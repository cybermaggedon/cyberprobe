
////////////////////////////////////////////////////////////////////////////
//
// TCP processing
//
////////////////////////////////////////////////////////////////////////////

#ifndef TCP_H
#define TCP_H

#include "context.h"
#include "analyser.h"

namespace analyser {
    
    // A TCP context.
    class tcp_context : public transport_context {
      public:
	
	// Constructor.
	tcp_context() {}

	// Constructor, describing flow address and parent pointer.
        tcp_context(const flow& a, context_ptr p) { addr = a; parent = p; }

	// Type is "tcp".
	virtual std::string get_type() { return "tcp"; }
    };
    
    class tcp {

      public:

	// TCP processing function.
	static void process(engine&,context_ptr c, 
			    const pdu_iter& s, const pdu_iter& e);

    };

};

#endif

