
#ifndef UDP_H
#define UDP_H

#include "context.h"
#include "analyser.h"

namespace analyser {
    
    class udp_context : public transport_context {
      public:
	udp_context() {}
        udp_context(const flow& a, context_ptr p) { addr = a; parent = p; }
	virtual std::string get_type() { return "udp"; }
    };
    
    class udp {

      public:
	static void process(engine& eng, context_ptr c, 
			    const pdu_iter& s, const pdu_iter& e);

    };

};

#endif

