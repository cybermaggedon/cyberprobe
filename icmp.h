
#ifndef ICMP_H
#define ICMP_H

#include "context.h"
#include "analyser.h"

namespace analyser {
    
    class icmp_context : public transport_context {
      public:
	icmp_context() {}
        icmp_context(const flow& a, context_ptr p) { addr = a; parent = p; }
	virtual std::string get_type() { return "udp"; }
    };
    
    class icmp {

      public:
	static void process(engine& eng, context_ptr c, 
			    const pdu_iter& s, const pdu_iter& e);

    };

};

#endif

