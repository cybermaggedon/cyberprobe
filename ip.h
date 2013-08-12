
#ifndef IP_H
#define IP_H

#include "context.h"
#include "analyser.h"

namespace analyser {
    
    class ip4_context : public network_context {
      public:
	ip4_context() {}
        ip4_context(const flow& a, context_ptr par) { 
	    parent = par;
	    addr = a; 
	}
	virtual std::string get_type() { return "ip4"; }
    };
    
    class ip {

      public:
	
	// IP header cksum
	static unsigned short calculate_cksum(const pdu_iter& s, 
					      const pdu_iter& e);

	static void process(engine&, context_ptr c, 
			    const pdu_iter& s, const pdu_iter& e);
	static void process_ip4(engine&, context_ptr c, const pdu_iter& s, 
				const pdu_iter& e);
	static void process_ip6(engine&, context_ptr c, const pdu_iter& s, 
				const pdu_iter& e);

    };

};

#endif

