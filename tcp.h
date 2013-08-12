
#ifndef TCP_H
#define TCP_H

#include "context.h"
#include "analyser.h"

namespace analyser {
    
    class tcp_context : public transport_context {
      public:
	tcp_context() {}
        tcp_context(const flow& a, context_ptr p) { addr = a; parent = p; }
	virtual std::string get_type() { return "tcp"; }
    };
    
    class tcp {

      public:
	static void process(engine&,context_ptr c, 
			    const pdu_iter& s, const pdu_iter& e);

    };

};

#endif

