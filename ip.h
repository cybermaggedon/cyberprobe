
#ifndef IP_H
#define IP_H

#include "context.h"
#include "analyser.h"

#include <deque>

namespace analyser {
    
    class ip;

    // An IP identifier.
    typedef uint32_t ip4_id;

    class fragment_hole {
    public:

	// Start of hole.
	unsigned long first;

	// End of hole.
	unsigned long last;

    };

    class fragment {
	
    public:

	// Start of frag
	unsigned long first;

	// End of frag
	unsigned long last;

	// Identification
	ip4_id id;

	// Frag itself
	std::vector<unsigned char> frag;
	
    };

    // List of fragment holes.
    typedef std::list<fragment_hole> hole_list;
    typedef std::list<fragment*> fragment_list;

    class ip4_context : public network_context {

	friend ip;

	// IP frag re-assembly hole list.
	std::map<ip4_id, hole_list> h_list;

	// IP frag index
	std::map<ip4_id, std::list<fragment*> > f_list;

	// IP headers for frags.
	std::map<ip4_id, pdu> hdrs_list;

	// Queue of fragments.
	static const int max_frag_list_len = 50;
	std::deque<fragment> frags;

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

