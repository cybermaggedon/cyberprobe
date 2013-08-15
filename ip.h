
#ifndef IP_H
#define IP_H

#include "context.h"
#include "analyser.h"

#include <deque>

namespace analyser {
    
    class ip;

    // An IP identifier.
    typedef uint32_t ip4_id;

    // A fragment hole.
    class fragment_hole {
    public:

	// Start of hole.
	unsigned long first;

	// End of hole.
	unsigned long last;

    };

    // A fragment.
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

    // List of fragment pointers.
    typedef std::list<fragment*> fragment_list;

    // IPv4 context
    class ip4_context : public context {

	friend ip;

	// IP frag re-assembly hole list.
	std::map<ip4_id, hole_list> h_list;

	// IP fragment index.  These are pointers into fragments which are
	// owned by the 'frags' variable.
	std::map<ip4_id, std::list<fragment*> > f_list;

	// IP headers for frags.
	std::map<ip4_id, pdu> hdrs_list;

	// Queue of fragments.
	static const int max_frag_list_len = 50;
	std::deque<fragment> frags;

      public:

	// Constructor.
        ip4_context(watcher& w) : context(w) {}

	// Constructor, specifying flow address and parent.
        ip4_context(watcher& w, const flow& a, context_ptr par) : context(w) { 
	    parent = par;
	    addr = a; 
	}

	// Type is "ip4".
	virtual std::string get_type() { return "ip4"; }

    };

    // Processing
    class ip {

      public:
	
	// Calculate IP header cksum
	static uint16_t calculate_cksum(pdu_iter s, 
					pdu_iter e);

	// Process an IP packet.  Works out the version, and calls appropriate
	// function.
	static void process(engine&, context_ptr c, 
			    pdu_iter s, pdu_iter e);

	// IPv4 processing.
	static void process_ip4(engine&, context_ptr c, pdu_iter s, 
				pdu_iter e);

	// IPv6 processing.
	static void process_ip6(engine&, context_ptr c, pdu_iter s, 
				pdu_iter e);

    };

};

#endif

