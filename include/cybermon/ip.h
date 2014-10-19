
#ifndef IP_H
#define IP_H

#include <stdint.h>

#include "context.h"
#include "manager.h"

#include <deque>

namespace cybermon {
    
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

	friend class ip;

	// IP frag re-assembly hole list.
	std::map<ip4_id, hole_list> h_list;

	// IP fragment index.  These are pointers into fragments which are
	// owned by the 'frags' variable.
	std::map<ip4_id, std::list<fragment*> > f_list;

	// IP headers for frags.
	std::map<ip4_id, pdu> hdrs_list;

	// Queue of fragments.
	static const unsigned int max_frag_list_len;
	std::deque<fragment> frags;

      public:

	// Constructor.
        ip4_context(manager& m) : context(m) {}

	// Constructor, specifying flow address and parent.
        ip4_context(manager& m, const flow_address& a, context_ptr par) : 
	context(m) { 
	    parent = par;
	    addr = a; 
	}

	// Type is "ip4".
	virtual std::string get_type() { return "ip4"; }

	typedef boost::shared_ptr<ip4_context> ptr;

	static context_ptr create(manager& m, const flow_address& f, 
				  context_ptr par) {
	    context_ptr cp = context_ptr(new ip4_context(m, f, par));
	    return cp;
	}

	// Given a flow address, returns the child context.
	static ptr get_or_create(context_ptr base, const flow_address& f) {
	    context_ptr cp = context::get_or_create(base, f, 
						    ip4_context::create);
	    ptr sp = boost::dynamic_pointer_cast<ip4_context>(cp);
	    return sp;
	}

    };

    // Processing
    class ip {

      public:
	
	// Calculate IP header cksum
	static uint16_t calculate_cksum(pdu_iter s, 
					pdu_iter e);

	// Process an IP packet.  Works out the version, and calls appropriate
	// function.
	static void process(manager&, context_ptr c, pdu_iter s, pdu_iter e);

	// IPv4 processing.
	static void process_ip4(manager&, context_ptr c, pdu_iter s, 
				pdu_iter e);

	// IPv6 processing.
	static void process_ip6(manager&, context_ptr c, pdu_iter s, 
				pdu_iter e);

    };

};

#endif

