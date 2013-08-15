
////////////////////////////////////////////////////////////////////////////
//
// TCP processing
//
////////////////////////////////////////////////////////////////////////////

#ifndef TCP_H
#define TCP_H

#include <set>

#include "context.h"
#include "analyser.h"
#include "serial.h"

namespace analyser {

    class tcp_segment {
    public:
	std::vector<unsigned char> segment;
	uint32_t first;
	uint32_t last;
	bool operator<(const tcp_segment& s) const {
	    return first < s.first;
	}
    };
    
    // A TCP context.
    class tcp_context : public context {
      public:

	bool syn_observed;

//	uint32_t seq_expected;
//	uint32_t seq_observed;

	serial<int32_t, uint32_t> seq_expected;

	static const int max_segments = 100;
	std::set<tcp_segment> segments;
	
	// Constructor.
        tcp_context(watcher& w) : context(w) {
	    syn_observed = false;
	}

	// Constructor, describing flow address and parent pointer.
    tcp_context(watcher& w, const flow& a, context_ptr p) : context(w) { 
	    addr = a; parent = p; 
	    syn_observed = false;
	}

	// Type is "tcp".
	virtual std::string get_type() { return "tcp"; }
    };

    class tcp {

      public:

	// Flags
	static const int FIN = 1;
	static const int SYN = 2;
	static const int RST = 4;
	static const int PSH = 8;
	static const int ACK = 16;
	static const int URG = 32;
	static const int ECE = 64;
	static const int CWR = 128;
	static const int NS = 256;

	// TCP processing function.
	static void process(engine&,context_ptr c, pdu_iter s, pdu_iter e);

    };

};

#endif

