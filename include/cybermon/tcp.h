
////////////////////////////////////////////////////////////////////////////
//
// TCP processing
//
////////////////////////////////////////////////////////////////////////////

#ifndef CYBERMON_TCP_H
#define CYBERMON_TCP_H

#include <stdint.h>

#include <set>

#include "context.h"
#include "manager.h"
#include "serial.h"
#include "protocol.h"

namespace cybermon {

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

	// This deals with stream synchronisation and tear-down (the SYN/FIN
	// stuff).
	bool syn_observed;
	bool fin_observed;
	bool connected;

	// Buffer for data for identification.
	static const unsigned int ident_buffer_max;
	std::string ident_buffer;

	// Once identified, the processing function.
	bool svc_idented;
	process_fn processor;

	// Sequence number.
	serial<int32_t, uint32_t> m_seq;
	serial<int32_t, uint32_t> m_first_seq;
	serial<int32_t, uint32_t> seq_expected;
	serial<int32_t, uint32_t> ack_received;

	// Segments buffer for reassembly.
	static const unsigned int max_segments;
	std::set<tcp_segment> segments;
	
	// Constructor.
        tcp_context(manager& m) : context(m) {
	    syn_observed = false;
	    connected = false;
	    svc_idented = false;
	    processor = 0;
	    fin_observed = false;
	}

	// Constructor, describing flow address and parent pointer.
        tcp_context(manager& m, const flow_address& a, context_ptr p) : 
	context(m) { 
	    addr = a; parent = p; 
	    syn_observed = false;
	    connected = false;
	    svc_idented = false;
	    processor = 0;
	    fin_observed = false;
	}

	// Type is "tcp".
	virtual std::string get_type() { return "tcp"; }

	typedef boost::shared_ptr<tcp_context> ptr;

	static context_ptr create(manager& m, const flow_address& f, 
				  context_ptr par) {
	    tcp_context* tc = new tcp_context(m, f, par);
	    return context_ptr(tc);
	}

	// Given a flow address, returns the child context.
	static ptr get_or_create(context_ptr base, const flow_address& f) {
	    context_ptr cp = context::get_or_create(base, f, 
						    tcp_context::create);
	    ptr sp = boost::dynamic_pointer_cast<tcp_context>(cp);
	    return sp;
	}

    };

    class tcp {

      public:

	// 1's complement checksum
	static void checksum(pdu_iter s, pdu_iter e, uint16_t& sum);

	// Calculate TCP cksum
	static uint16_t calculate_ip4_cksum(pdu_iter src,  // IPv4 address
					    pdu_iter dest, // IPv4 address
					    uint16_t protocol,
					    uint16_t length,
					    pdu_iter s,    // TCP hdr + body
					    pdu_iter e);

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
	static void process(manager&, context_ptr c, pdu_iter s, pdu_iter e);

	// Process on re-synchronised streams.
	static void post_process(manager&, tcp_context::ptr c, pdu_iter s, 
				 pdu_iter e);

    };

};

#endif

