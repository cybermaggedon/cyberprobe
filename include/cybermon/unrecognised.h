
////////////////////////////////////////////////////////////////////////////
//
// Protocols we don't recognise.
//
////////////////////////////////////////////////////////////////////////////

#ifndef CYBERMON_UNRECOGNISED_H
#define CYBERMON_UNRECOGNISED_H

#include <stdint.h>

#include <set>

#include <cybermon/context.h>
#include "manager.h"
//#include "serial.h"
#include "protocol.h"

namespace cybermon {
    
    // An unrecoginsed stream.
    class unrecognised_stream_context : public context {
      public:
	
	// Constructor.
        unrecognised_stream_context(manager& m) : 
	context(m) {
	}

	// Constructor, describing flow address and parent pointer.
        unrecognised_stream_context(manager& m, const flow_address& a, 
				    context_ptr p) : 
	context(m) { 
	    addr = a; parent = p; 
	}

	// Type.
	virtual std::string get_type() { return "unrecognised_stream"; }

	typedef boost::shared_ptr<unrecognised_stream_context> ptr;

	static context_ptr create(manager& m, const flow_address& f, 
				  context_ptr par) {
	    context_ptr cp = 
		context_ptr(new unrecognised_stream_context(m, f, par));
	    return cp;
	}

	// Given a flow address, returns the child context.
	static ptr get_or_create(context_ptr base, const flow_address& f) {
	    context_ptr cp = 
		context::get_or_create(base, f, 
				       unrecognised_stream_context::create);
	    ptr sp = 
		boost::dynamic_pointer_cast<unrecognised_stream_context>(cp);
	    return sp;
	}

    };

    // An unrecoginsed datagram
    class unrecognised_datagram_context : public context {
      public:
	
	// Constructor.
        unrecognised_datagram_context(manager& m) : 
	context(m) {
	}

	// Constructor, describing flow address and parent pointer.
        unrecognised_datagram_context(manager& m, const flow_address& a, 
				      context_ptr p) : 
	context(m) { 
	    addr = a; parent = p; 
	}

	// Type.
	virtual std::string get_type() { return "unrecognised_datagram"; }

	typedef boost::shared_ptr<unrecognised_datagram_context> ptr;

	static context_ptr create(manager& m, const flow_address& f, 
				  context_ptr par) {
	    context_ptr cp = 
		context_ptr(new unrecognised_datagram_context(m, f, par));
	    return cp;
	}

	// Given a flow address, returns the child context.
	static ptr get_or_create(context_ptr base, const flow_address& f) {
	    context_ptr cp = 
		context::get_or_create(base, f, 
				       unrecognised_datagram_context::create);
	    ptr sp = 
		boost::dynamic_pointer_cast<unrecognised_datagram_context>(cp);
	    return sp;
	}

    };

    class unrecognised {

    public:

	// HTTP request processing function.
	static void process_unrecognised_stream(manager&, context_ptr c, 
						pdu_iter s, pdu_iter e);

	// HTTP request processing function.
	static void process_unrecognised_datagram(manager&, context_ptr c, 
						  pdu_iter s, pdu_iter e);

    };

};

#endif

