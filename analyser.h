
////////////////////////////////////////////////////////////////////////////
//
// Packet analyser, analyses packet data, and triggers a set of events for
// things it observes.
//
////////////////////////////////////////////////////////////////////////////

#ifndef ANALYSER_H
#define ANALYSER_H

#include <string>
#include <vector>
#include <list>
#include <map>

#include "thread.h"
#include "pdu.h"
#include "context.h"

namespace analyser {

    // Observer interface.  The observer interface is called when various
    // reportable events occur.
    class observer {
    public:
	virtual void data(const context_ptr cp, const pdu_iter& s, 
			  const pdu_iter& e) = 0;
    };

    // Packet analysis engine.  Designed to be sub-classed, caller should
    // implement the 'observer' interface.
    class engine : public observer {
      private:

	// Lock for all state.
	threads::mutex lock;

	// Child contexts.
	std::map<std::string, context_ptr> contexts;

      public:

	// Constructor.
	engine() { }

	// Destructor.
	virtual ~engine() {}

	// Get the root context for a particular LIID.
	context_ptr get_root_context(const std::string& liid);

	// Close an unwanted root context.
	void close_root_context(const std::string& liid);

	// Process a packet within a context.  'c' describes the context,
	// 's' and 'e' are iterators pointing at the start and end of packet
	// data to process.
	void process(context_ptr c, const pdu_iter& s, const pdu_iter& e);

	// Utility function, given a context, iterates up through the parent
	// pointers, returning a list of contexts (including 'p').
	static void get_context_stack(context_ptr p, std::list<context_ptr>& l) {
	    while (p) {
		l.push_front(p);
		p = p->parent.lock();
	    }
	}

	// Given a context, locates the root context, and returns the liid and
	// target address.
	static void get_root_info(context_ptr p,
				  std::string& liid,
				  address& ta);
	
	// Given a context, locates the network context in the stack, and
	// returns the network contexts source and destination address.
	// Hint: probably IP addresses.
	static void get_network_info(context_ptr p,
				     address& src, address& dest);
	
	// Given a context, describe the address of the context in
	// human-readable format.
	static void describe(context_ptr p, std::ostream& out);
	
    };

};

#endif

