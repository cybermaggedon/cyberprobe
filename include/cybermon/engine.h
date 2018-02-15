
////////////////////////////////////////////////////////////////////////////
//
// Packet analyser, analyses packet data, and triggers a set of events for
// things it observes.
//
////////////////////////////////////////////////////////////////////////////

#ifndef CYBERMON_ENGINE_H
#define CYBERMON_ENGINE_H

#include <string>
#include <vector>
#include <list>
#include <map>

#include "thread.h"
#include "pdu.h"
#include "context.h"

#include "socket.h"
#include "reaper.h"
#include "observer.h"
#include "manager.h"

namespace cybermon {
    
    // Packet analysis engine.  Designed to be sub-classed, caller should
    // implement the 'observer' interface.
    class engine : public manager {
    private:

	// Lock for all state.
	threads::mutex lock;

	// Child contexts.
	typedef std::pair<std::string,std::string> root_id;
	std::map<root_id, context_ptr> contexts;

	// Process a packet within a context.  'c' describes the context,
	// 's' and 'e' are iterators pointing at the start and end of packet
	// data to process.
	void process(context_ptr c, const pdu_slice& s);

    public:

	// Constructor.
        engine() { }

	// Destructor.
	virtual ~engine() {}

	// Get the root context for a particular LIID.
	context_ptr get_root_context(const std::string& liid,
				     const std::string& network);

	// Close an unwanted root context.
	void close_root_context(const std::string& liid,
				const std::string& network);

	// Process a packet belong to a LIID.  'liid' describes the context,
	// 's' and 'e' are iterators pointing at the start and end of packet
	// data to process.
	void process(const std::string& liid, const std::string& network,
		     const pdu_slice& s) {
	    context_ptr c = get_root_context(liid, network);
	    process(c, s);
	}

	// Called when attacker is detected.
	void target_up(const std::string& liid,
		       const std::string& network,
		       const tcpip::address& addr,
		       const struct timeval& tv) {

	    // Get the root context for this LIID.
	    context_ptr c = get_root_context(liid, network);

	    // Record the known address.
	    root_context& rc = dynamic_cast<root_context&>(*c);
	    rc.set_trigger_address(addr);

	    // This is a reportable event.
	    trigger_up(liid, addr, tv);

	}

	// Called when attacker goes off the air.
	void target_down(const std::string& liid,
			 const std::string& network,
			 const struct timeval& tv) {

	  close_root_context(liid, network);

	    // This is a reportable event.
	    trigger_down(liid, tv);

	}

	// Utility function, given a context, iterates up through the parent
	// pointers, returning a list of contexts (including 'p').
	static void get_context_stack(context_ptr p, 
				      std::list<context_ptr>& l) {
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
				     std::string& network,
				     address& src, address& dest);
	
	// Given a context, describe the address of the context in
	// human-readable format.
	static void describe_src(context_ptr p, std::ostream& out);
	static void describe_dest(context_ptr p, std::ostream& out);
	
    };

};

#endif

