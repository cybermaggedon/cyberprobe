
////////////////////////////////////////////////////////////////////////////
//
// A class describing protocol contexts.
//
////////////////////////////////////////////////////////////////////////////

#ifndef CONTEXT_H
#define CONTEXT_H

#include "socket.h"

#include "address.h"
#include "flow.h"
#include "exception.h"
#include "reaper.h"
#include "base_context.h"
#include "manager.h"

namespace analyser {

    // Context class, describes the state around a 'flow' of data between
    // two endpoints at a particular network layer.
    class context : public base_context, public reapable {
      private:

      protected:

	// Watcher, tidies things up when they get old.
	manager& mgr;

      public:

	// Default time-to-live.
	static const int default_ttl = 10;

	// Constructor.
        context(manager& m) : reapable(m), mgr(m) { 
	}

	// Constructor, initialises parent pointer.
        context(manager& m, context_ptr parent) : 
	base_context(parent), reapable(m), mgr(m) { 
	}

	// Given a flow address, returns the child context.
	context_ptr get_context(const flow& f) {

	    lock.lock();

	    context_ptr c;
	    
	    if (children.find(f) != children.end())
		c = children[f];

	    lock.unlock();
	    
	    return c;

	}

	// Adds a child context.
	void add_child(const flow& f, context_ptr c) {
	    lock.lock();
	    if (children.find(f) != children.end())
		throw exception("That context already exists.");
	    children[f] = c;
	    lock.unlock();
	}

	// Destructor.
	virtual ~context() { 
	}

	// Delete myself.
	void reap() {

	    // Erase myself from my parent's child map.
	    // Should call my destructor, I guess.
	    context_ptr p = parent.lock();
	    if (p)
		p->children.erase(addr);

	}

    };

    // 'Root' context.  Root of a protocol stack, describes why that protocol
    // stack exists.  Basically reason for acquiring the data, indicated by
    // the LIID.
    class root_context : public context {
    private:

	// Don't set TTL on this, currently.  It's lifetime is managed by
	// the engine class.
	
	// LIID.
	std::string liid;

	// Address which caused acquisition of this data.
	address trigger_address;

      public:
	/* static context_ptr create(const std::string& liid) { */
	/*     root_context* c = new root_context(); */
	/*     c->liid = liid; */
	/*     return context_ptr(c); */
	/* } */
        root_context(manager& m) : 
	context(m) {
	    addr.src.layer = ROOT;
	    addr.dest.layer = ROOT;
	}

	virtual ~root_context() {}
	void set_trigger_address(const tcpip::address& a) {
	    if (a.universe == a.ipv4) {
		if (a.addr.size() == 4)
		    trigger_address.assign(a.addr, NETWORK, IP4);
	    }
	    if (a.universe == a.ipv6) {
		if (a.addr.size() == 16)
		    trigger_address.assign(a.addr, NETWORK, IP6);
	    }
	}

	address& get_trigger_address() { return trigger_address; }

	std::string& get_liid() {
	    return liid;
	}

	void set_liid(const std::string& l) {
	    liid = l;
	}

	virtual std::string get_type() { return "root"; }
    };

};

#endif

