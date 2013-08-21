
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

namespace cybermon {

    // Context class, describes the state around a 'flow' of data between
    // two endpoints at a particular network layer.
    class context : public base_context, public reapable {
      private:

      protected:

	// Watcher, tidies things up when they get old.
	manager& mgr;

      public:

	manager& get_manager() { return mgr; }

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

	typedef context_ptr (*creator)(manager&, const flow&, context_ptr);

	static context_ptr get_or_create(context_ptr base, const flow& f, 
					 creator create_fn) {

	    boost::shared_ptr<context> mc = 
		boost::dynamic_pointer_cast<context>(base);

	    mc->lock.lock();

	    context_ptr ch;

	    if (mc->children.find(f) != mc->children.end())
		ch = base->children[f];
	    else {

		ch = (*create_fn)(mc->mgr, f, mc);
		base->children[f] = ch;

		// We've just created a context!

		// Now, we try to look up the 'reverse' flow.  Here's it's
		// address...
		flow f_rev;
		f_rev.src = f.dest;
		f_rev.dest = f.src;

		// First of all, see if the base context's reverse has this
		// reverse flow.
		context_ptr base_rev = base->reverse.lock();
		if (base_rev) {

		    if (base_rev->children.find(f_rev) != 
			base_rev->children.end()) {

			// If the base's reverse has such a child, use that
			// as the new context's reverse.
			ch->reverse = base_rev->children[f_rev];

			// And vice versa...
			base_rev->children[f_rev]->reverse = ch;

		    }
		    

		} else {
		    
		    // The base has no reverse.  Try its children.

		    if (base->children.find(f_rev) != base->children.end()) {

			// If the base's reverse has such a child, use that
			// as the new context's reverse.
			ch->reverse = base->children[f_rev];

			// And vice versa...
			base->children[f_rev]->reverse = ch;

		    }

		}

	    }

	    mc->lock.unlock();

	    return ch;
	    
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

