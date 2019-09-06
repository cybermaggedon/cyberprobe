
////////////////////////////////////////////////////////////////////////////
//
// A class describing protocol contexts.
//
////////////////////////////////////////////////////////////////////////////

#ifndef CYBERMON_CONTEXT_H
#define CYBERMON_CONTEXT_H

#include <sys/time.h>

#include <cyberprobe/network/socket.h>
#include <cyberprobe/protocol/address.h>
#include <cyberprobe/protocol/flow.h>
#include <cyberprobe/protocol/base_context.h>
#include <cyberprobe/exception.h>
#include <cyberprobe/util/reaper.h>
#include <cyberprobe/analyser/manager.h>

namespace cyberprobe {

namespace protocol {

    // Context class, describes the state around a 'flow' of data between
    // two endpoints at a particular network layer.
    class context : public base_context, public util::reapable {
    private:

    protected:

	// Watcher, tidies things up when they get old.
	manager& mgr;

    public:

	manager& get_manager() { return mgr; }

	// Default time-to-live.
	static const int default_ttl = 120;

	// Constructor.
        context(manager& m) : reapable(m), mgr(m) { 
	}

	// Constructor, initialises parent pointer.
        context(manager& m, context_ptr parent) : 
            base_context(parent), reapable(m), mgr(m) { 
	}

#ifdef BROKEN
	context_ptr locate_other_endpoint(const std::list<flow_address>& a) {
	    return locate_other_endpoint(a, a.size());
	}

	context_ptr locate_other_endpoint(const std::list<flow_address>& ad,
					  int parents)
            {
                if (parents == 0)
                    throw exception("Parents must be > 0");

                context_ptr par_cp = get_parent();
                if (!par_cp)
                    throw exception("Parent is null");

                for(int i = 1; i < parents; i++) {
                    context_ptr parent_cp = get_parent();
                    if (!par_cp)
                        throw exception("Parent is null");
                }

                context_ptr cp = par_cp;

                for(std::list<flow_address>::const_iterator it = ad.begin();
                    it != ad.end();
                    it++) {
                    cp = cp->
                        }

            }

#endif

	// Given a flow address, returns the child context.
	context_ptr get_child(const flow_address& f) {

	    std::lock_guard<std::mutex> lock(mutex);

	    context_ptr c;
	    
	    if (children.find(f) != children.end())
		c = children[f];

	    return c;

	}

	// Adds a child context.
	void add_child(const flow_address& f, context_ptr c) {

	    std::lock_guard<std::mutex> lock(mutex);

	    if (children.find(f) != children.end())
		throw exception("That context already exists.");
	    children[f] = c;
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

	typedef context_ptr (*creator)(manager&, const flow_address&, 
				       context_ptr);

	static context_ptr get_or_create(context_ptr parent, 
					 const flow_address& f, 
					 creator create_fn) {

	    std::shared_ptr<context> mc = 
		std::dynamic_pointer_cast<context>(parent);

	    std::lock_guard<std::mutex> lock(mc->mutex);

	    context_ptr ch;

	    if (mc->children.find(f) != mc->children.end())
		ch = parent->children[f];
	    else {

		ch = (*create_fn)(mc->mgr, f, mc);
		parent->children[f] = ch;

		// Set creation time.
		gettimeofday(&(ch->creation), 0);

		// We've just created a context!

		// Now, we try to look up the 'reverse' flow.  Here's it's
		// address...
		flow_address f_rev;
		f_rev.src = f.dest;
		f_rev.dest = f.src;

		// First of all, see if the parent context's reverse has this
		// reverse flow.
		context_ptr parent_rev = parent->reverse.lock();
		if (parent_rev) {

		    if (parent_rev->children.find(f_rev) != 
			parent_rev->children.end()) {

			// If the parent's reverse has such a child, use that
			// as the new context's reverse.
			ch->reverse = parent_rev->children[f_rev];

			// And vice versa...
			parent_rev->children[f_rev]->reverse = ch;

		    }

		} else {

		    // The parent has no reverse.  Try its children.

		    // Only do this on a root context, otherwise we'll just
		    // find the same context in many cases.

		    if ((parent->get_type() == "root") && 
			(parent->children.find(f_rev) != parent->children.end())) {

			// If the parent's reverse has such a child, use that
			// as the new context's reverse.
			ch->reverse = parent->children[f_rev];

			// And vice versa...
			parent->children[f_rev]->reverse = ch;

		    }

		}

	    }

	    return ch;
	    
	}

    };

    // 'Root' context.  Root of a protocol stack, describes why that protocol
    // stack exists.  Basically reason for acquiring the data, indicated by
    // the device ID.
    class root_context : public context {
    private:

	// Don't set TTL on this, currently.  It's lifetime is managed by
	// the engine class.
	
	// LIID.
	std::string device;

	// NEID = network name.
	std::string network;

	// Address which caused acquisition of this data.
	address trigger_address;

    public:

        root_context(manager& m) : 
            context(m) {
	    addr.src.layer = ROOT;
	    addr.dest.layer = ROOT;
	}

	virtual ~root_context() {}
	void set_trigger_address(const tcpip::address& a) {
	    if (a.universe == a.ipv4) {
		if (a.addr.size() == 4)
                    trigger_address.set(a.addr, NETWORK, IP4);
	    }
	    if (a.universe == a.ipv6) {
		if (a.addr.size() == 16)
                    trigger_address.set(a.addr, NETWORK, IP6);
	    }
	}

	address& get_trigger_address() { return trigger_address; }

	std::string& get_device() {
	    return device;
	}

	void set_device(const std::string& d) {
	    device = d;
	}

	std::string& get_network() {
	    return network;
	}

	void set_network(const std::string& n) {
	    network = n;
	}

	virtual std::string get_type() { return "root"; }
    };

};

};

#endif

