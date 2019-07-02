
#ifndef CYBERMON_BASE_CONTEXT_H
#define CYBERMON_BASE_CONTEXT_H

#include <exception>
#include <memory>
#include <map>
#include <mutex>

#include <cybermon/flow.h>
#include <cybermon/exception.h>

namespace cybermon {

    // Context ID type.
    typedef unsigned long context_id;

    // Forward declarations.
    class base_context;

    // Shared pointer types.
    typedef std::shared_ptr<base_context> context_ptr;

    // Context class, describes the state around a 'flow' of data between
    // two endpoints at a particular network layer.
    class base_context {
    private:

	// Next context ID to hand out.
	static context_id next_context_id;
	static unsigned long total_contexts;

	// This context's ID.
	context_id id;

    public:

	// Time of creation.
	struct timeval creation;

	context_ptr get_reverse() {
	    return reverse.lock();
	}

	context_ptr get_parent() {
	    return parent.lock();
	}

	// The flow address.
	flow_address addr;

	void get_src(std::vector<unsigned char>& a, purpose& pu, 
                     protocol& pr) const {
            addr.src.get(a, pu, pr);
	}

	void get_dest(std::vector<unsigned char>& a, purpose& pu, 
                      protocol& pr) const {
	    addr.dest.get(a, pu, pr);
	}

	void get_src(std::string& type, std::string& address) const {
	    addr.src.get(type, address);
	}

	void get_dest(std::string& type, std::string& address) const {
	    addr.dest.get(type, address);
	}

	// Lock for all context state.
	std::mutex mutex;

	// Use weak_ptr for the parent link, cause otherwise there's a
	// shared_ptr cycle.
	std::weak_ptr<base_context> parent;

	// Use weak_ptr for the 'reverse flow' link, cause otherwise there's a
	// shared_ptr cycle.
	std::weak_ptr<base_context> reverse;

	// Child contexts.
	std::map<flow_address,context_ptr> children;

	// Constructor.
        base_context() { 
	    id = next_context_id++; 
	    total_contexts++;
	    // parent is initialised to 'null'.
	}

	// Constructor, initialises parent pointer.
        base_context(context_ptr parent) {
	    id = next_context_id++; 
	    this->parent = parent;
	    total_contexts++;
	}

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
	virtual ~base_context() { 
	    total_contexts--;
	}

	// Returns constructor ID.
	context_id get_id() { return id; }

	// Returns a context 'type'.
	virtual std::string get_type() = 0;

	// Delete myself.
	void delete_myself() {
	    // Erase myself from my parent's child map.
	    // Should call my destructor, I guess.
	    context_ptr p = parent.lock();
	    if (p)
		p->children.erase(addr);
	    else
		throw exception("Could not delete myself.");
	}

    };

};

#endif

