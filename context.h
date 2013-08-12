
#ifndef CONTEXT_H
#define CONTEXT_H

#include <vector>
#include <list>
#include <map>
#include <boost/shared_ptr.hpp>
#include <boost/weak_ptr.hpp>

#include "socket.h"
#include "thread.h"

#include "pdu.h"
#include "address.h"
#include "flow.h"
#include "exception.h"

namespace analyser {

    typedef unsigned long context_id;

    class context;
    class target_context;

    typedef boost::shared_ptr<context> context_ptr;
    typedef boost::shared_ptr<target_context> target_context_ptr;

    class context {
      private:
	static context_id next_context_id;
	context_id id;
      protected:
      public:
	flow addr;
	threads::mutex lock;

	// Use weak_ptr for the parent link, cause otherwise there's a
	// shared_ptr cycle.
	boost::weak_ptr<context> parent;

	std::map<flow,context_ptr> children;
	context() { 
	    id = next_context_id++; 
	    // parent is initialised to 'null'.
	}
	context(context_ptr parent) { 
	    id = next_context_id++; 
	    this->parent = parent;
	}

	context_ptr get_context(const flow& f) {

	    lock.lock();

	    context_ptr c;
	    
	    if (children.find(f) != children.end())
		c = children[f];

	    lock.unlock();
	    
	    return c;

	}

	void add_child(const flow& f, context_ptr c) {
	    lock.lock();
	    if (children.find(f) != children.end())
		throw exception("That context already exists.");
	    children[f] = c;
	    lock.unlock();
	}

	virtual ~context() {}
	context_id get_id() { return id; }

	virtual std::string get_type() = 0;

#ifdef BROKEN_NOT_DEFINED_YET
	// Casts
	target_context_ptr target() {
	    target_context* tc = dynamic_cast<target_context*>(this);
	    return target_context_ptr(tc);
	}
#endif

    };

    class target_context : public context {
      private:
	std::string liid;
      public:
	static context_ptr create(const std::string& liid) {
	    target_context* c = new target_context();
	    c->liid = liid;
	    return context_ptr(c);
	}
	void set_target_address(const tcpip::address& a) {
	    //FIXME: Do something with the address.
	}
	std::string get_liid() {
	    return liid;
	}
	virtual std::string get_type() { return "target"; }
    };
    
    class network_context : public context {
    };

    class transport_context : public context {
    };

};

#endif

