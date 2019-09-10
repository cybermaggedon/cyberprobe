
#include <cyberprobe/protocol/context.h>
#include <cyberprobe/analyser/engine.h>
#include <cyberprobe/protocol/ip.h>

using namespace cyberprobe::protocol;
using namespace cyberprobe::analyser;

context_ptr engine::get_root_context(const std::string& device,
				     const std::string& network)
{
    lock.lock();

    context_ptr c;

    root_id id(device, network);
    
    if (contexts.find(id) == contexts.end()) {
	c = context_ptr(new root_context(*this));
	
	root_context* rp = dynamic_cast<root_context*>(c.get());
	rp->set_device(device);
	rp->set_network(network);
	contexts[id] = c;
    } else
	c = contexts[id];

    lock.unlock();

    return c;
}

void engine::close_root_context(const std::string& device,
				const std::string& network)
{
    lock.lock();
    root_id id(device, network);
    contexts.erase(id);
    lock.unlock();
}

void engine::process(context_ptr c, const pdu_slice& sl)
{
    ip::process(*this, c, sl);
}

void engine::describe_src(context_ptr p, std::ostream& out)
{

    std::list<context_ptr> l;
    get_context_stack(p, l);

    bool need_sep = false;

    for(std::list<context_ptr>::iterator it = l.begin();
	it != l.end();
	it++) {

	if (need_sep)
	    out << "/";

	(*it)->addr.src.describe(out);

	need_sep = true;
    }

}

void engine::describe_dest(context_ptr p, std::ostream& out)
{

    std::list<context_ptr> l;
    get_context_stack(p, l);

    bool need_sep = false;

    for(std::list<context_ptr>::iterator it = l.begin();
	it != l.end();
	it++) {

	if (need_sep)
	    out << "/";

	(*it)->addr.dest.describe(out);
	need_sep = true;
    }

}

void engine::get_root_info(context_ptr p, std::string& device, address& a)
{

    while (p) {
	if (p->get_type() == "root") {

	    // Cast to root.
	    root_context& rc = 
		dynamic_cast<root_context&>(*p);
	    
	    device = rc.get_device();
	    a = rc.get_trigger_address();

	}
	p = p->parent.lock();
    }

//    throw std::runtime_error("No root context?!");

}

root_context& engine::get_root(context_ptr p)
{

    while (p) {
	if (p->get_type() == "root") {

	    // Cast to root.
	    root_context& rc = 
		dynamic_cast<root_context&>(*p);

            return rc;

	}
	p = p->parent.lock();
    }

    throw std::runtime_error("No root context?!");

}

void engine::get_network_info(context_ptr p,
			      std::string& net, address& src, address& dest)
{

    src = address();
    dest = address();
    while (p) {
        if (p->get_type() == "root") {
	    root_context& rc = dynamic_cast<root_context&>(*p);
	    net = rc.get_network();
	}
	if (p->get_type() == "ip4") {
	    src = p->addr.src;
	    dest = p->addr.dest;
	}
	if (p->get_type() == "ip6") {
	    src = p->addr.src;
	    dest = p->addr.dest;
	}
	p = p->parent.lock();
    }

}


