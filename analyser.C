
#include "thread.h"
#include "context.h"
#include "analyser.h"
#include "ip.h"

using namespace analyser;

context_ptr engine::get_root_context(const std::string& liid)
{
    lock.lock();

    context_ptr c;

    if (contexts.find(liid) == contexts.end()) {
	c = root_context::create(liid);
	contexts[liid] = c;
    } else
	c = contexts[liid];

    lock.unlock();

    return c;
}

void engine::process(context_ptr c, const pdu_iter& s, const pdu_iter& e)
{
    ip::process(*this, c, s, e);
}

void engine::describe(context_ptr p, std::ostream& out)
{

    std::list<context_ptr> l;
    get_context_stack(p, l);

    bool start = true;

    for(std::list<context_ptr>::iterator it = l.begin();
	it != l.end();
	it++) {
	if (start)
	    start = false;
	else
	    out << ", ";
	
	if ((*it)->get_type() == "target")
	    out << "root";
	else
	    (*it)->addr.src.describe(out);
    }
	    
    out << " -> ";

    start = true;
    for(std::list<context_ptr>::iterator it = l.begin();
	it != l.end();
	it++) {
	if (start)
	    start = false;
	else
	    out << ", ";

	if ((*it)->get_type() == "target")
	    out << "root";
	else
	    (*it)->addr.dest.describe(out);

    }

}

void engine::get_root_info(context_ptr p, std::string& liid, address& a)
{

    while (p) {
	if (p->get_type() == "target") {
	    liid = p->root().get_liid();
	    a = p->root().get_trigger_address();
	}
	p = p->parent.lock();
    }

}


void engine::get_network_info(context_ptr p, address& src, address& dest)
{

    src = address();
    dest = address();
    while (p) {
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


