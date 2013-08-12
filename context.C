
#include "socket.h"
#include "context.h"

using namespace analyser;

unsigned long context::next_context_id = 0;

#ifdef LASKDJKASD
context_ptr context::get_ip4_context(const tcpip::ip4_address& src, 
				     const tcpip::ip4_address& dest)
{

    flow addr(src, dest);

    lock.lock();

    context_ptr c;

    if (children.find(addr) == children.end()) {
	c = ip4_context::create(addr);
	children.insert(std::pair<flow,context_ptr>(addr,c));
    } else {
	c = children[addr];
    }

    lock.unlock();

    return c;

}


#endif


void context::describe(std::ostream& out)
{

#ifdef ARSE
    // Slightly kludgy, cause can't wrap a shared_ptr around 'this' because
    // it will get deleted.
    std::list<context_ptr> contexts;

    context_ptr p = parent.lock();
    while (p) {
	std::cerr << ",";
	p->addr.src.describe(out);
	p = p->parent.lock();
    }



    addr.src.describe(out);

    context_ptr p = parent.lock();
    while (p) {
	std::cerr << ",";
	p->addr.src.describe(out);
	p = p->parent.lock();
    }

    out << " -> ";

    addr.dest.describe(out);

    p = parent.lock();
    while (p) {
	std::cerr << ",";
	p->addr.dest.describe(out);
	p = p->parent.lock();
    }

#endif

}

