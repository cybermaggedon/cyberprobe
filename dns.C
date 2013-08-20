
#include "dns.h"
#include "manager.h"

using namespace analyser;

void dns::process(manager& mgr, context_ptr c, pdu_iter s, pdu_iter e)
{

    std::vector<unsigned char> empty;
    address src, dest;
    src.assign(empty, APPLICATION, DNS);
    dest.assign(empty, APPLICATION, DNS);

    flow f(src, dest);

    dns_context::ptr fc = dns_context::get_or_create(c, f);

    fc->lock.lock();

    try {
	mgr.unrecognised_stream(fc, s, e);
    } catch (std::exception& e) {
	fc->lock.unlock();
	throw e;
    }

    fc->lock.unlock();

}

