
#include "icmp.h"
#include "manager.h"

using namespace cybermon;

void icmp::process(manager& mgr, context_ptr c, pdu_iter s, pdu_iter e)
{

    std::vector<unsigned char> empty;
    address src, dest;
    src.set(empty, CONTROL, ICMP);
    dest.set(empty, CONTROL, ICMP);

    flow_address f(src, dest);

    // FIXME: Check checksum?

    icmp_context::ptr fc = icmp_context::get_or_create(c, f);

    // Set / update TTL on the context.
    // 120 seconds.
    fc->set_ttl(context::default_ttl);

    // Pass whole ICMP message.
    mgr.icmp(fc, s, e);

}

