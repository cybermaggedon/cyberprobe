
#include "icmp.h"
#include "manager.h"

using namespace analyser;

void icmp::process(manager& mgr, context_ptr c, pdu_iter s, pdu_iter e)
{

    address src, dest;
    src.assign(s, s, CONTROL, ICMP);
    dest.assign(s, s, CONTROL, ICMP);

    flow f(src, dest);

    // FIXME: Check checksum?

    icmp_context::ptr fc = icmp_context::get_or_create(c, f);

    // Set / update TTL on the context.
    // 120 seconds.
    fc->set_ttl(context::default_ttl);

    // Pass whole ICMP message.
    mgr.datagram(fc, s, e);

}

