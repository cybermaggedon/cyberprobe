
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

    context_ptr fc = c->get_context(f);

    if (fc.get() == 0) {
	fc = context_ptr(new icmp_context(mgr, f, c));
	c->add_child(f, fc);
    }

    icmp_context& ic = dynamic_cast<icmp_context&>(*fc);

    // Set / update TTL on the context.
    // 120 seconds.
    ic.set_ttl(context::default_ttl);

    // Pass whole ICMP message.
    mgr.datagram(fc, s, e);

}
