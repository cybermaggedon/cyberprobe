
#include "icmp.h"
#include "analyser.h"

using namespace analyser;

void icmp::process(engine& eng, context_ptr c, pdu_iter s, pdu_iter e)
{

    address src, dest;
    src.assign(s, s, CONTROL, ICMP);
    dest.assign(s, s, CONTROL, ICMP);

    flow f(src, dest);

    // FIXME: Check checksum?

    context_ptr fc = c->get_context(f);

    if (fc.get() == 0) {
	fc = context_ptr(new icmp_context(eng, f, c));
	c->add_child(f, fc);
    }

    // Set / update TTL on the context.
    // 120 seconds.
    fc->set_ttl(context::default_ttl);

    // Pass whole ICMP message.
    eng.datagram(fc, s, e);

}
