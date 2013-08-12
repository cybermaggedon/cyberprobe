
#include "icmp.h"
#include "analyser.h"

using namespace analyser;

void icmp::process(engine& eng, context_ptr c, 
		  const pdu_iter& s, const pdu_iter& e)
{

    address src, dest;
    src.assign(s, s, CONTROL, ICMP);
    dest.assign(s, s, CONTROL, ICMP);

    flow f(src, dest);

    // FIXME: Check checksum?

    context_ptr fc = c->get_context(f);

    if (fc.get() == 0) {
	fc = context_ptr(new icmp_context(f, c));
	c->add_child(f, fc);
    }

    // Pass whole ICMP message.
    eng.data(fc, s, e);

}
