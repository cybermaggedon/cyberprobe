
#include "udp.h"
#include "address.h"
#include "flow.h"
#include "analyser.h"

using namespace analyser;

void udp::process(engine& eng, context_ptr c, 
		  const pdu_iter& s, const pdu_iter& e)
{

    if ((e - s) < 8)
	throw exception("Header too small for UDP header");

    // UDP ports
    address src, dest;
    src.assign(s, s + 2, TRANSPORT, UDP);
    dest.assign(s + 2, s + 4, TRANSPORT, UDP);

    uint32_t length = (s[4] << 8) + s[5];
    
//    for(int i = 0; i < (e - s); i++) {
//	std::cerr << std::hex << (int) s[i] << " ";
//    }
//    std::cerr << std::endl;

    uint32_t cksum = (s[6] << 8) + s[7];

    if ((e - s) != length)
	throw exception("UDP header length doesn't agree with payload length");

    // FIXME: Check checksum?

    flow f(src, dest);

    context_ptr fc = c->get_context(f);

    if (fc.get() == 0) {
	fc = context_ptr(new udp_context(f, c));
	c->add_child(f, fc);
    }

    eng.data(fc, s + 4, e);

    // Now what?

}
