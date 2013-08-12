
#include "tcp.h"
#include "analyser.h"

using namespace analyser;

void tcp::process(engine& eng, context_ptr c, 
		  const pdu_iter& s, const pdu_iter& e)
{

    if ((e - s) < 20)
	throw exception("Header too small for TCP header");

    // TCP ports
    address src, dest;
    src.assign(s, s + 2, TRANSPORT, TCP);
    dest.assign(s + 2, s + 4, TRANSPORT, TCP);

    uint32_t seq = (s[4] << 24) + (s[5] << 16) + (s[6] << 8) + s[7];

    unsigned int offset = s[12] >> 4;
    unsigned int flags = (s[12] & 0xf) << 8 + s[13];
    uint32_t cksum = (s[16] << 8) + s[17];

    unsigned int header_length = 4 * offset;
    uint32_t length = (e - s) - header_length;

    // FIXME: Check checksum?

    flow f(src, dest);

    context_ptr fc = c->get_context(f);

    if (fc.get() == 0) {
	fc = context_ptr(new tcp_context(f, c));
	c->add_child(f, fc);
    }

    

    // Now what?

    eng.data(fc, s + header_length, e);

}
