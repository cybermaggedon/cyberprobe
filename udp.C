
#include "udp.h"
#include "address.h"
#include "flow.h"
#include "manager.h"

using namespace analyser;

void udp::process(manager& mgr, context_ptr c, pdu_iter s, pdu_iter e)
{

    if ((e - s) < 8)
	throw exception("Header too small for UDP header");

    // UDP ports
    address src, dest;
    src.assign(s, s + 2, TRANSPORT, UDP);
    dest.assign(s + 2, s + 4, TRANSPORT, UDP);

    uint32_t length = (s[4] << 8) + s[5];

    uint32_t cksum = (s[6] << 8) + s[7];

    if ((e - s) != length)
	throw exception("UDP header length doesn't agree with payload length");

    // FIXME: Check checksum?

    flow f(src, dest);

    udp_context::ptr fc = udp_context::get_or_create(c, f);

    // Set / update TTL on the context.
    // 120 seconds.
    fc->set_ttl(context::default_ttl);

    // Currently, we don't understand any protocols.
    mgr.unrecognised_datagram(fc, s + 4, e);

    // Now what?

}
