
#include <cybermon/udp.h>
#include <cybermon/address.h>
#include <cybermon/flow.h>
#include <cybermon/manager.h>
#include <cybermon/unrecognised.h>
#include <cybermon/dns.h>

using namespace cybermon;

void udp::process(manager& mgr, context_ptr c, pdu_iter s, pdu_iter e)
{

    if ((e - s) < 8)
	throw exception("Header too small for UDP header");

    // UDP ports
    address src, dest;
    src.set(s, s + 2, TRANSPORT, UDP);
    dest.set(s + 2, s + 4, TRANSPORT, UDP);

    uint32_t length = (s[4] << 8) + s[5];

    if ((e - s) != length)
	throw exception("UDP header length doesn't agree with payload length");

    // FIXME: Check checksum?

    flow_address f(src, dest);

    udp_context::ptr fc = udp_context::get_or_create(c, f);

    // Set / update TTL on the context.
    // 120 seconds.
    fc->set_ttl(context::default_ttl);

    pdu_iter start_of_dns_header = s + 8;
    if (dns::ident(src.get_uint16(), dest.get_uint16(), start_of_dns_header, e))
    {
	dns::process(mgr, fc, start_of_dns_header, e);
    } else  {

	unrecognised::process_unrecognised_datagram(mgr, fc, start_of_dns_header, e);

    }

}

