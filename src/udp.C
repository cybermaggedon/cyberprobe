
#include <cybermon/udp.h>

#include <cybermon/address.h>
#include <cybermon/flow.h>
#include <cybermon/manager.h>
#include <cybermon/udp_ports.h>
#include <cybermon/unrecognised.h>


using namespace cybermon;


void udp::process(manager& mgr, context_ptr c, pdu_iter s, pdu_iter e)
{
    if ((e - s) < 8) {
	    throw exception("Header too small for UDP header");
    }

    // UDP ports
    address src, dest;
    src.set(s, s + 2, TRANSPORT, UDP);
    dest.set(s + 2, s + 4, TRANSPORT, UDP);

    uint32_t length = (s[4] << 8) + s[5];

    if ((e - s) != length) {
	    throw exception("UDP header length doesn't agree with payload length");
    }

    // FIXME: Check checksum?

    flow_address f(src, dest);

    udp_context::ptr fc = udp_context::get_or_create(c, f);

    // Set / update TTL on the context.
    // 120 seconds.
    fc->set_ttl(context::default_ttl);

    pdu_iter start_of_next_protocol = s + 8;
    uint16_t src_port = src.get_uint16();
    uint16_t dst_port = dest.get_uint16();

    // Attempt to identify from the port number and
    // call the appropriate handler if there is one
    if (udp_ports::has_port_handler(src_port) || udp_ports::has_port_handler(dst_port))
    {
        fc->lock.lock();

        // Unfortunately now need to repeat the check
        // to determine port number has the associated handler
        if (udp_ports::has_port_handler(src_port))
        {
            fc->processor = udp_ports::get_port_handler(src_port);
        }
        else
        {
            fc->processor = udp_ports::get_port_handler(dst_port);
        }

        fc->lock.unlock();

        (*fc->processor)(mgr, fc, start_of_next_protocol, e);
        return;
    }
    else
    {

        unrecognised::process_unrecognised_datagram(mgr, fc, start_of_next_protocol, e);
    }
}


