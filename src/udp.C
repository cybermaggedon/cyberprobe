
#include <cyberprobe/protocol/udp.h>

#include <cyberprobe/protocol/address.h>
#include <cyberprobe/protocol/flow.h>
#include <cyberprobe/protocol/manager.h>
#include <cyberprobe/protocol/udp_ports.h>
#include <cyberprobe/protocol/unrecognised.h>


using namespace cyberprobe::protocol;


void udp::process(manager& mgr, context_ptr c, const pdu_slice& sl)
{
    pdu_iter s = sl.start;
    pdu_iter e = sl.end;

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
    flow_address f(src, dest, sl.direc);

    udp_context::ptr fc = udp_context::get_or_create(c, f);

    // Set / update TTL on the context.
    // 120 seconds.
    fc->set_ttl(context::default_ttl);

    pdu_iter start_of_next_protocol = s + 8;
    uint16_t src_port = src.get_uint16();
    uint16_t dst_port = dest.get_uint16();

    // Attempt to identify from the port number and
    // call the appropriate handler if there is one
    if (udp_ports::has_port_handler(src_port) ||
	udp_ports::has_port_handler(dst_port)) {

	std::unique_lock<std::mutex> lock(fc->mutex);

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

	pdu_slice sl2(start_of_next_protocol, e, sl.time, sl.direc);
	lock.unlock();
	(*fc->processor)(mgr, fc, sl2);
	return;
    } else {
	pdu_slice sl2(start_of_next_protocol, e, sl.time, sl.direc);
	unrecognised::process_unrecognised_datagram(mgr, fc, sl2);
    }
}


