
#include <cyberprobe/protocol/rtp_ssl.h>

#include <cyberprobe/protocol/address.h>
#include <cyberprobe/protocol/flow.h>
#include <cyberprobe/protocol/rtp_context.h>
#include <cyberprobe/event/event_implementations.h>


using namespace cyberprobe::protocol;


void rtp_ssl::process(manager& mgr, context_ptr c, const pdu_slice& sl)
{
    std::vector<unsigned char> empty;
    address src;
    address dest;
    src.set(empty, APPLICATION, RTP_SSL);
    dest.set(empty, APPLICATION, RTP_SSL);

    flow_address f(src, dest, sl.direc);

    rtp_context::ptr fc = rtp_context::get_or_create(c, f);

    // Set / update TTL on the context.
    // 120 seconds.
    fc->set_ttl(context::default_ttl);

    // Pass whole RTP SSL message.
    auto ev =
	std::make_shared<event::rtp_ssl>(fc, sl.start, sl.end, sl.time);
    mgr.handle(ev);

}

