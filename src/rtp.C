
#include <cybermon/rtp.h>

#include <boost/regex.hpp>

#include <string>

#include <cybermon/address.h>
#include <cybermon/flow.h>
#include <cybermon/rtp_context.h>
#include <cybermon/event_implementations.h>


using namespace cybermon;


void rtp::process(manager& mgr, context_ptr c, const pdu_slice& sl)
{
    std::vector<unsigned char> empty;
    address src;
    address dest;
    src.set(empty, APPLICATION, RTP);
    dest.set(empty, APPLICATION, RTP);

    flow_address f(src, dest, sl.direc);

    rtp_context::ptr fc = rtp_context::get_or_create(c, f);

    // Set / update TTL on the context.
    // 120 seconds.
    fc->set_ttl(context::default_ttl);

    // Pass whole RTP message.
    auto ev =
	std::make_shared<event::rtp>(fc, sl.start, sl.end, sl.time);
    mgr.handle(ev);
	
}

