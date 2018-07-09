
#include <cybermon/rtp_ssl.h>

#include <cybermon/address.h>
#include <cybermon/flow.h>
#include <cybermon/rtp_context.h>


using namespace cybermon;


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
    mgr.rtp_ssl(fc, sl.start, sl.end, sl.time);
}

