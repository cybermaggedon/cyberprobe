
#include <cybermon/rtp.h>

#include <boost/regex.hpp>

#include <string>

#include <cybermon/address.h>
#include <cybermon/flow.h>
#include <cybermon/rtp_context.h>


using namespace cybermon;


void rtp::process(manager& mgr, context_ptr c, pdu_iter s, pdu_iter e)
{
    std::vector<unsigned char> empty;
    address src;
    address dest;
    src.set(empty, APPLICATION, RTP);
    dest.set(empty, APPLICATION, RTP);

    flow_address f(src, dest);

    rtp_context::ptr fc = rtp_context::get_or_create(c, f);

    // Set / update TTL on the context.
    // 120 seconds.
    fc->set_ttl(context::default_ttl);

    std::cout << "RTP" << std::endl;

    // Pass whole RTP message.
    mgr.rtp(fc, s, e);
}

