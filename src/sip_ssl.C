
#include <cybermon/sip_ssl.h>

#include <cybermon/address.h>
#include <cybermon/flow.h>
#include <cybermon/sip_context.h>


using namespace cybermon;


void sip_ssl::process(manager& mgr, context_ptr c, const pdu_slice& sl)
{
    std::vector<unsigned char> empty;
    address src;
    address dest;
    src.set(empty, APPLICATION, SIP_SSL);
    dest.set(empty, APPLICATION, SIP_SSL);

    flow_address f(src, dest, sl.direc);

    sip_context::ptr fc = sip_context::get_or_create(c, f);

    // Set / update TTL on the context.
    // 120 seconds.
    fc->set_ttl(context::default_ttl);

    // Pass whole SIP SSL message.
    mgr.sip_ssl(fc, sl.start, sl.end, sl.time);
}

