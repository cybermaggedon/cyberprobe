
#include <cybermon/pop3.h>

#include <cybermon/address.h>
#include <cybermon/flow.h>
#include <cybermon/pop3_context.h>


using namespace cybermon;


void pop3::process(manager& mgr, context_ptr c, const pdu_slice& sl)
{
    std::vector<unsigned char> empty;
    address src;
    address dest;
    src.set(empty, APPLICATION, POP3);
    dest.set(empty, APPLICATION, POP3);

    flow_address f(src, dest);

    pop3_context::ptr fc = pop3_context::get_or_create(c, f);

    // Set / update TTL on the context.
    // 120 seconds.
    fc->set_ttl(context::default_ttl);

    // Pass whole POP3 message.
    mgr.pop3(fc, sl.start, sl.end, sl.time);
}

