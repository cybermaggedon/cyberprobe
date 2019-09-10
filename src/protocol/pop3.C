
#include <cyberprobe/protocol/pop3.h>

#include <cyberprobe/protocol/address.h>
#include <cyberprobe/protocol/flow.h>
#include <cyberprobe/protocol/pop3_context.h>
#include <cyberprobe/event/event_implementations.h>


using namespace cyberprobe::protocol;


void pop3::process(manager& mgr, context_ptr c, const pdu_slice& sl)
{
    std::vector<unsigned char> empty;
    address src;
    address dest;
    src.set(empty, APPLICATION, POP3);
    dest.set(empty, APPLICATION, POP3);

    flow_address f(src, dest, sl.direc);

    pop3_context::ptr fc = pop3_context::get_or_create(c, f);

    // Set / update TTL on the context.
    // 120 seconds.
    fc->set_ttl(context::default_ttl);

    // Pass whole POP3 message.
    auto ev =
	std::make_shared<event::pop3>(fc, sl.start, sl.end, sl.time);
    mgr.handle(ev);
}

