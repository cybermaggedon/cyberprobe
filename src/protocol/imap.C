
#include <cyberprobe/protocol/imap.h>

#include <cyberprobe/protocol/address.h>
#include <cyberprobe/protocol/flow.h>
#include <cyberprobe/protocol/imap_context.h>
#include <cyberprobe/event/event_implementations.h>

using namespace cyberprobe::protocol;


void imap::process(manager& mgr, context_ptr c, const pdu_slice& sl)
{
    pdu_iter s = sl.start;
    pdu_iter e = sl.end;

    std::vector<unsigned char> empty;
    address src;
    address dest;
    src.set(empty, APPLICATION, IMAP);
    dest.set(empty, APPLICATION, IMAP);

    flow_address f(src, dest, sl.direc);

    imap_context::ptr fc = imap_context::get_or_create(c, f);

    // Set / update TTL on the context.
    // 120 seconds.
    fc->set_ttl(context::default_ttl);

    // Pass whole IMAP message.
    auto ev =
	std::make_shared<event::imap>(fc, s, e, sl.time);
    mgr.handle(ev);

}

