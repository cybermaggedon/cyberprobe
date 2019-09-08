
#include <cyberprobe/protocol/imap_ssl.h>

#include <cyberprobe/protocol/address.h>
#include <cyberprobe/protocol/flow.h>
#include <cyberprobe/protocol/imap_ssl_context.h>
#include <cyberprobe/event/event_implementations.h>

using namespace cyberprobe::protocol;

void imap_ssl::process(manager& mgr, context_ptr c, const pdu_slice& sl)
{
    pdu_iter s = sl.start;
    pdu_iter e = sl.end;

    std::vector<unsigned char> empty;
    address src;
    address dest;
    src.set(empty, APPLICATION, IMAP_SSL);
    dest.set(empty, APPLICATION, IMAP_SSL);

    flow_address f(src, dest, sl.direc);

    imap_ssl_context::ptr fc = imap_ssl_context::get_or_create(c, f);

    // Set / update TTL on the context.
    // 120 seconds.
    fc->set_ttl(context::default_ttl);

    // Pass whole IMAP SSL message.
    auto ev =
	std::make_shared<event::imap_ssl>(fc, s, e, sl.time);
    mgr.handle(ev);

}

