
#include <cybermon/imap.h>

#include <cybermon/address.h>
#include <cybermon/flow.h>
#include <cybermon/imap_context.h>


using namespace cybermon;


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
    mgr.imap(fc, s, e, sl.time);

}

