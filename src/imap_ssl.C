
#include <cybermon/imap_ssl.h>

#include <cybermon/address.h>
#include <cybermon/flow.h>
#include <cybermon/imap_ssl_context.h>


using namespace cybermon;


void imap_ssl::process(manager& mgr, context_ptr c, pdu_iter s, pdu_iter e)
{
    std::vector<unsigned char> empty;
    address src;
    address dest;
    src.set(empty, APPLICATION, IMAP_SSL);
    dest.set(empty, APPLICATION, IMAP_SSL);

    flow_address f(src, dest);

    imap_ssl_context::ptr fc = imap_ssl_context::get_or_create(c, f);

    // Set / update TTL on the context.
    // 120 seconds.
    fc->set_ttl(context::default_ttl);

    // Pass whole IMAP SSL message.
    mgr.imap_ssl(fc, s, e);
}

