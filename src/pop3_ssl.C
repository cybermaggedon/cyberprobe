
#include <cybermon/pop3_ssl.h>

#include <cybermon/address.h>
#include <cybermon/flow.h>
#include <cybermon/pop3_ssl_context.h>


using namespace cybermon;


void pop3_ssl::process(manager& mgr, context_ptr c, pdu_iter s, pdu_iter e)
{
    std::vector<unsigned char> empty;
    address src;
    address dest;
    src.set(empty, APPLICATION, POP3_SSL);
    dest.set(empty, APPLICATION, POP3_SSL);

    flow_address f(src, dest);

    pop3_ssl_context::ptr fc = pop3_ssl_context::get_or_create(c, f);

    // Set / update TTL on the context.
    // 120 seconds.
    fc->set_ttl(context::default_ttl);

    // Pass whole POP3 SSL message.
    mgr.pop3_ssl(fc, s, e);
}

