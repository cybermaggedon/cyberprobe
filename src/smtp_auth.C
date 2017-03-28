
#include <cybermon/smtp_auth.h>

#include <cybermon/address.h>
#include <cybermon/flow.h>
#include <cybermon/manager.h>
#include <cybermon/smtp_auth_context.h>


using namespace cybermon;


void smtp_auth::process(manager& mgr, context_ptr c, pdu_iter s, pdu_iter e)
{
    std::vector<unsigned char> empty;
    address src;
    address dest;
    src.set(empty, APPLICATION, SMTP_AUTH);
    dest.set(empty, APPLICATION, SMTP_AUTH);

    flow_address f(src, dest);

    smtp_auth_context::ptr fc = smtp_auth_context::get_or_create(c, f);

    // Set / update TTL on the context.
    // 120 seconds.
    fc->set_ttl(context::default_ttl);

    // Pass whole SMTP_AUTH message.
    mgr.smtp_auth(fc, s, e);
}

