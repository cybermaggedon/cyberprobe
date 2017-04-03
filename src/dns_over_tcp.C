
#include <cybermon/dns_over_tcp.h>

#include <cybermon/address.h>
#include <cybermon/dns_context.h>
#include <cybermon/flow.h>


using namespace cybermon;


void dns_over_tcp::process(manager& mgr, context_ptr c, pdu_iter s, pdu_iter e)
{
    if ((e - s) < 12)
    {
        throw exception("Invalid DNS header length");
    }

    // Parse DNS.
    dns_decoder dec(s, e);
    dec.parse();

    std::vector<unsigned char> id;
    id.resize(2);
    id[0] = (dec.hdr.id & 0xff00) >> 8;
    id[1] = dec.hdr.id & 0xff;
    
    address src, dest;
    src.set(id, APPLICATION, DNS_OVER_TCP);
    dest.set(id, APPLICATION, DNS_OVER_TCP);

    flow_address f(src, dest);

    dns_context::ptr fc = dns_context::get_or_create(c, f);

    fc->lock.lock();

    try
    {
        mgr.dns_message(fc, dec.hdr, dec.queries, dec.answers,
                             dec.authorities, dec.additional);
    }
    catch (std::exception& e)
    {
	    fc->lock.unlock();
	    throw;
    }

    fc->lock.unlock();
}

