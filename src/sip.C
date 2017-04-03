
#include <cybermon/sip.h>

#include <boost/regex.hpp>

#include <string>

#include <cybermon/address.h>
#include <cybermon/flow.h>
#include <cybermon/sip_context.h>


using namespace cybermon;


void sip::process(manager& mgr, context_ptr c, pdu_iter s, pdu_iter e)
{
    std::vector<unsigned char> empty;
    address src;
    address dest;
    src.set(empty, APPLICATION, SIP);
    dest.set(empty, APPLICATION, SIP);

    flow_address f(src, dest);

    sip_context::ptr fc = sip_context::get_or_create(c, f);

    // Set / update TTL on the context.
    // 120 seconds.
    fc->set_ttl(context::default_ttl);

    static const boost::regex sip_request("(INVITE|BYE) (.*) SIP/2\\.. .*", boost::regex::extended);

    static const boost::regex sip_response("SIP/2\\.. .*");

    std::string ident_buffer;

    // Copy into the ident buffer.
    ident_buffer.insert(ident_buffer.end(), s, e);

    boost::match_results<std::string::const_iterator> what;

    if (regex_search(ident_buffer, what, sip_request, boost::match_continuous))
    {
        // For now just print the Invite or Bye line
//        std::cout << what[0] << std::endl;
    }
    else if (regex_search(ident_buffer, what, sip_response, boost::match_continuous))
    {
        // For now just print the Response line
//        std::cout << what[0] << std::endl;
    }

    // Pass whole SIP message.
    mgr.sip(fc, s, e);
}

